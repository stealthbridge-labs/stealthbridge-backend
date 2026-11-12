//! Optional ciphertext-only customer drafts. No money-moving endpoint, keys,
//! plaintext inspection, ZK claim or transaction signing. Mutations require
//! authenticated Next.js BFF HMAC, fresh timestamp and single-use nonce.
use crate::{server::AppState, wallet};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
const DOMAIN: &str = "stealthbridge-customer-ciphertext-vault-v1";
const PATH: &str = "/v1/account/drafts";
const MAX_SLOTS: i64 = 8;
type HmacSha256 = Hmac<Sha256>;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EncryptedEnvelope {
    schema_version: u8,
    network: String,
    cipher: String,
    kdf: String,
    iterations: u32,
    salt: String,
    iv: String,
    ciphertext: String,
}
/// Decode only minimal, unpadded canonical RFC 4648 base64url. Reject
/// non-zero discarded bits, invalid alphabet, oversized ciphertext and empty
/// tags before storing untrusted encrypted data. No extra crate dependency.
fn canonical_b64url(s: &str, min: usize, max: usize) -> bool {
    if s.is_empty() || s.len() > 4096 || s.len() % 4 == 1 {
        return false;
    }
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    let mut decoded = 0usize;
    for b in s.bytes() {
        let n = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return false,
        };
        acc = (acc << 6) | u32::from(n);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded += 1;
            acc &= (1u32 << bits) - 1;
        }
        if decoded > max {
            return false;
        }
    }
    (min..=max).contains(&decoded) && acc == 0
}
impl EncryptedEnvelope {
    pub(crate) fn valid(&self) -> bool {
        self.schema_version == 1
            && self.network == "testnet"
            && self.cipher == "AES-256-GCM"
            && self.kdf == "PBKDF2-HMAC-SHA256"
            && self.iterations == 600_000
            && canonical_b64url(&self.salt, 16, 16)
            && canonical_b64url(&self.iv, 12, 12)
            && canonical_b64url(&self.ciphertext, 17, 3072)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveDraft {
    id: Uuid,
    expected_revision: i32,
    encrypted: EncryptedEnvelope,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteDraft {
    id: Uuid,
    expected_revision: i32,
}
#[derive(Serialize)]
struct VaultRecord {
    id: Uuid,
    revision: i32,
    updated_at_unix: i64,
    encrypted: Value,
}
#[derive(Serialize)]
struct VaultResponse {
    schema_version: u8,
    network: &'static str,
    source: &'static str,
    account_address: String,
    drafts: Vec<VaultRecord>,
    payment_execution_enabled: bool,
    plaintext_available_to_server: bool,
}
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
fn enabled() -> bool {
    std::env::var("STEALTHBRIDGE_CUSTOMER_DRAFTS_ENABLED")
        .ok()
        .as_deref()
        == Some("true")
}
pub(crate) fn authorize_account_request(
    headers: &HeaderMap,
    state: &AppState,
    method: &str,
    body: &[u8],
    now: i64,
    domain: &str,
    path: &str,
) -> Option<(String, Option<Uuid>)> {
    let secret = state
        .account_bridge_secret
        .as_ref()
        .filter(|s| s.len() >= 32)?;
    let account = headers.get("x-stealthbridge-account")?.to_str().ok()?;
    wallet::decode_account_address(account)?;
    let issued = headers.get("x-stealthbridge-issued-at")?.to_str().ok()?;
    if issued.is_empty() || issued.len() > 12 || !issued.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let timestamp = issued.parse::<i64>().ok()?;
    if timestamp <= 0 || timestamp > now + 5 || now.saturating_sub(timestamp) > 30 {
        return None;
    }
    let raw_nonce = if method == "GET" {
        ""
    } else {
        headers.get("x-stealthbridge-nonce")?.to_str().ok()?
    };
    let nonce = if method == "GET" {
        None
    } else {
        Some(
            Uuid::parse_str(raw_nonce)
                .ok()
                .filter(|u| !u.is_nil() && u.to_string() == raw_nonce)?,
        )
    };
    let digest = if method == "GET" {
        String::new()
    } else {
        hex::encode(Sha256::digest(body))
    };
    let signature = headers.get("x-stealthbridge-signature")?.to_str().ok()?;
    if signature.len() != 64 || !signature.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let supplied = hex::decode(signature).ok()?;
    let text = format!("{domain}\n{method}\n{path}\n{account}\n{issued}\n{raw_nonce}\n{digest}\n");
    let mut mac = HmacSha256::new_from_slice(secret.as_ref()).ok()?;
    mac.update(text.as_bytes());
    mac.verify_slice(&supplied).ok()?;
    Some((account.into(), nonce))
}
fn authorized(
    headers: &HeaderMap,
    state: &AppState,
    method: &str,
    body: &[u8],
    now: i64,
) -> Option<(String, Option<Uuid>)> {
    authorize_account_request(headers, state, method, body, now, DOMAIN, PATH)
}
fn response(account: String, rows: Vec<VaultRecord>) -> Response {
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(VaultResponse {
            schema_version: 1,
            network: "testnet",
            source: "customer-ciphertext-vault",
            account_address: account,
            drafts: rows,
            payment_execution_enabled: false,
            plaintext_available_to_server: false,
        }),
    )
        .into_response()
}
fn row_value(row: sqlx::postgres::PgRow) -> Result<VaultRecord, sqlx::Error> {
    Ok(VaultRecord {
        id: row.try_get("draft_id")?,
        revision: row.try_get("revision")?,
        updated_at_unix: row.try_get("updated_at_unix")?,
        encrypted: row.try_get("envelope")?,
    })
}
const SELECT:&str="SELECT draft_id,revision,envelope,EXTRACT(EPOCH FROM updated_at)::bigint AS updated_at_unix FROM customer_ciphertext_drafts WHERE account_address=$1 ORDER BY updated_at DESC,draft_id DESC LIMIT 9";
pub async fn list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !enabled() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Some((account, _)) = authorized(&headers, &state, "GET", &[], now_unix()) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match tokio::time::timeout(
        Duration::from_secs(4),
        sqlx::query(SELECT).bind(&account).fetch_all(db),
    )
    .await
    {
        Ok(Ok(rows)) if rows.len() <= MAX_SLOTS as usize => {
            match rows.into_iter().map(row_value).collect() {
                Ok(value) => response(account, value),
                Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            }
        }
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
async fn mutate(
    db: &PgPool,
    account: &str,
    nonce: Uuid,
    action: &str,
    id: Uuid,
    revision: i32,
    envelope: Option<&EncryptedEnvelope>,
) -> Result<bool, sqlx::Error> {
    let mut tx = db.begin().await?;
    // One serialized writer per account prevents concurrent 9th-slot inserts.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 92715))")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    let claimed=sqlx::query_scalar::<_,Uuid>("INSERT INTO customer_ciphertext_draft_receipts(nonce,account_address,operation) VALUES($1,$2,$3) ON CONFLICT(nonce) DO NOTHING RETURNING nonce")
  .bind(nonce).bind(account).bind(action).fetch_optional(&mut *tx).await?;
    if claimed.is_none() {
        return Ok(false);
    }
    let updated = if action == "DELETE" {
        sqlx::query("DELETE FROM customer_ciphertext_drafts WHERE account_address=$1 AND draft_id=$2 AND revision=$3")
   .bind(account).bind(id).bind(revision).execute(&mut *tx).await?.rows_affected()==1
    } else if revision == 0 {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM customer_ciphertext_drafts WHERE account_address=$1",
        )
        .bind(account)
        .fetch_one(&mut *tx)
        .await?;
        if count >= MAX_SLOTS {
            return Ok(false);
        }
        let data = serde_json::to_value(envelope.expect("validated envelope"))
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        sqlx::query("INSERT INTO customer_ciphertext_drafts(account_address,draft_id,revision,envelope) VALUES($1,$2,1,$3) ON CONFLICT(account_address,draft_id) DO NOTHING")
   .bind(account).bind(id).bind(data).execute(&mut *tx).await?.rows_affected()==1
    } else {
        let data = serde_json::to_value(envelope.expect("validated envelope"))
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        sqlx::query("UPDATE customer_ciphertext_drafts SET envelope=$4,revision=revision+1,updated_at=now() WHERE account_address=$1 AND draft_id=$2 AND revision=$3 AND revision<1000000")
   .bind(account).bind(id).bind(revision).bind(data).execute(&mut *tx).await?.rows_affected()==1
    };
    if !updated {
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}
async fn write(state: Arc<AppState>, headers: HeaderMap, body: Bytes, method: &str) -> Response {
    if !enabled() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if body.is_empty() || body.len() > 6000 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some((account, Some(nonce))) = authorized(&headers, &state, method, &body, now_unix())
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let (id, revision, envelope) = if method == "PUT" {
        let Ok(payload) = serde_json::from_slice::<SaveDraft>(&body) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        if payload.id.is_nil()
            || payload.expected_revision < 0
            || payload.expected_revision > 999999
            || !payload.encrypted.valid()
        {
            return StatusCode::BAD_REQUEST.into_response();
        }
        (
            payload.id,
            payload.expected_revision,
            Some(payload.encrypted),
        )
    } else {
        let Ok(payload) = serde_json::from_slice::<DeleteDraft>(&body) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        if payload.id.is_nil() || payload.expected_revision < 1 {
            return StatusCode::BAD_REQUEST.into_response();
        }
        (payload.id, payload.expected_revision, None)
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let result = tokio::time::timeout(
        Duration::from_secs(4),
        mutate(db, &account, nonce, method, id, revision, envelope.as_ref()),
    )
    .await;
    match result {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => StatusCode::CONFLICT.into_response(),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
pub async fn put(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    write(state, headers, body, "PUT").await
}
pub async fn delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    write(state, headers, body, "DELETE").await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_plaintext_or_authorization_claims_accepted_in_envelope() {
        let good = EncryptedEnvelope {
            schema_version: 1,
            network: "testnet".into(),
            cipher: "AES-256-GCM".into(),
            kdf: "PBKDF2-HMAC-SHA256".into(),
            iterations: 600000,
            salt: "A".repeat(22),
            iv: "A".repeat(16),
            ciphertext: "A".repeat(28),
        };
        assert!(good.valid());
        assert!(!EncryptedEnvelope {
            salt: "B".repeat(22), // last two pad bits must be zero
            ..good.clone()
        }
        .valid());
        assert!(!EncryptedEnvelope {
            iv: "=".repeat(16), // padding is forbidden
            ..good.clone()
        }
        .valid());
        assert!(!EncryptedEnvelope {
            ciphertext: "A".repeat(24) + "=", // padded tags rejected
            ..good.clone()
        }
        .valid());
        assert!(!EncryptedEnvelope {
            iterations: 1,
            ..good.clone()
        }
        .valid());
        assert!(!EncryptedEnvelope {
            network: "public".into(),
            ..good.clone()
        }
        .valid());
        assert!(serde_json::from_str::<EncryptedEnvelope>(r#"{"schema_version":1,"network":"testnet","cipher":"AES-256-GCM","kdf":"PBKDF2-HMAC-SHA256","iterations":600000,"salt":"AAAAAAAAAAAAAAAAAAAAAA","iv":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA","payment_authorized":true}"#).is_err());
    }
    #[test]
    fn canonical_encoding_matches_browser_and_rejects_nonminimal_data() {
        assert!(canonical_b64url("AAAAAAAAAAAAAAAAAAAAAA", 16, 16));
        assert!(!canonical_b64url("AAAAAAAAAAAAAAAAAAAAAB", 16, 16));
        assert!(!canonical_b64url("AAAAAAAAAAAAAAAAAAAAA=", 16, 16));
        assert!(!canonical_b64url("AA+A", 3, 3));
        assert!(!canonical_b64url("A", 0, 4));
        assert!(!canonical_b64url("AAAAAAAAAAAAAAAA", 16, 16));
        assert!(canonical_b64url("AAAAAAAAAAAAAAAA", 12, 12));
        assert!(canonical_b64url(&"A".repeat(24), 17, 3072));
        assert!(!canonical_b64url(&"A".repeat(4097), 17, 3072));
    }
    #[test]
    fn rejects_unsigned_and_cross_network_requests() {
        let state = AppState::without_db();
        let headers = HeaderMap::new();
        assert!(authorized(&headers, &state, "PUT", b"{}", now_unix()).is_none());
        assert!(serde_json::from_str::<SaveDraft>(r#"{"id":"a12ef783-d60b-4427-aa62-d2562acd4cef","expected_revision":0,"encrypted":{},"recipient":"SECRET"}"#).is_err());
    }
    #[test]
    fn signatures_are_account_method_body_and_time_bound() {
        let mut state = AppState::without_db();
        let secret = b"secure-ci-only-customer-vault-bridge-secret-00";
        state.account_bridge_secret = Some(Arc::new(secret.to_vec()));
        let account = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
        let timestamp = now_unix().to_string();
        let nonce = Uuid::new_v4().to_string();
        let body = b"{\"example\":1}";
        let digest = hex::encode(Sha256::digest(body));
        let payload = format!("{DOMAIN}\nPUT\n{PATH}\n{account}\n{timestamp}\n{nonce}\n{digest}\n");
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        let mut headers = HeaderMap::new();
        headers.insert("x-stealthbridge-account", account.parse().unwrap());
        headers.insert("x-stealthbridge-issued-at", timestamp.parse().unwrap());
        headers.insert("x-stealthbridge-nonce", nonce.parse().unwrap());
        headers.insert("x-stealthbridge-signature", signature.parse().unwrap());
        assert_eq!(
            authorized(&headers, &state, "PUT", body, now_unix())
                .unwrap()
                .0,
            account
        );
        assert!(authorized(&headers, &state, "DELETE", body, now_unix()).is_none());
        assert!(authorized(&headers, &state, "PUT", b"altered", now_unix()).is_none());
        assert!(authorized(&headers, &state, "PUT", body, now_unix() + 40).is_none());
    }

    #[test]
    fn signed_vault_requests_reject_wrong_account_timestamp_and_nonce() {
        let mut state = AppState::without_db();
        let secret = b"vault-bridge-dev-fixture-only-32-bytes-secure";
        state.account_bridge_secret = Some(Arc::new(secret.to_vec()));
        let account = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
        let issued = now_unix().to_string();
        let nonce = Uuid::new_v4().to_string();
        let body = b"{\"encrypted\":\"ciphertext-only\"}";
        let digest = hex::encode(Sha256::digest(body));
        let payload = format!("{DOMAIN}\nPUT\n{PATH}\n{account}\n{issued}\n{nonce}\n{digest}\n");
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        let mut headers = HeaderMap::new();
        headers.insert("x-stealthbridge-account", account.parse().unwrap());
        headers.insert("x-stealthbridge-issued-at", issued.parse().unwrap());
        headers.insert("x-stealthbridge-nonce", nonce.parse().unwrap());
        headers.insert("x-stealthbridge-signature", signature.parse().unwrap());
        assert!(authorized(&headers, &state, "PUT", body, now_unix()).is_some());
        let mut forged = headers.clone();
        forged.insert(
            "x-stealthbridge-account",
            "GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN"
                .parse()
                .unwrap(),
        );
        assert!(authorized(&forged, &state, "PUT", body, now_unix()).is_none());
        let mut forged = headers.clone();
        forged.insert(
            "x-stealthbridge-nonce",
            Uuid::new_v4().to_string().parse().unwrap(),
        );
        assert!(authorized(&forged, &state, "PUT", body, now_unix()).is_none());
        assert!(authorized(&headers, &state, "PUT", body, now_unix() + 31).is_none());
        assert!(authorized(&headers, &state, "DELETE", body, now_unix()).is_none());
    }
    #[tokio::test]
    async fn postgres_vault_caps_slots_even_with_competing_writers() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let db = PgPool::connect(&url).await.expect("isolated CI database");
        sqlx::migrate!("./migrations")
            .run(&db)
            .await
            .expect("vault migration");
        // A different account from the other integration test; no shared
        // cross-test row count or operator identity required.
        let owner = "GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
        let data = EncryptedEnvelope {
            schema_version: 1,
            network: "testnet".into(),
            cipher: "AES-256-GCM".into(),
            kdf: "PBKDF2-HMAC-SHA256".into(),
            iterations: 600000,
            salt: "A".repeat(22),
            iv: "A".repeat(16),
            ciphertext: "A".repeat(40),
        };
        assert!(data.valid());
        let mut inserted = Vec::new();
        for _ in 0..7 {
            let id = Uuid::new_v4();
            assert!(
                mutate(&db, owner, Uuid::new_v4(), "PUT", id, 0, Some(&data))
                    .await
                    .unwrap()
            );
            inserted.push(id);
        }
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let a = mutate(&db, owner, Uuid::new_v4(), "PUT", first, 0, Some(&data));
        let b = mutate(&db, owner, Uuid::new_v4(), "PUT", second, 0, Some(&data));
        let (one, two) = tokio::join!(a, b);
        assert_ne!(
            one.unwrap(),
            two.unwrap(),
            "exactly one ninth-slot contender must fail"
        );
        let rows = sqlx::query(SELECT)
            .bind(owner)
            .fetch_all(&db)
            .await
            .unwrap();
        assert_eq!(rows.len(), 8);
        for row in rows {
            let id: Uuid = row.try_get("draft_id").unwrap();
            assert!(mutate(&db, owner, Uuid::new_v4(), "DELETE", id, 1, None)
                .await
                .unwrap());
        }
        assert!(sqlx::query(SELECT)
            .bind(owner)
            .fetch_all(&db)
            .await
            .unwrap()
            .is_empty());
    }
    #[tokio::test]
    async fn postgres_vault_is_account_scoped_revisioned_and_replay_safe() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let db = PgPool::connect(&url).await.expect("isolated CI database");
        sqlx::migrate!("./migrations")
            .run(&db)
            .await
            .expect("vault migration");
        let owner = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
        let other = "GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
        let record = Uuid::new_v4();
        let nonce = Uuid::new_v4();
        let data = EncryptedEnvelope {
            schema_version: 1,
            network: "testnet".into(),
            cipher: "AES-256-GCM".into(),
            kdf: "PBKDF2-HMAC-SHA256".into(),
            iterations: 600000,
            salt: "A".repeat(22),
            iv: "A".repeat(16),
            ciphertext: "A".repeat(40),
        };
        assert!(mutate(&db, owner, nonce, "PUT", record, 0, Some(&data))
            .await
            .unwrap());
        assert!(!mutate(&db, owner, nonce, "PUT", record, 0, Some(&data))
            .await
            .unwrap());
        assert!(
            !mutate(&db, owner, Uuid::new_v4(), "PUT", record, 0, Some(&data))
                .await
                .unwrap()
        );
        assert!(
            !mutate(&db, owner, Uuid::new_v4(), "PUT", record, 3, Some(&data))
                .await
                .unwrap()
        );
        let one = sqlx::query(SELECT)
            .bind(owner)
            .fetch_all(&db)
            .await
            .unwrap();
        assert!(one
            .iter()
            .any(|row| row.try_get::<Uuid, _>("draft_id").unwrap() == record));
        let foreign = sqlx::query(SELECT)
            .bind(other)
            .fetch_all(&db)
            .await
            .unwrap();
        assert!(!foreign
            .iter()
            .any(|row| row.try_get::<Uuid, _>("draft_id").unwrap() == record));
        assert!(
            mutate(&db, owner, Uuid::new_v4(), "PUT", record, 1, Some(&data))
                .await
                .unwrap()
        );
        assert!(
            !mutate(&db, owner, Uuid::new_v4(), "DELETE", record, 1, None)
                .await
                .unwrap()
        );
        assert!(
            !mutate(&db, other, Uuid::new_v4(), "DELETE", record, 2, None)
                .await
                .unwrap()
        );
        assert!(
            mutate(&db, owner, Uuid::new_v4(), "DELETE", record, 2, None)
                .await
                .unwrap()
        );
        let removed = sqlx::query(SELECT)
            .bind(owner)
            .fetch_all(&db)
            .await
            .unwrap();
        assert!(!removed
            .iter()
            .any(|row| row.try_get::<Uuid, _>("draft_id").unwrap() == record));
    }
}
