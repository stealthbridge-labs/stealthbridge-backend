//! Durable account-owned planning records. Never a quote or spending authority.
use crate::{
    customer_ciphertext_vault::{authorize_account_request, EncryptedEnvelope},
    server::AppState,
};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
const DOMAIN: &str = "stealthbridge-payment-instructions-v1";
const PATH: &str = "/v1/account/instructions";
const LIMIT: i64 = 50;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Create {
    id: Uuid,
    corridor_id: Uuid,
    route_fingerprint: String,
    expires_in_seconds: i64,
    encrypted: EncryptedEnvelope,
}
impl Create {
    fn valid(&self) -> bool {
        !self.id.is_nil()
            && !self.corridor_id.is_nil()
            && (300..=86400).contains(&self.expires_in_seconds)
            && self.route_fingerprint.len() == 64
            && self
                .route_fingerprint
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.encrypted.valid()
            && serde_json::to_vec(&self.encrypted).is_ok_and(|v| v.len() <= 4000)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cancel {
    id: Uuid,
    expected_revision: i32,
}
#[derive(Debug)]
enum StoreError {
    Database(sqlx::Error),
    Conflict,
}
impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        Self::Database(e)
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
fn enabled() -> bool {
    std::env::var("STEALTHBRIDGE_PAYMENT_INSTRUCTIONS_ENABLED")
        .ok()
        .as_deref()
        == Some("true")
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn route_fingerprint(
    id: Uuid,
    origin: &str,
    destination: &str,
    asset: &str,
    issuer: Option<&str>,
    rail: &str,
) -> String {
    digest(
        format!(
            "StealthBridge route snapshot v1\n{id}\n{origin}\n{destination}\n{asset}\n{}\n{rail}\n",
            issuer.unwrap_or("")
        )
        .as_bytes(),
    )
}
async fn lock_account(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account: &str,
    nonce: Uuid,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 92716))")
        .bind(account)
        .execute(&mut **tx)
        .await?;
    let used: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM customer_payment_instruction_receipts WHERE nonce=$1)",
    )
    .bind(nonce)
    .fetch_one(&mut **tx)
    .await?;
    if used {
        return Err(StoreError::Conflict);
    }
    Ok(())
}
async fn claim_nonce(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account: &str,
    nonce: Uuid,
    method: &str,
) -> Result<(), StoreError> {
    let used = sqlx::query_scalar::<_, Uuid>("INSERT INTO customer_payment_instruction_receipts(nonce,account_address,operation) VALUES($1,$2,$3) ON CONFLICT(nonce) DO NOTHING RETURNING nonce")
        .bind(nonce).bind(account).bind(method).fetch_optional(&mut **tx).await?;
    if used.is_none() {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

async fn save(
    db: &PgPool,
    account: &str,
    nonce: Uuid,
    input: &Create,
    stamp: i64,
) -> Result<(), StoreError> {
    let payload = serde_json::to_vec(input).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let hash = digest(&payload);
    let mut tx = db.begin().await?;
    lock_account(&mut tx, account, nonce).await?;
    let existing: Option<String> = sqlx::query_scalar("SELECT request_sha256 FROM customer_payment_instructions WHERE account_address=$1 AND id=$2")
        .bind(account).bind(input.id).fetch_optional(&mut *tx).await?;
    if let Some(existing) = existing {
        if existing != hash {
            return Err(StoreError::Conflict);
        }
        tx.commit().await?;
        return Ok(());
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM customer_payment_instructions WHERE account_address=$1",
    )
    .bind(account)
    .fetch_one(&mut *tx)
    .await?;
    if count >= LIMIT {
        return Err(StoreError::Conflict);
    }
    // Lock catalog metadata against an operator edit during registration.
    let route = sqlx::query("SELECT origin_country,destination_country,asset_code,asset_issuer,privacy_rail FROM corridors WHERE id=$1 AND enabled=true FOR SHARE")
        .bind(input.corridor_id).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
    let origin: String = route.try_get("origin_country")?;
    let destination: String = route.try_get("destination_country")?;
    let asset: String = route.try_get("asset_code")?;
    let issuer: Option<String> = route.try_get("asset_issuer")?;
    let rail: String = route.try_get("privacy_rail")?;
    if input.route_fingerprint
        != route_fingerprint(
            input.corridor_id,
            &origin,
            &destination,
            &asset,
            issuer.as_deref(),
            &rail,
        )
    {
        return Err(StoreError::Conflict);
    }
    let expires = stamp
        .checked_add(input.expires_in_seconds)
        .ok_or(StoreError::Conflict)?;
    let envelope =
        serde_json::to_value(&input.encrypted).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    claim_nonce(&mut tx, account, nonce, "PUT").await?;
    sqlx::query("INSERT INTO customer_payment_instructions(account_address,id,corridor_id,route_fingerprint,request_sha256,envelope,created_at_unix,expires_at_unix) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(account).bind(input.id).bind(input.corridor_id).bind(&input.route_fingerprint).bind(hash).bind(envelope).bind(stamp).bind(expires).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO customer_payment_instruction_events(account_address,instruction_id,revision,state,recorded_at_unix) VALUES($1,$2,1,'saved',$3)")
        .bind(account).bind(input.id).bind(stamp).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
async fn cancel(
    db: &PgPool,
    account: &str,
    nonce: Uuid,
    input: &Cancel,
    stamp: i64,
) -> Result<(), StoreError> {
    let mut tx = db.begin().await?;
    lock_account(&mut tx, account, nonce).await?;
    let row = sqlx::query("SELECT state,revision,expires_at_unix FROM customer_payment_instructions WHERE account_address=$1 AND id=$2 FOR UPDATE")
        .bind(account).bind(input.id).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
    let state: String = row.try_get("state")?;
    let revision: i32 = row.try_get("revision")?;
    if state == "cancelled" && revision == input.expected_revision + 1 {
        tx.commit().await?;
        return Ok(());
    }
    if state != "saved"
        || revision != input.expected_revision
        || stamp >= row.try_get::<i64, _>("expires_at_unix")?
    {
        return Err(StoreError::Conflict);
    }
    claim_nonce(&mut tx, account, nonce, "POST").await?;
    sqlx::query("UPDATE customer_payment_instructions SET state='cancelled',revision=2 WHERE account_address=$1 AND id=$2")
        .bind(account).bind(input.id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO customer_payment_instruction_events(account_address,instruction_id,revision,state,recorded_at_unix) VALUES($1,$2,2,'cancelled',$3)")
        .bind(account).bind(input.id).bind(stamp).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
async fn directory(db: &PgPool, account: &str, stamp: i64) -> Result<Value, sqlx::Error> {
    let rows = sqlx::query("SELECT id,corridor_id,route_fingerprint,envelope,state,revision,created_at_unix,expires_at_unix,(SELECT recorded_at_unix FROM customer_payment_instruction_events e WHERE e.account_address=i.account_address AND e.instruction_id=i.id AND e.revision=2) AS cancelled_at_unix FROM customer_payment_instructions i WHERE account_address=$1 ORDER BY created_at_unix DESC,id DESC LIMIT 51")
        .bind(account).fetch_all(db).await?;
    if rows.len() > LIMIT as usize {
        return Err(sqlx::Error::Protocol("instruction quota exceeded".into()));
    }
    let mut items = Vec::new();
    for row in rows {
        let state: String = row.try_get("state")?;
        let expires: i64 = row.try_get("expires_at_unix")?;
        items.push(json!({"id":row.try_get::<Uuid,_>("id")?,"corridor_id":row.try_get::<Uuid,_>("corridor_id")?,
            "route_fingerprint":row.try_get::<String,_>("route_fingerprint")?,"encrypted":row.try_get::<Value,_>("envelope")?,
            "state":if state=="saved" && stamp>=expires {"expired"} else {&state},"revision":row.try_get::<i32,_>("revision")?,
            "created_at_unix":row.try_get::<i64,_>("created_at_unix")?,"expires_at_unix":expires,"cancelled_at_unix":row.try_get::<Option<i64>,_>("cancelled_at_unix")?}));
    }
    Ok(
        json!({"schema_version":1,"network":"testnet","source":"customer-payment-instructions","account_address":account,
        "observed_at_unix":stamp,"items":items,"payment_execution_enabled":false,"plaintext_available_to_server":false}),
    )
}
async fn handle(state: Arc<AppState>, headers: HeaderMap, body: Bytes, method: &str) -> Response {
    let result = async {
        if !enabled() {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        if method != "GET" && (body.is_empty() || body.len() > 6000) {
            return StatusCode::BAD_REQUEST.into_response();
        }
        let stamp = now();
        let Some((account, nonce)) =
            authorize_account_request(&headers, &state, method, &body, stamp, DOMAIN, PATH)
        else {
            return StatusCode::UNAUTHORIZED.into_response();
        };
        let Some(db) = state.db.as_ref() else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        if method == "GET" {
            return match directory(db, &account, stamp).await {
                Ok(data) => Json(data).into_response(),
                Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
        }
        let Some(nonce) = nonce else {
            return StatusCode::UNAUTHORIZED.into_response();
        };
        let result = if method == "PUT" {
            let Ok(input) = serde_json::from_slice::<Create>(&body) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            if !input.valid() {
                return StatusCode::BAD_REQUEST.into_response();
            }
            save(db, &account, nonce, &input, stamp).await
        } else {
            let Ok(input) = serde_json::from_slice::<Cancel>(&body) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            if input.id.is_nil() || input.expected_revision != 1 {
                return StatusCode::BAD_REQUEST.into_response();
            }
            cancel(db, &account, nonce, &input, stamp).await
        };
        match result {
            Ok(()) => StatusCode::NO_CONTENT,
            Err(StoreError::Conflict) => StatusCode::CONFLICT,
            Err(StoreError::Database(e)) => {
                let _ = e;
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
        .into_response()
    };
    let mut response = tokio::time::timeout(Duration::from_secs(4), result)
        .await
        .unwrap_or_else(|_| StatusCode::SERVICE_UNAVAILABLE.into_response());
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    response
}
pub async fn get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle(state, headers, Bytes::new(), "GET").await
}
pub async fn put(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    handle(state, headers, body, "PUT").await
}
pub async fn post(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    handle(state, headers, body, "POST").await
}

#[cfg(test)]
mod tests {
    use super::*;
    const OWNER: &str = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
    const OTHER: &str = "GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
    fn input(corridor_id: Uuid) -> Create {
        serde_json::from_value(json!({"id":Uuid::new_v4(),"corridor_id":corridor_id,
            "route_fingerprint":route_fingerprint(corridor_id,"AA","BB","TEST_INSTRUCTION",None,"private-payments"),"expires_in_seconds":300,
            "encrypted":{"schema_version":1,"network":"testnet","cipher":"AES-256-GCM","kdf":"PBKDF2-HMAC-SHA256","iterations":600000,
            "salt":"AAAAAAAAAAAAAAAAAAAAAA","iv":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"}})).unwrap()
    }
    #[test]
    fn route_snapshot_matches_independent_sdk_vector() {
        assert_eq!(
            route_fingerprint(
                Uuid::parse_str("a12ef783-d60b-4427-aa62-d2562acd4cef").unwrap(),
                "NG",
                "GB",
                "USDC",
                None,
                "private-payments"
            ),
            "20c275c9036c67194652e03698526070566bafc86cb1cc523f76df6161441c20"
        );
    }
    #[test]
    fn rejects_plaintext_authority_and_unsupported_expiration() {
        let mut value = serde_json::to_value(input(Uuid::new_v4())).unwrap();
        assert!(serde_json::from_value::<Create>(value.clone())
            .unwrap()
            .valid());
        let mut oversized = value.clone();
        oversized["encrypted"]["ciphertext"] = json!("A".repeat(4096));
        assert!(!serde_json::from_value::<Create>(oversized).unwrap().valid());
        value["recipient"] = json!("NEVER_ACCEPT_PLAINTEXT");
        assert!(serde_json::from_value::<Create>(value).is_err());
        let mut data = input(Uuid::new_v4());
        data.expires_in_seconds = 86401;
        assert!(!data.valid());
        data.expires_in_seconds = 299;
        assert!(!data.valid());
    }
    #[test]
    fn authentication_binds_domain_method_body_account_and_freshness() {
        use hmac::{Hmac, Mac};
        let mut state = AppState::without_db();
        let secret = b"instruction-ci-fixture-bridge-secret-32-bytes";
        state.account_bridge_secret = Some(Arc::new(secret.to_vec()));
        let nonce = Uuid::new_v4();
        let body = b"{}";
        let stamp = now();
        let text = format!(
            "{DOMAIN}\nPUT\n{PATH}\n{OWNER}\n{stamp}\n{nonce}\n{}\n",
            digest(body)
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(text.as_bytes());
        let mut headers = HeaderMap::new();
        for (key, value) in [
            ("x-stealthbridge-account", OWNER.to_owned()),
            ("x-stealthbridge-issued-at", stamp.to_string()),
            ("x-stealthbridge-nonce", nonce.to_string()),
            (
                "x-stealthbridge-signature",
                hex::encode(mac.finalize().into_bytes()),
            ),
        ] {
            headers.insert(key, value.parse().unwrap());
        }
        let auth =
            |h: &HeaderMap, m, b, t, d, p| authorize_account_request(h, &state, m, b, t, d, p);
        assert!(auth(&headers, "PUT", body, stamp, DOMAIN, PATH).is_some());
        assert!(auth(&headers, "POST", body, stamp, DOMAIN, PATH).is_none());
        assert!(auth(&headers, "PUT", b"different", stamp, DOMAIN, PATH).is_none());
        assert!(auth(&headers, "PUT", body, stamp + 31, DOMAIN, PATH).is_none());
        assert!(auth(
            &headers,
            "PUT",
            body,
            stamp,
            "stealthbridge-customer-ciphertext-vault-v1",
            "/v1/account/drafts"
        )
        .is_none());
        headers.insert("x-stealthbridge-account", OTHER.parse().unwrap());
        assert!(auth(&headers, "PUT", body, stamp, DOMAIN, PATH).is_none());
    }
    #[tokio::test]
    async fn durable_instructions_are_private_scoped_idempotent_expiring_and_cancellable() {
        let db = PgPool::connect(&std::env::var("DATABASE_URL").expect("isolated CI database"))
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        let corridor = Uuid::new_v4();
        sqlx::query("INSERT INTO corridors(id,origin_country,destination_country,asset_code,privacy_rail,enabled) VALUES($1,'AA','BB','TEST_INSTRUCTION','private-payments',true)").bind(corridor).execute(&db).await.unwrap();
        let data = input(corridor);
        let stamp = now();
        let nonce = Uuid::new_v4();
        let nonce2 = Uuid::new_v4();
        let (a, b) = tokio::join!(
            save(&db, OWNER, nonce, &data, stamp),
            save(&db, OWNER, nonce2, &data, stamp)
        );
        assert!(a.is_ok() && b.is_ok());
        let spent: Uuid = sqlx::query_scalar(
            "SELECT nonce FROM customer_payment_instruction_receipts WHERE nonce IN ($1,$2)",
        )
        .bind(nonce)
        .bind(nonce2)
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(matches!(
            save(&db, OWNER, spent, &data, stamp).await,
            Err(StoreError::Conflict)
        ));
        let mut changed = input(corridor);
        changed.id = data.id;
        changed.expires_in_seconds = 600;
        assert!(matches!(
            save(&db, OWNER, Uuid::new_v4(), &changed, stamp).await,
            Err(StoreError::Conflict)
        ));
        let list = directory(&db, OWNER, stamp).await.unwrap();
        assert_eq!(
            list["items"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v["id"] == data.id.to_string())
                .count(),
            1
        );
        assert_eq!(
            directory(&db, OTHER, stamp).await.unwrap()["items"],
            json!([])
        );
        assert_eq!(list["payment_execution_enabled"], false);
        let cancel_input = Cancel {
            id: data.id,
            expected_revision: 1,
        };
        assert!(matches!(
            cancel(&db, OTHER, Uuid::new_v4(), &cancel_input, stamp).await,
            Err(StoreError::Conflict)
        ));
        let (a, b) = tokio::join!(
            cancel(&db, OWNER, Uuid::new_v4(), &cancel_input, stamp),
            cancel(&db, OWNER, Uuid::new_v4(), &cancel_input, stamp)
        );
        assert!(a.is_ok() && b.is_ok());
        let events:i64=sqlx::query_scalar("SELECT count(*) FROM customer_payment_instruction_events WHERE account_address=$1 AND instruction_id=$2").bind(OWNER).bind(data.id).fetch_one(&db).await.unwrap();
        assert_eq!(events, 2);
        let expired = input(corridor);
        save(&db, OWNER, Uuid::new_v4(), &expired, stamp)
            .await
            .unwrap();
        assert!(matches!(
            cancel(
                &db,
                OWNER,
                Uuid::new_v4(),
                &Cancel {
                    id: expired.id,
                    expected_revision: 1
                },
                stamp + 300
            )
            .await,
            Err(StoreError::Conflict)
        ));
        let list = directory(&db, OWNER, stamp + 300).await.unwrap();
        assert!(list["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == expired.id.to_string() && v["state"] == "expired"));
        let stale = input(corridor);
        sqlx::query("UPDATE corridors SET asset_code='CHANGED_TEST' WHERE id=$1")
            .bind(corridor)
            .execute(&db)
            .await
            .unwrap();
        assert!(matches!(
            save(&db, OWNER, Uuid::new_v4(), &stale, stamp).await,
            Err(StoreError::Conflict)
        ));
        for id in [data.id, expired.id] {
            sqlx::query("DELETE FROM customer_payment_instruction_events WHERE account_address=$1 AND instruction_id=$2").bind(OWNER).bind(id).execute(&db).await.unwrap();
            sqlx::query(
                "DELETE FROM customer_payment_instructions WHERE account_address=$1 AND id=$2",
            )
            .bind(OWNER)
            .bind(id)
            .execute(&db)
            .await
            .unwrap();
        }
        sqlx::query("DELETE FROM corridors WHERE id=$1")
            .bind(corridor)
            .execute(&db)
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn event_failure_rolls_back_record_and_receipt_and_retries_do_not_grow_storage() {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").expect("isolated CI database"))
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        let account = "GALROFYXC4LROFYXC4LROFYXC4LROFYXC4LROFYXC4LROFYXC4LRPFOD";
        let baseline: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM customer_payment_instruction_receipts WHERE account_address=$1",
        )
        .bind(account)
        .fetch_one(&db)
        .await
        .unwrap();
        let corridor = Uuid::new_v4();
        let data = input(corridor);
        let stamp = now();
        sqlx::query("INSERT INTO corridors(id,origin_country,destination_country,asset_code,privacy_rail,enabled) VALUES($1,'AA','BB','TEST_INSTRUCTION','private-payments',true)").bind(corridor).execute(&db).await.unwrap();
        sqlx::query("CREATE TEMP TABLE customer_payment_instruction_events (LIKE public.customer_payment_instruction_events INCLUDING ALL, CHECK (current_setting('stealthbridge.fail_instruction_event',true) IS DISTINCT FROM 'on'))").execute(&db).await.unwrap();
        sqlx::query("SET stealthbridge.fail_instruction_event='on'")
            .execute(&db)
            .await
            .unwrap();
        assert!(matches!(
            save(&db, account, Uuid::new_v4(), &data, stamp).await,
            Err(StoreError::Database(_))
        ));
        assert_eq!(
            directory(&db, account, stamp).await.unwrap()["items"],
            json!([])
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM customer_payment_instruction_receipts WHERE account_address=$1",
        )
        .bind(account)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(count, baseline);
        sqlx::query("SET stealthbridge.fail_instruction_event='off'")
            .execute(&db)
            .await
            .unwrap();
        save(&db, account, Uuid::new_v4(), &data, stamp)
            .await
            .unwrap();
        let request = Cancel {
            id: data.id,
            expected_revision: 1,
        };
        sqlx::query("SET stealthbridge.fail_instruction_event='on'")
            .execute(&db)
            .await
            .unwrap();
        assert!(matches!(
            cancel(&db, account, Uuid::new_v4(), &request, stamp).await,
            Err(StoreError::Database(_))
        ));
        assert_eq!(
            directory(&db, account, stamp).await.unwrap()["items"][0]["state"],
            "saved"
        );
        sqlx::query("SET stealthbridge.fail_instruction_event='off'")
            .execute(&db)
            .await
            .unwrap();
        for _ in 0..5 {
            save(&db, account, Uuid::new_v4(), &data, stamp)
                .await
                .unwrap();
            cancel(&db, account, Uuid::new_v4(), &request, stamp)
                .await
                .unwrap();
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM customer_payment_instruction_receipts WHERE account_address=$1",
        )
        .bind(account)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(count, baseline + 2);
        sqlx::query("DELETE FROM customer_payment_instruction_events WHERE account_address=$1")
            .bind(account)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM customer_payment_instructions WHERE account_address=$1")
            .bind(account)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM corridors WHERE id=$1")
            .bind(corridor)
            .execute(&db)
            .await
            .unwrap();
    }
}
