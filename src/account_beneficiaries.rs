//! Account-owned saved recipients / beneficiaries persisted in PostgreSQL.
//! Supports canonical Stellar G..., M..., C..., and CAP-84 W... addresses.
//! Never verifies recipient identity, asset trustlines, or enables execution.

use crate::{customer_ciphertext_vault::authorize_account_request, server::AppState, wallet};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const DOMAIN: &str = "stealthbridge-account-beneficiaries-v1";
const PATH: &str = "/v1/account/beneficiaries";
const MAX_BENEFICIARIES_PER_ACCOUNT: i64 = 25;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpsertBeneficiary {
    id: Uuid,
    recipient_address: String,
    label: String,
    flow: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteBeneficiary {
    id: Uuid,
}

#[derive(Clone, Debug, Serialize)]
struct BeneficiaryRecord {
    id: Uuid,
    recipient_address: String,
    recipient_kind: String,
    label: String,
    flow: String,
    created_at_unix: i64,
    updated_at_unix: i64,
}

#[derive(Serialize)]
struct BeneficiaryDirectory {
    schema_version: u8,
    network: &'static str,
    source: &'static str,
    account_address: String,
    items: Vec<BeneficiaryRecord>,
    identity_verified: bool,
    payment_execution_enabled: bool,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(1)
}

fn enabled() -> bool {
    std::env::var("STEALTHBRIDGE_ACCOUNT_BENEFICIARIES_ENABLED")
        .ok()
        .as_deref()
        == Some("true")
}

fn recipient_kind_label(addr: &wallet::StellarAddress) -> &'static str {
    match addr {
        wallet::StellarAddress::Classic(_) => "classic",
        wallet::StellarAddress::MuxedClassic { .. } => "muxed-classic",
        wallet::StellarAddress::Contract(_) => "contract",
        wallet::StellarAddress::MuxedContract { .. } => "muxed-contract",
    }
}

fn valid_label(label: &str) -> bool {
    let chars = label.chars().count();
    (1..=48).contains(&chars)
        && label.trim() == label
        && !label.chars().any(|c| c.is_control() || c == '<' || c == '>')
}

fn valid_flow(flow: &str) -> bool {
    matches!(flow, "personal" | "business")
}

fn directory_response(account: String, items: Vec<BeneficiaryRecord>) -> Response {
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(BeneficiaryDirectory {
            schema_version: 1,
            network: "testnet",
            source: "neon-account-beneficiaries",
            account_address: account,
            items,
            identity_verified: false,
            payment_execution_enabled: false,
        }),
    )
        .into_response()
}

fn row_to_record(row: sqlx::postgres::PgRow) -> Result<BeneficiaryRecord, sqlx::Error> {
    Ok(BeneficiaryRecord {
        id: row.try_get("id")?,
        recipient_address: row.try_get("recipient_address")?,
        recipient_kind: row.try_get("recipient_kind")?,
        label: row.try_get("label")?,
        flow: row.try_get("flow")?,
        created_at_unix: row.try_get("created_at_unix")?,
        updated_at_unix: row.try_get("updated_at_unix")?,
    })
}

const SELECT_ALL: &str = "SELECT id, recipient_address, recipient_kind, label, flow, created_at_unix, updated_at_unix
 FROM account_beneficiaries
 WHERE account_address=$1
 ORDER BY updated_at_unix DESC, id DESC
 LIMIT 25";

pub async fn list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !enabled() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Some((account, _)) =
        authorize_account_request(&headers, &state, "GET", &[], now_unix(), DOMAIN, PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match tokio::time::timeout(
        Duration::from_secs(4),
        sqlx::query(SELECT_ALL).bind(&account).fetch_all(db),
    )
    .await
    {
        Ok(Ok(rows)) => match rows.into_iter().map(row_to_record).collect() {
            Ok(items) => directory_response(account, items),
            Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        },
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn run_upsert(
    db: &PgPool,
    account: &str,
    nonce: Uuid,
    payload: &UpsertBeneficiary,
    recipient_kind: &str,
) -> Result<Option<Vec<BeneficiaryRecord>>, sqlx::Error> {
    let now = now_unix();
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 92731))")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    let claimed = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO account_beneficiary_receipts(nonce, account_address, operation)
         VALUES($1, $2, 'PUT') ON CONFLICT(nonce) DO NOTHING RETURNING nonce",
    )
    .bind(nonce)
    .bind(account)
    .fetch_optional(&mut *tx)
    .await?;
    if claimed.is_none() {
        return Ok(None);
    }

    let existing_same = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM account_beneficiaries
         WHERE account_address=$1 AND recipient_address=$2 AND flow=$3",
    )
    .bind(account)
    .bind(&payload.recipient_address)
    .bind(&payload.flow)
    .fetch_one(&mut *tx)
    .await?;

    if existing_same == 0 {
        let total = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM account_beneficiaries WHERE account_address=$1",
        )
        .bind(account)
        .fetch_one(&mut *tx)
        .await?;
        if total >= MAX_BENEFICIARIES_PER_ACCOUNT {
            return Ok(None);
        }
    }

    sqlx::query(
        "INSERT INTO account_beneficiaries(
            account_address, id, recipient_address, recipient_kind, label, flow, created_at_unix, updated_at_unix
         ) VALUES($1, $2, $3, $4, $5, $6, $7, $7)
         ON CONFLICT(account_address, recipient_address, flow) DO UPDATE SET
            label = EXCLUDED.label,
            recipient_kind = EXCLUDED.recipient_kind,
            updated_at_unix = EXCLUDED.updated_at_unix",
    )
    .bind(account)
    .bind(payload.id)
    .bind(&payload.recipient_address)
    .bind(recipient_kind)
    .bind(&payload.label)
    .bind(&payload.flow)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    let rows = sqlx::query(SELECT_ALL)
        .bind(account)
        .fetch_all(&mut *tx)
        .await?;
    let items: Vec<BeneficiaryRecord> = rows
        .into_iter()
        .map(row_to_record)
        .collect::<Result<Vec<_>, _>>()?;
    tx.commit().await?;
    Ok(Some(items))
}

async fn run_delete(
    db: &PgPool,
    account: &str,
    nonce: Uuid,
    id: Uuid,
) -> Result<Option<Vec<BeneficiaryRecord>>, sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 92731))")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    let claimed = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO account_beneficiary_receipts(nonce, account_address, operation)
         VALUES($1, $2, 'DELETE') ON CONFLICT(nonce) DO NOTHING RETURNING nonce",
    )
    .bind(nonce)
    .bind(account)
    .fetch_optional(&mut *tx)
    .await?;
    if claimed.is_none() {
        return Ok(None);
    }

    let affected = sqlx::query(
        "DELETE FROM account_beneficiaries WHERE account_address=$1 AND id=$2",
    )
    .bind(account)
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if affected != 1 {
        return Ok(None);
    }

    let rows = sqlx::query(SELECT_ALL)
        .bind(account)
        .fetch_all(&mut *tx)
        .await?;
    let items: Vec<BeneficiaryRecord> = rows
        .into_iter()
        .map(row_to_record)
        .collect::<Result<Vec<_>, _>>()?;
    tx.commit().await?;
    Ok(Some(items))
}

pub async fn upsert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !enabled() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if body.is_empty() || body.len() > 2048 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some((account, Some(nonce))) =
        authorize_account_request(&headers, &state, "PUT", &body, now_unix(), DOMAIN, PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(payload) = serde_json::from_slice::<UpsertBeneficiary>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if payload.id.is_nil()
        || !valid_label(&payload.label)
        || !valid_flow(&payload.flow)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(parsed_addr) = wallet::parse_canonical_stellar_address(&payload.recipient_address)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let kind = recipient_kind_label(&parsed_addr);

    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match tokio::time::timeout(
        Duration::from_secs(4),
        run_upsert(db, &account, nonce, &payload, kind),
    )
    .await
    {
        Ok(Ok(Some(items))) => directory_response(account, items),
        Ok(Ok(None)) => StatusCode::CONFLICT.into_response(),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

pub async fn remove(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !enabled() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if body.is_empty() || body.len() > 512 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some((account, Some(nonce))) =
        authorize_account_request(&headers, &state, "DELETE", &body, now_unix(), DOMAIN, PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(payload) = serde_json::from_slice::<DeleteBeneficiary>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if payload.id.is_nil() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match tokio::time::timeout(
        Duration::from_secs(4),
        run_delete(db, &account, nonce, payload.id),
    )
    .await
    {
        Ok(Ok(Some(items))) => directory_response(account, items),
        Ok(Ok(None)) => StatusCode::CONFLICT.into_response(),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    #[test]
    fn label_and_flow_validation_rejects_markup_and_whitespace() {
        assert!(valid_label("Ghana Supplier"));
        assert!(!valid_label(""));
        assert!(!valid_label(" Leading"));
        assert!(!valid_label("<script>"));
        assert!(valid_flow("personal"));
        assert!(valid_flow("business"));
        assert!(!valid_flow("admin"));
    }

    #[tokio::test]
    async fn database_beneficiaries_support_protocol30_and_replay_protection() {
        std::env::set_var("STEALTHBRIDGE_ACCOUNT_BENEFICIARIES_ENABLED", "true");
        let url = std::env::var("DATABASE_URL").expect("CI PostgreSQL");
        let pool = PgPool::connect(&url).await.expect("connect");
        sqlx::migrate!("./migrations").run(&pool).await.expect("migrate");

        let account = "GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
        let w_recipient = "WDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW6AAAAAAAAAAAFKW6A";
        let c_recipient = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
        let mut state = AppState::without_db();
        state.db = Some(pool.clone());
        let key = b"ci-test-beneficiaries-backend-hmac-secret";
        state.account_bridge_secret = Some(Arc::new(key.to_vec()));
        let app = crate::server::router(state);

        let sign = |method: &str, nonce: &str, body: &str| {
            let stamp = now_unix().to_string();
            let digest = if method == "GET" {
                String::new()
            } else {
                hex::encode(Sha256::digest(body.as_bytes()))
            };
            let text = format!("{DOMAIN}\n{method}\n{PATH}\n{account}\n{stamp}\n{nonce}\n{digest}\n");
            let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
            mac.update(text.as_bytes());
            let sig = hex::encode(mac.finalize().into_bytes());
            (stamp, sig)
        };

        let bid = Uuid::new_v4();
        let put_body = serde_json::json!({
            "id": bid,
            "recipient_address": w_recipient,
            "label": "Treasury Muxed",
            "flow": "business"
        })
        .to_string();
        let n1 = Uuid::new_v4().to_string();
        let (ts1, s1) = sign("PUT", &n1, &put_body);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(PATH)
                    .header("content-type", "application/json")
                    .header("x-stealthbridge-account", account)
                    .header("x-stealthbridge-issued-at", &ts1)
                    .header("x-stealthbridge-nonce", &n1)
                    .header("x-stealthbridge-signature", &s1)
                    .body(Body::from(put_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Replay must return 409 CONFLICT
        let replay = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(PATH)
                    .header("content-type", "application/json")
                    .header("x-stealthbridge-account", account)
                    .header("x-stealthbridge-issued-at", &ts1)
                    .header("x-stealthbridge-nonce", &n1)
                    .header("x-stealthbridge-signature", &s1)
                    .body(Body::from(put_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::CONFLICT);

        // Contract address upsert works and lists cleanly
        let cid = Uuid::new_v4();
        let put_c = serde_json::json!({
            "id": cid,
            "recipient_address": c_recipient,
            "label": "Contract Vault",
            "flow": "personal"
        })
        .to_string();
        let n2 = Uuid::new_v4().to_string();
        let (ts2, s2) = sign("PUT", &n2, &put_c);
        let resp2 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(PATH)
                    .header("content-type", "application/json")
                    .header("x-stealthbridge-account", account)
                    .header("x-stealthbridge-issued-at", &ts2)
                    .header("x-stealthbridge-nonce", &n2)
                    .header("x-stealthbridge-signature", &s2)
                    .body(Body::from(put_c))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);

        // Delete one entry cleanly
        let del_body = serde_json::json!({ "id": cid }).to_string();
        let n3 = Uuid::new_v4().to_string();
        let (ts3, s3) = sign("DELETE", &n3, &del_body);
        let del = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(PATH)
                    .header("content-type", "application/json")
                    .header("x-stealthbridge-account", account)
                    .header("x-stealthbridge-issued-at", &ts3)
                    .header("x-stealthbridge-nonce", &n3)
                    .header("x-stealthbridge-signature", &s3)
                    .body(Body::from(del_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del.status(), StatusCode::OK);

        // Cleanup test records cleanly
        sqlx::query("DELETE FROM account_beneficiaries WHERE account_address=$1")
            .bind(account)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM account_beneficiary_receipts WHERE account_address=$1")
            .bind(account)
            .execute(&pool)
            .await
            .unwrap();
    }
}
