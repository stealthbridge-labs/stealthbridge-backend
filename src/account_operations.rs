//! Customer-owned Soroban Smart Account bindings and organization-scoped
//! Business Invoices, Webhooks, and API Credentials stored in PostgreSQL.
//! Uses canonical HMAC BFF attestation (`authorize_account_request`),
//! single-use nonce replay receipts, and tenant RBAC against `organization_members`.

use crate::{customer_ciphertext_vault::authorize_account_request, server::AppState, wallet};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const SA_DOMAIN: &str = "stealthbridge-account-smart-accounts-v1";
const SA_PATH: &str = "/v1/account/smart-accounts";
const INV_DOMAIN: &str = "stealthbridge-business-invoices-v1";
const INV_PATH: &str = "/v1/business/invoices";
const WH_DOMAIN: &str = "stealthbridge-business-webhooks-v1";
const WH_PATH: &str = "/v1/business/webhooks";
const KEY_DOMAIN: &str = "stealthbridge-business-api-credentials-v1";
const KEY_PATH: &str = "/v1/business/api-credentials";

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(1)
}

fn valid_label(label: &str, min: usize, max: usize) -> bool {
    let n = label.chars().count();
    (min..=max).contains(&n)
        && label.trim() == label
        && !label
            .chars()
            .any(|c| c.is_control() || c == '<' || c == '>')
}

pub fn valid_https_webhook_url(raw: &str) -> bool {
    if raw.len() < 12 || raw.len() > 256 || raw.trim() != raw {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(raw) else {
        return false;
    };
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    // Audit H-4: the previous prefix denylist missed 172.16/12, 169.254/16
    // (cloud metadata), 100.64/10 and decimal/hex/octal IPv4 spellings. The URL
    // parser normalises all of those to `Host::Ipv4`, so any IP literal is
    // refused outright: webhook endpoints must be DNS names. DNS names that
    // resolve to private ranges must additionally be rejected at delivery
    // time, after resolution (there is no delivery worker yet).
    // `domain()` is None for every IPv4/IPv6 literal host.
    let Some(host) = url.domain() else {
        return false;
    };
    let lower = host.to_ascii_lowercase();
    const INTERNAL_SUFFIXES: [&str; 7] = [
        ".localhost",
        ".local",
        ".internal",
        ".intranet",
        ".lan",
        ".home.arpa",
        ".corp",
    ];
    if lower == "localhost"
        || INTERNAL_SUFFIXES.iter().any(|s| lower.ends_with(s))
        || url.port().is_some_and(|p| p != 443)
    {
        return false;
    }
    // Require a dotted name whose final label is alphabetic (a real TLD).
    match lower.rsplit_once('.') {
        Some((rest, tld)) => {
            !rest.is_empty() && tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_lowercase())
        }
        None => false,
    }
}

async fn resolve_org_role(
    db: &PgPool,
    account: &str,
    organization_id: Uuid,
) -> Result<Option<(String, String)>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT m.role, o.status FROM organization_members m
         INNER JOIN organizations o ON o.id = m.organization_id
         WHERE m.organization_id = $1 AND m.subject = $2 AND m.revoked_at IS NULL
         LIMIT 1",
    )
    .bind(organization_id)
    .bind(account)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let role: String = row.try_get("role")?;
    let status: String = row.try_get("status")?;
    // Audit H-5: only operator-activated organizations may issue credentials,
    // webhooks or invoices. `pending` is self-registered and unverified, and
    // team invites / business reviews already require `active`.
    if status != "active" {
        return Ok(None);
    }
    Ok(Some((role, status)))
}

async fn claim_nonce(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    table: &str,
    nonce: Uuid,
    account: &str,
    op: &str,
) -> Result<bool, sqlx::Error> {
    let sql = format!(
        "INSERT INTO {table}(nonce, account_address, operation) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING nonce"
    );
    let inserted = sqlx::query(&sql)
        .bind(nonce)
        .bind(account)
        .bind(op)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(inserted.is_some())
}

// ---------- 1. Smart Account Bindings (/v1/account/smart-accounts) ----------

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpsertSmartAccount {
    contract_address: String,
    label: String,
    guardian_address: Option<String>,
    recovery_delay_ledgers: i32,
    webauthn_credential_id: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteSmartAccount {
    contract_address: String,
}

#[derive(Serialize)]
struct SmartAccountRecord {
    contract_address: String,
    label: String,
    guardian_address: Option<String>,
    recovery_delay_ledgers: i32,
    webauthn_credential_id: Option<String>,
    created_at_unix: i64,
    updated_at_unix: i64,
}

pub async fn list_smart_accounts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let Some((account, _)) =
        authorize_account_request(&headers, &state, "GET", &[], now_unix(), SA_DOMAIN, SA_PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Ok(rows)) = tokio::time::timeout(
        Duration::from_secs(4),
        sqlx::query(
            "SELECT contract_address, label, guardian_address, recovery_delay_ledgers, webauthn_credential_id, created_at_unix, updated_at_unix
             FROM account_smart_accounts WHERE account_address = $1 ORDER BY updated_at_unix DESC LIMIT 16",
        )
        .bind(&account)
        .fetch_all(db),
    )
    .await
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let Ok(contract_address) = row.try_get::<String, _>("contract_address") else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        items.push(SmartAccountRecord {
            contract_address,
            label: row.try_get("label").unwrap_or_default(),
            guardian_address: row.try_get("guardian_address").unwrap_or(None),
            recovery_delay_ledgers: row.try_get("recovery_delay_ledgers").unwrap_or(100),
            webauthn_credential_id: row.try_get("webauthn_credential_id").unwrap_or(None),
            created_at_unix: row.try_get("created_at_unix").unwrap_or(1),
            updated_at_unix: row.try_get("updated_at_unix").unwrap_or(1),
        });
    }
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(serde_json::json!({
            "schema_version": 1,
            "network": "testnet",
            "source": "neon-account-smart-accounts",
            "account_address": account,
            "items": items
        })),
    )
        .into_response()
}

pub async fn upsert_smart_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = now_unix();
    let Some((account, Some(nonce))) =
        authorize_account_request(&headers, &state, "PUT", &body, now, SA_DOMAIN, SA_PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(payload) = serde_json::from_slice::<UpsertSmartAccount>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !matches!(
        wallet::parse_canonical_stellar_address(&payload.contract_address),
        Some(wallet::StellarAddress::Contract(_))
    ) || !valid_label(&payload.label, 1, 48)
        || !(100..=100_000).contains(&payload.recovery_delay_ledgers)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Some(ref g) = payload.guardian_address {
        if wallet::decode_account_address(g).is_none() {
            return StatusCode::BAD_REQUEST.into_response();
        }
    }
    if let Some(ref cred) = payload.webauthn_credential_id {
        if !valid_label(cred, 16, 128) {
            return StatusCode::BAD_REQUEST.into_response();
        }
    }
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(mut tx) = db.begin().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(true) = claim_nonce(
        &mut tx,
        "account_smart_account_receipts",
        nonce,
        &account,
        "PUT",
    )
    .await
    else {
        return StatusCode::CONFLICT.into_response();
    };
    if sqlx::query(
        "INSERT INTO account_smart_accounts(account_address, contract_address, label, guardian_address, recovery_delay_ledgers, webauthn_credential_id, created_at_unix, updated_at_unix)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
         ON CONFLICT(account_address, contract_address) DO UPDATE
         SET label = EXCLUDED.label, guardian_address = EXCLUDED.guardian_address,
             recovery_delay_ledgers = EXCLUDED.recovery_delay_ledgers,
             webauthn_credential_id = EXCLUDED.webauthn_credential_id,
             updated_at_unix = EXCLUDED.updated_at_unix",
    )
    .bind(&account)
    .bind(&payload.contract_address)
    .bind(&payload.label)
    .bind(&payload.guardian_address)
    .bind(payload.recovery_delay_ledgers)
    .bind(&payload.webauthn_credential_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if tx.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    list_smart_accounts_after_mutation(db, &account).await
}

pub async fn delete_smart_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = now_unix();
    let Some((account, Some(nonce))) =
        authorize_account_request(&headers, &state, "DELETE", &body, now, SA_DOMAIN, SA_PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(payload) = serde_json::from_slice::<DeleteSmartAccount>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !matches!(
        wallet::parse_canonical_stellar_address(&payload.contract_address),
        Some(wallet::StellarAddress::Contract(_))
    ) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(mut tx) = db.begin().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(true) = claim_nonce(
        &mut tx,
        "account_smart_account_receipts",
        nonce,
        &account,
        "DELETE",
    )
    .await
    else {
        return StatusCode::CONFLICT.into_response();
    };
    let _ = sqlx::query(
        "DELETE FROM account_smart_accounts WHERE account_address = $1 AND contract_address = $2",
    )
    .bind(&account)
    .bind(&payload.contract_address)
    .execute(&mut *tx)
    .await;
    if tx.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    list_smart_accounts_after_mutation(db, &account).await
}

async fn list_smart_accounts_after_mutation(db: &PgPool, account: &str) -> Response {
    let Ok(rows) = sqlx::query(
        "SELECT contract_address, label, guardian_address, recovery_delay_ledgers, webauthn_credential_id, created_at_unix, updated_at_unix
         FROM account_smart_accounts WHERE account_address = $1 ORDER BY updated_at_unix DESC LIMIT 16",
    )
    .bind(account)
    .fetch_all(db)
    .await
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let items: Vec<SmartAccountRecord> = rows
        .into_iter()
        .map(|row| SmartAccountRecord {
            contract_address: row.try_get("contract_address").unwrap_or_default(),
            label: row.try_get("label").unwrap_or_default(),
            guardian_address: row.try_get("guardian_address").unwrap_or(None),
            recovery_delay_ledgers: row.try_get("recovery_delay_ledgers").unwrap_or(100),
            webauthn_credential_id: row.try_get("webauthn_credential_id").unwrap_or(None),
            created_at_unix: row.try_get("created_at_unix").unwrap_or(1),
            updated_at_unix: row.try_get("updated_at_unix").unwrap_or(1),
        })
        .collect();
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(serde_json::json!({
            "schema_version": 1,
            "network": "testnet",
            "source": "neon-account-smart-accounts",
            "account_address": account,
            "items": items
        })),
    )
        .into_response()
}

// ---------- 2. Organization Invoices (/v1/business/invoices) ----------

#[derive(Deserialize)]
pub struct OrgQuery {
    pub organization_id: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpsertInvoice {
    organization_id: Uuid,
    id: Uuid,
    invoice_number: String,
    counterparty_name: String,
    recipient_address: String,
    asset_code: String,
    amount_stroops: i64,
    due_at_unix: i64,
    status: String,
    privacy_mode: String,
}

#[derive(Serialize)]
struct InvoiceRecord {
    id: Uuid,
    organization_id: Uuid,
    invoice_number: String,
    counterparty_name: String,
    recipient_address: String,
    asset_code: String,
    amount_stroops: i64,
    due_at_unix: i64,
    status: String,
    privacy_mode: String,
    created_by: String,
    created_at_unix: i64,
    updated_at_unix: i64,
}

pub async fn list_invoices(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OrgQuery>,
    headers: HeaderMap,
) -> Response {
    let Some((account, _)) = authorize_account_request(
        &headers,
        &state,
        "GET",
        &[],
        now_unix(),
        INV_DOMAIN,
        INV_PATH,
    ) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Some(_)) = resolve_org_role(db, &account, query.organization_id).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Ok(rows) = sqlx::query(
        "SELECT id, organization_id, invoice_number, counterparty_name, recipient_address, asset_code, amount_stroops, due_at_unix, status, privacy_mode, created_by, created_at_unix, updated_at_unix
         FROM business_invoices WHERE organization_id = $1 ORDER BY updated_at_unix DESC LIMIT 50",
    )
    .bind(query.organization_id)
    .fetch_all(db)
    .await
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let items: Vec<InvoiceRecord> = rows
        .into_iter()
        .map(|row| InvoiceRecord {
            id: row.try_get("id").unwrap_or_default(),
            organization_id: row.try_get("organization_id").unwrap_or_default(),
            invoice_number: row.try_get("invoice_number").unwrap_or_default(),
            counterparty_name: row.try_get("counterparty_name").unwrap_or_default(),
            recipient_address: row.try_get("recipient_address").unwrap_or_default(),
            asset_code: row.try_get("asset_code").unwrap_or_default(),
            amount_stroops: row.try_get("amount_stroops").unwrap_or(0),
            due_at_unix: row.try_get("due_at_unix").unwrap_or(1),
            status: row.try_get("status").unwrap_or_default(),
            privacy_mode: row.try_get("privacy_mode").unwrap_or_default(),
            created_by: row.try_get("created_by").unwrap_or_default(),
            created_at_unix: row.try_get("created_at_unix").unwrap_or(1),
            updated_at_unix: row.try_get("updated_at_unix").unwrap_or(1),
        })
        .collect();
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(serde_json::json!({
            "schema_version": 1,
            "network": "testnet",
            "organization_id": query.organization_id,
            "items": items
        })),
    )
        .into_response()
}

pub async fn upsert_invoice(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = now_unix();
    let Some((account, Some(nonce))) =
        authorize_account_request(&headers, &state, "PUT", &body, now, INV_DOMAIN, INV_PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(payload) = serde_json::from_slice::<UpsertInvoice>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !valid_label(&payload.invoice_number, 2, 48)
        || !valid_label(&payload.counterparty_name, 2, 64)
        || wallet::parse_canonical_stellar_address(&payload.recipient_address).is_none()
        || !matches!(payload.asset_code.as_str(), "XLM" | "USDC" | "EURC")
        || payload.amount_stroops <= 0
        || payload.due_at_unix <= 0
        || !matches!(
            payload.status.as_str(),
            // Audit M-2: `settled_testnet` is evidence of an on-chain payment
            // and may only be written by ledger reconciliation, never by a client.
            "draft" | "issued" | "cancelled"
        )
        || !matches!(
            payload.privacy_mode.as_str(),
            "public-testnet" | "private-payments-groth16" | "confidential-token"
        )
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Some((role, _))) = resolve_org_role(db, &account, payload.organization_id).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !matches!(role.as_str(), "owner" | "admin" | "operator") {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(mut tx) = db.begin().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(true) = claim_nonce(&mut tx, "business_invoice_receipts", nonce, &account, "PUT").await
    else {
        return StatusCode::CONFLICT.into_response();
    };
    if sqlx::query(
        "INSERT INTO business_invoices(organization_id, id, invoice_number, counterparty_name, recipient_address, asset_code, amount_stroops, due_at_unix, status, privacy_mode, created_by, created_at_unix, updated_at_unix)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)
         ON CONFLICT(organization_id, id) DO UPDATE
         SET invoice_number = EXCLUDED.invoice_number, counterparty_name = EXCLUDED.counterparty_name,
             recipient_address = EXCLUDED.recipient_address, asset_code = EXCLUDED.asset_code,
             amount_stroops = EXCLUDED.amount_stroops, due_at_unix = EXCLUDED.due_at_unix,
             status = EXCLUDED.status, privacy_mode = EXCLUDED.privacy_mode,
             updated_at_unix = EXCLUDED.updated_at_unix",
    )
    .bind(payload.organization_id)
    .bind(payload.id)
    .bind(&payload.invoice_number)
    .bind(&payload.counterparty_name)
    .bind(&payload.recipient_address)
    .bind(&payload.asset_code)
    .bind(payload.amount_stroops)
    .bind(payload.due_at_unix)
    .bind(&payload.status)
    .bind(&payload.privacy_mode)
    .bind(&account)
    .bind(now)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return StatusCode::CONFLICT.into_response();
    }
    if tx.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(serde_json::json!({ "saved": true, "id": payload.id, "updated_at_unix": now })),
    )
        .into_response()
}

// ---------- 3. Organization Webhooks (/v1/business/webhooks) ----------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateWebhook {
    organization_id: Uuid,
    id: Uuid,
    endpoint_url: String,
    subscribed_events: String,
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteOrgItem {
    organization_id: Uuid,
    id: Uuid,
}

#[derive(Serialize)]
struct WebhookRecord {
    id: Uuid,
    organization_id: Uuid,
    endpoint_url: String,
    subscribed_events: String,
    secret_prefix: String,
    enabled: bool,
    created_by: String,
    created_at_unix: i64,
    updated_at_unix: i64,
}

pub async fn list_webhooks(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OrgQuery>,
    headers: HeaderMap,
) -> Response {
    let Some((account, _)) =
        authorize_account_request(&headers, &state, "GET", &[], now_unix(), WH_DOMAIN, WH_PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Some((role, _))) = resolve_org_role(db, &account, query.organization_id).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !matches!(role.as_str(), "owner" | "admin" | "operator") {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(rows) = sqlx::query(
        "SELECT id, organization_id, endpoint_url, subscribed_events, secret_prefix, enabled, created_by, created_at_unix, updated_at_unix
         FROM business_webhooks WHERE organization_id = $1 ORDER BY updated_at_unix DESC LIMIT 20",
    )
    .bind(query.organization_id)
    .fetch_all(db)
    .await
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let items: Vec<WebhookRecord> = rows
        .into_iter()
        .map(|row| WebhookRecord {
            id: row.try_get("id").unwrap_or_default(),
            organization_id: row.try_get("organization_id").unwrap_or_default(),
            endpoint_url: row.try_get("endpoint_url").unwrap_or_default(),
            subscribed_events: row.try_get("subscribed_events").unwrap_or_default(),
            secret_prefix: row.try_get("secret_prefix").unwrap_or_default(),
            enabled: row.try_get("enabled").unwrap_or(true),
            created_by: row.try_get("created_by").unwrap_or_default(),
            created_at_unix: row.try_get("created_at_unix").unwrap_or(1),
            updated_at_unix: row.try_get("updated_at_unix").unwrap_or(1),
        })
        .collect();
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(serde_json::json!({ "schema_version": 1, "organization_id": query.organization_id, "items": items })),
    )
        .into_response()
}

pub async fn upsert_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = now_unix();
    let Some((account, Some(nonce))) =
        authorize_account_request(&headers, &state, "PUT", &body, now, WH_DOMAIN, WH_PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(payload) = serde_json::from_slice::<CreateWebhook>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !valid_https_webhook_url(&payload.endpoint_url)
        || !valid_label(&payload.subscribed_events, 3, 256)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Some((role, _))) = resolve_org_role(db, &account, payload.organization_id).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !matches!(role.as_str(), "owner" | "admin") {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(mut tx) = db.begin().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(true) = claim_nonce(&mut tx, "business_webhook_receipts", nonce, &account, "PUT").await
    else {
        return StatusCode::CONFLICT.into_response();
    };
    let raw_secret = format!(
        "sbwh_test_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let prefix: String = raw_secret.chars().take(14).collect();
    let secret_sha256 = hex::encode(Sha256::digest(raw_secret.as_bytes()));
    if sqlx::query(
        "INSERT INTO business_webhooks(organization_id, id, endpoint_url, subscribed_events, secret_prefix, secret_sha256, enabled, created_by, created_at_unix, updated_at_unix)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)
         ON CONFLICT(organization_id, id) DO UPDATE
         SET endpoint_url = EXCLUDED.endpoint_url, subscribed_events = EXCLUDED.subscribed_events,
             enabled = EXCLUDED.enabled, updated_at_unix = EXCLUDED.updated_at_unix,
             secret_prefix = EXCLUDED.secret_prefix, secret_sha256 = EXCLUDED.secret_sha256",
    )
    .bind(payload.organization_id)
    .bind(payload.id)
    .bind(&payload.endpoint_url)
    .bind(&payload.subscribed_events)
    .bind(&prefix)
    .bind(&secret_sha256)
    .bind(payload.enabled)
    .bind(&account)
    .bind(now)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if tx.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(serde_json::json!({
            "saved": true,
            "id": payload.id,
            "secret_prefix": prefix,
            "signing_secret_once": raw_secret,
            "updated_at_unix": now
        })),
    )
        .into_response()
}

pub async fn delete_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = now_unix();
    let Some((account, Some(nonce))) =
        authorize_account_request(&headers, &state, "DELETE", &body, now, WH_DOMAIN, WH_PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(payload) = serde_json::from_slice::<DeleteOrgItem>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Some((role, _))) = resolve_org_role(db, &account, payload.organization_id).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !matches!(role.as_str(), "owner" | "admin") {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(mut tx) = db.begin().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(true) = claim_nonce(
        &mut tx,
        "business_webhook_receipts",
        nonce,
        &account,
        "DELETE",
    )
    .await
    else {
        return StatusCode::CONFLICT.into_response();
    };
    let _ = sqlx::query("DELETE FROM business_webhooks WHERE organization_id = $1 AND id = $2")
        .bind(payload.organization_id)
        .bind(payload.id)
        .execute(&mut *tx)
        .await;
    if tx.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(serde_json::json!({ "deleted": true, "id": payload.id })),
    )
        .into_response()
}

// ---------- 4. Organization API Credentials (/v1/business/api-credentials) ----------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueApiCredential {
    organization_id: Uuid,
    id: Uuid,
    label: String,
    scopes: String,
}

#[derive(Serialize)]
struct ApiCredentialRecord {
    id: Uuid,
    organization_id: Uuid,
    label: String,
    scopes: String,
    key_prefix: String,
    created_by: String,
    created_at_unix: i64,
    revoked_at_unix: Option<i64>,
}

pub async fn list_api_credentials(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OrgQuery>,
    headers: HeaderMap,
) -> Response {
    let Some((account, _)) = authorize_account_request(
        &headers,
        &state,
        "GET",
        &[],
        now_unix(),
        KEY_DOMAIN,
        KEY_PATH,
    ) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Some((role, _))) = resolve_org_role(db, &account, query.organization_id).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !matches!(role.as_str(), "owner" | "admin") {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(rows) = sqlx::query(
        "SELECT id, organization_id, label, scopes, key_prefix, created_by, created_at_unix, revoked_at_unix
         FROM business_api_credentials WHERE organization_id = $1 ORDER BY created_at_unix DESC LIMIT 25",
    )
    .bind(query.organization_id)
    .fetch_all(db)
    .await
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let items: Vec<ApiCredentialRecord> = rows
        .into_iter()
        .map(|row| ApiCredentialRecord {
            id: row.try_get("id").unwrap_or_default(),
            organization_id: row.try_get("organization_id").unwrap_or_default(),
            label: row.try_get("label").unwrap_or_default(),
            scopes: row.try_get("scopes").unwrap_or_default(),
            key_prefix: row.try_get("key_prefix").unwrap_or_default(),
            created_by: row.try_get("created_by").unwrap_or_default(),
            created_at_unix: row.try_get("created_at_unix").unwrap_or(1),
            revoked_at_unix: row.try_get("revoked_at_unix").unwrap_or(None),
        })
        .collect();
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(serde_json::json!({ "schema_version": 1, "organization_id": query.organization_id, "items": items })),
    )
        .into_response()
}

pub async fn issue_api_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = now_unix();
    let Some((account, Some(nonce))) =
        authorize_account_request(&headers, &state, "POST", &body, now, KEY_DOMAIN, KEY_PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(payload) = serde_json::from_slice::<IssueApiCredential>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !valid_label(&payload.label, 2, 48) || !valid_label(&payload.scopes, 4, 128) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Some((role, _))) = resolve_org_role(db, &account, payload.organization_id).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !matches!(role.as_str(), "owner" | "admin") {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(mut tx) = db.begin().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(true) = claim_nonce(
        &mut tx,
        "business_api_credential_receipts",
        nonce,
        &account,
        "POST",
    )
    .await
    else {
        return StatusCode::CONFLICT.into_response();
    };
    let raw_token = format!(
        "sb_test_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let key_prefix: String = raw_token.chars().take(16).collect();
    let secret_sha256 = hex::encode(Sha256::digest(raw_token.as_bytes()));
    if sqlx::query(
        "INSERT INTO business_api_credentials(organization_id, id, label, scopes, key_prefix, secret_sha256, created_by, created_at_unix)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(payload.organization_id)
    .bind(payload.id)
    .bind(&payload.label)
    .bind(&payload.scopes)
    .bind(&key_prefix)
    .bind(&secret_sha256)
    .bind(&account)
    .bind(now)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return StatusCode::CONFLICT.into_response();
    }
    if tx.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(serde_json::json!({
            "issued": true,
            "id": payload.id,
            "key_prefix": key_prefix,
            "token_once": raw_token,
            "created_at_unix": now
        })),
    )
        .into_response()
}

pub async fn revoke_api_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = now_unix();
    let Some((account, Some(nonce))) =
        authorize_account_request(&headers, &state, "DELETE", &body, now, KEY_DOMAIN, KEY_PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(payload) = serde_json::from_slice::<DeleteOrgItem>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Some((role, _))) = resolve_org_role(db, &account, payload.organization_id).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !matches!(role.as_str(), "owner" | "admin") {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(mut tx) = db.begin().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(true) = claim_nonce(
        &mut tx,
        "business_api_credential_receipts",
        nonce,
        &account,
        "DELETE",
    )
    .await
    else {
        return StatusCode::CONFLICT.into_response();
    };
    let _ = sqlx::query(
        "UPDATE business_api_credentials SET revoked_at_unix = $1
         WHERE organization_id = $2 AND id = $3 AND revoked_at_unix IS NULL",
    )
    .bind(now)
    .bind(payload.organization_id)
    .bind(payload.id)
    .execute(&mut *tx)
    .await;
    if tx.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(serde_json::json!({ "revoked": true, "id": payload.id, "revoked_at_unix": now })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_url_rejects_http_localhost_and_private_hosts() {
        assert!(valid_https_webhook_url(
            "https://hooks.acme-treasury.example/stealthbridge"
        ));
        assert!(!valid_https_webhook_url(
            "http://hooks.acme-treasury.example/stealthbridge"
        ));
        assert!(!valid_https_webhook_url("https://localhost/webhook"));
        assert!(!valid_https_webhook_url("https://127.0.0.1/webhook"));
        assert!(!valid_https_webhook_url("https://192.168.1.10/webhook"));
        assert!(!valid_https_webhook_url(
            "https://user:pass@hooks.example.com/hook"
        ));
    }

    /// Audit H-4 bypasses of the old prefix denylist.
    #[test]
    fn webhook_url_rejects_every_ip_literal_and_internal_name() {
        for raw in [
            "https://172.16.0.5/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://100.64.0.1/hook",
            "https://2130706433/hook",
            "https://0x7f000001/hook",
            "https://0177.0.0.1/hook",
            "https://8.8.8.8/hook",
            "https://[::1]/hook",
            "https://[fd00::1]/hook",
            "https://metadata.google.internal/hook",
            "https://router.lan/hook",
            "https://printer.home.arpa/hook",
            "https://hooks.example.com:8443/hook",
            "https://nodot/hook",
        ] {
            assert!(!valid_https_webhook_url(raw), "{raw} must be rejected");
        }
        assert!(valid_https_webhook_url(
            "https://hooks.example.com:443/hook"
        ));
    }
}
