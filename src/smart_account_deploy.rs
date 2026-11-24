//! `/v1/account/smart-accounts/deployments`: relayed, on-chain smart-account
//! creation for a signed-in customer (Testnet only).
//!
//! POST submits a factory `create_account` whose owner is the customer's
//! passkey public key (and, by default, whose guardian is the customer's
//! signed-in Stellar wallet, giving them a recovery path). GET lists the
//! customer's deployments and promotes `submitted` rows to `deployed` or
//! `failed` strictly from Stellar RPC `getTransaction`. A row never claims
//! `deployed` without an observed successful transaction.
//!
//! Configuration (all required, otherwise 503):
//! `STEALTHBRIDGE_RELAYER_SECRET` (S... fee payer, holds no account authority),
//! `STEALTHBRIDGE_SMART_ACCOUNT_FACTORY` (C...), `STEALTHBRIDGE_WEBAUTHN_RP_ID`.

use crate::{
    customer_ciphertext_vault::authorize_account_request,
    relayer::{self, RelayError, SignerKey, TxStatus},
    server::AppState,
    wallet,
};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const DOMAIN: &str = "stealthbridge-smart-account-deploy-v1";
const PATH: &str = "/v1/account/smart-accounts/deployments";
const MAX_PER_ACCOUNT: i64 = 3;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

struct RelayConfig {
    key: ed25519_dalek::SigningKey,
    factory: String,
    rp_id: String,
}

fn config() -> Option<RelayConfig> {
    let key = relayer::relayer_key(&std::env::var("STEALTHBRIDGE_RELAYER_SECRET").ok()?)?;
    let factory = std::env::var("STEALTHBRIDGE_SMART_ACCOUNT_FACTORY").ok()?;
    stellar_strkey::Contract::from_string(&factory).ok()?;
    let rp_id = std::env::var("STEALTHBRIDGE_WEBAUTHN_RP_ID").ok()?;
    valid_rp_id(&rp_id).then_some(RelayConfig {
        key,
        factory,
        rp_id,
    })
}

/// A WebAuthn RP ID is a registrable domain (no scheme, port or path).
pub fn valid_rp_id(rp: &str) -> bool {
    (3..=253).contains(&rp.len())
        && rp.contains('.')
        && rp
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !rp.starts_with('.')
        && !rp.ends_with('.')
}

fn valid_credential_id(id: &str) -> bool {
    (16..=256).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployRequest {
    pub label: String,
    /// Uncompressed P-256 point from the passkey: 04 || X || Y, lowercase hex.
    pub public_key_hex: String,
    /// WebAuthn credential id (base64url), needed later to request assertions.
    pub credential_id: String,
    /// Make the signed-in Stellar wallet the account's recovery guardian.
    pub wallet_guardian: bool,
}

impl DeployRequest {
    pub fn validated(&self) -> Option<SignerKey> {
        let label_ok = (1..=48).contains(&self.label.trim().len())
            && !self
                .label
                .chars()
                .any(|c| c.is_control() || c == '<' || c == '>');
        let lower = self.public_key_hex == self.public_key_hex.to_ascii_lowercase();
        if !label_ok || !lower || !valid_credential_id(&self.credential_id) {
            return None;
        }
        SignerKey::secp256r1_from_hex(&self.public_key_hex)
    }
}

fn private(body: serde_json::Value, status: StatusCode) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(body),
    )
        .into_response()
}

fn relay_status(e: RelayError) -> StatusCode {
    match e {
        RelayError::InvalidInput => StatusCode::BAD_REQUEST,
        // Simulation fails when the factory refuses, e.g. AccountExists.
        RelayError::Simulation => StatusCode::CONFLICT,
        RelayError::FeeTooHigh => StatusCode::SERVICE_UNAVAILABLE,
        RelayError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        RelayError::NotTestnet | RelayError::Rpc | RelayError::Rejected => StatusCode::BAD_GATEWAY,
    }
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let stamp = now();
    let Some((account, Some(nonce))) =
        authorize_account_request(&headers, &state, "POST", &body, stamp, DOMAIN, PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(cfg) = config() else {
        return private(
            json!({"code":"RELAYER_NOT_CONFIGURED"}),
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(req) = serde_json::from_slice::<DeployRequest>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(owner) = req.validated() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let guardian = if req.wallet_guardian {
        match wallet::decode_account_address(&account) {
            Some(k) => Some(SignerKey::Ed25519(k)),
            None => return StatusCode::BAD_REQUEST.into_response(),
        }
    } else {
        None
    };

    // Claim the nonce and enforce the per-account quota atomically, then
    // release the DB before any network call.
    let Ok(mut tx) = db.begin().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let claimed = sqlx::query(
        "INSERT INTO account_smart_account_deploy_receipts(nonce,account_address) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(nonce)
    .bind(&account)
    .execute(&mut *tx)
    .await;
    if !matches!(claimed, Ok(r) if r.rows_affected() == 1) {
        return StatusCode::CONFLICT.into_response();
    }
    let used: Result<i64, _> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM account_smart_account_deployments WHERE account_address=$1 AND status<>'failed'",
    )
    .bind(&account)
    .fetch_one(&mut *tx)
    .await;
    match used {
        Ok(n) if n < MAX_PER_ACCOUNT => {}
        Ok(_) => {
            return private(
                json!({"code":"DEPLOYMENT_LIMIT_REACHED"}),
                StatusCode::TOO_MANY_REQUESTS,
            )
        }
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    if tx.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    let rp_hash = relayer::rp_id_hash(&cfg.rp_id);
    let submitted = match relayer::submit_account(
        &state,
        &cfg.key,
        &cfg.factory,
        &owner,
        rp_hash,
        guardian.as_ref(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            return private(
                json!({"code":"RELAY_FAILED","reason":format!("{e:?}")}),
                relay_status(e),
            )
        }
    };
    let inserted = sqlx::query(
        "INSERT INTO account_smart_account_deployments(account_address,contract_address,label,owner_public_key,credential_id,rp_id,guardian_address,factory_address,network,tx_hash,status,created_at_unix,updated_at_unix)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,'testnet',$9,'submitted',$10,$10)",
    )
    .bind(&account)
    .bind(&submitted.contract)
    .bind(req.label.trim())
    .bind(&req.public_key_hex)
    .bind(&req.credential_id)
    .bind(&cfg.rp_id)
    .bind(req.wallet_guardian.then_some(account.as_str()))
    .bind(&cfg.factory)
    .bind(&submitted.tx_hash)
    .bind(stamp)
    .execute(db)
    .await;
    if inserted.is_err() {
        // The transaction was submitted; surface its identifiers so the
        // client can still confirm it on-chain.
        return private(
            json!({"code":"RECORD_FAILED","contract_address":submitted.contract,"tx_hash":submitted.tx_hash}),
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    private(
        json!({
            "network":"testnet",
            "contract_address": submitted.contract,
            "tx_hash": submitted.tx_hash,
            "status":"submitted",
            "rp_id": cfg.rp_id,
            "wallet_guardian": req.wallet_guardian
        }),
        StatusCode::ACCEPTED,
    )
}

pub async fn list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let stamp = now();
    let Some((account, _)) =
        authorize_account_request(&headers, &state, "GET", &[], stamp, DOMAIN, PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(rows) = sqlx::query(
        "SELECT contract_address,label,owner_public_key,credential_id,rp_id,guardian_address,factory_address,tx_hash,status,ledger,created_at_unix
         FROM account_smart_account_deployments WHERE account_address=$1 ORDER BY created_at_unix DESC LIMIT 10",
    )
    .bind(&account)
    .fetch_all(db)
    .await
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let contract: String = row.get("contract_address");
        let tx_hash: String = row.get("tx_hash");
        let mut status: String = row.get("status");
        let mut ledger: Option<i64> = row.get("ledger");
        if status == "submitted" {
            // Promote only on observed chain state; RPC failure keeps 'submitted'.
            let next = match relayer::transaction_status(&state, &tx_hash).await {
                Ok(TxStatus::Success { ledger: l }) => Some(("deployed", Some(l as i64))),
                Ok(TxStatus::Failed) => Some(("failed", None)),
                _ => None,
            };
            if let Some((s, l)) = next {
                let updated = sqlx::query(
                    "UPDATE account_smart_account_deployments SET status=$3, ledger=$4, updated_at_unix=$5
                     WHERE account_address=$1 AND contract_address=$2 AND status='submitted'",
                )
                .bind(&account)
                .bind(&contract)
                .bind(s)
                .bind(l)
                .bind(stamp)
                .execute(db)
                .await;
                if updated.is_ok() {
                    status = s.to_owned();
                    ledger = l;
                }
            }
        }
        items.push(json!({
            "contract_address": contract,
            "label": row.get::<String,_>("label"),
            "owner_public_key": row.get::<String,_>("owner_public_key"),
            "credential_id": row.get::<String,_>("credential_id"),
            "rp_id": row.get::<String,_>("rp_id"),
            "guardian_address": row.get::<Option<String>,_>("guardian_address"),
            "factory_address": row.get::<String,_>("factory_address"),
            "tx_hash": tx_hash,
            "status": status,
            "ledger": ledger,
            "created_at_unix": row.get::<i64,_>("created_at_unix"),
        }));
    }
    private(
        json!({
            "schema_version": 1,
            "network": "testnet",
            "account_address": account,
            "relayer_configured": config().is_some(),
            "max_deployments": MAX_PER_ACCOUNT,
            "deployments": items
        }),
        StatusCode::OK,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(pk: &str, cred: &str, label: &str) -> DeployRequest {
        DeployRequest {
            label: label.into(),
            public_key_hex: pk.into(),
            credential_id: cred.into(),
            wallet_guardian: true,
        }
    }

    #[test]
    fn validates_passkey_inputs() {
        let pk = format!("04{}", "ab".repeat(64));
        assert!(req(&pk, "AbCdEfGhIjKlMnOpQrSt", "Everyday")
            .validated()
            .is_some());
        assert!(req(&pk.to_uppercase(), "AbCdEfGhIjKlMnOpQrSt", "Everyday")
            .validated()
            .is_none());
        assert!(req(&pk, "short", "Everyday").validated().is_none());
        assert!(req(&pk, "has+plus/slash=pad1234", "Everyday")
            .validated()
            .is_none());
        assert!(req(&pk, "AbCdEfGhIjKlMnOpQrSt", "").validated().is_none());
        assert!(req(&pk, "AbCdEfGhIjKlMnOpQrSt", "<script>")
            .validated()
            .is_none());
        assert!(req(
            &format!("02{}", "ab".repeat(64)),
            "AbCdEfGhIjKlMnOpQrSt",
            "x"
        )
        .validated()
        .is_none());
    }

    #[test]
    fn rp_id_is_a_bare_domain() {
        assert!(valid_rp_id("stealthbridge.vercel.app"));
        assert!(!valid_rp_id("https://stealthbridge.vercel.app"));
        assert!(!valid_rp_id("stealthbridge.vercel.app:443"));
        assert!(!valid_rp_id("localhost"));
        assert!(!valid_rp_id("Stealthbridge.app"));
    }

    #[test]
    fn simulation_refusal_maps_to_conflict() {
        assert_eq!(relay_status(RelayError::Simulation), StatusCode::CONFLICT);
        assert_eq!(
            relay_status(RelayError::NotTestnet),
            StatusCode::BAD_GATEWAY
        );
    }
}
