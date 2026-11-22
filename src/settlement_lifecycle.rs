//! Controlled account-owned Testnet settlement lifecycle state machine,
//! canonical intent binding, idempotency, transactional journal/outbox, live
//! Testnet RPC observation, and strict separation of chain finality vs fiat payout.

use crate::{
    customer_ciphertext_vault::authorize_account_request,
    privacy_rails::{
        evaluate_rail_preflight, AssetTransferSemantics, PrivacyArchitectureKind,
        PrivacyRailPreflightRequest, ProductSegment,
    },
    server::AppState,
    transaction, wallet, webhook,
};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const DOMAIN: &str = "stealthbridge-settlement-lifecycle-v1";
const PATH: &str = "/v1/account/settlements";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const MAX_ACTIVE_PER_ACCOUNT: i64 = 50;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    InstructionCreated,
    CorridorVerified,
    AssetRecipientVerified,
    QuoteUnavailable,
    Quoted,
    PolicyVerified,
    CustomerAuthorized,
    PrivacyProofPending,
    PrivacyProofVerified,
    TxSubmitted,
    ChainFinalized,
    ChainFailed,
    PayoutPending,
    PayoutCompleted,
    PayoutFailed,
    DisputeOpen,
    ReversalPending,
    Reversed,
    Reconciled,
    Expired,
    Cancelled,
}

impl LifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InstructionCreated => "instruction_created",
            Self::CorridorVerified => "corridor_verified",
            Self::AssetRecipientVerified => "asset_recipient_verified",
            Self::QuoteUnavailable => "quote_unavailable",
            Self::Quoted => "quoted",
            Self::PolicyVerified => "policy_verified",
            Self::CustomerAuthorized => "customer_authorized",
            Self::PrivacyProofPending => "privacy_proof_pending",
            Self::PrivacyProofVerified => "privacy_proof_verified",
            Self::TxSubmitted => "tx_submitted",
            Self::ChainFinalized => "chain_finalized",
            Self::ChainFailed => "chain_failed",
            Self::PayoutPending => "payout_pending",
            Self::PayoutCompleted => "payout_completed",
            Self::PayoutFailed => "payout_failed",
            Self::DisputeOpen => "dispute_open",
            Self::ReversalPending => "reversal_pending",
            Self::Reversed => "reversed",
            Self::Reconciled => "reconciled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "instruction_created" => Self::InstructionCreated,
            "corridor_verified" => Self::CorridorVerified,
            "asset_recipient_verified" => Self::AssetRecipientVerified,
            "quote_unavailable" => Self::QuoteUnavailable,
            "quoted" => Self::Quoted,
            "policy_verified" => Self::PolicyVerified,
            "customer_authorized" => Self::CustomerAuthorized,
            "privacy_proof_pending" => Self::PrivacyProofPending,
            "privacy_proof_verified" => Self::PrivacyProofVerified,
            "tx_submitted" => Self::TxSubmitted,
            "chain_finalized" => Self::ChainFinalized,
            "chain_failed" => Self::ChainFailed,
            "payout_pending" => Self::PayoutPending,
            "payout_completed" => Self::PayoutCompleted,
            "payout_failed" => Self::PayoutFailed,
            "dispute_open" => Self::DisputeOpen,
            "reversal_pending" => Self::ReversalPending,
            "reversed" => Self::Reversed,
            "reconciled" => Self::Reconciled,
            "expired" => Self::Expired,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Reconciled | Self::Reversed | Self::Expired | Self::Cancelled
        )
    }

    pub fn can_transition(self, next: Self) -> bool {
        use LifecycleState::*;
        matches!(
            (self, next),
            (InstructionCreated, CorridorVerified)
                | (CorridorVerified, AssetRecipientVerified)
                | (AssetRecipientVerified, QuoteUnavailable)
                | (AssetRecipientVerified, Quoted)
                | (QuoteUnavailable, PolicyVerified)
                | (Quoted, PolicyVerified)
                | (PolicyVerified, CustomerAuthorized)
                | (CustomerAuthorized, PrivacyProofPending)
                | (CustomerAuthorized, PrivacyProofVerified)
                | (PrivacyProofPending, PrivacyProofVerified)
                | (PrivacyProofVerified, TxSubmitted)
                | (TxSubmitted, ChainFinalized)
                | (TxSubmitted, ChainFailed)
                | (ChainFailed, CustomerAuthorized)
                | (ChainFinalized, PayoutPending)
                | (ChainFinalized, Reconciled)
                | (ChainFinalized, DisputeOpen)
                | (ChainFailed, DisputeOpen)
                | (ChainFailed, ReversalPending)
                | (PayoutPending, PayoutCompleted)
                | (PayoutPending, PayoutFailed)
                | (PayoutPending, DisputeOpen)
                | (PayoutFailed, PayoutPending)
                | (PayoutFailed, DisputeOpen)
                | (PayoutFailed, ReversalPending)
                | (PayoutCompleted, Reconciled)
                | (PayoutCompleted, DisputeOpen)
                | (DisputeOpen, ReversalPending)
                | (DisputeOpen, Reconciled)
                | (ReversalPending, Reversed)
                | (
                    InstructionCreated
                        | CorridorVerified
                        | AssetRecipientVerified
                        | QuoteUnavailable
                        | Quoted
                        | PolicyVerified
                        | CustomerAuthorized
                        | PrivacyProofPending,
                    Cancelled | Expired
                )
        )
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSettlementRequest {
    pub id: Uuid,
    pub organization_id: Option<Uuid>,
    pub instruction_id: Option<Uuid>,
    pub corridor_id: Uuid,
    pub route_fingerprint: String,
    pub idempotency_key: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount_minor_units: i64,
    pub recipient_address: String,
    pub privacy_rail: String,
    pub expires_in_seconds: i64,
    pub quote_evidence: Option<ProviderCallbackEnvelope>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCallbackEnvelope {
    pub timestamp: String,
    pub signature_hex: String,
    pub key_id: String,
    pub provider: String,
    pub raw_json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum LifecycleAction {
    VerifyPolicy {
        id: Uuid,
        expected_revision: i32,
        policy_commitment_sha256: String,
    },
    Authorize {
        id: Uuid,
        expected_revision: i32,
        customer_auth_sha256: String,
        ed25519_signature_hex: Option<String>,
        acknowledge_transparent_testnet_only: bool,
        privacy_rail_proof_verified: bool,
    },
    SubmitTx {
        id: Uuid,
        expected_revision: i32,
        testnet_tx_hash: String,
    },
    ObserveTx {
        id: Uuid,
        expected_revision: i32,
    },
    RequestPayout {
        id: Uuid,
        expected_revision: i32,
    },
    ProviderCallback {
        id: Uuid,
        expected_revision: i32,
        outcome: String,
        callback: ProviderCallbackEnvelope,
    },
    Retry {
        id: Uuid,
        expected_revision: i32,
    },
    OpenDispute {
        id: Uuid,
        expected_revision: i32,
        reason_code: String,
    },
    RequestReversal {
        id: Uuid,
        expected_revision: i32,
        reason_code: String,
    },
    ConfirmReversal {
        id: Uuid,
        expected_revision: i32,
        reason_code: String,
    },
    Reconcile {
        id: Uuid,
        expected_revision: i32,
    },
    Cancel {
        id: Uuid,
        expected_revision: i32,
    },
}

#[derive(Debug)]
enum StoreError {
    Database,
    Conflict,
    BadRequest,
    RpcUnavailable,
}

impl From<sqlx::Error> for StoreError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn enabled() -> bool {
    std::env::var("STEALTHBRIDGE_SETTLEMENT_LIFECYCLE_ENABLED")
        .ok()
        .as_deref()
        == Some("true")
}

fn lower_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn safe_reason(s: &str) -> bool {
    (3..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_:-".contains(&b))
}

fn route_fingerprint(
    id: Uuid,
    origin: &str,
    destination: &str,
    asset: &str,
    issuer: Option<&str>,
    rail: &str,
) -> String {
    hex::encode(Sha256::digest(
        format!(
            "StealthBridge route snapshot v1\n{id}\n{origin}\n{destination}\n{asset}\n{}\n{rail}\n",
            issuer.unwrap_or("")
        )
        .as_bytes(),
    ))
}

/// Deterministic canonical request digest shared across Rust, SDK, and Contracts.
pub fn canonical_intent_digest(account: &str, req: &CreateSettlementRequest) -> String {
    let org = req
        .organization_id
        .map(|v| v.to_string())
        .unwrap_or_default();
    let inst = req
        .instruction_id
        .map(|v| v.to_string())
        .unwrap_or_default();
    let issuer = req.asset_issuer.as_deref().unwrap_or("");
    let canonical = format!(
        "StealthBridge settlement intent v1\n{account}\n{org}\n{inst}\n{}\n{}\n{}\n{issuer}\n{}\n{}\n{}\n",
        req.corridor_id,
        req.route_fingerprint,
        req.asset_code,
        req.amount_minor_units,
        req.recipient_address,
        req.privacy_rail
    );
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

fn verify_account_ed25519_digest(account: &str, digest_hex: &str, sig_hex: &str) -> bool {
    let Some(decoded) = wallet::decode_account_address(account) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&decoded) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(digest_hex.as_bytes(), &sig).is_ok()
}

fn verify_provider_secret(
    env_var: &str,
    tenant: Uuid,
    envelope: &ProviderCallbackEnvelope,
    stamp: i64,
) -> Option<webhook::VerifiedEvent> {
    let secret = std::env::var(env_var).ok()?;
    let secret_bytes = secret.as_bytes();
    if secret_bytes.len() < 32 {
        return None;
    }
    let key = webhook::ProviderKey {
        id: &envelope.key_id,
        secret: secret_bytes,
        valid_from_unix: stamp - 86400,
        valid_until_unix: stamp + 86400,
    };
    let keyring = [key];
    webhook::verify_scoped_event(
        envelope.raw_json.as_bytes(),
        &envelope.timestamp,
        &envelope.signature_hex,
        webhook::ProviderScope {
            tenant,
            provider: &envelope.provider,
            key_id: &envelope.key_id,
            keyring: &keyring,
        },
        stamp,
    )
    .ok()
    .map(|v| v.event)
}

async fn lock_account(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account: &str,
    nonce: Uuid,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 93817))")
        .bind(account)
        .execute(&mut **tx)
        .await?;
    let used: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM account_settlement_receipts WHERE nonce=$1)",
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
    let used = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO account_settlement_receipts(nonce,account_address,operation) VALUES($1,$2,$3) ON CONFLICT(nonce) DO NOTHING RETURNING nonce",
    )
    .bind(nonce)
    .bind(account)
    .bind(method)
    .fetch_optional(&mut **tx)
    .await?;
    if used.is_none() {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

struct TransitionRecord<'a> {
    account: &'a str,
    settlement_id: Uuid,
    revision: i32,
    previous: Option<LifecycleState>,
    next: LifecycleState,
    reason_code: &'a str,
    tx_hash: Option<&'a str>,
    stamp: i64,
}

async fn write_event_and_outbox(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    rec: TransitionRecord<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO account_settlement_events(account_address,settlement_id,revision,previous_state,next_state,reason_code,tx_hash,recorded_at_unix) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(rec.account)
    .bind(rec.settlement_id)
    .bind(rec.revision)
    .bind(rec.previous.map(LifecycleState::as_str))
    .bind(rec.next.as_str())
    .bind(rec.reason_code)
    .bind(rec.tx_hash)
    .bind(rec.stamp)
    .execute(&mut **tx)
    .await?;

    let payload = json!({
        "settlement_id": rec.settlement_id,
        "account_address": rec.account,
        "revision": rec.revision,
        "previous_state": rec.previous.map(LifecycleState::as_str),
        "next_state": rec.next.as_str(),
        "reason_code": rec.reason_code,
        "tx_hash": rec.tx_hash,
        "recorded_at_unix": rec.stamp,
        "fiat_payouts_enabled": false,
        "mainnet_enabled": false
    });
    sqlx::query(
        "INSERT INTO account_settlement_outbox(account_address,settlement_id,revision,event_type,payload,created_at_unix) VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(rec.account)
    .bind(rec.settlement_id)
    .bind(rec.revision)
    .bind(format!("settlement.{}", rec.next.as_str()))
    .bind(payload)
    .bind(rec.stamp)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

impl CreateSettlementRequest {
    pub fn valid(&self) -> bool {
        !self.id.is_nil()
            && !self.corridor_id.is_nil()
            && (300..=86400).contains(&self.expires_in_seconds)
            && (16..=128).contains(&self.idempotency_key.len())
            && self
                .idempotency_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":_-".contains(&b))
            && lower_hex64(&self.route_fingerprint)
            && !self.asset_code.is_empty()
            && self.asset_code.len() <= 32
            && self.amount_minor_units > 0
            && wallet::parse_canonical_stellar_address(&self.recipient_address).is_some()
            && matches!(
                self.privacy_rail.as_str(),
                "private-payments" | "confidential-token"
            )
    }
}

async fn create_lifecycle(
    db: &PgPool,
    account: &str,
    nonce: Uuid,
    req: &CreateSettlementRequest,
    stamp: i64,
) -> Result<(StatusCode, Value), StoreError> {
    let decoded_recipient = wallet::parse_canonical_stellar_address(&req.recipient_address)
        .ok_or(StoreError::BadRequest)?;
    let recipient_kind = match decoded_recipient {
        wallet::StellarAddress::Classic(_) => "classic",
        wallet::StellarAddress::MuxedClassic { .. } => "muxed-classic",
        wallet::StellarAddress::Contract(_) => "contract",
        wallet::StellarAddress::MuxedContract { .. } => "muxed-contract",
    };
    let intent_hash = canonical_intent_digest(account, req);

    let mut tx = db.begin().await?;
    lock_account(&mut tx, account, nonce).await?;

    // Check idempotency key first so retries return exact stored record without duplication.
    let existing = sqlx::query(
        "SELECT id,request_sha256,state,revision,quote_status,payout_status,reconciliation_status,expires_at_unix FROM account_settlement_lifecycles WHERE account_address=$1 AND idempotency_key=$2",
    )
    .bind(account)
    .bind(&req.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = existing {
        let prior_hash: String = row.try_get("request_sha256")?;
        if prior_hash != intent_hash {
            return Err(StoreError::Conflict);
        }
        let body = json!({
            "id": row.try_get::<Uuid, _>("id")?,
            "request_sha256": prior_hash,
            "state": row.try_get::<String, _>("state")?,
            "revision": row.try_get::<i32, _>("revision")?,
            "quote_status": row.try_get::<String, _>("quote_status")?,
            "payout_status": row.try_get::<String, _>("payout_status")?,
            "reconciliation_status": row.try_get::<String, _>("reconciliation_status")?,
            "expires_at_unix": row.try_get::<i64, _>("expires_at_unix")?,
            "idempotent_replay": true
        });
        tx.commit().await?;
        return Ok((StatusCode::OK, body));
    }

    let active_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM account_settlement_lifecycles WHERE account_address=$1",
    )
    .bind(account)
    .fetch_one(&mut *tx)
    .await?;
    if active_count >= MAX_ACTIVE_PER_ACCOUNT {
        return Err(StoreError::Conflict);
    }

    // Tenant isolation check if organization_id supplied (must be an active member).
    if let Some(org_id) = req.organization_id {
        let is_member: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM organization_members WHERE organization_id=$1 AND account_address=$2 AND status='active')",
        )
        .bind(org_id)
        .bind(account)
        .fetch_one(&mut *tx)
        .await?;
        if !is_member {
            return Err(StoreError::Conflict);
        }
    }

    // Optional instruction linkage check: must belong to same account, corridor, and remain active.
    if let Some(inst_id) = req.instruction_id {
        let inst = sqlx::query(
            "SELECT corridor_id,state,expires_at_unix FROM customer_payment_instructions WHERE account_address=$1 AND id=$2 FOR SHARE",
        )
        .bind(account)
        .bind(inst_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::Conflict)?;
        let inst_corridor: Uuid = inst.try_get("corridor_id")?;
        let inst_state: String = inst.try_get("state")?;
        let inst_expires: i64 = inst.try_get("expires_at_unix")?;
        if inst_corridor != req.corridor_id || inst_state != "saved" || stamp >= inst_expires {
            return Err(StoreError::Conflict);
        }
    }

    // Stage 2: Lock corridor metadata and verify exact snapshot fingerprint, asset & rail.
    let route = sqlx::query(
        "SELECT origin_country,destination_country,asset_code,asset_issuer,privacy_rail FROM corridors WHERE id=$1 AND enabled=true FOR SHARE",
    )
    .bind(req.corridor_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(StoreError::Conflict)?;
    let origin: String = route.try_get("origin_country")?;
    let destination: String = route.try_get("destination_country")?;
    let asset_code: String = route.try_get("asset_code")?;
    let asset_issuer: Option<String> = route.try_get("asset_issuer")?;
    let privacy_rail: String = route.try_get("privacy_rail")?;
    if asset_code != req.asset_code
        || asset_issuer != req.asset_issuer
        || privacy_rail != req.privacy_rail
        || req.route_fingerprint
            != route_fingerprint(
                req.corridor_id,
                &origin,
                &destination,
                &asset_code,
                asset_issuer.as_deref(),
                &privacy_rail,
            )
    {
        return Err(StoreError::Conflict);
    }

    // Stage 4: Quote check — never fabricate FX or liquidity.
    let tenant_for_quote = req.organization_id.unwrap_or(req.corridor_id);
    let verified_quote = req.quote_evidence.as_ref().and_then(|q| {
        verify_provider_secret(
            "STEALTHBRIDGE_QUOTE_PROVIDER_SECRET",
            tenant_for_quote,
            q,
            stamp,
        )
    });
    let (final_state, quote_status, quote_sha256, quote_reason) = if let Some(q) = verified_quote {
        (
            LifecycleState::Quoted,
            "provider_verified",
            Some(q.payload_sha256),
            "provider_quote_verified",
        )
    } else {
        (
            LifecycleState::QuoteUnavailable,
            "unavailable",
            None,
            "no_live_fx_or_liquidity_provider",
        )
    };

    let expires = stamp
        .checked_add(req.expires_in_seconds)
        .ok_or(StoreError::Conflict)?;

    claim_nonce(&mut tx, account, nonce, "PUT").await?;
    sqlx::query(
        "INSERT INTO account_settlement_lifecycles(account_address,id,organization_id,instruction_id,corridor_id,route_fingerprint,idempotency_key,request_sha256,asset_code,asset_issuer,amount_minor_units,recipient_address,recipient_kind,privacy_rail,privacy_rail_verified,quote_status,quote_sha256,state,revision,expires_at_unix,created_at_unix,updated_at_unix) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,false,$15,$16,$17,4,$18,$19,$19)",
    )
    .bind(account)
    .bind(req.id)
    .bind(req.organization_id)
    .bind(req.instruction_id)
    .bind(req.corridor_id)
    .bind(&req.route_fingerprint)
    .bind(&req.idempotency_key)
    .bind(&intent_hash)
    .bind(&req.asset_code)
    .bind(&req.asset_issuer)
    .bind(req.amount_minor_units)
    .bind(&req.recipient_address)
    .bind(recipient_kind)
    .bind(&req.privacy_rail)
    .bind(quote_status)
    .bind(&quote_sha256)
    .bind(final_state.as_str())
    .bind(expires)
    .bind(stamp)
    .execute(&mut *tx)
    .await?;

    // Record exact progressive journal & outbox stages 1 -> 2 -> 3 -> 4 atomically.
    for (rev, prev, next, reason) in [
        (
            1,
            None,
            LifecycleState::InstructionCreated,
            "intent_registered",
        ),
        (
            2,
            Some(LifecycleState::InstructionCreated),
            LifecycleState::CorridorVerified,
            "corridor_snapshot_verified",
        ),
        (
            3,
            Some(LifecycleState::CorridorVerified),
            LifecycleState::AssetRecipientVerified,
            "asset_and_recipient_validated",
        ),
        (
            4,
            Some(LifecycleState::AssetRecipientVerified),
            final_state,
            quote_reason,
        ),
    ] {
        write_event_and_outbox(
            &mut tx,
            TransitionRecord {
                account,
                settlement_id: req.id,
                revision: rev,
                previous: prev,
                next,
                reason_code: reason,
                tx_hash: None,
                stamp,
            },
        )
        .await?;
    }

    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        json!({
            "id": req.id,
            "request_sha256": intent_hash,
            "state": final_state.as_str(),
            "revision": 4,
            "quote_status": quote_status,
            "payout_status": "unavailable",
            "reconciliation_status": "pending",
            "expires_at_unix": expires,
            "idempotent_replay": false
        }),
    ))
}

async fn advance_lifecycle(
    state: &AppState,
    db: &PgPool,
    account: &str,
    nonce: Uuid,
    action: &LifecycleAction,
    stamp: i64,
) -> Result<Value, StoreError> {
    let (settlement_id, expected_revision) = match action {
        LifecycleAction::VerifyPolicy {
            id,
            expected_revision,
            ..
        }
        | LifecycleAction::Authorize {
            id,
            expected_revision,
            ..
        }
        | LifecycleAction::SubmitTx {
            id,
            expected_revision,
            ..
        }
        | LifecycleAction::ObserveTx {
            id,
            expected_revision,
        }
        | LifecycleAction::RequestPayout {
            id,
            expected_revision,
        }
        | LifecycleAction::ProviderCallback {
            id,
            expected_revision,
            ..
        }
        | LifecycleAction::Retry {
            id,
            expected_revision,
        }
        | LifecycleAction::OpenDispute {
            id,
            expected_revision,
            ..
        }
        | LifecycleAction::RequestReversal {
            id,
            expected_revision,
            ..
        }
        | LifecycleAction::ConfirmReversal {
            id,
            expected_revision,
            ..
        }
        | LifecycleAction::Reconcile {
            id,
            expected_revision,
        }
        | LifecycleAction::Cancel {
            id,
            expected_revision,
        } => (*id, *expected_revision),
    };

    // For live RPC observation, query Stellar Testnet RPC BEFORE locking DB rows.
    let mut observed_tx_result: Option<transaction::TransactionObservation> = None;
    if let LifecycleAction::ObserveTx { .. } = action {
        let tx_hash_opt: Option<String> = sqlx::query_scalar(
            "SELECT testnet_tx_hash FROM account_settlement_lifecycles WHERE account_address=$1 AND id=$2",
        )
        .bind(account)
        .bind(settlement_id)
        .fetch_optional(db)
        .await?
        .flatten();
        let tx_hash = tx_hash_opt.ok_or(StoreError::Conflict)?;
        let net = state
            .rpc("getNetwork")
            .await
            .map_err(|_| StoreError::RpcUnavailable)?;
        if net.get("passphrase").and_then(Value::as_str) != Some(TESTNET_PASSPHRASE) {
            return Err(StoreError::RpcUnavailable);
        }
        let rpc_res = state
            .rpc_with_params("getTransaction", Some(json!({"hash": tx_hash})))
            .await
            .map_err(|_| StoreError::RpcUnavailable)?;
        let parsed = transaction::parse_result(&tx_hash, &rpc_res)
            .map_err(|_| StoreError::RpcUnavailable)?
            .ok_or(StoreError::Conflict)?;
        observed_tx_result = Some(parsed);
    }

    let mut tx = db.begin().await?;
    lock_account(&mut tx, account, nonce).await?;

    let row = sqlx::query(
        "SELECT state,revision,expires_at_unix,organization_id,corridor_id,request_sha256,privacy_rail,testnet_tx_hash,payout_status,reconciliation_status FROM account_settlement_lifecycles WHERE account_address=$1 AND id=$2 FOR UPDATE",
    )
    .bind(account)
    .bind(settlement_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(StoreError::Conflict)?;

    let cur_str: String = row.try_get("state")?;
    let cur = LifecycleState::parse(&cur_str).ok_or(StoreError::Conflict)?;
    let revision: i32 = row.try_get("revision")?;
    let expires: i64 = row.try_get("expires_at_unix")?;
    let org_id: Option<Uuid> = row.try_get("organization_id")?;
    let corridor_id: Uuid = row.try_get("corridor_id")?;
    let request_sha256: String = row.try_get("request_sha256")?;
    let privacy_rail: String = row.try_get("privacy_rail")?;
    let mut tx_hash_col: Option<String> = row.try_get("testnet_tx_hash")?;
    let mut payout_status: String = row.try_get("payout_status")?;
    let mut reconciliation_status: String = row.try_get("reconciliation_status")?;

    if revision != expected_revision {
        return Err(StoreError::Conflict);
    }

    // Expire active pre-submission intents deterministically past expires_at_unix.
    if stamp >= expires && cur.can_transition(LifecycleState::Expired) {
        let next_rev = revision + 1;
        claim_nonce(&mut tx, account, nonce, "POST").await?;
        sqlx::query(
            "UPDATE account_settlement_lifecycles SET state='expired',revision=$3,last_error_code='expired',updated_at_unix=$4 WHERE account_address=$1 AND id=$2",
        )
        .bind(account)
        .bind(settlement_id)
        .bind(next_rev)
        .bind(stamp)
        .execute(&mut *tx)
        .await?;
        write_event_and_outbox(
            &mut tx,
            TransitionRecord {
                account,
                settlement_id,
                revision: next_rev,
                previous: Some(cur),
                next: LifecycleState::Expired,
                reason_code: "instruction_window_expired",
                tx_hash: None,
                stamp,
            },
        )
        .await?;
        tx.commit().await?;
        return Err(StoreError::Conflict);
    }

    let next_state: LifecycleState;
    let reason_code: String;
    let mut policy_digest_update: Option<String> = None;
    let mut customer_auth_update: Option<String> = None;
    let mut privacy_verified_update: Option<bool> = None;
    let mut obs_ledger_update: Option<i64> = None;
    let mut obs_at_update: Option<i64> = None;
    let mut chain_status_update: Option<String> = None;
    let mut provider_event_update: Option<String> = None;
    let mut last_error_update: Option<String> = None;

    match action {
        LifecycleAction::VerifyPolicy {
            policy_commitment_sha256,
            ..
        } => {
            if !lower_hex64(policy_commitment_sha256)
                || !cur.can_transition(LifecycleState::PolicyVerified)
            {
                return Err(StoreError::Conflict);
            }
            let enabled_ok: bool = sqlx::query_scalar("SELECT enabled FROM corridors WHERE id=$1")
                .bind(corridor_id)
                .fetch_optional(&mut *tx)
                .await?
                .unwrap_or(false);
            if !enabled_ok {
                return Err(StoreError::Conflict);
            }
            next_state = LifecycleState::PolicyVerified;
            reason_code = "policy_commitment_recorded".to_owned();
            policy_digest_update = Some(policy_commitment_sha256.clone());
        }
        LifecycleAction::Authorize {
            customer_auth_sha256,
            ed25519_signature_hex,
            acknowledge_transparent_testnet_only,
            privacy_rail_proof_verified,
            ..
        } => {
            if !lower_hex64(customer_auth_sha256)
                || !cur.can_transition(LifecycleState::CustomerAuthorized)
            {
                return Err(StoreError::Conflict);
            }
            // Customer authorization digest must bind request_sha256 + account.
            let expected_auth = hex::encode(Sha256::digest(
                format!("stealthbridge-auth-v1\n{account}\n{request_sha256}\n").as_bytes(),
            ));
            if *customer_auth_sha256 != expected_auth {
                return Err(StoreError::Conflict);
            }
            if let Some(sig_hex) = ed25519_signature_hex {
                if !verify_account_ed25519_digest(account, &request_sha256, sig_hex) {
                    return Err(StoreError::Conflict);
                }
            }
            // Stage 7: Evaluate isolated privacy rail adapter rules cleanly.
            let rail_enum = match privacy_rail.as_str() {
                "private-payments" => PrivacyArchitectureKind::PrivatePayments,
                _ => PrivacyArchitectureKind::ConfidentialToken,
            };
            let rail_eval = evaluate_rail_preflight(&PrivacyRailPreflightRequest {
                segment: if org_id.is_some() {
                    ProductSegment::Business
                } else {
                    ProductSegment::Personal
                },
                rail: rail_enum,
                network_passphrase: TESTNET_PASSPHRASE.to_owned(),
                asset_semantics: AssetTransferSemantics::ExactTransferSep41,
                account_created_ledger: 5_800_000,
                rpc_oldest_retained_ledger: 5_696_840,
                durable_indexer_available: true,
                recovery_seed_backed_up: true,
                external_operator_or_issuer_verified: *privacy_rail_proof_verified,
                sac_pool_frozen_or_shortfall: false,
            });
            customer_auth_update = Some(customer_auth_sha256.clone());
            // First emit customer_authorized atomically, then stage 7 result if eligible.
            if *privacy_rail_proof_verified && rail_eval.architecturally_eligible {
                next_state = LifecycleState::PrivacyProofVerified;
                privacy_verified_update = Some(true);
                reason_code = "privacy_rail_proof_attested".to_owned();
            } else if *acknowledge_transparent_testnet_only {
                next_state = LifecycleState::PrivacyProofVerified;
                privacy_verified_update = Some(false);
                reason_code = "transparent_testnet_rail_disclosed".to_owned();
            } else {
                next_state = LifecycleState::PrivacyProofPending;
                privacy_verified_update = Some(false);
                reason_code = "privacy_rail_unverified_halt".to_owned();
            }
        }
        LifecycleAction::SubmitTx {
            testnet_tx_hash, ..
        } => {
            if !lower_hex64(testnet_tx_hash) || !cur.can_transition(LifecycleState::TxSubmitted) {
                return Err(StoreError::Conflict);
            }
            next_state = LifecycleState::TxSubmitted;
            tx_hash_col = Some(testnet_tx_hash.clone());
            reason_code = "testnet_tx_submitted".to_owned();
        }
        LifecycleAction::ObserveTx { .. } => {
            let obs = observed_tx_result.ok_or(StoreError::Conflict)?;
            if obs.status == "SUCCESS" {
                if !cur.can_transition(LifecycleState::ChainFinalized) {
                    return Err(StoreError::Conflict);
                }
                next_state = LifecycleState::ChainFinalized;
                reason_code = "testnet_ledger_finalized".to_owned();
                chain_status_update = Some("SUCCESS".to_owned());
            } else {
                if !cur.can_transition(LifecycleState::ChainFailed) {
                    return Err(StoreError::Conflict);
                }
                next_state = LifecycleState::ChainFailed;
                reason_code = "testnet_tx_failed_onchain".to_owned();
                chain_status_update = Some("FAILED".to_owned());
                last_error_update = Some("chain_tx_failed".to_owned());
            }
            obs_ledger_update = Some(obs.ledger as i64);
            obs_at_update = Some(obs.closed_at_unix.parse::<i64>().unwrap_or(stamp));
        }
        LifecycleAction::RequestPayout { .. } => {
            if std::env::var("STEALTHBRIDGE_PAYOUT_PROVIDER_SECRET")
                .ok()
                .is_none_or(|s| s.len() < 32)
                || !cur.can_transition(LifecycleState::PayoutPending)
            {
                return Err(StoreError::Conflict);
            }
            next_state = LifecycleState::PayoutPending;
            payout_status = "pending".to_owned();
            reason_code = "payout_requested_from_provider".to_owned();
        }
        LifecycleAction::ProviderCallback {
            outcome, callback, ..
        } => {
            let tenant = org_id.unwrap_or(corridor_id);
            let verified = verify_provider_secret(
                "STEALTHBRIDGE_PAYOUT_PROVIDER_SECRET",
                tenant,
                callback,
                stamp,
            )
            .ok_or(StoreError::Conflict)?;
            if outcome == "completed" {
                if !cur.can_transition(LifecycleState::PayoutCompleted) {
                    return Err(StoreError::Conflict);
                }
                next_state = LifecycleState::PayoutCompleted;
                payout_status = "completed".to_owned();
                reason_code = "provider_payout_completed".to_owned();
            } else if outcome == "failed" {
                if !cur.can_transition(LifecycleState::PayoutFailed) {
                    return Err(StoreError::Conflict);
                }
                next_state = LifecycleState::PayoutFailed;
                payout_status = "failed".to_owned();
                reason_code = "provider_payout_failed".to_owned();
                last_error_update = Some("provider_payout_failed".to_owned());
            } else {
                return Err(StoreError::BadRequest);
            }
            provider_event_update = Some(verified.event_id);
        }
        LifecycleAction::Retry { .. } => {
            if cur == LifecycleState::ChainFailed {
                next_state = LifecycleState::CustomerAuthorized;
                reason_code = "retry_after_chain_failure".to_owned();
                tx_hash_col = None;
                last_error_update = None;
            } else if cur == LifecycleState::PayoutFailed {
                next_state = LifecycleState::PayoutPending;
                payout_status = "pending".to_owned();
                reason_code = "retry_after_payout_failure".to_owned();
                last_error_update = None;
            } else {
                return Err(StoreError::Conflict);
            }
        }
        LifecycleAction::OpenDispute {
            reason_code: rc, ..
        } => {
            if !safe_reason(rc) || !cur.can_transition(LifecycleState::DisputeOpen) {
                return Err(StoreError::BadRequest);
            }
            next_state = LifecycleState::DisputeOpen;
            reconciliation_status = "disputed".to_owned();
            reason_code = rc.clone();
            last_error_update = Some(rc.clone());
        }
        LifecycleAction::RequestReversal {
            reason_code: rc, ..
        } => {
            if !safe_reason(rc) || !cur.can_transition(LifecycleState::ReversalPending) {
                return Err(StoreError::BadRequest);
            }
            next_state = LifecycleState::ReversalPending;
            payout_status = "reversed".to_owned();
            reconciliation_status = "disputed".to_owned();
            reason_code = rc.clone();
        }
        LifecycleAction::ConfirmReversal {
            reason_code: rc, ..
        } => {
            if !safe_reason(rc) || !cur.can_transition(LifecycleState::Reversed) {
                return Err(StoreError::BadRequest);
            }
            next_state = LifecycleState::Reversed;
            payout_status = "reversed".to_owned();
            reconciliation_status = "reversed".to_owned();
            reason_code = rc.clone();
        }
        LifecycleAction::Reconcile { .. } => {
            if !cur.can_transition(LifecycleState::Reconciled) {
                return Err(StoreError::Conflict);
            }
            next_state = LifecycleState::Reconciled;
            reconciliation_status = "matched".to_owned();
            reason_code = "lifecycle_reconciled".to_owned();
        }
        LifecycleAction::Cancel { .. } => {
            if !cur.can_transition(LifecycleState::Cancelled) {
                return Err(StoreError::Conflict);
            }
            next_state = LifecycleState::Cancelled;
            reason_code = "customer_cancelled".to_owned();
        }
    }

    let next_rev = revision + 1;
    claim_nonce(&mut tx, account, nonce, "POST").await?;
    sqlx::query(
        "UPDATE account_settlement_lifecycles SET state=$3,revision=$4,policy_commitment_sha256=COALESCE($5,policy_commitment_sha256),customer_auth_sha256=COALESCE($6,customer_auth_sha256),privacy_rail_verified=COALESCE($7,privacy_rail_verified),testnet_tx_hash=$8,observed_ledger=COALESCE($9,observed_ledger),observed_at_unix=COALESCE($10,observed_at_unix),chain_status=COALESCE($11,chain_status),provider_event_id=COALESCE($12,provider_event_id),payout_status=$13,reconciliation_status=$14,last_error_code=$15,updated_at_unix=$16 WHERE account_address=$1 AND id=$2",
    )
    .bind(account)
    .bind(settlement_id)
    .bind(next_state.as_str())
    .bind(next_rev)
    .bind(policy_digest_update)
    .bind(customer_auth_update)
    .bind(privacy_verified_update)
    .bind(&tx_hash_col)
    .bind(obs_ledger_update)
    .bind(obs_at_update)
    .bind(&chain_status_update)
    .bind(&provider_event_update)
    .bind(&payout_status)
    .bind(&reconciliation_status)
    .bind(&last_error_update)
    .bind(stamp)
    .execute(&mut *tx)
    .await?;

    write_event_and_outbox(
        &mut tx,
        TransitionRecord {
            account,
            settlement_id,
            revision: next_rev,
            previous: Some(cur),
            next: next_state,
            reason_code: &reason_code,
            tx_hash: tx_hash_col.as_deref(),
            stamp,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(json!({
        "id": settlement_id,
        "state": next_state.as_str(),
        "revision": next_rev,
        "payout_status": payout_status,
        "reconciliation_status": reconciliation_status,
        "testnet_tx_hash": tx_hash_col,
        "observed_ledger": obs_ledger_update,
        "chain_status": chain_status_update,
        "fiat_payouts_enabled": false,
        "mainnet_enabled": false
    }))
}

async fn directory(db: &PgPool, account: &str, stamp: i64) -> Result<Value, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id,organization_id,instruction_id,corridor_id,route_fingerprint,idempotency_key,request_sha256,asset_code,asset_issuer,amount_minor_units,recipient_address,recipient_kind,privacy_rail,privacy_rail_verified,quote_status,quote_sha256,policy_commitment_sha256,customer_auth_sha256,state,revision,expires_at_unix,testnet_tx_hash,observed_ledger,observed_at_unix,chain_status,provider_event_id,payout_status,reconciliation_status,last_error_code,created_at_unix,updated_at_unix FROM account_settlement_lifecycles WHERE account_address=$1 ORDER BY created_at_unix DESC,id DESC LIMIT 51",
    )
    .bind(account)
    .fetch_all(db)
    .await?;
    if rows.len() > MAX_ACTIVE_PER_ACCOUNT as usize {
        return Err(sqlx::Error::Protocol("settlement quota exceeded".into()));
    }
    let mut items = Vec::new();
    for r in rows {
        let id: Uuid = r.try_get("id")?;
        let state_raw: String = r.try_get("state")?;
        let expires: i64 = r.try_get("expires_at_unix")?;
        let effective_state = if stamp >= expires
            && LifecycleState::parse(&state_raw)
                .is_some_and(|s| s.can_transition(LifecycleState::Expired))
        {
            "expired"
        } else {
            state_raw.as_str()
        };
        let events_rows = sqlx::query(
            "SELECT revision,previous_state,next_state,reason_code,tx_hash,recorded_at_unix FROM account_settlement_events WHERE account_address=$1 AND settlement_id=$2 ORDER BY revision ASC",
        )
        .bind(account)
        .bind(id)
        .fetch_all(db)
        .await?;
        let mut events = Vec::new();
        for ev in events_rows {
            events.push(json!({
                "revision": ev.try_get::<i32,_>("revision")?,
                "previous_state": ev.try_get::<Option<String>,_>("previous_state")?,
                "next_state": ev.try_get::<String,_>("next_state")?,
                "reason_code": ev.try_get::<String,_>("reason_code")?,
                "tx_hash": ev.try_get::<Option<String>,_>("tx_hash")?,
                "recorded_at_unix": ev.try_get::<i64,_>("recorded_at_unix")?
            }));
        }
        items.push(json!({
            "id": id,
            "organization_id": r.try_get::<Option<Uuid>,_>("organization_id")?,
            "instruction_id": r.try_get::<Option<Uuid>,_>("instruction_id")?,
            "corridor_id": r.try_get::<Uuid,_>("corridor_id")?,
            "route_fingerprint": r.try_get::<String,_>("route_fingerprint")?,
            "idempotency_key": r.try_get::<String,_>("idempotency_key")?,
            "request_sha256": r.try_get::<String,_>("request_sha256")?,
            "asset_code": r.try_get::<String,_>("asset_code")?,
            "asset_issuer": r.try_get::<Option<String>,_>("asset_issuer")?,
            "amount_minor_units": r.try_get::<i64,_>("amount_minor_units")?,
            "recipient_address": r.try_get::<String,_>("recipient_address")?,
            "recipient_kind": r.try_get::<String,_>("recipient_kind")?,
            "privacy_rail": r.try_get::<String,_>("privacy_rail")?,
            "privacy_rail_verified": r.try_get::<bool,_>("privacy_rail_verified")?,
            "quote_status": r.try_get::<String,_>("quote_status")?,
            "quote_sha256": r.try_get::<Option<String>,_>("quote_sha256")?,
            "policy_commitment_sha256": r.try_get::<Option<String>,_>("policy_commitment_sha256")?,
            "customer_auth_sha256": r.try_get::<Option<String>,_>("customer_auth_sha256")?,
            "state": effective_state,
            "revision": r.try_get::<i32,_>("revision")?,
            "expires_at_unix": expires,
            "testnet_tx_hash": r.try_get::<Option<String>,_>("testnet_tx_hash")?,
            "observed_ledger": r.try_get::<Option<i64>,_>("observed_ledger")?,
            "observed_at_unix": r.try_get::<Option<i64>,_>("observed_at_unix")?,
            "chain_status": r.try_get::<Option<String>,_>("chain_status")?,
            "payout_status": r.try_get::<String,_>("payout_status")?,
            "reconciliation_status": r.try_get::<String,_>("reconciliation_status")?,
            "last_error_code": r.try_get::<Option<String>,_>("last_error_code")?,
            "created_at_unix": r.try_get::<i64,_>("created_at_unix")?,
            "updated_at_unix": r.try_get::<i64,_>("updated_at_unix")?,
            "events": events
        }));
    }
    Ok(json!({
        "schema_version": 1,
        "network": "testnet",
        "source": "account-settlement-lifecycles",
        "account_address": account,
        "observed_at_unix": stamp,
        "items": items,
        "mainnet_enabled": false,
        "live_fx_enabled": false,
        "fiat_payouts_enabled": false
    }))
}

async fn handle(state: Arc<AppState>, headers: HeaderMap, body: Bytes, method: &str) -> Response {
    let result = async {
        if !enabled() {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        if method != "GET" && (body.is_empty() || body.len() > 8192) {
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
        if method == "PUT" {
            let Ok(req) = serde_json::from_slice::<CreateSettlementRequest>(&body) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            if !req.valid() {
                return StatusCode::BAD_REQUEST.into_response();
            }
            return match create_lifecycle(db, &account, nonce, &req, stamp).await {
                Ok((status, payload)) => (status, Json(payload)).into_response(),
                Err(StoreError::BadRequest) => StatusCode::BAD_REQUEST.into_response(),
                Err(StoreError::Conflict) => StatusCode::CONFLICT.into_response(),
                Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
        }
        let Ok(action) = serde_json::from_slice::<LifecycleAction>(&body) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        match advance_lifecycle(&state, db, &account, nonce, &action, stamp).await {
            Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
            Err(StoreError::BadRequest) => StatusCode::BAD_REQUEST.into_response(),
            Err(StoreError::Conflict) => StatusCode::CONFLICT.into_response(),
            Err(StoreError::RpcUnavailable) => StatusCode::BAD_GATEWAY.into_response(),
            Err(StoreError::Database) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    };
    let mut response = tokio::time::timeout(Duration::from_secs(10), result)
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
    use ed25519_dalek::{Signer, SigningKey};

    const OWNER: &str = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";

    #[test]
    fn canonical_digest_and_state_machine_enforce_chain_vs_payout_boundary() {
        assert!(!LifecycleState::ChainFinalized.can_transition(LifecycleState::PayoutCompleted));
        assert!(LifecycleState::ChainFinalized.can_transition(LifecycleState::PayoutPending));
        assert!(LifecycleState::ChainFinalized.can_transition(LifecycleState::DisputeOpen));
        assert!(LifecycleState::DisputeOpen.can_transition(LifecycleState::ReversalPending));
        assert!(LifecycleState::ReversalPending.can_transition(LifecycleState::Reversed));
        assert!(!LifecycleState::ChainFinalized.is_terminal());
        assert!(LifecycleState::Reconciled.is_terminal());

        let req = CreateSettlementRequest {
            id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            organization_id: None,
            instruction_id: None,
            corridor_id: Uuid::parse_str("a12ef783-d60b-4427-aa62-d2562acd4cef").unwrap(),
            route_fingerprint: "20c275c9036c67194652e03698526070566bafc86cb1cc523f76df6161441c20"
                .to_owned(),
            idempotency_key: "idem-key-1234567890".to_owned(),
            asset_code: "USDC".to_owned(),
            asset_issuer: None,
            amount_minor_units: 2_500_000,
            recipient_address: OWNER.to_owned(),
            privacy_rail: "private-payments".to_owned(),
            expires_in_seconds: 3600,
            quote_evidence: None,
        };
        assert!(req.valid());
        let d1 = canonical_intent_digest(OWNER, &req);
        assert_eq!(d1.len(), 64);
        assert_eq!(d1, canonical_intent_digest(OWNER, &req));
    }

    #[test]
    fn verifies_ed25519_customer_authorization_for_disposable_testnet_keypair() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk_bytes = sk.verifying_key().to_bytes();
        let addr = stellar_strkey::ed25519::PublicKey(pk_bytes).to_string();
        let digest = hex::encode(Sha256::digest(b"canonical-intent-test"));
        let sig = sk.sign(digest.as_bytes());
        let sig_hex = hex::encode(sig.to_bytes());
        assert!(verify_account_ed25519_digest(&addr, &digest, &sig_hex));
        assert!(!verify_account_ed25519_digest(
            &addr,
            &hex::encode([0xaa; 32]),
            &sig_hex
        ));
    }
}
