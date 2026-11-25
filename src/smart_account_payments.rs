//! Passkey-authorized payments from StealthBridge smart accounts.
//!
//! Trust model
//! -----------
//! The customer's passkey signs the *Soroban authorization payload*:
//! `sha256(HashIdPreimage::SorobanAuthorization{network_id, nonce,
//! signature_expiration_ledger, invocation})`, where `invocation` is exactly
//! `token.transfer(from = smart account, to, amount)`. The Stellar host
//! derives this payload itself and hands it to the account's `__check_auth`,
//! which verifies the WebAuthn assertion (RP ID hash, UP/UV flags, exact
//! `challenge`, P-256 signature, low-S). Therefore:
//!
//! - the relayer only pays fees; it cannot produce a passing signature and so
//!   cannot move customer funds;
//! - recipient, asset, amount, network, account or nonce substitution changes
//!   the payload and fails on-chain; the host consumes the nonce (no replay);
//! - the signature expires at `signature_expiration_ledger`.
//!
//! The backend re-checks everything off-chain only to fail fast and to keep
//! honest state; the contract is the authority. Confirmation is derived from
//! the executed transaction envelope plus status `SUCCESS`, never from a
//! client claim.

use crate::{
    customer_ciphertext_vault::authorize_account_request,
    relayer::{self, RelayError},
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
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature as P256Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use stellar_xdr::{
    AccountId, AlphaNum12, AlphaNum4, Asset, AssetCode12, AssetCode4, ContractId,
    ContractIdPreimage, Hash, HashIdPreimage, HashIdPreimageContractId,
    HashIdPreimageSorobanAuthorization, HostFunction, Int128Parts, InvokeContractArgs,
    InvokeHostFunctionOp, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions,
    PublicKey, ReadXdr, ScAddress, ScBytes, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec,
    SequenceNumber, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanCredentials,
    Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
};
use uuid::Uuid;

const DOMAIN: &str = "stealthbridge-smart-account-payments-v1";
pub const PATH: &str = "/v1/account/smart-accounts/payments";
const BALANCES_DOMAIN: &str = "stealthbridge-smart-account-balances-v1";
pub const BALANCES_PATH: &str = "/v1/account/smart-accounts/balances";
/// ~10 minutes at 5s ledgers: how long a prepared payment may be signed.
const AUTH_VALIDITY_LEDGERS: u32 = 120;
const MAX_ASSERTION_BYTES: usize = 2048;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// --------------------------------------------------------------------- assets

/// A payable asset: the native lumen or a classic asset, always settled
/// through its Stellar Asset Contract (SAC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayAsset {
    pub code: String,
    pub issuer: Option<String>,
}

impl PayAsset {
    pub fn parse(s: &str) -> Option<Self> {
        if s == "XLM" {
            return Some(PayAsset {
                code: "XLM".into(),
                issuer: None,
            });
        }
        let (code, issuer) = s.split_once(':')?;
        let ok_code =
            (1..=12).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_alphanumeric());
        (ok_code && wallet::decode_account_address(issuer).is_some()).then(|| PayAsset {
            code: code.into(),
            issuer: Some(issuer.into()),
        })
    }

    pub fn id(&self) -> String {
        match &self.issuer {
            None => "XLM".into(),
            Some(i) => format!("{}:{}", self.code, i),
        }
    }

    fn xdr(&self) -> Option<Asset> {
        let Some(issuer) = &self.issuer else {
            return Some(Asset::Native);
        };
        let key = wallet::decode_account_address(issuer)?;
        let account = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key)));
        let b = self.code.as_bytes();
        Some(if b.len() <= 4 {
            let mut c = [0u8; 4];
            c[..b.len()].copy_from_slice(b);
            Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(c),
                issuer: account,
            })
        } else {
            let mut c = [0u8; 12];
            c[..b.len()].copy_from_slice(b);
            Asset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(c),
                issuer: account,
            })
        })
    }

    /// Deterministic SAC contract id for this asset on `passphrase`.
    pub fn contract_id(&self, passphrase: &str) -> Option<[u8; 32]> {
        let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
            network_id: Hash(relayer::network_id(passphrase)),
            contract_id_preimage: ContractIdPreimage::Asset(self.xdr()?),
        });
        Some(Sha256::digest(preimage.to_xdr(Limits::none()).ok()?).into())
    }
}

/// Assets customers may pay with: `STEALTHBRIDGE_PAYMENT_ASSETS`, a comma
/// separated list of `XLM` and/or `CODE:ISSUER`. Defaults to XLM only.
pub fn allowed_assets() -> Vec<PayAsset> {
    std::env::var("STEALTHBRIDGE_PAYMENT_ASSETS")
        .ok()
        .map(|v| {
            v.split(',')
                .filter_map(|a| PayAsset::parse(a.trim()))
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            vec![PayAsset {
                code: "XLM".into(),
                issuer: None,
            }]
        })
}

// ------------------------------------------------------------- XDR builders

fn contract_address(hash: [u8; 32]) -> ScAddress {
    ScAddress::Contract(ContractId(Hash(hash)))
}

/// `Address` ScVal for a G... account or C... contract.
pub fn address_scval(s: &str) -> Option<ScVal> {
    match wallet::parse_canonical_stellar_address(s)? {
        wallet::StellarAddress::Classic(k) => Some(ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(k)),
        )))),
        wallet::StellarAddress::Contract(h) => Some(ScVal::Address(contract_address(h))),
        _ => None,
    }
}

fn i128_scval(v: i64) -> ScVal {
    let v = i128::from(v);
    ScVal::I128(Int128Parts {
        hi: (v >> 64) as i64,
        lo: v as u64,
    })
}

/// The exact invocation the passkey authorizes.
pub fn transfer_args(
    token: [u8; 32],
    from: &str,
    to: &str,
    amount: i64,
) -> Option<InvokeContractArgs> {
    Some(InvokeContractArgs {
        contract_address: contract_address(token),
        function_name: ScSymbol("transfer".try_into().ok()?),
        args: vec![address_scval(from)?, address_scval(to)?, i128_scval(amount)]
            .try_into()
            .ok()?,
    })
}

pub fn invoke_tx(
    relayer: [u8; 32],
    sequence: i64,
    call: InvokeContractArgs,
    auth: Vec<SorobanAuthorizationEntry>,
) -> Option<Transaction> {
    Some(Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(relayer)),
        fee: 100_000,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(call),
                auth: auth.try_into().ok()?,
            }),
        }]
        .try_into()
        .ok()?,
        ext: TransactionExt::V0,
    })
}

fn envelope_b64(tx: &Transaction) -> String {
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: vec![].try_into().unwrap(),
    });
    relayer::b64(&env.to_xdr(Limits::none()).unwrap())
}

fn decode_xdr<T: ReadXdr>(b64: &str, max: usize) -> Option<T> {
    let bytes = crate::governance_code::decode_base64_bounded(b64, max).ok()?;
    T::from_xdr(&bytes, Limits::len(bytes.len())).ok()
}

/// From a recording-mode simulation, accept exactly one auth entry: address
/// credentials for `account`, root invocation identical to `expected`, and no
/// sub-invocations. Anything else is refused.
pub fn expected_auth_entry(
    sim: &Value,
    account: [u8; 32],
    expected: &InvokeContractArgs,
) -> Option<SorobanAuthorizationEntry> {
    let list = sim["results"][0]["auth"].as_array()?;
    if list.len() != 1 {
        return None;
    }
    let entry: SorobanAuthorizationEntry = decode_xdr(list[0].as_str()?, 16 * 1024)?;
    let SorobanCredentials::Address(creds) = &entry.credentials else {
        return None;
    };
    if creds.address != contract_address(account) {
        return None;
    }
    let SorobanAuthorizedFunction::ContractFn(call) = &entry.root_invocation.function else {
        return None;
    };
    (call == expected && entry.root_invocation.sub_invocations.is_empty()).then_some(entry)
}

/// Canonical preimage and payload for an entry with its expiration set.
pub fn authorization_preimage(
    entry: &SorobanAuthorizationEntry,
    passphrase: &str,
) -> Option<(Vec<u8>, [u8; 32])> {
    let SorobanCredentials::Address(creds) = &entry.credentials else {
        return None;
    };
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(relayer::network_id(passphrase)),
        nonce: creds.nonce,
        signature_expiration_ledger: creds.signature_expiration_ledger,
        invocation: entry.root_invocation.clone(),
    });
    let bytes = preimage.to_xdr(Limits::none()).ok()?;
    let payload: [u8; 32] = Sha256::digest(&bytes).into();
    Some((bytes, payload))
}

// ------------------------------------------------------------------ WebAuthn

pub fn b64url_decode(s: &str, max: usize) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() > max * 4 / 3 + 4 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0 && out.len() <= max).then_some(out)
}

pub fn b64url(bytes: &[u8]) -> String {
    relayer::b64(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

#[derive(Debug, PartialEq, Eq)]
pub enum AssertionError {
    Encoding,
    RpId,
    Flags,
    ClientData,
    Challenge,
    Origin,
    Signature,
}

/// Verified WebAuthn assertion, ready for `AuthSignature::WebAuthn`.
pub struct VerifiedAssertion {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    /// Raw r||s with s normalized to the low half (the host rejects high-S).
    pub signature: [u8; 64],
}

/// Off-chain mirror of the account contract's WebAuthn rules, plus an origin
/// check. Accepts a DER (as returned by WebAuthn) or raw 64-byte signature.
pub fn verify_assertion(
    owner_public_key: &[u8; 65],
    rp_id: &str,
    payload: &[u8; 32],
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: &[u8],
) -> Result<VerifiedAssertion, AssertionError> {
    if authenticator_data.len() < 37 || client_data_json.len() > 2048 {
        return Err(AssertionError::Encoding);
    }
    if authenticator_data[..32] != relayer::rp_id_hash(rp_id) {
        return Err(AssertionError::RpId);
    }
    if authenticator_data[32] & 0x05 != 0x05 {
        return Err(AssertionError::Flags);
    }
    let cd: Value =
        serde_json::from_slice(&client_data_json).map_err(|_| AssertionError::ClientData)?;
    if cd["type"].as_str() != Some("webauthn.get") {
        return Err(AssertionError::ClientData);
    }
    if cd["challenge"].as_str() != Some(b64url(payload).as_str()) {
        return Err(AssertionError::Challenge);
    }
    let origin_ok = cd["origin"].as_str() == Some(&format!("https://{rp_id}"))
        || (relayer::local_network_allowed()
            && cd["origin"]
                .as_str()
                .is_some_and(|o| o.starts_with("http://localhost")));
    if !origin_ok || cd["crossOrigin"].as_bool() == Some(true) {
        return Err(AssertionError::Origin);
    }
    let sig = if signature.len() == 64 {
        P256Signature::from_slice(signature)
    } else {
        P256Signature::from_der(signature)
    }
    .map_err(|_| AssertionError::Encoding)?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let key =
        VerifyingKey::from_sec1_bytes(owner_public_key).map_err(|_| AssertionError::Encoding)?;
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    let digest: [u8; 32] = Sha256::digest(&signed).into();
    key.verify_prehash(&digest, &sig)
        .map_err(|_| AssertionError::Signature)?;
    let mut raw = [0u8; 64];
    raw.copy_from_slice(&sig.to_bytes());
    Ok(VerifiedAssertion {
        authenticator_data,
        client_data_json,
        signature: raw,
    })
}

/// `Vec<AuthSignature>` holding one `AuthSignature::WebAuthn(WebAuthnProof)`.
/// Struct fields are encoded as a map with keys in ascending order.
pub fn webauthn_signature_scval(signer_id: [u8; 32], a: &VerifiedAssertion) -> Option<ScVal> {
    let entry = |k: &str, v: Vec<u8>| -> Option<ScMapEntry> {
        Some(ScMapEntry {
            key: ScVal::Symbol(ScSymbol(k.try_into().ok()?)),
            val: ScVal::Bytes(ScBytes(v.try_into().ok()?)),
        })
    };
    let proof = ScVal::Map(Some(ScMap(
        vec![
            entry("authenticator_data", a.authenticator_data.clone())?,
            entry("client_data_json", a.client_data_json.clone())?,
            entry("signature", a.signature.to_vec())?,
            entry("signer_id", signer_id.to_vec())?,
        ]
        .try_into()
        .ok()?,
    )));
    let variant = ScVal::Vec(Some(ScVec(
        vec![ScVal::Symbol(ScSymbol("WebAuthn".try_into().ok()?)), proof]
            .try_into()
            .ok()?,
    )));
    Some(ScVal::Vec(Some(ScVec(vec![variant].try_into().ok()?))))
}

pub fn secp256r1_signer_id(public_key: &[u8; 65]) -> [u8; 32] {
    let mut raw = vec![2u8];
    raw.extend_from_slice(public_key);
    Sha256::digest(&raw).into()
}

// ------------------------------------------------------------ chain evidence

/// True only if a successful envelope executed exactly `expected` with the
/// smart account's address credentials. Used to confirm payments.
pub fn envelope_executes(
    rpc_result: &Value,
    account: [u8; 32],
    expected: &InvokeContractArgs,
) -> bool {
    let Some(env) = rpc_result["envelopeXdr"]
        .as_str()
        .and_then(|b| decode_xdr::<TransactionEnvelope>(b, 256 * 1024))
    else {
        return false;
    };
    let TransactionEnvelope::Tx(v1) = env else {
        return false;
    };
    v1.tx.operations.iter().any(|op| {
        let OperationBody::InvokeHostFunction(f) = &op.body else {
            return false;
        };
        let HostFunction::InvokeContract(call) = &f.host_function else {
            return false;
        };
        call == expected
            && f.auth.iter().any(|e| {
                matches!(&e.credentials, SorobanCredentials::Address(c) if c.address == contract_address(account))
            })
    })
}

// ------------------------------------------------------------------- service

struct Config {
    key: ed25519_dalek::SigningKey,
}

fn config() -> Option<Config> {
    Some(Config {
        key: relayer::relayer_key(&std::env::var("STEALTHBRIDGE_RELAYER_SECRET").ok()?)?,
    })
}

fn reply(body: Value, status: StatusCode) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(body),
    )
        .into_response()
}

fn fail(code: &str, status: StatusCode) -> Response {
    reply(json!({ "code": code }), status)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
pub enum PaymentAction {
    Prepare {
        contract_address: String,
        destination: String,
        asset: String,
        amount_stroops: i64,
    },
    Submit {
        id: Uuid,
        authenticator_data: String,
        client_data_json: String,
        signature: String,
    },
}

struct OwnedAccount {
    owner_public_key: [u8; 65],
    credential_id: String,
    rp_id: String,
}

async fn owned_deployed_account(
    db: &sqlx::PgPool,
    account: &str,
    contract: &str,
) -> Result<Option<OwnedAccount>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT owner_public_key, credential_id, rp_id FROM account_smart_account_deployments
         WHERE account_address=$1 AND contract_address=$2 AND status='deployed'",
    )
    .bind(account)
    .bind(contract)
    .fetch_optional(db)
    .await?;
    Ok(row.and_then(|r| {
        let pk: String = r.get("owner_public_key");
        let pk: [u8; 65] = hex::decode(pk).ok()?.try_into().ok()?;
        Some(OwnedAccount {
            owner_public_key: pk,
            credential_id: r.get("credential_id"),
            rp_id: r.get("rp_id"),
        })
    }))
}

async fn latest_ledger(state: &AppState) -> Result<u32, RelayError> {
    let r = state
        .rpc("getLatestLedger")
        .await
        .map_err(|_| RelayError::Rpc)?;
    r["sequence"]
        .as_u64()
        .map(|s| s as u32)
        .ok_or(RelayError::Rpc)
}

async fn simulate(state: &AppState, tx: &Transaction) -> Result<Value, RelayError> {
    state
        .rpc_with_params(
            "simulateTransaction",
            Some(json!({"transaction": envelope_b64(tx)})),
        )
        .await
        .map_err(|_| RelayError::Rpc)
}

struct PrepareRequest {
    contract: String,
    destination: String,
    asset: String,
    amount: i64,
}

async fn prepare(
    state: &AppState,
    db: &sqlx::PgPool,
    cfg: &Config,
    account: &str,
    req: PrepareRequest,
    stamp: i64,
) -> Response {
    let PrepareRequest {
        contract,
        destination,
        asset,
        amount,
    } = req;
    let Some(asset) = PayAsset::parse(&asset).filter(|a| allowed_assets().contains(a)) else {
        return fail("ASSET_NOT_SUPPORTED", StatusCode::BAD_REQUEST);
    };
    if amount <= 0 || destination == contract || address_scval(&destination).is_none() {
        return fail("INVALID_PAYMENT", StatusCode::BAD_REQUEST);
    }
    let Some(account_hash) = relayer::contract_hash(&contract) else {
        return fail("INVALID_PAYMENT", StatusCode::BAD_REQUEST);
    };
    let owned = match owned_deployed_account(db, account, &contract).await {
        Ok(Some(o)) => o,
        Ok(None) => return fail("SMART_ACCOUNT_NOT_FOUND", StatusCode::NOT_FOUND),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let passphrase = match relayer::network_passphrase(state).await {
        Ok(p) => p,
        Err(_) => return fail("NETWORK_UNAVAILABLE", StatusCode::BAD_GATEWAY),
    };
    let Some(token) = asset.contract_id(&passphrase) else {
        return fail("ASSET_NOT_SUPPORTED", StatusCode::BAD_REQUEST);
    };
    let Some(call) = transfer_args(token, &contract, &destination, amount) else {
        return fail("INVALID_PAYMENT", StatusCode::BAD_REQUEST);
    };
    let relayer_pub = cfg.key.verifying_key().to_bytes();
    let seq = match relayer::relayer_sequence(state, relayer_pub).await {
        Ok(s) => s,
        Err(_) => return fail("NETWORK_UNAVAILABLE", StatusCode::BAD_GATEWAY),
    };
    let Some(tx) = invoke_tx(relayer_pub, seq + 1, call.clone(), vec![]) else {
        return fail("INVALID_PAYMENT", StatusCode::BAD_REQUEST);
    };
    let sim = match simulate(state, &tx).await {
        Ok(s) => s,
        Err(_) => return fail("NETWORK_UNAVAILABLE", StatusCode::BAD_GATEWAY),
    };
    if sim.get("error").is_some_and(|e| !e.is_null()) {
        // e.g. insufficient balance or missing trustline at the destination.
        return fail("PAYMENT_WOULD_FAIL", StatusCode::UNPROCESSABLE_ENTITY);
    }
    let Some(mut entry) = expected_auth_entry(&sim, account_hash, &call) else {
        return fail("UNEXPECTED_AUTHORIZATION", StatusCode::BAD_GATEWAY);
    };
    let ledger = match latest_ledger(state).await {
        Ok(l) => l,
        Err(_) => return fail("NETWORK_UNAVAILABLE", StatusCode::BAD_GATEWAY),
    };
    let expiration = ledger + AUTH_VALIDITY_LEDGERS;
    let nonce = match &mut entry.credentials {
        SorobanCredentials::Address(c) => {
            c.signature_expiration_ledger = expiration;
            c.nonce
        }
        _ => return fail("UNEXPECTED_AUTHORIZATION", StatusCode::BAD_GATEWAY),
    };
    let Some((preimage, payload)) = authorization_preimage(&entry, &passphrase) else {
        return fail("UNEXPECTED_AUTHORIZATION", StatusCode::BAD_GATEWAY);
    };
    let fee: i64 = sim["minResourceFee"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let id = Uuid::new_v4();
    let entry_b64 = relayer::b64(&entry.to_xdr(Limits::none()).unwrap());
    let inserted = sqlx::query(
        "INSERT INTO account_smart_account_payments(id,account_address,contract_address,destination,asset,asset_contract,amount_stroops,network_passphrase,auth_entry_xdr,signature_payload,auth_nonce,expiration_ledger,fee_estimate_stroops,status,created_at_unix,updated_at_unix)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'prepared',$14,$14)",
    )
    .bind(id)
    .bind(account)
    .bind(&contract)
    .bind(&destination)
    .bind(asset.id())
    .bind(stellar_strkey::Contract(token).to_string().as_str())
    .bind(amount)
    .bind(&passphrase)
    .bind(&entry_b64)
    .bind(hex::encode(payload))
    .bind(nonce)
    .bind(i64::from(expiration))
    .bind(fee)
    .bind(stamp)
    .execute(db)
    .await;
    if inserted.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    reply(
        json!({
            "id": id,
            "status": "prepared",
            "contract_address": contract,
            "destination": destination,
            "asset": asset.id(),
            "asset_contract": stellar_strkey::Contract(token).to_string().as_str(),
            "amount_stroops": amount,
            "network_passphrase": passphrase,
            "expiration_ledger": expiration,
            "fee_estimate_stroops": fee,
            "fee_payer": "stealthbridge-relayer",
            // The passkey signs sha256(preimage); clients can recompute it.
            "authorization_preimage_xdr": relayer::b64(&preimage),
            "challenge": b64url(&payload),
            "credential_id": owned.credential_id,
            "rp_id": owned.rp_id,
        }),
        StatusCode::CREATED,
    )
}

#[allow(clippy::too_many_arguments)]
async fn submit(
    state: &AppState,
    db: &sqlx::PgPool,
    cfg: &Config,
    account: &str,
    id: Uuid,
    authenticator_data: &str,
    client_data_json: &str,
    signature: &str,
    stamp: i64,
) -> Response {
    let (Some(ad), Some(cd), Some(sig)) = (
        b64url_decode(authenticator_data, MAX_ASSERTION_BYTES),
        b64url_decode(client_data_json, MAX_ASSERTION_BYTES),
        b64url_decode(signature, 80),
    ) else {
        return fail("INVALID_ASSERTION", StatusCode::BAD_REQUEST);
    };
    // Atomically claim the prepared payment: concurrent or repeated submits
    // of the same intent cannot both proceed.
    let claimed = sqlx::query(
        "UPDATE account_smart_account_payments SET status='submitting', updated_at_unix=$3
         WHERE id=$1 AND account_address=$2 AND status='prepared'
         RETURNING contract_address,destination,asset_contract,amount_stroops,network_passphrase,auth_entry_xdr,signature_payload,expiration_ledger",
    )
    .bind(id)
    .bind(account)
    .bind(stamp)
    .fetch_optional(db)
    .await;
    let row = match claimed {
        Ok(Some(r)) => r,
        Ok(None) => return fail("PAYMENT_NOT_PENDING", StatusCode::CONFLICT),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let contract: String = row.get("contract_address");
    let mark = |status: &'static str, code: &'static str| {
        let db = db.clone();
        async move {
            let _ = sqlx::query(
                "UPDATE account_smart_account_payments SET status=$2, error_code=$3, updated_at_unix=$4 WHERE id=$1",
            )
            .bind(id)
            .bind(status)
            .bind(code)
            .bind(now())
            .execute(&db)
            .await;
        }
    };
    let owned = match owned_deployed_account(db, account, &contract).await {
        Ok(Some(o)) => o,
        _ => {
            mark("failed", "SMART_ACCOUNT_NOT_FOUND").await;
            return fail("SMART_ACCOUNT_NOT_FOUND", StatusCode::NOT_FOUND);
        }
    };
    let payload: [u8; 32] = match hex::decode(row.get::<String, _>("signature_payload"))
        .ok()
        .and_then(|v| v.try_into().ok())
    {
        Some(p) => p,
        None => {
            mark("failed", "CORRUPT_INTENT").await;
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let assertion = match verify_assertion(
        &owned.owner_public_key,
        &owned.rp_id,
        &payload,
        ad,
        cd,
        &sig,
    ) {
        Ok(a) => a,
        Err(e) => {
            // The intent stays usable only if nothing was signed wrongly; a
            // bad assertion returns it to `prepared` so the customer may retry.
            let _ = sqlx::query("UPDATE account_smart_account_payments SET status='prepared' WHERE id=$1 AND status='submitting'")
                .bind(id)
                .execute(db)
                .await;
            return reply(
                json!({"code":"ASSERTION_REJECTED","reason":format!("{e:?}")}),
                StatusCode::UNPROCESSABLE_ENTITY,
            );
        }
    };
    let expiration: i64 = row.get("expiration_ledger");
    match latest_ledger(state).await {
        Ok(l) if i64::from(l) < expiration => {}
        Ok(_) => {
            mark("expired", "AUTHORIZATION_EXPIRED").await;
            return fail("AUTHORIZATION_EXPIRED", StatusCode::GONE);
        }
        Err(_) => {
            let _ = sqlx::query("UPDATE account_smart_account_payments SET status='prepared' WHERE id=$1 AND status='submitting'")
                .bind(id)
                .execute(db)
                .await;
            return fail("NETWORK_UNAVAILABLE", StatusCode::BAD_GATEWAY);
        }
    }
    let passphrase: String = row.get("network_passphrase");
    let Some(mut entry) =
        decode_xdr::<SorobanAuthorizationEntry>(&row.get::<String, _>("auth_entry_xdr"), 16 * 1024)
    else {
        mark("failed", "CORRUPT_INTENT").await;
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let SorobanAuthorizedFunction::ContractFn(call) = entry.root_invocation.function.clone() else {
        mark("failed", "CORRUPT_INTENT").await;
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let signer_id = secp256r1_signer_id(&owned.owner_public_key);
    let Some(sig_val) = webauthn_signature_scval(signer_id, &assertion) else {
        mark("failed", "ENCODING").await;
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let SorobanCredentials::Address(c) = &mut entry.credentials {
        c.signature = sig_val;
    }
    let relayer_pub = cfg.key.verifying_key().to_bytes();
    let built = async {
        let seq = relayer::relayer_sequence(state, relayer_pub).await?;
        let tx =
            invoke_tx(relayer_pub, seq + 1, call, vec![entry]).ok_or(RelayError::InvalidInput)?;
        // Enforcing simulation: the account's __check_auth decides here.
        let sim = simulate(state, &tx).await?;
        if sim.get("error").is_some_and(|e| !e.is_null()) {
            return Err(RelayError::Simulation);
        }
        relayer::assemble_signed(tx, &sim)
    }
    .await;
    let ready = match built {
        Ok(t) => t,
        Err(RelayError::Simulation) => {
            mark("failed", "REJECTED_BY_ACCOUNT").await;
            return fail("REJECTED_BY_ACCOUNT", StatusCode::UNPROCESSABLE_ENTITY);
        }
        Err(_) => {
            let _ = sqlx::query("UPDATE account_smart_account_payments SET status='prepared' WHERE id=$1 AND status='submitting'")
                .bind(id)
                .execute(db)
                .await;
            return fail("NETWORK_UNAVAILABLE", StatusCode::BAD_GATEWAY);
        }
    };
    let hash = relayer::transaction_hash(&ready, &passphrase);
    let envelope = relayer::sign(ready, &passphrase, &cfg.key);
    let sent = state
        .rpc_with_params(
            "sendTransaction",
            Some(json!({"transaction": relayer::b64(&envelope.to_xdr(Limits::none()).unwrap())})),
        )
        .await;
    let accepted =
        matches!(&sent, Ok(v) if matches!(v["status"].as_str(), Some("PENDING" | "DUPLICATE")));
    if !accepted {
        mark("failed", "SUBMISSION_REJECTED").await;
        return fail("SUBMISSION_REJECTED", StatusCode::BAD_GATEWAY);
    }
    let _ = sqlx::query(
        "UPDATE account_smart_account_payments SET status='submitted', tx_hash=$2, updated_at_unix=$3 WHERE id=$1",
    )
    .bind(id)
    .bind(&hash)
    .bind(now())
    .execute(db)
    .await;
    reply(
        json!({"id": id, "status": "submitted", "tx_hash": hash}),
        StatusCode::ACCEPTED,
    )
}

async fn refresh_and_list(
    state: &AppState,
    db: &sqlx::PgPool,
    account: &str,
) -> Result<Vec<Value>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id,contract_address,destination,asset,asset_contract,amount_stroops,status,tx_hash,ledger,expiration_ledger,fee_estimate_stroops,error_code,created_at_unix
         FROM account_smart_account_payments WHERE account_address=$1 ORDER BY created_at_unix DESC LIMIT 25",
    )
    .bind(account)
    .fetch_all(db)
    .await?;
    let latest = latest_ledger(state).await.ok();
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id: Uuid = r.get("id");
        let mut status: String = r.get("status");
        let mut ledger: Option<i64> = r.get("ledger");
        let mut error: Option<String> = r.get("error_code");
        let contract: String = r.get("contract_address");
        let destination: String = r.get("destination");
        let asset_contract: String = r.get("asset_contract");
        let amount: i64 = r.get("amount_stroops");
        let tx_hash: Option<String> = r.get("tx_hash");
        let expiration: i64 = r.get("expiration_ledger");
        if status == "prepared" && latest.is_some_and(|l| i64::from(l) >= expiration) {
            status = "expired".into();
            sqlx::query("UPDATE account_smart_account_payments SET status='expired' WHERE id=$1 AND status='prepared'")
                .bind(id).execute(db).await?;
        }
        if status == "submitted" {
            if let Some(hash) = &tx_hash {
                let observed = state
                    .rpc_with_params("getTransaction", Some(json!({"hash": hash})))
                    .await
                    .ok();
                if let Some(res) = observed {
                    let expected = relayer::contract_hash(&asset_contract)
                        .zip(relayer::contract_hash(&contract))
                        .and_then(|(t, a)| {
                            transfer_args(t, &contract, &destination, amount).map(|c| (a, c))
                        });
                    let next = match (res["status"].as_str(), expected) {
                        (Some("SUCCESS"), Some((acct, call)))
                            if envelope_executes(&res, acct, &call) =>
                        {
                            Some(("confirmed", res["ledger"].as_i64(), None))
                        }
                        (Some("SUCCESS"), _) => Some(("failed", None, Some("EVIDENCE_MISMATCH"))),
                        (Some("FAILED"), _) => {
                            Some(("failed", res["ledger"].as_i64(), Some("FAILED_ON_CHAIN")))
                        }
                        _ => None,
                    };
                    if let Some((s, l, e)) = next {
                        sqlx::query("UPDATE account_smart_account_payments SET status=$2, ledger=$3, error_code=$4, updated_at_unix=$5 WHERE id=$1 AND status='submitted'")
                            .bind(id).bind(s).bind(l).bind(e).bind(now()).execute(db).await?;
                        status = s.into();
                        ledger = l;
                        error = e.map(Into::into);
                    }
                }
            }
        }
        out.push(json!({
            "id": id,
            "contract_address": contract,
            "destination": destination,
            "asset": r.get::<String,_>("asset"),
            "asset_contract": asset_contract,
            "amount_stroops": amount,
            "status": status,
            "tx_hash": tx_hash,
            "ledger": ledger,
            "fee_estimate_stroops": r.get::<i64,_>("fee_estimate_stroops"),
            "error_code": error,
            "created_at_unix": r.get::<i64,_>("created_at_unix"),
        }));
    }
    Ok(out)
}

pub async fn get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some((account, _)) =
        authorize_account_request(&headers, &state, "GET", &[], now(), DOMAIN, PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match refresh_and_list(&state, db, &account).await {
        Ok(items) => reply(
            json!({
                "schema_version": 1,
                "account_address": account,
                "payments_configured": config().is_some(),
                "assets": allowed_assets().iter().map(PayAsset::id).collect::<Vec<_>>(),
                "payments": items,
            }),
            StatusCode::OK,
        ),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

pub async fn post(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let stamp = now();
    let Some((account, Some(nonce))) =
        authorize_account_request(&headers, &state, "POST", &body, stamp, DOMAIN, PATH)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(cfg) = config() else {
        return fail("PAYMENTS_NOT_CONFIGURED", StatusCode::SERVICE_UNAVAILABLE);
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(action) = serde_json::from_slice::<PaymentAction>(&body) else {
        return fail("INVALID_PAYMENT", StatusCode::BAD_REQUEST);
    };
    let claimed = sqlx::query(
        "INSERT INTO account_smart_account_payment_receipts(nonce,account_address) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(nonce)
    .bind(&account)
    .execute(db)
    .await;
    if !matches!(claimed, Ok(r) if r.rows_affected() == 1) {
        return fail("REPLAYED_REQUEST", StatusCode::CONFLICT);
    }
    match action {
        PaymentAction::Prepare {
            contract_address,
            destination,
            asset,
            amount_stroops,
        } => {
            let req = PrepareRequest {
                contract: contract_address,
                destination,
                asset,
                amount: amount_stroops,
            };
            prepare(&state, db, &cfg, &account, req, stamp).await
        }
        PaymentAction::Submit {
            id,
            authenticator_data,
            client_data_json,
            signature,
        } => {
            submit(
                &state,
                db,
                &cfg,
                &account,
                id,
                &authenticator_data,
                &client_data_json,
                &signature,
                stamp,
            )
            .await
        }
    }
}

/// Live balances of the caller's deployed smart accounts, read from each
/// asset contract by simulation (no transaction is submitted).
pub async fn balances(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some((account, _)) = authorize_account_request(
        &headers,
        &state,
        "GET",
        &[],
        now(),
        BALANCES_DOMAIN,
        BALANCES_PATH,
    ) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let (Some(db), Some(cfg)) = (state.db.as_ref(), config()) else {
        return fail("PAYMENTS_NOT_CONFIGURED", StatusCode::SERVICE_UNAVAILABLE);
    };
    let Ok(rows) = sqlx::query(
        "SELECT contract_address FROM account_smart_account_deployments WHERE account_address=$1 AND status='deployed' ORDER BY created_at_unix DESC LIMIT 3",
    )
    .bind(&account)
    .fetch_all(db)
    .await
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(passphrase) = relayer::network_passphrase(&state).await else {
        return fail("NETWORK_UNAVAILABLE", StatusCode::BAD_GATEWAY);
    };
    let relayer_pub = cfg.key.verifying_key().to_bytes();
    let mut out = Vec::new();
    for r in rows {
        let contract: String = r.get("contract_address");
        let mut assets = Vec::new();
        for asset in allowed_assets() {
            let Some(token) = asset.contract_id(&passphrase) else {
                continue;
            };
            let call = InvokeContractArgs {
                contract_address: contract_address(token),
                function_name: ScSymbol("balance".try_into().unwrap()),
                args: vec![address_scval(&contract).unwrap()].try_into().unwrap(),
            };
            let balance = match invoke_tx(relayer_pub, 1, call, vec![]) {
                Some(tx) => simulate(&state, &tx).await.ok().and_then(|sim| {
                    let v: ScVal = decode_xdr(sim["results"][0]["xdr"].as_str()?, 1024)?;
                    match v {
                        ScVal::I128(p) => {
                            Some(((i128::from(p.hi) << 64) | i128::from(p.lo)).to_string())
                        }
                        _ => None,
                    }
                }),
                None => None,
            };
            assets.push(json!({"asset": asset.id(), "balance_stroops": balance}));
        }
        out.push(json!({"contract_address": contract, "balances": assets}));
    }
    reply(
        json!({"schema_version": 1, "account_address": account, "accounts": out}),
        StatusCode::OK,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

    const ACCOUNT: &str = "CAUJ5FMGDISNYEU7T6EQDYRLFF7CVC5F2PXJVEHQHY7HM275I2X6ITH6";
    const DEST: &str = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
    const RP: &str = "stealthbridge.vercel.app";

    #[test]
    fn native_sac_id_matches_the_known_testnet_contract() {
        let xlm = PayAsset::parse("XLM").unwrap();
        let id = xlm.contract_id(relayer::TESTNET_PASSPHRASE).unwrap();
        assert_eq!(
            stellar_strkey::Contract(id).to_string().as_str(),
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
        );
        // The SAC id depends on the network: no cross-network reuse.
        assert_ne!(Some(id), xlm.contract_id(relayer::STANDALONE_PASSPHRASE));
    }

    #[test]
    fn parses_and_rejects_assets() {
        assert!(
            PayAsset::parse("USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5")
                .is_some()
        );
        assert!(PayAsset::parse("USDC").is_none());
        assert!(PayAsset::parse(
            "TOO-LONG-CODE:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
        )
        .is_none());
        assert!(PayAsset::parse("USDC:GNOTANISSUER").is_none());
    }

    fn entry_for(
        call: &InvokeContractArgs,
        account: [u8; 32],
        subs: bool,
    ) -> SorobanAuthorizationEntry {
        use stellar_xdr::{SorobanAddressCredentials, SorobanAuthorizedInvocation};
        let inv = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(call.clone()),
            sub_invocations: vec![].try_into().unwrap(),
        };
        let mut root = inv.clone();
        if subs {
            root.sub_invocations = vec![inv].try_into().unwrap();
        }
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: contract_address(account),
                nonce: 42,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: root,
        }
    }

    fn sim_with(entries: &[SorobanAuthorizationEntry]) -> Value {
        json!({"results":[{"auth": entries.iter().map(|e| relayer::b64(&e.to_xdr(Limits::none()).unwrap())).collect::<Vec<_>>()}]})
    }

    #[test]
    fn only_the_exact_transfer_authorization_is_accepted() {
        let acct = relayer::contract_hash(ACCOUNT).unwrap();
        let token = [7u8; 32];
        let call = transfer_args(token, ACCOUNT, DEST, 25_000_000).unwrap();
        assert!(
            expected_auth_entry(&sim_with(&[entry_for(&call, acct, false)]), acct, &call).is_some()
        );
        // Different amount, different account, extra sub-invocations, or two
        // entries are all refused before the customer is asked to sign.
        let other = transfer_args(token, ACCOUNT, DEST, 25_000_001).unwrap();
        assert!(
            expected_auth_entry(&sim_with(&[entry_for(&other, acct, false)]), acct, &call)
                .is_none()
        );
        assert!(
            expected_auth_entry(&sim_with(&[entry_for(&call, [9; 32], false)]), acct, &call)
                .is_none()
        );
        assert!(
            expected_auth_entry(&sim_with(&[entry_for(&call, acct, true)]), acct, &call).is_none()
        );
        let e = entry_for(&call, acct, false);
        assert!(expected_auth_entry(&sim_with(&[e.clone(), e]), acct, &call).is_none());
    }

    #[test]
    fn payload_binds_network_nonce_and_expiry() {
        let acct = relayer::contract_hash(ACCOUNT).unwrap();
        let call = transfer_args([7u8; 32], ACCOUNT, DEST, 1).unwrap();
        let mut e = entry_for(&call, acct, false);
        let (_, p1) = authorization_preimage(&e, relayer::TESTNET_PASSPHRASE).unwrap();
        let (_, p2) = authorization_preimage(&e, relayer::STANDALONE_PASSPHRASE).unwrap();
        assert_ne!(p1, p2);
        if let SorobanCredentials::Address(c) = &mut e.credentials {
            c.signature_expiration_ledger = 99;
        }
        let (_, p3) = authorization_preimage(&e, relayer::TESTNET_PASSPHRASE).unwrap();
        assert_ne!(p1, p3);
    }

    struct Fixture {
        key: SigningKey,
        pk: [u8; 65],
        payload: [u8; 32],
    }

    fn fixture() -> Fixture {
        let key = SigningKey::from_bytes(&[11u8; 32].into()).unwrap();
        let pk: [u8; 65] = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        Fixture {
            key,
            pk,
            payload: [3u8; 32],
        }
    }

    fn assertion(
        f: &Fixture,
        rp: &str,
        flags: u8,
        challenge: &[u8; 32],
        origin: &str,
        kind: &str,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut ad = relayer::rp_id_hash(rp).to_vec();
        ad.push(flags);
        ad.extend_from_slice(&1u32.to_be_bytes());
        let cd = format!(
            r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
            b64url(challenge)
        )
        .into_bytes();
        let mut signed = ad.clone();
        signed.extend_from_slice(&Sha256::digest(&cd));
        let digest: [u8; 32] = Sha256::digest(&signed).into();
        let sig: P256Signature = f.key.sign_prehash(&digest).unwrap();
        (ad, cd, sig.to_der().as_bytes().to_vec())
    }

    #[test]
    fn verifies_der_assertions_and_normalizes_to_low_s() {
        let f = fixture();
        let (ad, cd, der) = assertion(
            &f,
            RP,
            0x05,
            &f.payload,
            "https://stealthbridge.vercel.app",
            "webauthn.get",
        );
        let ok = verify_assertion(&f.pk, RP, &f.payload, ad.clone(), cd.clone(), &der).unwrap();
        let s = P256Signature::from_slice(&ok.signature).unwrap();
        assert!(s.normalize_s().is_none(), "signature must already be low-S");
        // A high-S variant of the same signature is accepted and normalized.
        let low = P256Signature::from_der(&der).unwrap();
        let low = low.normalize_s().unwrap_or(low);
        let high = P256Signature::from_scalars(low.r(), -*low.s()).unwrap();
        let again = verify_assertion(&f.pk, RP, &f.payload, ad, cd, &high.to_bytes()).unwrap();
        assert_eq!(again.signature, ok.signature);
    }

    #[test]
    fn rejects_every_tampered_assertion() {
        let f = fixture();
        let good_origin = "https://stealthbridge.vercel.app";
        type Case<'a> = (&'a str, u8, [u8; 32], &'a str, &'a str, AssertionError);
        let cases: [Case; 6] = [
            (
                "evil.example",
                0x05,
                f.payload,
                good_origin,
                "webauthn.get",
                AssertionError::RpId,
            ),
            (
                RP,
                0x01,
                f.payload,
                good_origin,
                "webauthn.get",
                AssertionError::Flags,
            ),
            (
                RP,
                0x04,
                f.payload,
                good_origin,
                "webauthn.get",
                AssertionError::Flags,
            ),
            (
                RP,
                0x05,
                [9u8; 32],
                good_origin,
                "webauthn.get",
                AssertionError::Challenge,
            ),
            (
                RP,
                0x05,
                f.payload,
                "https://evil.example",
                "webauthn.get",
                AssertionError::Origin,
            ),
            (
                RP,
                0x05,
                f.payload,
                good_origin,
                "webauthn.create",
                AssertionError::ClientData,
            ),
        ];
        for (rp, flags, challenge, origin, kind, want) in cases {
            let (ad, cd, der) = assertion(&f, rp, flags, &challenge, origin, kind);
            assert_eq!(
                verify_assertion(&f.pk, RP, &f.payload, ad, cd, &der).err(),
                Some(want)
            );
        }
        // Signature by another key.
        let other = SigningKey::from_bytes(&[12u8; 32].into()).unwrap();
        let g = Fixture {
            key: other,
            pk: f.pk,
            payload: f.payload,
        };
        let (ad, cd, der) = assertion(&g, RP, 0x05, &f.payload, good_origin, "webauthn.get");
        assert_eq!(
            verify_assertion(&f.pk, RP, &f.payload, ad, cd, &der).err(),
            Some(AssertionError::Signature)
        );
        // Garbage encodings.
        assert_eq!(
            verify_assertion(&f.pk, RP, &f.payload, vec![0; 10], vec![], &[0; 64]).err(),
            Some(AssertionError::Encoding)
        );
    }

    #[test]
    fn signature_scval_is_the_contracts_webauthn_variant() {
        let a = VerifiedAssertion {
            authenticator_data: vec![1; 37],
            client_data_json: b"{}".to_vec(),
            signature: [2; 64],
        };
        let ScVal::Vec(Some(outer)) = webauthn_signature_scval([4; 32], &a).unwrap() else {
            panic!()
        };
        let ScVal::Vec(Some(variant)) = &outer[0] else {
            panic!()
        };
        assert!(matches!(&variant[0], ScVal::Symbol(s) if s.0.as_slice() == b"WebAuthn"));
        let ScVal::Map(Some(m)) = &variant[1] else {
            panic!()
        };
        let keys: Vec<String> = m
            .iter()
            .map(|e| match &e.key {
                ScVal::Symbol(s) => String::from_utf8(s.0.to_vec()).unwrap(),
                _ => String::new(),
            })
            .collect();
        assert_eq!(
            keys,
            [
                "authenticator_data",
                "client_data_json",
                "signature",
                "signer_id"
            ]
        );
    }

    #[test]
    fn base64url_round_trips_and_rejects_padding_and_alphabet() {
        for v in [
            vec![],
            vec![1u8],
            vec![1, 2],
            vec![1, 2, 3],
            (0..=255u8).collect::<Vec<_>>(),
        ] {
            if v.is_empty() {
                continue;
            }
            assert_eq!(b64url_decode(&b64url(&v), 1024).unwrap(), v);
        }
        assert!(b64url_decode("ab+c", 16).is_none());
        assert!(b64url_decode("abc=", 16).is_none());
        assert!(b64url_decode(&"A".repeat(100), 8).is_none());
    }

    #[test]
    fn confirms_only_an_envelope_that_executed_the_authorized_transfer() {
        let acct = relayer::contract_hash(ACCOUNT).unwrap();
        let call = transfer_args([7u8; 32], ACCOUNT, DEST, 5).unwrap();
        let tx = invoke_tx(
            [1; 32],
            1,
            call.clone(),
            vec![entry_for(&call, acct, false)],
        )
        .unwrap();
        let res = json!({"envelopeXdr": envelope_b64(&tx)});
        assert!(envelope_executes(&res, acct, &call));
        let other = transfer_args([7u8; 32], ACCOUNT, DEST, 6).unwrap();
        assert!(!envelope_executes(&res, acct, &other));
        assert!(!envelope_executes(&res, [9; 32], &call));
        assert!(!envelope_executes(&json!({}), acct, &call));
    }
}

#[cfg(test)]
mod parity_fixture {
    use super::*;
    use stellar_xdr::{SorobanAddressCredentials, SorobanAuthorizedInvocation};

    /// Cross-repo fixture: the SDK's verifyPreparedPayment must accept exactly
    /// this preimage for the same inputs (stealthbridge-sdk
    /// tests/smart-account-payments.test.mjs).
    pub const FIXTURE_PREIMAGE_B64: &str = include_str!("../tests/fixtures/payment-preimage.b64");

    pub fn fixture_preimage() -> (Vec<u8>, [u8; 32]) {
        let token = PayAsset::parse("XLM")
            .unwrap()
            .contract_id(relayer::TESTNET_PASSPHRASE)
            .unwrap();
        let account = "CAUJ5FMGDISNYEU7T6EQDYRLFF7CVC5F2PXJVEHQHY7HM275I2X6ITH6";
        let call = transfer_args(
            token,
            account,
            "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX",
            125_000_000,
        )
        .unwrap();
        let entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: contract_address(relayer::contract_hash(account).unwrap()),
                nonce: 42,
                signature_expiration_ledger: 1000,
                signature: ScVal::Void,
            }),
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(call),
                sub_invocations: vec![].try_into().unwrap(),
            },
        };
        authorization_preimage(&entry, relayer::TESTNET_PASSPHRASE).unwrap()
    }

    #[test]
    fn preimage_matches_committed_cross_repo_fixture() {
        let (bytes, _) = fixture_preimage();
        assert_eq!(relayer::b64(&bytes), FIXTURE_PREIMAGE_B64.trim());
    }
}
