//! Fee-sponsored relay for OpenZeppelin smart accounts on Stellar.
//!
//! Wallets are instances of the canonical OpenZeppelin `stellar-accounts`
//! v0.8.0 account build (`c514d35e…`, uploaded on Testnet by the Stellar
//! smart-account-kit maintainers; hash verified on-chain 2026-11-26). Passkeys
//! are `External` signers checked by the shared WebAuthn verifier contract.
//!
//! The endpoint is wire-compatible with `stellar/smart-account-kit`'s
//! relayer-proxy `{func, auth}` mode, so the official kit can use StealthBridge
//! as its `relayerUrl` (through the session-authenticated BFF). It mirrors that
//! proxy's fail-closed checks and is stricter in two places: the WebAuthn
//! verifier must be the allowlisted one, and CAP-84 muxed contract addresses are
//! refused wherever a plain contract is required.
//!
//! Trust model: the relayer is only the transaction source and fee payer. It
//! adds no authorization; every auth entry is verified on-chain by the wallet's
//! own `__check_auth` (or, for deployment, by the deployer's signature). The
//! checks here bound what StealthBridge pays for: they are not ownership proofs.

use crate::{
    customer_ciphertext_vault::authorize_account_request,
    relayer::{self, RelayError},
    server::AppState,
};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use stellar_xdr::{
    ContractDataDurability, ContractExecutable, ContractId, ContractIdPreimage, Hash, HostFunction,
    InvokeContractArgs, InvokeHostFunctionOp, LedgerEntryData, LedgerKey, LedgerKeyContractData,
    Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, ReadXdr, ScAddress, ScVal,
    SequenceNumber, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
};

const DOMAIN: &str = "stealthbridge-oz-relay-v1";
pub const PATH: &str = "/v1/account/smart-accounts/oz/relay";
pub const MAX_AUTH_ENTRIES: usize = 8;
const MAX_FIELD_BYTES: usize = 48 * 1024;
/// Same ceiling as the reference relayer proxy.
pub const MAX_RESOURCE_FEE: u64 = 1_000_000;

/// OpenZeppelin stellar-accounts v0.8.0 `multisig-account-example`, 48,273 bytes.
pub const ACCOUNT_WASM_V080: &str =
    "c514d35ea67eaea9bfc1fb3327854c0c06111bc1ddebd4fe217c504c1004b9e1";
/// The WebAuthn verifier every smart-account-kit passkey signer uses on Testnet.
pub const TESTNET_WEBAUTHN_VERIFIER: &str =
    "CC7EKIHQP3TN4CARQDND6CEOY2UXLWWC2X5GHTD5NLAT7BG5GPZIOM3F";
/// Wallet self-calls the reference proxy sponsors (account management + execute).
pub const WALLET_FUNCTIONS: [&str; 11] = [
    "execute",
    "upgrade",
    "add_policy",
    "remove_policy",
    "add_signer",
    "remove_signer",
    "add_context_rule",
    "remove_context_rule",
    "batch_add_signer",
    "update_context_rule_name",
    "update_context_rule_valid_until",
];

/// The kit's deterministic, publicly derivable deployer: it authorizes only the
/// contract-id preimage of a deployment and is never a fee source.
pub fn shared_deployer() -> [u8; 32] {
    let seed: [u8; 32] = Sha256::digest(b"openzeppelin-smart-account-kit").into();
    ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
}

// ----------------------------------------------------------------- policy

#[derive(Clone, Debug)]
pub struct Policy {
    pub account_wasm: Vec<[u8; 32]>,
    pub deploy_wasm: Vec<[u8; 32]>,
    pub deployers: Vec<[u8; 32]>,
    pub verifiers: Vec<[u8; 32]>,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

pub fn contract_bytes(c: &str) -> Option<[u8; 32]> {
    match stellar_strkey::Strkey::from_string(c).ok()? {
        stellar_strkey::Strkey::Contract(stellar_strkey::Contract(b)) => Some(b),
        _ => None,
    }
}

impl Policy {
    pub fn testnet() -> Self {
        let wasm = vec![hex32(ACCOUNT_WASM_V080).expect("pinned hash")];
        Self {
            account_wasm: wasm.clone(),
            deploy_wasm: wasm,
            deployers: vec![shared_deployer()],
            verifiers: vec![contract_bytes(TESTNET_WEBAUTHN_VERIFIER).expect("pinned verifier")],
        }
    }
}

// ------------------------------------------------------------- validation

#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    /// Malformed request (HTTP 400).
    Invalid(&'static str),
    /// Well-formed but not sponsorable (HTTP 403).
    Forbidden(&'static str),
}

/// What must still be confirmed on-chain before sponsoring.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub kind: &'static str,
    /// Contracts whose instance must run an allowlisted account WASM.
    pub wallets: Vec<[u8; 32]>,
    /// Contracts whose instance must be a Stellar Asset Contract.
    pub tokens: Vec<[u8; 32]>,
}

/// A plain contract address. CAP-84 muxed contracts and every other arm fail.
fn contract_of(a: &ScAddress) -> Option<[u8; 32]> {
    match a {
        ScAddress::Contract(ContractId(Hash(b))) => Some(*b),
        _ => None,
    }
}

fn account_or_contract(a: &ScAddress) -> Option<[u8; 32]> {
    match a {
        ScAddress::Contract(ContractId(Hash(b))) => Some(*b),
        ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(Uint256(b)),
        )) => Some(*b),
        _ => None,
    }
}

/// V1 or V2 address credentials. Source-account and delegate credentials are refused.
fn credential_address(e: &SorobanAuthorizationEntry) -> Option<&ScAddress> {
    match &e.credentials {
        SorobanCredentials::Address(c) | SorobanCredentials::AddressV2(c) => Some(&c.address),
        _ => None,
    }
}

fn xdr_eq<T: WriteXdr>(a: &T, b: &T) -> bool {
    matches!((a.to_xdr(Limits::none()), b.to_xdr(Limits::none())), (Ok(x), Ok(y)) if x == y)
}

fn only_calls(inv: &SorobanAuthorizedInvocation, contract: [u8; 32]) -> bool {
    match &inv.function {
        SorobanAuthorizedFunction::ContractFn(c) => {
            contract_of(&c.contract_address) == Some(contract)
                && inv.sub_invocations.iter().all(|s| only_calls(s, contract))
        }
        _ => false,
    }
}

fn sym(v: &ScVal) -> Option<&str> {
    match v {
        ScVal::Symbol(s) => std::str::from_utf8(s.0.as_slice()).ok(),
        _ => None,
    }
}

/// The kit's one-passkey constructor: `(signers: Vec<Signer>, policies: Map<Address, Val>)`
/// with exactly one `External(verifier, 0x04‖X‖Y‖credential_id)` signer and
/// `salt = sha256(credential_id)`. Spam defense, not an ownership proof.
fn check_constructor(args: &[ScVal], salt: &[u8; 32], p: &Policy) -> Result<(), Reject> {
    let bad = Reject::Forbidden("DEPLOY_CONSTRUCTOR_INVALID");
    let [ScVal::Vec(Some(signers)), ScVal::Map(policies)] = args else {
        return Err(bad);
    };
    let [ScVal::Vec(Some(signer))] = signers.as_slice() else {
        return Err(Reject::Forbidden("DEPLOY_SIGNER_COUNT"));
    };
    let [tag, ScVal::Address(verifier), ScVal::Bytes(key)] = signer.as_slice() else {
        return Err(Reject::Forbidden("DEPLOY_SIGNER_NOT_EXTERNAL"));
    };
    if sym(tag) != Some("External") {
        return Err(Reject::Forbidden("DEPLOY_SIGNER_NOT_EXTERNAL"));
    }
    let verifier = contract_of(verifier).ok_or(Reject::Forbidden("DEPLOY_VERIFIER_INVALID"))?;
    if !p.verifiers.contains(&verifier) {
        return Err(Reject::Forbidden("DEPLOY_VERIFIER_NOT_ALLOWED"));
    }
    let key = key.0.as_slice();
    if key.len() <= 65 || key[0] != 0x04 {
        return Err(Reject::Forbidden("DEPLOY_KEY_INVALID"));
    }
    let derived: [u8; 32] = Sha256::digest(&key[65..]).into();
    if &derived != salt {
        return Err(Reject::Forbidden("DEPLOY_SALT_MISMATCH"));
    }
    for entry in policies.as_ref().map(|m| m.0.as_slice()).unwrap_or(&[]) {
        match &entry.key {
            ScVal::Address(a) if contract_of(a).is_some() => {}
            _ => return Err(Reject::Forbidden("DEPLOY_POLICY_INVALID")),
        }
    }
    Ok(())
}

/// Pure, network-free validation of a `{func, auth}` submission.
pub fn classify(
    func: &HostFunction,
    auth: &[SorobanAuthorizationEntry],
    p: &Policy,
) -> Result<Plan, Reject> {
    if auth.is_empty() || auth.len() > MAX_AUTH_ENTRIES {
        return Err(Reject::Invalid("AUTH_COUNT"));
    }
    match func {
        HostFunction::CreateContractV2(deploy) => {
            let [entry] = auth else {
                return Err(Reject::Forbidden("DEPLOY_AUTH_COUNT"));
            };
            let ContractExecutable::Wasm(Hash(wasm)) = &deploy.executable else {
                return Err(Reject::Forbidden("DEPLOY_EXECUTABLE"));
            };
            if !p.deploy_wasm.contains(wasm) {
                return Err(Reject::Forbidden("DEPLOY_WASM_NOT_ALLOWED"));
            }
            let ContractIdPreimage::Address(pre) = &deploy.contract_id_preimage else {
                return Err(Reject::Forbidden("DEPLOY_PREIMAGE"));
            };
            let deployer =
                account_or_contract(&pre.address).ok_or(Reject::Forbidden("DEPLOY_PREIMAGE"))?;
            if !p.deployers.contains(&deployer) {
                return Err(Reject::Forbidden("DEPLOYER_NOT_ALLOWED"));
            }
            check_constructor(deploy.constructor_args.as_slice(), &pre.salt.0, p)?;
            // V1 address credentials from the deployer, authorizing exactly this deployment.
            let SorobanCredentials::Address(c) = &entry.credentials else {
                return Err(Reject::Forbidden("DEPLOY_CREDENTIALS"));
            };
            let root = &entry.root_invocation;
            let same = matches!(&root.function,
                SorobanAuthorizedFunction::CreateContractV2HostFn(a) if xdr_eq(a, deploy));
            if account_or_contract(&c.address) != Some(deployer)
                || !root.sub_invocations.is_empty()
                || !same
            {
                return Err(Reject::Forbidden("DEPLOY_AUTH_MISMATCH"));
            }
            Ok(Plan {
                kind: "deploy",
                wallets: vec![],
                tokens: vec![],
            })
        }
        HostFunction::InvokeContract(call) if sym_fn(call) == Some("transfer") => {
            let [entry] = auth else {
                return Err(Reject::Forbidden("TRANSFER_AUTH_COUNT"));
            };
            let [ScVal::Address(from), _, _] = call.args.as_slice() else {
                return Err(Reject::Forbidden("TRANSFER_ARGS"));
            };
            let from = contract_of(from).ok_or(Reject::Forbidden("TRANSFER_FROM_NOT_CONTRACT"))?;
            let wallet = credential_address(entry).and_then(contract_of);
            let root = &entry.root_invocation;
            let same = matches!(&root.function,
                SorobanAuthorizedFunction::ContractFn(a) if xdr_eq(a, call));
            if wallet != Some(from) || !root.sub_invocations.is_empty() || !same {
                return Err(Reject::Forbidden("TRANSFER_AUTH_MISMATCH"));
            }
            let token = contract_of(&call.contract_address)
                .ok_or(Reject::Forbidden("TRANSFER_TOKEN_NOT_CONTRACT"))?;
            Ok(Plan {
                kind: "transfer",
                wallets: vec![from],
                tokens: vec![token],
            })
        }
        HostFunction::InvokeContract(call) => {
            let wallet = contract_of(&call.contract_address)
                .ok_or(Reject::Forbidden("WALLET_NOT_CONTRACT"))?;
            if !sym_fn(call).is_some_and(|f| WALLET_FUNCTIONS.contains(&f)) {
                return Err(Reject::Forbidden("WALLET_FUNCTION_NOT_ALLOWED"));
            }
            for entry in auth {
                if credential_address(entry).and_then(contract_of) != Some(wallet) {
                    return Err(Reject::Forbidden("WALLET_AUTH_MISMATCH"));
                }
                let root = &entry.root_invocation;
                let same = matches!(&root.function,
                    SorobanAuthorizedFunction::ContractFn(a) if xdr_eq(a, call));
                if !same || !only_calls(root, wallet) {
                    return Err(Reject::Forbidden("WALLET_AUTH_MISMATCH"));
                }
            }
            Ok(Plan {
                kind: "wallet",
                wallets: vec![wallet],
                tokens: vec![],
            })
        }
        _ => Err(Reject::Forbidden("HOST_FUNCTION_NOT_ALLOWED")),
    }
}

fn sym_fn(call: &InvokeContractArgs) -> Option<&str> {
    std::str::from_utf8(call.function_name.0.as_slice()).ok()
}

// ------------------------------------------------------------ on-chain checks

fn instance_key(contract: [u8; 32]) -> Option<String> {
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(ContractId(Hash(contract))),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    Some(relayer::b64(&key.to_xdr(Limits::none()).ok()?))
}

/// The executable of a live contract instance, read from the ledger.
async fn executable(
    state: &AppState,
    contract: [u8; 32],
) -> Result<Option<ContractExecutable>, ()> {
    let key = instance_key(contract).ok_or(())?;
    let r = state
        .rpc_with_params("getLedgerEntries", Some(json!({"keys": [key]})))
        .await?;
    let Some(xdr) = r["entries"][0]["xdr"].as_str() else {
        return Ok(None);
    };
    let bytes = crate::governance_code::decode_base64_bounded(xdr, 64 * 1024).map_err(|_| ())?;
    match LedgerEntryData::from_xdr(&bytes, Limits::len(bytes.len())).map_err(|_| ())? {
        LedgerEntryData::ContractData(d) => match d.val {
            ScVal::ContractInstance(i) => Ok(Some(i.executable)),
            _ => Ok(None),
        },
        _ => Ok(None),
    }
}

async fn confirm_on_chain(
    state: &AppState,
    plan: &Plan,
    p: &Policy,
) -> Result<(), (&'static str, StatusCode)> {
    for w in &plan.wallets {
        match executable(state, *w).await {
            Ok(Some(ContractExecutable::Wasm(Hash(h)))) if p.account_wasm.contains(&h) => {}
            Ok(_) => return Err(("WALLET_NOT_ALLOWED", StatusCode::FORBIDDEN)),
            Err(_) => return Err(("NETWORK_UNAVAILABLE", StatusCode::SERVICE_UNAVAILABLE)),
        }
    }
    for t in &plan.tokens {
        match executable(state, *t).await {
            Ok(Some(ContractExecutable::StellarAsset)) => {}
            Ok(_) => return Err(("TOKEN_NOT_ALLOWED", StatusCode::FORBIDDEN)),
            Err(_) => return Err(("NETWORK_UNAVAILABLE", StatusCode::SERVICE_UNAVAILABLE)),
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ service

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn reply(body: Value, status: StatusCode) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(body),
    )
        .into_response()
}

/// The smart-account-kit relayer client reads `success`, `error`, `errorCode`.
fn fail(code: &str, status: StatusCode) -> Response {
    reply(
        json!({"success": false, "error": code, "errorCode": code}),
        status,
    )
}

fn decode<T: ReadXdr>(b64: &str) -> Option<T> {
    let bytes = crate::governance_code::decode_base64_bounded(b64, MAX_FIELD_BYTES).ok()?;
    T::from_xdr(&bytes, Limits::len(bytes.len())).ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    func: String,
    auth: Vec<String>,
}

pub fn host_tx(
    relayer: [u8; 32],
    sequence: i64,
    func: HostFunction,
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
                host_function: func,
                auth: auth.try_into().ok()?,
            }),
        }]
        .try_into()
        .ok()?,
        ext: TransactionExt::V0,
    })
}

fn envelope_b64(tx: &Transaction) -> Option<String> {
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: vec![].try_into().ok()?,
    });
    Some(relayer::b64(&env.to_xdr(Limits::none()).ok()?))
}

/// Refuse failed, restore-needing or over-ceiling simulations before paying.
pub fn simulation_ok(sim: &Value) -> Result<(), &'static str> {
    if sim.get("error").is_some_and(|e| !e.is_null()) {
        return Err("SIMULATION_FAILED");
    }
    if sim.get("restorePreamble").is_some_and(|r| !r.is_null()) {
        return Err("RESTORE_REQUIRED");
    }
    let fee = sim["minResourceFee"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| sim["minResourceFee"].as_u64())
        .ok_or("SIMULATION_FAILED")?;
    if fee > MAX_RESOURCE_FEE {
        return Err("RESOURCE_FEE_TOO_HIGH");
    }
    Ok(())
}

/// `POST /v1/account/smart-accounts/oz/relay`, called only by the BFF with a
/// signed-in customer's HMAC. Body: the kit's `{func, auth}` (base64 XDR).
pub async fn relay(
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
    let Some(key) = std::env::var("STEALTHBRIDGE_RELAYER_SECRET")
        .ok()
        .and_then(|s| relayer::relayer_key(&s))
    else {
        return fail("RELAYER_NOT_CONFIGURED", StatusCode::SERVICE_UNAVAILABLE);
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(req) = serde_json::from_slice::<Body>(&body) else {
        return fail("INVALID_REQUEST", StatusCode::BAD_REQUEST);
    };
    if req.auth.is_empty() || req.auth.len() > MAX_AUTH_ENTRIES {
        return fail("AUTH_COUNT", StatusCode::BAD_REQUEST);
    }
    let Some(func) = decode::<HostFunction>(&req.func) else {
        return fail("INVALID_XDR", StatusCode::BAD_REQUEST);
    };
    let Some(auth) = req
        .auth
        .iter()
        .map(|a| decode::<SorobanAuthorizationEntry>(a))
        .collect::<Option<Vec<_>>>()
    else {
        return fail("INVALID_XDR", StatusCode::BAD_REQUEST);
    };
    let passphrase = match relayer::network_passphrase(&state).await {
        Ok(p) => p,
        Err(_) => return fail("NETWORK_UNAVAILABLE", StatusCode::BAD_GATEWAY),
    };
    if passphrase != crate::smart_account_kit::TESTNET && !relayer::local_network_allowed() {
        return fail("NETWORK_NOT_ALLOWED", StatusCode::FORBIDDEN);
    }
    let policy = Policy::testnet();
    let plan = match classify(&func, &auth, &policy) {
        Ok(p) => p,
        Err(Reject::Invalid(c)) => return fail(c, StatusCode::BAD_REQUEST),
        Err(Reject::Forbidden(c)) => return fail(c, StatusCode::FORBIDDEN),
    };
    if let Err((code, status)) = confirm_on_chain(&state, &plan, &policy).await {
        return fail(code, status);
    }
    // Replay protection for the signed BFF request (one nonce, one submission).
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
    let relayer_pub = key.verifying_key().to_bytes();
    let Some(lock) = relayer::lock_relayer(db).await else {
        return fail("RELAYER_BUSY", StatusCode::SERVICE_UNAVAILABLE);
    };
    let max_time = (now() + relayer::TX_VALIDITY_SECS) as u64;
    let built = async {
        let seq = relayer::relayer_sequence(&state, relayer_pub).await?;
        let tx = host_tx(relayer_pub, seq + 1, func, auth).ok_or(RelayError::InvalidInput)?;
        let tx = relayer::with_time_bounds(tx, max_time);
        let b64 = envelope_b64(&tx).ok_or(RelayError::InvalidInput)?;
        let sim = state
            .rpc_with_params("simulateTransaction", Some(json!({"transaction": b64})))
            .await
            .map_err(|_| RelayError::Rpc)?;
        simulation_ok(&sim).map_err(|_| RelayError::Simulation)?;
        relayer::assemble_signed(tx, &sim)
    }
    .await;
    let ready = match built {
        Ok(t) => t,
        Err(RelayError::Simulation) => {
            lock.release().await;
            return fail("SIMULATION_REJECTED", StatusCode::UNPROCESSABLE_ENTITY);
        }
        Err(RelayError::FeeTooHigh) => {
            lock.release().await;
            return fail("FEE_TOO_HIGH", StatusCode::PAYLOAD_TOO_LARGE);
        }
        Err(_) => {
            lock.release().await;
            return fail("NETWORK_UNAVAILABLE", StatusCode::BAD_GATEWAY);
        }
    };
    let hash = relayer::transaction_hash(&ready, &passphrase);
    let envelope = relayer::sign(ready, &passphrase, &key);
    let outcome = relayer::send_envelope(&state, &envelope).await;
    lock.release().await;
    tracing::info!(kind = plan.kind, tx = %hash, "oz relay submission");
    match outcome {
        relayer::SendOutcome::Accepted => reply(
            json!({"success": true, "hash": hash, "status": "submitted", "kind": plan.kind}),
            StatusCode::ACCEPTED,
        ),
        relayer::SendOutcome::Ambiguous => reply(
            json!({"success": true, "hash": hash, "status": "pending", "kind": plan.kind}),
            StatusCode::ACCEPTED,
        ),
        relayer::SendOutcome::Rejected => fail("SUBMISSION_REJECTED", StatusCode::BAD_GATEWAY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::{
        BytesM, ContractIdPreimageFromAddress, CreateContractArgsV2, ScBytes, ScMap, ScSymbol,
        ScVec, SorobanAddressCredentials, StringM, VecM,
    };

    fn c(b: u8) -> ScAddress {
        ScAddress::Contract(ContractId(Hash([b; 32])))
    }
    fn g(b: [u8; 32]) -> ScAddress {
        ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(Uint256(b)),
        ))
    }
    fn symv(s: &str) -> ScVal {
        ScVal::Symbol(ScSymbol(StringM::try_from(s).unwrap()))
    }
    fn policy() -> Policy {
        Policy {
            account_wasm: vec![[0xAA; 32]],
            deploy_wasm: vec![[0xAA; 32]],
            deployers: vec![shared_deployer()],
            verifiers: vec![[0x77; 32]],
        }
    }
    fn entry(addr: ScAddress, f: SorobanAuthorizedFunction, v2: bool) -> SorobanAuthorizationEntry {
        let cred = SorobanAddressCredentials {
            address: addr,
            nonce: 7,
            signature_expiration_ledger: 100,
            signature: ScVal::Void,
        };
        SorobanAuthorizationEntry {
            credentials: if v2 {
                SorobanCredentials::AddressV2(cred)
            } else {
                SorobanCredentials::Address(cred)
            },
            root_invocation: SorobanAuthorizedInvocation {
                function: f,
                sub_invocations: VecM::default(),
            },
        }
    }
    fn deploy(cred_id: &[u8], verifier: u8, salt_ok: bool) -> CreateContractArgsV2 {
        let mut key = vec![0x04];
        key.extend([1u8; 64]);
        key.extend(cred_id);
        let salt: [u8; 32] = if salt_ok {
            Sha256::digest(cred_id).into()
        } else {
            [9; 32]
        };
        let signer = ScVal::Vec(Some(ScVec(
            vec![
                symv("External"),
                ScVal::Address(c(verifier)),
                ScVal::Bytes(ScBytes(BytesM::try_from(key).unwrap())),
            ]
            .try_into()
            .unwrap(),
        )));
        CreateContractArgsV2 {
            contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                address: g(shared_deployer()),
                salt: Uint256(salt),
            }),
            executable: ContractExecutable::Wasm(Hash([0xAA; 32])),
            constructor_args: vec![
                ScVal::Vec(Some(ScVec(vec![signer].try_into().unwrap()))),
                ScVal::Map(Some(ScMap(VecM::default()))),
            ]
            .try_into()
            .unwrap(),
        }
    }
    fn transfer(token: u8, from: ScAddress) -> InvokeContractArgs {
        InvokeContractArgs {
            contract_address: c(token),
            function_name: ScSymbol(StringM::try_from("transfer").unwrap()),
            args: vec![ScVal::Address(from), ScVal::Address(c(0x22)), ScVal::I32(5)]
                .try_into()
                .unwrap(),
        }
    }

    #[test]
    fn shared_deployer_matches_the_kit() {
        // Keypair.fromRawEd25519Seed(sha256("openzeppelin-smart-account-kit")) in the kit.
        // Cross-checked with @stellar/stellar-sdk, and equal to the deployment
        // source recorded in the kit's stellar-accounts v0.8 deployment manifest.
        let g = stellar_strkey::ed25519::PublicKey(shared_deployer()).to_string();
        assert_eq!(
            g,
            "GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N"
        );
    }

    #[test]
    fn deployment_of_one_passkey_wallet_is_sponsorable() {
        let d = deploy(b"credential-1", 0x77, true);
        let a = entry(
            g(shared_deployer()),
            SorobanAuthorizedFunction::CreateContractV2HostFn(d.clone()),
            false,
        );
        let plan = classify(&HostFunction::CreateContractV2(d), &[a], &policy()).unwrap();
        assert_eq!(plan.kind, "deploy");
    }

    #[test]
    fn deployment_rejects_unknown_verifier_salt_wasm_and_v2_credentials() {
        let p = policy();
        for (d, code) in [
            (deploy(b"cred", 0x78, true), "DEPLOY_VERIFIER_NOT_ALLOWED"),
            (deploy(b"cred", 0x77, false), "DEPLOY_SALT_MISMATCH"),
        ] {
            let a = entry(
                g(shared_deployer()),
                SorobanAuthorizedFunction::CreateContractV2HostFn(d.clone()),
                false,
            );
            assert_eq!(
                classify(&HostFunction::CreateContractV2(d), &[a], &p),
                Err(Reject::Forbidden(code))
            );
        }
        let mut d = deploy(b"cred", 0x77, true);
        d.executable = ContractExecutable::Wasm(Hash([0xBB; 32]));
        let a = entry(
            g(shared_deployer()),
            SorobanAuthorizedFunction::CreateContractV2HostFn(d.clone()),
            false,
        );
        assert_eq!(
            classify(&HostFunction::CreateContractV2(d), &[a], &p),
            Err(Reject::Forbidden("DEPLOY_WASM_NOT_ALLOWED"))
        );
        let d = deploy(b"cred", 0x77, true);
        let a = entry(
            g(shared_deployer()),
            SorobanAuthorizedFunction::CreateContractV2HostFn(d.clone()),
            true,
        );
        assert_eq!(
            classify(&HostFunction::CreateContractV2(d), &[a], &p),
            Err(Reject::Forbidden("DEPLOY_CREDENTIALS"))
        );
    }

    #[test]
    fn deployment_auth_must_match_the_function_exactly() {
        let d = deploy(b"cred", 0x77, true);
        let other = deploy(b"other", 0x77, true);
        let a = entry(
            g(shared_deployer()),
            SorobanAuthorizedFunction::CreateContractV2HostFn(other),
            false,
        );
        assert_eq!(
            classify(&HostFunction::CreateContractV2(d), &[a], &policy()),
            Err(Reject::Forbidden("DEPLOY_AUTH_MISMATCH"))
        );
    }

    #[test]
    fn transfer_from_a_wallet_needs_wallet_and_sac_checks() {
        let call = transfer(0x33, c(0x44));
        for v2 in [false, true] {
            let a = entry(
                c(0x44),
                SorobanAuthorizedFunction::ContractFn(call.clone()),
                v2,
            );
            let plan =
                classify(&HostFunction::InvokeContract(call.clone()), &[a], &policy()).unwrap();
            assert_eq!(
                plan,
                Plan {
                    kind: "transfer",
                    wallets: vec![[0x44; 32]],
                    tokens: vec![[0x33; 32]]
                }
            );
        }
    }

    #[test]
    fn transfer_rejects_account_source_other_signer_and_altered_amount() {
        let p = policy();
        let from_g = transfer(0x33, g([5; 32]));
        let a = entry(
            g([5; 32]),
            SorobanAuthorizedFunction::ContractFn(from_g.clone()),
            false,
        );
        assert_eq!(
            classify(&HostFunction::InvokeContract(from_g), &[a], &p),
            Err(Reject::Forbidden("TRANSFER_FROM_NOT_CONTRACT"))
        );
        let call = transfer(0x33, c(0x44));
        let a = entry(
            c(0x45),
            SorobanAuthorizedFunction::ContractFn(call.clone()),
            false,
        );
        assert_eq!(
            classify(&HostFunction::InvokeContract(call.clone()), &[a], &p),
            Err(Reject::Forbidden("TRANSFER_AUTH_MISMATCH"))
        );
        let mut signed = call.clone();
        signed.args = vec![
            ScVal::Address(c(0x44)),
            ScVal::Address(c(0x22)),
            ScVal::I32(1),
        ]
        .try_into()
        .unwrap();
        let a = entry(
            c(0x44),
            SorobanAuthorizedFunction::ContractFn(signed),
            false,
        );
        assert_eq!(
            classify(&HostFunction::InvokeContract(call), &[a], &p),
            Err(Reject::Forbidden("TRANSFER_AUTH_MISMATCH"))
        );
    }

    #[test]
    fn muxed_contract_source_is_refused() {
        let mux = ScAddress::MuxedContract(stellar_xdr::MuxedContract {
            id: 1,
            contract_id: ContractId(Hash([0x44; 32])),
        });
        let call = transfer(0x33, mux.clone());
        let a = entry(
            mux,
            SorobanAuthorizedFunction::ContractFn(call.clone()),
            false,
        );
        assert_eq!(
            classify(&HostFunction::InvokeContract(call), &[a], &policy()),
            Err(Reject::Forbidden("TRANSFER_FROM_NOT_CONTRACT"))
        );
    }

    #[test]
    fn wallet_management_calls_are_limited_to_the_allowlist() {
        let mk = |f: &str| InvokeContractArgs {
            contract_address: c(0x44),
            function_name: ScSymbol(StringM::try_from(f).unwrap()),
            args: VecM::default(),
        };
        let ok = mk("execute");
        let a = entry(
            c(0x44),
            SorobanAuthorizedFunction::ContractFn(ok.clone()),
            false,
        );
        assert_eq!(
            classify(&HostFunction::InvokeContract(ok), &[a], &policy())
                .unwrap()
                .kind,
            "wallet"
        );
        let bad = mk("drain");
        let a = entry(
            c(0x44),
            SorobanAuthorizedFunction::ContractFn(bad.clone()),
            false,
        );
        assert_eq!(
            classify(&HostFunction::InvokeContract(bad), &[a], &policy()),
            Err(Reject::Forbidden("WALLET_FUNCTION_NOT_ALLOWED"))
        );
    }

    #[test]
    fn source_account_credentials_and_empty_auth_are_refused() {
        let call = transfer(0x33, c(0x44));
        let mut a = entry(
            c(0x44),
            SorobanAuthorizedFunction::ContractFn(call.clone()),
            false,
        );
        a.credentials = SorobanCredentials::SourceAccount;
        assert!(classify(&HostFunction::InvokeContract(call.clone()), &[a], &policy()).is_err());
        assert_eq!(
            classify(&HostFunction::InvokeContract(call), &[], &policy()),
            Err(Reject::Invalid("AUTH_COUNT"))
        );
    }

    #[test]
    fn simulation_ceiling_restore_and_errors() {
        assert!(simulation_ok(&json!({"minResourceFee":"5000"})).is_ok());
        assert_eq!(
            simulation_ok(&json!({"minResourceFee":"1000001"})),
            Err("RESOURCE_FEE_TOO_HIGH")
        );
        assert_eq!(
            simulation_ok(&json!({"minResourceFee":"1","restorePreamble":{}})),
            Err("RESTORE_REQUIRED")
        );
        assert_eq!(
            simulation_ok(&json!({"error":"HostError"})),
            Err("SIMULATION_FAILED")
        );
    }

    /// A real kit-shaped deployment built with @stellar/stellar-sdk 16.4.1 against
    /// Testnet (the deployer auth is signed by the public deterministic deployer),
    /// which Stellar RPC simulated successfully on 2026-11-26 with the
    /// StealthBridge relayer as source. Nothing was broadcast.
    #[test]
    fn real_kit_deployment_payload_is_accepted() {
        let raw = include_str!("../tests/fixtures/oz-kit-deploy.testnet.json");
        let v: Value = serde_json::from_str(raw).unwrap();
        let func = decode::<HostFunction>(v["func"].as_str().unwrap()).unwrap();
        let auth: Vec<SorobanAuthorizationEntry> = v["auth"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| decode(a.as_str().unwrap()).unwrap())
            .collect();
        let plan = classify(&func, &auth, &Policy::testnet()).unwrap();
        assert_eq!(plan.kind, "deploy");
        // Tampering with the signed deployment is refused before any RPC call.
        let HostFunction::CreateContractV2(mut d) = func else {
            panic!()
        };
        d.constructor_args = vec![ScVal::Void, ScVal::Void].try_into().unwrap();
        assert!(classify(
            &HostFunction::CreateContractV2(d),
            &auth,
            &Policy::testnet()
        )
        .is_err());
    }

    #[test]
    fn pinned_testnet_policy_decodes() {
        let p = Policy::testnet();
        assert_eq!(hex::encode(p.account_wasm[0]), ACCOUNT_WASM_V080);
        assert_eq!(p.verifiers.len(), 1);
    }
}
