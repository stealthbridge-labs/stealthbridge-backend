//! Read-only Testnet protocol deployment discovery (`protocol-deployment.v3.json`)
//! and live Soroban RPC instance inspection across PrivacyVerifier, SmartAccount,
//! SettlementAdapter, and FeeVault.

use crate::{governance_code, server::AppState, smart_account, wallet};
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{collections::HashSet, sync::Arc};

const V3_MANIFEST: &str = include_str!("../deployments/testnet/protocol-deployment.v3.json");
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const PROTOCOL_NAMES: [&str; 4] = [
    "privacy-verifier",
    "smart-account",
    "settlement-adapter",
    "fee-vault",
];

#[derive(Clone, Debug, Serialize)]
pub struct ProtocolContractEntry {
    pub name: String,
    pub contract_id: String,
    pub wasm_sha256: String,
    pub deployment_tx: String,
    pub deployment_ledger: u64,
    pub observed_paused: bool,
    pub readback_wasm_matches: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct LiveContractStatus {
    pub name: String,
    pub contract_id: String,
    pub expected_wasm_sha256: String,
    pub observed_wasm_sha256: Option<String>,
    pub wasm_matches: bool,
    pub instance_found: bool,
    pub live_until_ledger: Option<u64>,
    pub last_modified_ledger: Option<u64>,
}

fn hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[derive(Debug)]
pub struct ProtocolManifestError;

pub fn validate_v3_manifest(value: &Value) -> Result<(), ProtocolManifestError> {
    if value["schemaVersion"].as_u64() != Some(3)
        || value["recordType"].as_str() != Some("soroban-testnet-protocol-deployment-manifest")
        || value["network"].as_str() != Some("testnet")
        || value["networkPassphrase"].as_str() != Some(TESTNET_PASSPHRASE)
    {
        return Err(ProtocolManifestError);
    }
    let scope = value["scope"].as_object().ok_or(ProtocolManifestError)?;
    for k in [
        "mainnet_enabled",
        "fiat_payouts_enabled",
        "live_fx_enabled",
        "external_audit_completed",
    ] {
        if scope.get(k).and_then(Value::as_bool) != Some(false) {
            return Err(ProtocolManifestError);
        }
    }
    for k in [
        "testnet_governance_deployed",
        "testnet_privacy_verifier_deployed",
        "testnet_smart_account_deployed",
        "testnet_settlement_adapter_deployed",
        "testnet_fee_vault_deployed",
        "testnet_groth16_pairing_verified",
    ] {
        if scope.get(k).and_then(Value::as_bool) != Some(true) {
            return Err(ProtocolManifestError);
        }
    }

    let proto = value["protocolContracts"]
        .as_object()
        .ok_or(ProtocolManifestError)?;
    if proto.len() != PROTOCOL_NAMES.len() {
        return Err(ProtocolManifestError);
    }
    let mut seen_ids = HashSet::new();
    for name in PROTOCOL_NAMES {
        let entry = proto
            .get(name)
            .and_then(Value::as_object)
            .ok_or(ProtocolManifestError)?;
        let cid = entry
            .get("contractId")
            .and_then(Value::as_str)
            .ok_or(ProtocolManifestError)?;
        let wasm = entry
            .get("wasmSha256")
            .and_then(Value::as_str)
            .ok_or(ProtocolManifestError)?;
        let tx = entry
            .get("deploymentTx")
            .and_then(Value::as_str)
            .ok_or(ProtocolManifestError)?;
        let ledger = entry
            .get("deploymentLedger")
            .and_then(Value::as_u64)
            .ok_or(ProtocolManifestError)?;
        if !matches!(
            wallet::parse_canonical_stellar_address(cid),
            Some(wallet::StellarAddress::Contract(_))
        ) || !seen_ids.insert(cid.to_owned())
            || !hex64(wasm)
            || !hex64(tx)
            || ledger == 0
            || entry.get("readbackWasmMatches").and_then(Value::as_bool) != Some(true)
        {
            return Err(ProtocolManifestError);
        }
    }
    if proto["fee-vault"]["observedPaused"] != json!(true)
        || proto["fee-vault"]["observedClaimsPaused"] != json!(true)
    {
        return Err(ProtocolManifestError);
    }
    Ok(())
}

pub fn load_validated_entries() -> Result<(Value, Vec<ProtocolContractEntry>), ProtocolManifestError>
{
    let manifest: Value = serde_json::from_str(V3_MANIFEST).map_err(|_| ProtocolManifestError)?;
    validate_v3_manifest(&manifest)?;
    let mut entries = Vec::with_capacity(PROTOCOL_NAMES.len());
    for name in PROTOCOL_NAMES {
        let c = &manifest["protocolContracts"][name];
        entries.push(ProtocolContractEntry {
            name: name.to_owned(),
            contract_id: c["contractId"]
                .as_str()
                .ok_or(ProtocolManifestError)?
                .to_owned(),
            wasm_sha256: c["wasmSha256"]
                .as_str()
                .ok_or(ProtocolManifestError)?
                .to_owned(),
            deployment_tx: c["deploymentTx"]
                .as_str()
                .ok_or(ProtocolManifestError)?
                .to_owned(),
            deployment_ledger: c["deploymentLedger"]
                .as_u64()
                .ok_or(ProtocolManifestError)?,
            observed_paused: c["observedPaused"].as_bool().unwrap_or(false),
            readback_wasm_matches: c["readbackWasmMatches"].as_bool().unwrap_or(false),
        });
    }
    Ok((manifest, entries))
}

pub async fn protocol_contracts() -> Response {
    let Ok((manifest, entries)) = load_validated_entries() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    (
        [(header::CACHE_CONTROL, "public, max-age=30")],
        Json(json!({
            "schema_version": 3,
            "network": "testnet",
            "network_passphrase": TESTNET_PASSPHRASE,
            "source": "stealthbridge-contracts/deployments/testnet/protocol-deployment.v3.json",
            "contracts": entries,
            "governance_contracts": manifest["governanceContracts"],
            "privacy_verifier_proof_tx": manifest["protocolContracts"]["privacy-verifier"]["liveProofVerifyTx"],
            "privacy_verifier_proof_ledger": manifest["protocolContracts"]["privacy-verifier"]["liveProofVerifyLedger"],
            "scope": manifest["scope"],
            "payment_execution_enabled": false,
            "mainnet_enabled": false,
            "fiat_payouts_enabled": false
        })),
    )
        .into_response()
}

pub fn evaluate_live_entries(
    entries: &[ProtocolContractEntry],
    keys: &[String],
    rpc_reply: &Value,
) -> Result<(u64, Vec<LiveContractStatus>), ProtocolManifestError> {
    let latest_ledger = rpc_reply["latestLedger"]
        .as_u64()
        .ok_or(ProtocolManifestError)?;
    if latest_ledger == 0 {
        return Err(ProtocolManifestError);
    }
    let rpc_items = rpc_reply["entries"]
        .as_array()
        .ok_or(ProtocolManifestError)?;
    let mut out = Vec::with_capacity(entries.len());
    for (entry, key) in entries.iter().zip(keys.iter()) {
        let matched = rpc_items
            .iter()
            .find(|item| item["key"].as_str() == Some(key.as_str()));
        let mut status = LiveContractStatus {
            name: entry.name.clone(),
            contract_id: entry.contract_id.clone(),
            expected_wasm_sha256: entry.wasm_sha256.clone(),
            observed_wasm_sha256: None,
            wasm_matches: false,
            instance_found: false,
            live_until_ledger: None,
            last_modified_ledger: None,
        };
        if let Some(item) = matched {
            let xdr = item["xdr"].as_str().ok_or(ProtocolManifestError)?;
            let hash =
                governance_code::executable_hash(xdr, key).map_err(|_| ProtocolManifestError)?;
            let last_mod = item["lastModifiedLedgerSeq"].as_u64();
            let live_until = item["liveUntilLedgerSeq"].as_u64();
            status.instance_found = live_until.is_some_and(|l| l >= latest_ledger);
            status.wasm_matches = hash == entry.wasm_sha256 && status.instance_found;
            status.observed_wasm_sha256 = Some(hash);
            status.live_until_ledger = live_until;
            status.last_modified_ledger = last_mod;
        }
        out.push(status);
    }
    Ok((latest_ledger, out))
}

pub async fn protocol_contracts_live(State(state): State<Arc<AppState>>) -> Response {
    let Ok((manifest, entries)) = load_validated_entries() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut keys = Vec::with_capacity(entries.len());
    for entry in &entries {
        let Some(k) = smart_account::instance_ledger_key(&entry.contract_id) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        keys.push(k);
    }
    let Ok(rpc_reply) = state
        .rpc_with_params(
            "getLedgerEntries",
            Some(json!({ "keys": keys, "xdrFormat": "base64" })),
        )
        .await
    else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let Ok((observed_ledger, statuses)) = evaluate_live_entries(&entries, &keys, &rpc_reply) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let all_wasm_verified = statuses.iter().all(|s| s.instance_found && s.wasm_matches);
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "schema_version": 3,
            "network": "testnet",
            "network_passphrase": TESTNET_PASSPHRASE,
            "source": "stellar-rpc/getLedgerEntries+protocol-deployment.v3.json",
            "observed_ledger_sequence": observed_ledger,
            "all_contracts_live_and_hash_matched": all_wasm_verified,
            "contracts": statuses,
            "scope": manifest["scope"],
            "mainnet_enabled": false,
            "fiat_payouts_enabled": false
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_v3_manifest_validates_cleanly() {
        let (_, entries) = load_validated_entries().expect("bundled v3 manifest must be valid");
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn v3_manifest_rejects_overclaimed_scope_or_unpaused_fee_vault() {
        let base: Value = serde_json::from_str(V3_MANIFEST).unwrap();
        let mut bad_mainnet = base.clone();
        bad_mainnet["scope"]["mainnet_enabled"] = json!(true);
        assert!(validate_v3_manifest(&bad_mainnet).is_err());

        let mut bad_vault = base.clone();
        bad_vault["protocolContracts"]["fee-vault"]["observedPaused"] = json!(false);
        assert!(validate_v3_manifest(&bad_vault).is_err());
    }
}
