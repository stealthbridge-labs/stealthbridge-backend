//! Public upstream artifact health only. No customer custody or execution authority.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use stellar_xdr::{LedgerEntryData, Limits, ReadXdr, WriteXdr};

pub(crate) const TESTNET: &str = "Test SDF Network ; September 2015";
const LOW_TTL: u32 = 120_960;
const NAMES: [&str; 7] = [
    "account_code",
    "webauthn_instance",
    "webauthn_code",
    "threshold_instance",
    "threshold_code",
    "spendingLimit_instance",
    "spendingLimit_code",
];
const RELEASE: &str = include_str!("../assets/smart-account-kit-release.json");

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Code,
    Instance,
}
#[derive(Clone, Deserialize)]
struct Target {
    name: String,
    kind: Kind,
    expected_wasm_hash: String,
    ledger_key: String,
    wasm_size: Option<usize>,
    contract_id: Option<String>,
}
#[derive(Deserialize)]
struct Inventory {
    network: String,
    network_passphrase: String,
    kit_version: String,
    entries: Vec<Target>,
}
fn inventory() -> Result<Vec<Target>, ()> {
    let inventory: Inventory = serde_json::from_str(RELEASE).map_err(|_| ())?;
    if inventory.network != "testnet"
        || inventory.network_passphrase != TESTNET
        || inventory.kit_version != "0.10.0"
        || inventory.entries.len() != 7
    {
        return Err(());
    }
    for (i, target) in inventory.entries.iter().enumerate() {
        if target.name != NAMES[i] {
            return Err(());
        }
        let hash = hex::decode(&target.expected_wasm_hash).map_err(|_| ())?;
        if hash.len() != 32 {
            return Err(());
        }
        match target.kind {
            Kind::Code => {
                let key = crate::governance_code::decode_base64(&target.ledger_key)?;
                if key.len() != 36 || key[..4] != 7u32.to_be_bytes() || key[4..] != hash {
                    return Err(());
                }
            }
            Kind::Instance => {
                if crate::smart_account::instance_ledger_key(
                    target.contract_id.as_deref().ok_or(())?,
                )
                .as_deref()
                    != Some(target.ledger_key.as_str())
                {
                    return Err(());
                }
            }
        }
    }
    if inventory.entries[0].wasm_size != Some(48_273) {
        return Err(());
    }
    Ok(inventory.entries)
}
pub(crate) fn ledger_keys() -> Result<Vec<String>, ()> {
    Ok(inventory()?.into_iter().map(|t| t.ledger_key).collect())
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Live,
    LowTtl,
    Unavailable,
    Mismatch,
}
#[derive(Debug, Serialize)]
pub(crate) struct Entry {
    name: String,
    kind: Kind,
    expected_wasm_hash: String,
    observed_wasm_hash: Option<String>,
    status: Status,
    live_until_ledger: Option<u32>,
    ttl_remaining_ledgers: Option<u32>,
}
#[derive(Debug, Serialize)]
pub(crate) struct Observation {
    schema_version: u8,
    network: &'static str,
    source: &'static str,
    observed_at_unix: u64,
    observed_ledger_sequence: u32,
    kit_version: &'static str,
    entries: Vec<Entry>,
    all_entries_healthy: bool,
    customer_smart_account_factory_deployed: bool,
    customer_smart_account_created: bool,
    credential_recovery_verified: bool,
    privacy_proofs_verified: bool,
    mainnet_enabled: bool,
    financial_execution_enabled: bool,
    operator_managed_deployment: bool,
}
#[derive(Debug, PartialEq)]
pub(crate) enum ObserveError {
    Invalid,
    Stale,
}
impl From<()> for ObserveError {
    fn from(_: ()) -> Self {
        Self::Invalid
    }
}
fn ledger(v: &Value) -> Result<u32, ()> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 0)
        .ok_or(())
}
fn limits() -> Limits {
    Limits {
        depth: 64,
        len: 2 * 1024 * 1024,
    }
}

/// Fully decode LedgerEntryData, re-encode to reject noncanonical XDR, and
/// independently hash the opaque WASM bytes (never the enclosing XDR).
fn identity(target: &Target, xdr: &str) -> Result<(String, bool), ()> {
    let bytes = crate::governance_code::decode_base64_bounded(xdr, 2 * 1024 * 1024)?;
    let data = LedgerEntryData::from_xdr(&bytes, limits()).map_err(|_| ())?;
    if data.to_xdr(limits()).map_err(|_| ())? != bytes {
        return Err(());
    }
    match (&target.kind, data) {
        (Kind::Code, LedgerEntryData::ContractCode(code)) => {
            let computed = hex::encode(Sha256::digest(code.code.as_slice()));
            let embedded = hex::encode(code.hash.0);
            let matches = computed == target.expected_wasm_hash
                && embedded == computed
                && target.wasm_size.is_none_or(|size| size == code.code.len());
            Ok((computed, matches))
        }
        (Kind::Instance, LedgerEntryData::ContractData(_)) => {
            // Reuse the existing contract-key and WASM executable prefix check;
            // the complete decode above also validates the storage-map tail.
            let hash = crate::governance_code::executable_hash(xdr, &target.ledger_key)?;
            let matches = hash == target.expected_wasm_hash;
            Ok((hash, matches))
        }
        _ => Err(()),
    }
}
fn entry(target: &Target, raw: Option<&Value>, sequence: u32) -> Result<Entry, ()> {
    let mut result = Entry {
        name: target.name.clone(),
        kind: target.kind,
        expected_wasm_hash: target.expected_wasm_hash.clone(),
        observed_wasm_hash: None,
        status: Status::Unavailable,
        live_until_ledger: None,
        ttl_remaining_ledgers: None,
    };
    let Some(raw) = raw else {
        return Ok(result);
    };
    let modified = ledger(&raw["lastModifiedLedgerSeq"])?;
    if modified > sequence {
        return Err(());
    }
    let expiry = raw["liveUntilLedgerSeq"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(())?;
    let (hash, matches) = identity(target, raw["xdr"].as_str().ok_or(())?)?;
    result.observed_wasm_hash = Some(hash);
    // A zero sentinel or a positive expiration in the past is not verified
    // live TTL. Never expose a stale expiry as a current live-until ledger.
    result.ttl_remaining_ledgers = if expiry > 0 {
        expiry.checked_sub(sequence)
    } else {
        None
    };
    result.live_until_ledger = result.ttl_remaining_ledgers.map(|_| expiry);
    result.status = if !matches {
        Status::Mismatch
    } else {
        match result.ttl_remaining_ledgers {
            None => Status::Unavailable,
            Some(n) if n <= LOW_TTL => Status::LowTtl,
            Some(_) => Status::Live,
        }
    };
    Ok(result)
}

/// Called with AppState::network's independently verified Testnet head. Freshness
/// is checked after the batched read so RPC latency cannot leave a stale green.
pub(crate) fn assess(
    reply: &Value,
    passphrase: &str,
    head: u64,
    closed: &str,
    now: u64,
) -> Result<Observation, ObserveError> {
    assess_targets(reply, passphrase, head, closed, now, &inventory()?)
}
fn assess_targets(
    reply: &Value,
    passphrase: &str,
    head: u64,
    closed: &str,
    now: u64,
    targets: &[Target],
) -> Result<Observation, ObserveError> {
    if passphrase != TESTNET || head == 0 || head > u32::MAX as u64 {
        return Err(ObserveError::Invalid);
    }
    let close = closed.parse::<u64>().map_err(|_| ObserveError::Invalid)?;
    if close == 0 || close > now || now - close > 180 {
        return Err(ObserveError::Stale);
    }
    let sequence = ledger(&reply["latestLedger"])?;
    if u64::from(sequence).abs_diff(head) > 15 {
        return Err(ObserveError::Invalid);
    }
    let raw = reply["entries"].as_array().ok_or(())?;
    let mut keyed = std::collections::HashMap::new();
    for item in raw {
        let key = item["key"].as_str().ok_or(())?;
        if !targets.iter().any(|t| t.ledger_key == key) || keyed.insert(key, item).is_some() {
            return Err(ObserveError::Invalid);
        }
    }
    let entries = targets
        .iter()
        .map(|target| {
            entry(
                target,
                keyed.get(target.ledger_key.as_str()).copied(),
                sequence,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let all_entries_healthy =
        entries.len() == 7 && entries.iter().all(|entry| entry.status == Status::Live);
    Ok(Observation {
        schema_version: 1,
        network: "testnet",
        source: "stellar-rpc/pinned-smart-account-kit",
        observed_at_unix: now,
        observed_ledger_sequence: sequence,
        kit_version: "0.10.0",
        entries,
        all_entries_healthy,
        customer_smart_account_factory_deployed: false,
        customer_smart_account_created: false,
        credential_recovery_verified: false,
        privacy_proofs_verified: false,
        mainnet_enabled: false,
        financial_execution_enabled: false,
        operator_managed_deployment: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base64(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let a = c[0];
            let b = *c.get(1).unwrap_or(&0);
            let d = *c.get(2).unwrap_or(&0);
            out.push(A[(a >> 2) as usize] as char);
            out.push(A[(((a & 3) << 4) | (b >> 4)) as usize] as char);
            out.push(if c.len() > 1 {
                A[(((b & 15) << 2) | (d >> 6)) as usize] as char
            } else {
                '='
            });
            out.push(if c.len() > 2 {
                A[(d & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }
    fn word(bytes: &mut Vec<u8>, n: u32) {
        bytes.extend_from_slice(&n.to_be_bytes());
    }
    fn code_bytes(wasm: &[u8], embedded: &str, extension: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        word(&mut bytes, 7);
        word(&mut bytes, extension);
        if extension == 1 {
            // v1.ext and costInputs.ext, followed by ten uint32 cost inputs.
            for _ in 0..12 {
                word(&mut bytes, 0);
            }
        }
        bytes.extend_from_slice(&hex::decode(embedded).unwrap());
        word(&mut bytes, wasm.len() as u32);
        bytes.extend_from_slice(wasm);
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
        bytes
    }
    fn instance_bytes(target: &Target, hash: &str) -> Vec<u8> {
        let key = crate::governance_code::decode_base64(&target.ledger_key).unwrap();
        let mut bytes = Vec::new();
        for n in [6, 0, 1] {
            word(&mut bytes, n);
        }
        bytes.extend_from_slice(&key[8..40]);
        for n in [20, 1, 19, 0] {
            word(&mut bytes, n);
        }
        bytes.extend_from_slice(&hex::decode(hash).unwrap());
        word(&mut bytes, 0);
        bytes
    }
    fn raw(target: &Target, xdr: Vec<u8>, expiry: u32) -> Value {
        json!({"key":target.ledger_key,"xdr":base64(&xdr),
            "lastModifiedLedgerSeq":99,"liveUntilLedgerSeq":expiry})
    }
    // Synthetic bytes and synthetic code pins are scoped to tests. Production
    // always uses the compiled release inventory; no fixture can turn it green.
    fn fixture() -> (Vec<Target>, Value) {
        let mut targets = inventory().unwrap();
        let mut entries = Vec::new();
        for target in &mut targets {
            let xdr = if target.kind == Kind::Code {
                let wasm = vec![42; target.wasm_size.unwrap_or(73)];
                let mut key = 7u32.to_be_bytes().to_vec();
                // Distinguish synthetic code fixtures with the same byte size.
                // Different pinned keys are needed for the three validator codes.
                let mut wasm = wasm;
                wasm[0] = entries.len() as u8;
                target.expected_wasm_hash = hex::encode(Sha256::digest(&wasm));
                key.extend_from_slice(&hex::decode(&target.expected_wasm_hash).unwrap());
                target.ledger_key = base64(&key);
                code_bytes(&wasm, &target.expected_wasm_hash, 1)
            } else {
                instance_bytes(target, &target.expected_wasm_hash)
            };
            entries.push(raw(target, xdr, 100 + LOW_TTL + 1));
        }
        (targets, json!({"latestLedger":100,"entries":entries}))
    }
    fn observe(targets: &[Target], reply: &Value) -> Result<Observation, ObserveError> {
        assess_targets(reply, TESTNET, 100, "1000", 1100, targets)
    }
    #[test]
    fn exact_local_release_inventory_and_key_identity() {
        let targets = inventory().unwrap();
        assert_eq!(targets.len(), 7);
        assert_eq!(
            targets[0].expected_wasm_hash,
            "c514d35ea67eaea9bfc1fb3327854c0c06111bc1ddebd4fe217c504c1004b9e1"
        );
        assert_eq!(targets[0].wasm_size, Some(48_273));
        assert_eq!(
            targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            NAMES
        );
        let keys = ledger_keys().unwrap();
        assert_eq!(
            keys.iter().collect::<std::collections::HashSet<_>>().len(),
            7
        );
        assert!(observe(&targets, &json!({"latestLedger":100,"entries":[]})).is_ok());
    }
    #[test]
    fn canonical_contract_code_ext_zero_and_one_hash_actual_bytes_and_size() {
        let mut target = inventory().unwrap().remove(0);
        let wasm = vec![42; 48_273];
        target.expected_wasm_hash = hex::encode(Sha256::digest(&wasm));
        for ext in [0, 1] {
            let bytes = code_bytes(&wasm, &target.expected_wasm_hash, ext);
            assert!(base64(&bytes).len() > 64_000);
            let (hash, matches) = identity(&target, &base64(&bytes)).unwrap();
            assert_eq!(hash, target.expected_wasm_hash);
            assert!(matches);
            let mut changed = wasm.clone();
            changed[100] ^= 1;
            assert!(
                !identity(
                    &target,
                    &base64(&code_bytes(&changed, &target.expected_wasm_hash, ext))
                )
                .unwrap()
                .1
            );
            let wrong_embedded = code_bytes(&wasm, &"ab".repeat(32), ext);
            assert!(!identity(&target, &base64(&wrong_embedded)).unwrap().1);
            let mut wrong_size = target.clone();
            wrong_size.wasm_size = Some(48_272);
            assert!(!identity(&wrong_size, &base64(&bytes)).unwrap().1);
            let mut trailing = bytes.clone();
            trailing.extend_from_slice(&[0; 4]);
            assert!(identity(&target, &base64(&trailing)).is_err());
            assert!(identity(&target, &base64(&bytes[..bytes.len() - 1])).is_err());
            let mut padding = bytes.clone();
            *padding.last_mut().unwrap() = 1;
            assert!(identity(&target, &base64(&padding)).is_err());
        }
        let bad = code_bytes(&wasm, &target.expected_wasm_hash, 2);
        assert!(identity(&target, &base64(&bad)).is_err());
        assert!(identity(&target, "A?==").is_err());
        assert!(identity(&target, "AR==").is_err());
    }
    #[test]
    fn code_state_ttl_boundaries_zero_expired_and_missing_never_fabricated() {
        let (targets, mut reply) = fixture();
        for (expiry, status, remaining, until) in [
            (
                100 + LOW_TTL + 1,
                Status::Live,
                Some(LOW_TTL + 1),
                Some(100 + LOW_TTL + 1),
            ),
            (
                100 + LOW_TTL,
                Status::LowTtl,
                Some(LOW_TTL),
                Some(100 + LOW_TTL),
            ),
            (100, Status::LowTtl, Some(0), Some(100)),
            // Historical expiration must never be surfaced as a current
            // usable live-until value in the public customer API.
            (99, Status::Unavailable, None, None),
            (0, Status::Unavailable, None, None),
        ] {
            reply["entries"][0]["liveUntilLedgerSeq"] = json!(expiry);
            let result = observe(&targets, &reply).unwrap();
            let row = &result.entries[0];
            assert_eq!(row.status, status);
            assert_eq!(row.ttl_remaining_ledgers, remaining);
            assert_eq!(row.live_until_ledger, until);
            assert_eq!(result.all_entries_healthy, status == Status::Live);
        }
        for bad in [
            Value::Null,
            json!(-1),
            json!("123456"),
            json!(u64::MAX),
            json!(1.5),
        ] {
            reply["entries"][0]["liveUntilLedgerSeq"] = bad;
            assert!(observe(&targets, &reply).is_err());
        }
        reply["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("liveUntilLedgerSeq");
        assert!(observe(&targets, &reply).is_err());
    }
    #[test]
    fn sparse_results_preserve_order_and_nulls_duplicates_and_extra_keys_fail_closed() {
        let (targets, reply) = fixture();
        let mut sparse = reply.clone();
        sparse["entries"].as_array_mut().unwrap().remove(0);
        sparse["entries"].as_array_mut().unwrap().reverse();
        let result = observe(&targets, &sparse).unwrap();
        assert_eq!(result.entries.len(), 7);
        assert!(!result.all_entries_healthy);
        assert_eq!(result.entries[0].status, Status::Unavailable);
        assert!(result.entries[0].observed_wasm_hash.is_none());
        assert!(result.entries[0].live_until_ledger.is_none());
        assert!(result.entries[0].ttl_remaining_ledgers.is_none());
        assert_eq!(result.entries[1].name, "webauthn_instance");
        let mut duplicate = reply.clone();
        duplicate["entries"]
            .as_array_mut()
            .unwrap()
            .push(reply["entries"][0].clone());
        assert!(observe(&targets, &duplicate).is_err());
        let mut extra = reply.clone();
        extra["entries"][0]["key"] = json!("unexpected");
        assert!(observe(&targets, &extra).is_err());
        for entries in [Value::Null, json!({}), json!([{}])] {
            let mut bad = reply.clone();
            bad["entries"] = entries;
            assert!(observe(&targets, &bad).is_err());
        }
    }
    #[test]
    fn code_and_instance_divergence_is_mismatch_not_green() {
        let (targets, mut reply) = fixture();
        reply["entries"][0]["xdr"] = json!(base64(&code_bytes(
            &[1, 2, 3],
            &targets[0].expected_wasm_hash,
            1
        )));
        reply["entries"][1]["xdr"] = json!(base64(&instance_bytes(&targets[1], &"ab".repeat(32))));
        let result = observe(&targets, &reply).unwrap();
        assert_eq!(result.entries[0].status, Status::Mismatch);
        assert_eq!(result.entries[1].status, Status::Mismatch);
        assert!(!result.all_entries_healthy);
        reply["entries"][1]["xdr"] = json!(base64(&instance_bytes(
            &targets[3],
            &targets[1].expected_wasm_hash
        )));
        assert!(observe(&targets, &reply).is_err());
        let mut invalid_tail = instance_bytes(&targets[1], &targets[1].expected_wasm_hash);
        invalid_tail.extend_from_slice(&[0; 4]);
        reply["entries"][1]["xdr"] = json!(base64(&invalid_tail));
        assert!(observe(&targets, &reply).is_err());
    }
    #[test]
    fn malformed_entries_and_ledgers_fail_closed() {
        let (targets, reply) = fixture();
        for bad in [
            json!(0),
            json!(u64::MAX),
            json!("100"),
            json!(116),
            Value::Null,
        ] {
            let mut v = reply.clone();
            v["latestLedger"] = bad;
            assert!(observe(&targets, &v).is_err());
        }
        for field in ["lastModifiedLedgerSeq", "xdr", "key"] {
            let mut v = reply.clone();
            v["entries"][0].as_object_mut().unwrap().remove(field);
            assert!(observe(&targets, &v).is_err());
        }
        let mut v = reply.clone();
        v["entries"][0]["lastModifiedLedgerSeq"] = json!(101);
        assert!(observe(&targets, &v).is_err());
        v["entries"][0]["lastModifiedLedgerSeq"] = json!(0);
        assert!(observe(&targets, &v).is_err());
    }
    #[test]
    fn network_identity_head_distance_and_freshness_required() {
        let (targets, reply) = fixture();
        assert!(assess_targets(
            &reply,
            "Public Global Stellar Network ; September 2015",
            100,
            "1000",
            1100,
            &targets
        )
        .is_err());
        for (closed, now) in [("1000", 1181), ("0", 1100), ("1101", 1100), ("bad", 1100)] {
            assert!(assess_targets(&reply, TESTNET, 100, closed, now, &targets).is_err());
        }
        assert!(assess_targets(&reply, TESTNET, 100, "1000", 1180, &targets).is_ok());
        assert!(assess_targets(&reply, TESTNET, 115, "1000", 1100, &targets).is_ok());
        assert!(assess_targets(&reply, TESTNET, 116, "1000", 1100, &targets).is_err());
        assert!(assess_targets(&reply, TESTNET, u64::MAX, "1000", 1100, &targets).is_err());
    }
    #[test]
    fn exact_wire_shape_and_disabled_customer_and_financial_flags_even_when_healthy() {
        let (targets, reply) = fixture();
        let result = observe(&targets, &reply).unwrap();
        assert!(result.all_entries_healthy);
        let json = serde_json::to_value(result).unwrap();
        let expected_entries = targets
            .iter()
            .enumerate()
            .map(|(i, target)| {
                json!({
                    "name": NAMES[i],
                    "kind": if i == 0 || i % 2 == 0 { "code" } else { "instance" },
                    "expected_wasm_hash": target.expected_wasm_hash,
                    "observed_wasm_hash": target.expected_wasm_hash,
                    "status": "live", "live_until_ledger": 100 + LOW_TTL + 1,
                    "ttl_remaining_ledgers": LOW_TTL + 1,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            json,
            json!({
                "schema_version": 1, "network": "testnet",
                "source": "stellar-rpc/pinned-smart-account-kit",
                "observed_at_unix": 1100, "observed_ledger_sequence": 100,
                "kit_version": "0.10.0", "entries": expected_entries,
                "all_entries_healthy": true,
                "customer_smart_account_factory_deployed": false,
                "customer_smart_account_created": false,
                "credential_recovery_verified": false, "privacy_proofs_verified": false,
                "mainnet_enabled": false, "financial_execution_enabled": false,
                "operator_managed_deployment": true,
            })
        );
        assert_eq!(json.as_object().unwrap().len(), 15);
        assert_eq!(json["source"], "stellar-rpc/pinned-smart-account-kit");
        assert_eq!(json["kit_version"], "0.10.0");
        assert_eq!(json["operator_managed_deployment"], true);
        for flag in [
            "customer_smart_account_factory_deployed",
            "customer_smart_account_created",
            "credential_recovery_verified",
            "privacy_proofs_verified",
            "mainnet_enabled",
            "financial_execution_enabled",
        ] {
            assert_eq!(json[flag], false, "{flag}");
        }
        for row in json["entries"].as_array().unwrap() {
            assert_eq!(row.as_object().unwrap().len(), 7);
        }
    }
}
