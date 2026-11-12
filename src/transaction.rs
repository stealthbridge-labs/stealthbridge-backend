//! Privacy-aware read-only transaction observation.
//! Stellar RPC returns XDR and events that may reveal parties and other metadata.
//! The public API intentionally projects only status and ledger inclusion.

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionObservation {
    pub hash: String,
    pub status: String,
    pub ledger: u64,
    pub closed_at_unix: String,
    pub latest_ledger: u64,
    pub source: &'static str,
}

pub fn valid_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whitelist output from Stellar-RPC; never proxy envelopeXdr, resultXdr,
/// events, return values, secret parameters or partner metadata.
pub fn parse_result(
    hash: &str,
    result: &Value,
) -> Result<Option<TransactionObservation>, &'static str> {
    if !valid_hash(hash) {
        return Err("invalid transaction observation");
    }
    let returned = result
        .get("txHash")
        .and_then(Value::as_str)
        .ok_or("invalid transaction observation")?;
    if !returned.eq_ignore_ascii_case(hash) {
        return Err("invalid transaction observation");
    }
    match result
        .get("status")
        .and_then(Value::as_str)
        .ok_or("invalid transaction observation")?
    {
        "NOT_FOUND" => Ok(None),
        "SUCCESS" | "FAILED" => {
            let status = result["status"]
                .as_str()
                .ok_or("invalid transaction observation")?
                .to_owned();
            let ledger = result["ledger"]
                .as_u64()
                .ok_or("invalid transaction observation")?;
            let latest_ledger = result["latestLedger"]
                .as_u64()
                .ok_or("invalid transaction observation")?;
            let closed_at_unix = result["createdAt"]
                .as_str()
                .ok_or("invalid transaction observation")?
                .to_owned();
            if ledger == 0
                || ledger > latest_ledger
                || closed_at_unix.is_empty()
                || closed_at_unix.len() > 20
                || !closed_at_unix.bytes().all(|x| x.is_ascii_digit())
            {
                return Err("invalid transaction observation");
            }
            Ok(Some(TransactionObservation {
                hash: hash.to_ascii_lowercase(),
                status,
                ledger,
                latest_ledger,
                closed_at_unix,
                source: "stellar-rpc",
            }))
        }
        _ => Err("invalid transaction observation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn rejects_invalid_hashes() {
        assert!(valid_hash(HASH));
        assert!(!valid_hash("not-a-hash"));
        assert!(!valid_hash(&("z".repeat(64))));
        assert!(!valid_hash(&format!("{} ", HASH)));
    }
    #[test]
    fn exposes_status_without_leaking_xdr() {
        let raw = json!({"txHash":HASH,"status":"SUCCESS","ledger":50,
            "latestLedger":60,"createdAt":"1760000000","envelopeXdr":"private",
            "events":{"contractEventsXdr":["sensitive"]}});
        let public = parse_result(HASH, &raw).expect("valid").expect("found");
        let serialized = serde_json::to_string(&public).expect("json");
        assert_eq!(public.status, "SUCCESS");
        assert!(!serialized.contains("private"));
        assert!(!serialized.contains("sensitive"));
        assert!(!serialized.contains("events"));
    }
    #[test]
    fn errors_on_status_or_hash_substitution() {
        assert!(parse_result(HASH, &json!({"status":"SUCCESS","txHash":"00"})).is_err());
        assert!(parse_result(HASH, &json!({"status":"PENDING","txHash":HASH})).is_err());
        assert_eq!(
            parse_result(HASH, &json!({"status":"NOT_FOUND","txHash":HASH})),
            Ok(None)
        );
    }
    #[test]
    fn rejects_impossible_inclusion_and_unbounded_timestamps() {
        let raw = json!({"txHash":HASH,"status":"SUCCESS","ledger":50,
            "latestLedger":60,"createdAt":"1760000000"});
        for timestamp in ["", " ", "-1", "1.0", "123456789012345678901"] {
            let mut bad = raw.clone();
            bad["createdAt"] = json!(timestamp);
            assert!(parse_result(HASH, &bad).is_err());
        }
        for ledger in [0, 61] {
            let mut bad = raw.clone();
            bad["ledger"] = json!(ledger);
            assert!(parse_result(HASH, &bad).is_err());
        }
    }
}
