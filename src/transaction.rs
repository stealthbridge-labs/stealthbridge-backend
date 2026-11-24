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

/// The payment a settlement intent promised, used to bind on-chain evidence
/// to the intent (audit C-5). Only classic `Payment` operations to `G`/`M`
/// destinations are recognised; anything else is treated as a mismatch.
pub struct ExpectedPayment<'a> {
    /// Ed25519 key of the paying (signed-in) account.
    pub payer: [u8; 32],
    pub recipient: &'a str,
    /// `"XLM"` with no issuer means the native asset.
    pub asset_code: &'a str,
    pub asset_issuer: Option<&'a str>,
    /// Stroops (7 decimal places), exactly as stored on the intent.
    pub amount: i64,
}

fn muxed_key(m: &stellar_xdr::MuxedAccount) -> ([u8; 32], Option<u64>) {
    match m {
        stellar_xdr::MuxedAccount::Ed25519(k) => (k.0, None),
        stellar_xdr::MuxedAccount::MuxedEd25519(m) => (m.ed25519.0, Some(m.id)),
    }
}

fn asset_matches(asset: &stellar_xdr::Asset, code: &str, issuer: Option<&str>) -> bool {
    use stellar_xdr::{AccountId, Asset, PublicKey};
    let issuer_key = |id: &AccountId| -> [u8; 32] {
        let AccountId(PublicKey::PublicKeyTypeEd25519(k)) = id;
        k.0
    };
    let padded = |n: usize| -> Option<Vec<u8>> {
        let b = code.as_bytes();
        if b.is_empty() || b.len() > n || !b.iter().all(u8::is_ascii_alphanumeric) {
            return None;
        }
        let mut v = b.to_vec();
        v.resize(n, 0);
        Some(v)
    };
    match (asset, issuer) {
        (Asset::Native, None) => code == "XLM",
        (Asset::CreditAlphanum4(a), Some(iss)) => {
            padded(4).as_deref() == Some(&a.asset_code.0[..])
                && crate::wallet::decode_account_address(iss) == Some(issuer_key(&a.issuer))
        }
        (Asset::CreditAlphanum12(a), Some(iss)) => {
            code.len() > 4
                && padded(12).as_deref() == Some(&a.asset_code.0[..])
                && crate::wallet::decode_account_address(iss) == Some(issuer_key(&a.issuer))
        }
        _ => false,
    }
}

/// True only if the transaction envelope in a `getTransaction` reply contains a
/// classic Payment from `expected.payer` to exactly `expected.recipient` of
/// exactly `expected.amount` of the expected asset. Without this check any
/// successful transaction hash, including someone else's, could "finalize"
/// a settlement (audit C-5).
pub fn envelope_pays(rpc_result: &Value, expected: &ExpectedPayment<'_>) -> bool {
    use stellar_xdr::{
        FeeBumpTransactionInnerTx, Limits, OperationBody, ReadXdr, TransactionEnvelope,
    };
    let Some(b64) = rpc_result.get("envelopeXdr").and_then(Value::as_str) else {
        return false;
    };
    let Ok(bytes) = crate::governance_code::decode_base64_bounded(b64, 512 * 1024) else {
        return false;
    };
    let Ok(envelope) = TransactionEnvelope::from_xdr(&bytes, Limits::len(bytes.len())) else {
        return false;
    };
    let tx = match &envelope {
        TransactionEnvelope::Tx(v1) => &v1.tx,
        TransactionEnvelope::TxFeeBump(fb) => match &fb.tx.inner_tx {
            FeeBumpTransactionInnerTx::Tx(v1) => &v1.tx,
        },
        // Legacy v0 envelopes are not produced by current wallets.
        TransactionEnvelope::TxV0(_) => return false,
    };
    let want_dest = match crate::wallet::parse_canonical_stellar_address(expected.recipient) {
        Some(crate::wallet::StellarAddress::Classic(k)) => (k, None),
        Some(crate::wallet::StellarAddress::MuxedClassic { ed25519, id }) => (ed25519, Some(id)),
        _ => return false,
    };
    let (tx_source, _) = muxed_key(&tx.source_account);
    tx.operations.iter().any(|op| {
        let source = op
            .source_account
            .as_ref()
            .map(|m| muxed_key(m).0)
            .unwrap_or(tx_source);
        match &op.body {
            OperationBody::Payment(p) => {
                source == expected.payer
                    && muxed_key(&p.destination) == want_dest
                    && p.amount == expected.amount
                    && asset_matches(&p.asset, expected.asset_code, expected.asset_issuer)
            }
            _ => false,
        }
    })
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

#[cfg(test)]
mod envelope_binding_tests {
    use super::*;
    use serde_json::json;
    use stellar_xdr::{
        AccountId, AlphaNum4, Asset, AssetCode4, Limits, Memo, MuxedAccount, Operation,
        OperationBody, PaymentOp, Preconditions, PublicKey, SequenceNumber, Transaction,
        TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
    };

    const PAYER: [u8; 32] = [1; 32];
    const RECIPIENT: [u8; 32] = [2; 32];
    const ISSUER: [u8; 32] = [3; 32];

    fn strkey_g(k: [u8; 32]) -> String {
        stellar_strkey::ed25519::PublicKey(k)
            .to_string()
            .as_str()
            .to_owned()
    }

    fn envelope(source: [u8; 32], dest: [u8; 32], asset: Asset, amount: i64) -> Value {
        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(dest)),
                asset,
                amount,
            }),
        };
        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source)),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });
        let bytes = env.to_xdr(Limits::none()).unwrap();
        json!({ "envelopeXdr": base64(&bytes) })
    }

    fn base64(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn usdc() -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USDC"),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(ISSUER))),
        })
    }

    #[test]
    fn binds_payer_recipient_asset_and_amount() {
        let recipient = strkey_g(RECIPIENT);
        let issuer = strkey_g(ISSUER);
        let expected = ExpectedPayment {
            payer: PAYER,
            recipient: &recipient,
            asset_code: "USDC",
            asset_issuer: Some(&issuer),
            amount: 25_000_000,
        };
        assert!(envelope_pays(
            &envelope(PAYER, RECIPIENT, usdc(), 25_000_000),
            &expected
        ));
        // Someone else's transaction.
        assert!(!envelope_pays(
            &envelope([9; 32], RECIPIENT, usdc(), 25_000_000),
            &expected
        ));
        // Wrong recipient, amount or asset.
        assert!(!envelope_pays(
            &envelope(PAYER, [8; 32], usdc(), 25_000_000),
            &expected
        ));
        assert!(!envelope_pays(
            &envelope(PAYER, RECIPIENT, usdc(), 24_999_999),
            &expected
        ));
        assert!(!envelope_pays(
            &envelope(PAYER, RECIPIENT, Asset::Native, 25_000_000),
            &expected
        ));
        // Missing or garbage envelope.
        assert!(!envelope_pays(&json!({}), &expected));
        assert!(!envelope_pays(&json!({"envelopeXdr": "AAAA"}), &expected));
    }

    #[test]
    fn native_asset_requires_no_issuer() {
        let recipient = strkey_g(RECIPIENT);
        let expected = ExpectedPayment {
            payer: PAYER,
            recipient: &recipient,
            asset_code: "XLM",
            asset_issuer: None,
            amount: 10,
        };
        assert!(envelope_pays(
            &envelope(PAYER, RECIPIENT, Asset::Native, 10),
            &expected
        ));
        assert!(!envelope_pays(
            &envelope(PAYER, RECIPIENT, usdc(), 10),
            &expected
        ));
    }
}
