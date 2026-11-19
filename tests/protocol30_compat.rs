use stealthbridge_backend::{
    ledger_events, privacy_commitment, smart_account,
    wallet::{
        self, parse_canonical_stellar_address, resolve_classic_recipient_account,
        resolve_contract_recipient, StellarAddress,
    },
};
use stellar_xdr::{LedgerHeader, Limits, ReadXdr, ScAddress, WriteXdr};

const PROTOCOL_30_HEADER_XDR: &str = "AAAAHmw8kthQpKTQ2qpvW8nysSjqV3w3XwdYn1kFTL2VbJJfRshoO26OX/aFza8udj5qHPW9F3S4TWQPH/wbUB9c0ooAAAAAav6zfgAAAAAAAAADAAABofLtJR8AAAAAqCTNGLyddQZNKZpbW6ykO8OqLzJpOBU9jC+btctt8DMAAABALwu6ocrCMwSKXqrNM+5phMsAv7P5VPSOvtmlwHoesw9Zw3kdh7FPCNcKo0vvX0NEporhedkGZcqxMSjy74w9ASta2i/ajySkDZhEYdhSp0Ddo5kv2jQY01lUPNxX6np9jg3A82l7tY+FXEBKbCMemrbgzzt8ik3WDmCmiCN+WrwAWKnuDeC2s6dkAAAAAC1OoDnojwAAAAAAAAAAAA7+BwAAAGQATEtAAAAAyETvn9ZrZehNiqj5Y7KEZHgzZ/RWr6tWLJWAt9U1fKGmmLuxB73eocKyGxtLEOFZzPwpd6hvwktnRHems2/OYSR6CDyv2R7HfBKIznNMdymHVTlBasg62C6eXMNsFhLTcETAaAz0AcKXg+0YuEt37ZCofX9OhI4/zMdPViWaDD1oAAAAAA==";
const SC_ADDRESS_MUXED_CONTRACT_B64: &str =
    "AAAABQAAAAAAAAAq5eOEnsJlmcTbrHR1iaeycsUHmwrKUhyH3n/rXAXnl28=";

const G: &str = "GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
const C: &str = "CDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW7JOB";
const M: &str = "MC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNWAAAAAAAAAAAAGDYO";
const M_MAX: &str = "MC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX7777777777775DTC";
const W: &str = "WDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW6AAAAAAAAAAAFKW6A";
const W_ZERO: &str = "WDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW6AAAAAAAAAAAACCWK";
const W_MAX: &str = "WDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW77777777777775SMG";
const W_BAD_BIT: &str = "WDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW6AAAAAAAAAAAFKW6B";
const M_BAD_BIT: &str = "MAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6EJCCD2H32MBCWAGR";

fn decode_b64(input: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc = 0_u32;
    let mut bits = 0_u32;
    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid base64"),
        };
        acc = (acc << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

#[test]
fn decodes_live_protocol_30_header_and_cap84_scaddress_xdr() {
    let limits = Limits::none();
    let header_bytes = decode_b64(PROTOCOL_30_HEADER_XDR);
    let header = LedgerHeader::from_xdr(&header_bytes, limits.clone())
        .expect("decode Protocol 30 Testnet LedgerHeader");
    assert_eq!(header.ledger_version, 30);
    assert_eq!(header.ledger_seq, 5_810_670);
    assert_eq!(header.to_xdr(limits.clone()).unwrap(), header_bytes);

    let sc_bytes = decode_b64(SC_ADDRESS_MUXED_CONTRACT_B64);
    let sc = ScAddress::from_xdr(&sc_bytes, limits.clone())
        .expect("decode CAP-84 ScAddress::MuxedContract");
    assert!(matches!(sc, ScAddress::MuxedContract(_)));
    assert_eq!(sc.to_xdr(limits).unwrap(), sc_bytes);
}

#[test]
fn classic_contract_muxed_and_w_address_compatibility_vectors() {
    assert!(wallet::decode_account_address(G).is_some());
    assert!(ledger_events::valid_contract_id(C));
    assert!(smart_account::instance_ledger_key(C).is_some());

    // Classic G-only and C-only validators must keep excluding muxed forms directly.
    assert!(wallet::decode_account_address(M).is_none());
    assert!(wallet::decode_account_address(W).is_none());
    assert!(!ledger_events::valid_contract_id(W));
    assert!(smart_account::instance_ledger_key(W).is_none());

    assert!(matches!(
        parse_canonical_stellar_address(G),
        Some(StellarAddress::Classic(_))
    ));
    assert!(matches!(
        parse_canonical_stellar_address(C),
        Some(StellarAddress::Contract(_))
    ));
    assert!(matches!(
        parse_canonical_stellar_address(M),
        Some(StellarAddress::MuxedClassic { id: 1, .. })
    ));
    assert!(matches!(
        parse_canonical_stellar_address(M_MAX),
        Some(StellarAddress::MuxedClassic { id: u64::MAX, .. })
    ));
    assert!(matches!(
        parse_canonical_stellar_address(W),
        Some(StellarAddress::MuxedContract { id: 42, .. })
    ));
    assert!(matches!(
        parse_canonical_stellar_address(W_ZERO),
        Some(StellarAddress::MuxedContract { id: 0, .. })
    ));
    assert!(matches!(
        parse_canonical_stellar_address(W_MAX),
        Some(StellarAddress::MuxedContract { id: u64::MAX, .. })
    ));

    assert_eq!(resolve_classic_recipient_account(M).as_deref(), Some(G));
    assert_eq!(resolve_classic_recipient_account(G).as_deref(), Some(G));
    assert_eq!(resolve_classic_recipient_account(W), None);
    assert_eq!(resolve_contract_recipient(W).as_deref(), Some(C));
    assert_eq!(resolve_contract_recipient(C).as_deref(), Some(C));
    assert_eq!(resolve_contract_recipient(M), None);

    // Non-canonical trailing padding bit, lowercase, whitespace, wrong prefixes, bad CRCs fail closed.
    for bad in [
        W_BAD_BIT,
        M_BAD_BIT,
        &W.to_ascii_lowercase(),
        &format!(" {W}"),
        "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "WAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(parse_canonical_stellar_address(bad).is_none(), "{bad}");
        assert!(resolve_classic_recipient_account(bad).is_none(), "{bad}");
        assert!(resolve_contract_recipient(bad).is_none(), "{bad}");
    }
}

#[test]
fn privacy_review_commitment_accepts_canonical_m_and_w_recipients_but_keeps_g_sender() {
    let sender = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
    for recipient in [M, W, W_MAX] {
        let draft = privacy_commitment::ReviewDraft {
            corridor_id: "a12ef783-d60b-4427-aa62-d2562acd4cef",
            origin_country: "NG",
            destination_country: "GB",
            asset_code: "USDC",
            asset_issuer: Some(sender),
            privacy_rail: "confidential-token",
            sender,
            recipient,
            amount: "10.5",
            reference: "INV_P30",
        };
        let canonical = privacy_commitment::canonical_review_draft(&draft)
            .expect("accept M/W recipient in canonical review");
        assert!(canonical.contains(&format!("recipient:{recipient}\n")));
        assert!(privacy_commitment::digest_review_draft(&draft, &"a1".repeat(32)).is_ok());
    }

    // Senders and classic issuers remain G-only.
    let bad_sender = privacy_commitment::ReviewDraft {
        corridor_id: "a12ef783-d60b-4427-aa62-d2562acd4cef",
        origin_country: "NG",
        destination_country: "GB",
        asset_code: "USDC",
        asset_issuer: Some(sender),
        privacy_rail: "confidential-token",
        sender: M,
        recipient: W,
        amount: "10.5",
        reference: "INV_P30",
    };
    assert!(privacy_commitment::canonical_review_draft(&bad_sender).is_err());
}

mod postgres_tests {
    use super::*;
    use sqlx::PgPool;
    use uuid::Uuid;

    #[tokio::test]
    async fn postgres_schema_supports_69_char_muxed_and_w_addresses_and_protects_g_owners() {
        let url = std::env::var("DATABASE_URL").expect("CI PostgreSQL required");
        let pool = PgPool::connect(&url).await.expect("connection");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations");

        let org_id = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id, display_name) VALUES ($1, 'PROTOCOL30_ORG')")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("org fixture");

        // Generic membership / issuer columns accept 69-char M... and W... identities.
        for addr in [M, W] {
            sqlx::query(
                "INSERT INTO organization_members(organization_id, subject, role) VALUES ($1, $2, 'viewer')",
            )
            .bind(org_id)
            .bind(addr)
            .execute(&pool)
            .await
            .expect("69-char M/W subject allowed");
        }

        let corridor_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO corridors(id, origin_country, destination_country, asset_code, asset_issuer, privacy_rail) \
             VALUES ($1, 'NG', 'GB', 'USDC', $2, 'confidential-token')",
        )
        .bind(corridor_id)
        .bind(W)
        .execute(&pool)
        .await
        .expect("69-char issuer width supported");

        // Owner-scoped classic tables reject 69-char M/W addresses at the DB constraint layer.
        for bad_owner in [M, W] {
            assert!(sqlx::query(
                "INSERT INTO customer_profiles(account_address, display_name, use_case) VALUES ($1, 'Muxed', 'personal')",
            )
            .bind(bad_owner)
            .execute(&pool)
            .await
            .is_err());
        }
    }
}
