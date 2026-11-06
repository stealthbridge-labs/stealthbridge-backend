//! Offline Testnet review fingerprints. This deliberately has NO HTTP route,
//! persistence, signing or fund-moving authority. Incoming amount/recipient
//! preimages must never be collected by the public API to verify a fingerprint.
use sha2::{Digest, Sha256};

const DOMAIN: &str = "StealthBridge private local review v1";
const PASSPHRASE: &str = "Test SDF Network ; September 2015";

pub struct ReviewDraft<'a> {
    pub corridor_id: &'a str,
    pub origin_country: &'a str,
    pub destination_country: &'a str,
    pub asset_code: &'a str,
    pub asset_issuer: Option<&'a str>,
    pub privacy_rail: &'a str,
    pub sender: &'a str,
    pub recipient: &'a str,
    pub amount: &'a str,
    pub reference: &'a str,
}
fn all_ascii(value: &str, min: usize, max: usize, allowed: impl Fn(u8) -> bool) -> bool {
    (min..=max).contains(&value.len()) && value.bytes().all(allowed)
}
fn valid_amount(value: &str) -> bool {
    let mut split=value.split('.');
    let integer=split.next().unwrap_or("");
    let fraction=split.next();
    if split.next().is_some() || !all_ascii(integer,1,12,|b|b.is_ascii_digit()) ||
      (integer.len()>1 && integer.starts_with('0')) ||
      fraction.is_some_and(|f|!all_ascii(f,1,7,|b|b.is_ascii_digit())) {return false;}
    value.bytes().any(|b| matches!(b,b'1'..=b'9'))
}
fn valid_public_recipient(value:&str)->bool{
    crate::wallet::decode_account_address(value).is_some() ||
      crate::ledger_events::valid_contract_id(value)
}
pub fn canonical_review_draft(d: &ReviewDraft<'_>) -> Result<String, &'static str> {
    if uuid::Uuid::parse_str(d.corridor_id).ok().is_none_or(|v|v.to_string()!=d.corridor_id) ||
      !all_ascii(d.origin_country,2,2,|b|b.is_ascii_uppercase()) ||
      !all_ascii(d.destination_country,2,2,|b|b.is_ascii_uppercase()) ||
      d.origin_country==d.destination_country ||
      !all_ascii(d.asset_code,1,64,|b|b.is_ascii_alphanumeric()||b"_:-".contains(&b)) ||
      d.asset_issuer.is_some_and(|s|crate::wallet::decode_account_address(s).is_none()) ||
      !["private-payments","confidential-token"].contains(&d.privacy_rail) ||
      crate::wallet::decode_account_address(d.sender).is_none() ||
      !valid_public_recipient(d.recipient) || d.sender==d.recipient ||
      !valid_amount(d.amount) ||
      !all_ascii(d.reference,0,64,|b|b.is_ascii_alphanumeric()||b"_-".contains(&b)) {
        return Err("invalid_local_review_draft");
    }
    Ok(format!("{DOMAIN}\nnetwork:{PASSPHRASE}\ncorridor:{}\norigin:{}\ndestination:{}\nasset:{}\nissuer:{}\nrail:{}\nsender:{}\nrecipient:{}\namount:{}\nreference:{}\n",
      d.corridor_id,d.origin_country,d.destination_country,d.asset_code,
      d.asset_issuer.unwrap_or(""),d.privacy_rail,d.sender,d.recipient,d.amount,d.reference))
}
/// Test-vector parity with TypeScript; nonce must be an unpredictable 256-bit
/// SECRET. A digest is neither ZK nor a payment authorization.
pub fn digest_review_draft(d: &ReviewDraft<'_>,nonce_hex:&str)->Result<String,&'static str>{
    if !all_ascii(nonce_hex,64,64,|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) {
        return Err("invalid_local_review_nonce");
    }
    // A fixed all-zero nonce is an unsafe deterministic review receipt.
    // No server-side review verifier is introduced: preimages remain local.
    if nonce_hex.bytes().all(|b| b == b'0') {
        return Err("invalid_local_review_nonce");
    }
    let canonical=canonical_review_draft(d)?;
    let digest=Sha256::digest(format!("{DOMAIN} nonce:{nonce_hex}\n{canonical}").as_bytes());
    Ok(hex::encode(digest))
}
#[cfg(test)]mod tests{
    use super::*;
    fn draft()->ReviewDraft<'static>{
        let sender="GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
        ReviewDraft{corridor_id:"a12ef783-d60b-4427-aa62-d2562acd4cef",
          origin_country:"NG",destination_country:"GB",asset_code:"USDC",
          asset_issuer:Some(sender),privacy_rail:"confidential-token",sender,
          recipient:"GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN",
          amount:"120.50",reference:"INV_248"}
    }
    #[test]fn local_receipt_is_deterministic_and_sensitive_to_edits(){
        let mut d=draft();let nonce="a1".repeat(32);
        let digest=digest_review_draft(&d,&nonce).unwrap();
        assert_eq!(digest,"4f1d1a8cbf79a6d8b8d6780034de12339983540d836e9879ce1a3e03bd38f571");
        d.amount="120.51";
        assert_ne!(digest,digest_review_draft(&d,&nonce).unwrap());
        d.amount="120.50";d.reference="INV_249";
        assert_ne!(digest,digest_review_draft(&d,&nonce).unwrap());
    }
    #[test]fn reject_cross_network_input_and_ambiguous_formats(){
        let mut d=draft();
        for bad in ["0","01.1","12e2","100.12345678","-100"]{
            d.amount=bad;assert!(canonical_review_draft(&d).is_err(),"{bad}");
        }
        d.amount="120.50";d.reference="X\nrecipient:attacker";
        assert!(canonical_review_draft(&d).is_err());
        d.reference="INV_248";d.recipient="GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(canonical_review_draft(&d).is_err());
        assert!(digest_review_draft(&draft(),"aa").is_err());
        assert!(digest_review_draft(&draft(),&"0".repeat(64)).is_err());
        assert!(digest_review_draft(&draft(),&"A".repeat(64)).is_err());
    }
    #[test]fn independent_receipt_fields_always_change_the_digest(){
        let nonce="a1".repeat(32);
        let base=digest_review_draft(&draft(),&nonce).unwrap();
        let mut d=draft();d.origin_country="GH";
        assert_ne!(digest_review_draft(&d,&nonce).unwrap(),base);
        let mut d=draft();d.destination_country="FR";
        assert_ne!(digest_review_draft(&d,&nonce).unwrap(),base);
        let mut d=draft();d.privacy_rail="private-payments";
        assert_ne!(digest_review_draft(&d,&nonce).unwrap(),base);
        let mut d=draft();d.asset_code="XLM";
        assert_ne!(digest_review_draft(&d,&nonce).unwrap(),base);
        let mut d=draft();d.asset_issuer=None;
        assert_ne!(digest_review_draft(&d,&nonce).unwrap(),base);
        let mut d=draft();d.corridor_id="b12ef783-d60b-4427-aa62-d2562acd4cef";
        assert_ne!(digest_review_draft(&d,&nonce).unwrap(),base);
        assert_ne!(digest_review_draft(&draft(),&"a2".repeat(32)).unwrap(),base);
    }
}
