//! Canonical unsigned business review context shared with the TypeScript SDK.
//! Network/domain separation protects against cross-environment digest reuse.
//! A digest is NOT a signed authorization or a Stellar transaction.

use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusinessOperation {
    InvoiceReview,
    VendorOnboarding,
    TreasuryPolicy,
}
impl BusinessOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvoiceReview => "invoice-review",
            Self::VendorOnboarding => "vendor-onboarding",
            Self::TreasuryPolicy => "treasury-policy",
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError { InvalidIdentifier }

fn alphanumeric(subject: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&subject.len())
        && subject.bytes().all(|b| b.is_ascii_alphanumeric())
}
fn slug(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b==b'_' || b==b'-')
}
/// Fixed-field, ASCII-only, network-specific envelope; serialized identically
/// by the reviewed browser/Node SDK. No amounts, wallet keys or PII are included.
pub fn canonical_business_envelope(
    organization: Uuid,
    actor: &str,
    operation: BusinessOperation,
    reference: &str,
    request_key: &str,
) -> Result<String,EnvelopeError> {
    if organization.is_nil() || !alphanumeric(actor,8,128) ||
        !slug(reference,8,64) || !slug(request_key,16,128) {
        return Err(EnvelopeError::InvalidIdentifier);
    }
    Ok(format!(
        "StealthBridge business review\nnetwork:Test SDF Network ; September 2015\n\
organization:{organization}\nactor:{actor}\noperation:{}\nreference:{reference}\nrequest_key:{request_key}\n",
        operation.as_str()
    ))
}
pub fn digest_business_envelope(
    organization: Uuid,
    actor: &str,
    operation: BusinessOperation,
    reference: &str,
    request_key: &str,
) -> Result<[u8;32],EnvelopeError> {
    let content=canonical_business_envelope(organization,actor,operation,reference,request_key)?;
    Ok(Sha256::digest(content.as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_canonical_digest_as_browser_sdk() {
        let org=Uuid::parse_str("a12ef783-d60b-4427-aa62-d2562acd4cef").unwrap();
        let digest=digest_business_envelope(
            org, "GTESTMAKER000000001", BusinessOperation::InvoiceReview,
            "INVOICE_001", "synthetic_business_request_0001"
        ).unwrap();
        assert_eq!(hex::encode(digest),
            "ca2561966d4cc43cb2593fe2fb151ab31ba7d6aefd15363975d053a8b13d4b36");
    }
    #[test]
    fn request_identity_and_network_binding_are_unambiguous() {
        let org=Uuid::new_v4();
        let before=digest_business_envelope(
            org,"GTESTMAKER000000001",BusinessOperation::InvoiceReview,
            "INVOICE_001","synthetic_business_request_0001"
        ).unwrap();
        let second=digest_business_envelope(
            org,"GTESTMAKER000000001",BusinessOperation::InvoiceReview,
            "INVOICE_002","synthetic_business_request_0001"
        ).unwrap();
        assert_ne!(before,second);
        assert!(canonical_business_envelope(
            org,"GTESTMAKER000000001",BusinessOperation::InvoiceReview,
            "BAD\nnetwork:public","synthetic_business_request_0001"
        ).is_err());
    }
}
