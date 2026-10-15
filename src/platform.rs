//! Public product inventory. It is descriptive, not an entitlement or a payment switch.
//! Never derive transfer authority from this catalog.
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct PlatformModule {
    pub id: &'static str,
    pub audiences: &'static [&'static str],
    pub availability: &'static str,
    pub description: &'static str,
}

#[derive(Serialize)]
pub struct PlatformCatalog {
    pub product: &'static str,
    pub network: &'static str,
    pub payment_execution_enabled: bool,
    pub privacy_verified: bool,
    pub mainnet_enabled: bool,
    pub modules: Vec<PlatformModule>,
}

fn module(id: &'static str, audiences: &'static [&'static str], availability: &'static str, description: &'static str) -> PlatformModule {
    PlatformModule { id, audiences, availability, description }
}

/// This inventory intentionally reports *capability scope*, never eligibility,
/// liquidity, contract deployment, authentication or permission to send funds.
pub fn catalog() -> PlatformCatalog {
    PlatformCatalog {
        product: "StealthBridge",
        network: "testnet",
        payment_execution_enabled: false,
        privacy_verified: false,
        mainnet_enabled: false,
        modules: vec![
            module("wallet", &["consumer", "business"], "planned", "Wallet connection exists in the preview; authenticated signing is unavailable."),
            module("corridors", &["consumer", "business", "developer", "partner"], "metadata-only", "Operator-configured database catalog; not a live payout or quote."),
            module("quotes", &["consumer", "business", "developer"], "blocked", "No approved FX or liquidity quote providers."),
            module("payments", &["consumer", "business", "developer"], "blocked", "No independently verified confidential transfer execution."),
            module("batch-payouts", &["business", "developer"], "blocked", "Batch signing and payout authorization are not available."),
            module("approvals", &["business"], "planned", "Tenant-scoped role enforcement and signed approvals are pending."),
            module("reconciliation", &["business", "developer", "partner"], "planned", "Read-model design exists; independent payout reconciliation is pending."),
            module("webhooks", &["business", "developer", "partner"], "planned", "Signed callback validation primitives are not a public delivery service."),
            module("privacy-proofs", &["consumer", "business", "developer"], "blocked", "Neither confidential rail has independent deployment and proof evidence."),
            module("disclosure", &["business", "partner"], "planned", "Selective disclosure requires reviewed cryptographic and legal controls."),
            module("partner-settlement", &["business", "partner"], "blocked", "Licensed fiat partners and settlement acknowledgements are unverified."),
        ],
    }
}

pub async fn platform_modules() -> Json<PlatformCatalog> {
    Json(catalog())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn inventory_is_bounded_unique_and_never_unlocks_value_movement() {
        let inventory = catalog();
        assert_eq!(inventory.product, "StealthBridge");
        assert_eq!(inventory.network, "testnet");
        assert!(!inventory.payment_execution_enabled);
        assert!(!inventory.privacy_verified);
        assert!(!inventory.mainnet_enabled);
        assert_eq!(inventory.modules.len(), 11);
        let mut ids = HashSet::new();
        for item in inventory.modules {
            assert!(ids.insert(item.id), "duplicate module");
            assert!(!item.audiences.is_empty());
            assert!(matches!(item.availability, "metadata-only" | "planned" | "blocked"));
            assert!(!item.description.is_empty());
            if item.availability == "metadata-only" {
                assert_eq!(item.id, "corridors");
            }
        }
    }
}
