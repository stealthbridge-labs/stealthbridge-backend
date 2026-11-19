//! Milestone 4 isolated backend adapter boundaries for evaluating third-party
//! Stellar privacy rails without coupling StealthBridge proprietary logic or
//! misrepresenting off-chain encrypted drafts as on-chain confidentiality.

use serde::Serialize;

pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivacyArchitectureKind {
    LocalEncryptedDraft,
    PrivatePayments,
    ConfidentialToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProductSegment {
    Personal,
    Business,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssetTransferSemantics {
    ExactTransferSep41,
    FeeOnTransfer,
    Rebasing,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RailBlockReason {
    DraftNotOnChainSettlement,
    RailSegmentMismatch,
    WrongNetworkPassphrase,
    AssetNotExactTransferSep41,
    SorobanRuntimeMismatch,
    LedgerHistoryPrunedWithoutIndexer,
    MissingRecoverySeed,
    ProverOrVkUnverified,
    ExternalOperatorOrIssuerUnverified,
    SacPoolFreezeOrClawbackHazard,
    ExecutionDisabled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObserverDisclosureBoundary {
    pub public_sender_or_fee_payer: bool,
    pub public_recipient_on_edge: bool,
    pub public_recipient_on_internal_transfer: bool,
    pub public_edge_amount: bool,
    pub public_internal_amount: bool,
    pub public_counterparty_graph: bool,
    pub auditor_or_global_view_key_disclosure: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PrivacyRailAdapterDescriptor {
    pub rail: PrivacyArchitectureKind,
    pub evaluated_for: Option<ProductSegment>,
    pub upstream_repository: Option<&'static str>,
    pub pinned_commit_or_tag: Option<&'static str>,
    pub license_model: &'static str,
    pub required_soroban_sdk: Option<&'static str>,
    pub production_ready: bool,
    pub execution_enabled: bool,
    pub disclosure: ObserverDisclosureBoundary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyRailPreflightRequest {
    pub segment: ProductSegment,
    pub rail: PrivacyArchitectureKind,
    pub network_passphrase: String,
    pub asset_semantics: AssetTransferSemantics,
    pub account_created_ledger: u32,
    pub rpc_oldest_retained_ledger: u32,
    pub durable_indexer_available: bool,
    pub recovery_seed_backed_up: bool,
    pub external_operator_or_issuer_verified: bool,
    pub sac_pool_frozen_or_shortfall: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PrivacyRailPreflightResult {
    pub rail: PrivacyArchitectureKind,
    pub architecturally_eligible: bool,
    pub production_ready: bool,
    pub execution_enabled: bool,
    pub block_reasons: Vec<RailBlockReason>,
    pub disclosure: ObserverDisclosureBoundary,
}

pub fn describe_rail_adapter(rail: PrivacyArchitectureKind) -> PrivacyRailAdapterDescriptor {
    match rail {
        PrivacyArchitectureKind::LocalEncryptedDraft => PrivacyRailAdapterDescriptor {
            rail,
            evaluated_for: None,
            upstream_repository: None,
            pinned_commit_or_tag: None,
            license_model: "StealthBridge MIT",
            required_soroban_sdk: None,
            production_ready: false,
            execution_enabled: false,
            disclosure: ObserverDisclosureBoundary {
                public_sender_or_fee_payer: false,
                public_recipient_on_edge: false,
                public_recipient_on_internal_transfer: false,
                public_edge_amount: false,
                public_internal_amount: false,
                public_counterparty_graph: false,
                auditor_or_global_view_key_disclosure: false,
            },
        },
        PrivacyArchitectureKind::PrivatePayments => PrivacyRailAdapterDescriptor {
            rail,
            evaluated_for: Some(ProductSegment::Personal),
            upstream_repository: Some("https://github.com/NethermindEth/stellar-private-payments"),
            pinned_commit_or_tag: Some("cebb972b5872cba3a1cc40bcdfab297168ccc1d7"),
            license_model: "Apache-2.0 workspace; circomlib LGPL-3.0 + circuit-compiler GPL-3.0 artifacts",
            required_soroban_sdk: Some("28.x (BN254 pairing host)"),
            production_ready: false,
            execution_enabled: false,
            disclosure: ObserverDisclosureBoundary {
                public_sender_or_fee_payer: true,
                public_recipient_on_edge: true,
                public_recipient_on_internal_transfer: false,
                public_edge_amount: true,
                public_internal_amount: false,
                public_counterparty_graph: false,
                auditor_or_global_view_key_disclosure: false,
            },
        },
        PrivacyArchitectureKind::ConfidentialToken => PrivacyRailAdapterDescriptor {
            rail,
            evaluated_for: Some(ProductSegment::Business),
            upstream_repository: Some("https://github.com/OpenZeppelin/stellar-contracts"),
            pinned_commit_or_tag: Some("v0.8.0 (ddc327eb92d63709436da3a8455f641c2d5476c5)"),
            license_model: "MIT",
            required_soroban_sdk: Some("28.x (UltraHonk + Poseidon2 host)"),
            production_ready: false,
            execution_enabled: false,
            disclosure: ObserverDisclosureBoundary {
                public_sender_or_fee_payer: true,
                public_recipient_on_edge: true,
                public_recipient_on_internal_transfer: true,
                public_edge_amount: true,
                public_internal_amount: false,
                public_counterparty_graph: true,
                auditor_or_global_view_key_disclosure: true,
            },
        },
    }
}

pub fn evaluate_rail_preflight(req: &PrivacyRailPreflightRequest) -> PrivacyRailPreflightResult {
    let spec = describe_rail_adapter(req.rail);
    let mut reasons = Vec::new();

    match (req.segment, req.rail) {
        (_, PrivacyArchitectureKind::LocalEncryptedDraft) => {
            reasons.push(RailBlockReason::DraftNotOnChainSettlement);
        }
        (ProductSegment::Personal, PrivacyArchitectureKind::ConfidentialToken)
        | (ProductSegment::Business, PrivacyArchitectureKind::PrivatePayments) => {
            reasons.push(RailBlockReason::RailSegmentMismatch);
        }
        _ => {}
    }

    if req.network_passphrase != TESTNET_PASSPHRASE {
        reasons.push(RailBlockReason::WrongNetworkPassphrase);
    }
    if req.asset_semantics != AssetTransferSemantics::ExactTransferSep41 {
        reasons.push(RailBlockReason::AssetNotExactTransferSep41);
    }
    reasons.push(RailBlockReason::SorobanRuntimeMismatch);
    if req.account_created_ledger < req.rpc_oldest_retained_ledger && !req.durable_indexer_available {
        reasons.push(RailBlockReason::LedgerHistoryPrunedWithoutIndexer);
    }
    if !req.recovery_seed_backed_up {
        reasons.push(RailBlockReason::MissingRecoverySeed);
    }
    if req.sac_pool_frozen_or_shortfall {
        reasons.push(RailBlockReason::SacPoolFreezeOrClawbackHazard);
    }
    reasons.push(RailBlockReason::ProverOrVkUnverified);
    if !req.external_operator_or_issuer_verified {
        reasons.push(RailBlockReason::ExternalOperatorOrIssuerUnverified);
    }
    reasons.push(RailBlockReason::ExecutionDisabled);

    let eligible = req.rail != PrivacyArchitectureKind::LocalEncryptedDraft
        && !reasons.contains(&RailBlockReason::RailSegmentMismatch)
        && !reasons.contains(&RailBlockReason::WrongNetworkPassphrase)
        && !reasons.contains(&RailBlockReason::AssetNotExactTransferSep41)
        && !reasons.contains(&RailBlockReason::LedgerHistoryPrunedWithoutIndexer)
        && !reasons.contains(&RailBlockReason::SacPoolFreezeOrClawbackHazard)
        && req.recovery_seed_backed_up;

    PrivacyRailPreflightResult {
        rail: req.rail,
        architecturally_eligible: eligible,
        production_ready: false,
        execution_enabled: false,
        block_reasons: reasons,
        disclosure: spec.disclosure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_vault_and_commitments_never_qualify_as_onchain_privacy_rails() {
        let res = evaluate_rail_preflight(&PrivacyRailPreflightRequest {
            segment: ProductSegment::Personal,
            rail: PrivacyArchitectureKind::LocalEncryptedDraft,
            network_passphrase: TESTNET_PASSPHRASE.to_string(),
            asset_semantics: AssetTransferSemantics::ExactTransferSep41,
            account_created_ledger: 5_800_000,
            rpc_oldest_retained_ledger: 5_696_840,
            durable_indexer_available: true,
            recovery_seed_backed_up: true,
            external_operator_or_issuer_verified: true,
            sac_pool_frozen_or_shortfall: false,
        });
        assert!(!res.architecturally_eligible);
        assert!(!res.production_ready);
        assert!(!res.execution_enabled);
        assert!(res
            .block_reasons
            .contains(&RailBlockReason::DraftNotOnChainSettlement));
    }

    #[test]
    fn enforces_distinct_observer_visibility_and_rejects_cross_rail_swaps() {
        let spp = describe_rail_adapter(PrivacyArchitectureKind::PrivatePayments);
        let ct = describe_rail_adapter(PrivacyArchitectureKind::ConfidentialToken);
        assert!(!spp.production_ready);
        assert!(!ct.production_ready);
        assert!(!spp.disclosure.public_counterparty_graph);
        assert!(ct.disclosure.public_counterparty_graph);
        assert!(ct.disclosure.auditor_or_global_view_key_disclosure);

        let swap = evaluate_rail_preflight(&PrivacyRailPreflightRequest {
            segment: ProductSegment::Business,
            rail: PrivacyArchitectureKind::PrivatePayments,
            network_passphrase: TESTNET_PASSPHRASE.to_string(),
            asset_semantics: AssetTransferSemantics::ExactTransferSep41,
            account_created_ledger: 5_800_000,
            rpc_oldest_retained_ledger: 5_696_840,
            durable_indexer_available: true,
            recovery_seed_backed_up: true,
            external_operator_or_issuer_verified: true,
            sac_pool_frozen_or_shortfall: false,
        });
        assert!(!swap.architecturally_eligible);
        assert!(swap.block_reasons.contains(&RailBlockReason::RailSegmentMismatch));
    }

    #[test]
    fn enforces_exact_transfer_sep41_retention_window_and_sac_freeze_hazards() {
        let failed = evaluate_rail_preflight(&PrivacyRailPreflightRequest {
            segment: ProductSegment::Business,
            rail: PrivacyArchitectureKind::ConfidentialToken,
            network_passphrase: "Public Global Stellar Network ; September 2015".to_string(),
            asset_semantics: AssetTransferSemantics::FeeOnTransfer,
            account_created_ledger: 5_500_000,
            rpc_oldest_retained_ledger: 5_696_840,
            durable_indexer_available: false,
            recovery_seed_backed_up: false,
            external_operator_or_issuer_verified: false,
            sac_pool_frozen_or_shortfall: true,
        });
        assert!(!failed.architecturally_eligible);
        assert!(failed
            .block_reasons
            .contains(&RailBlockReason::WrongNetworkPassphrase));
        assert!(failed
            .block_reasons
            .contains(&RailBlockReason::AssetNotExactTransferSep41));
        assert!(failed
            .block_reasons
            .contains(&RailBlockReason::LedgerHistoryPrunedWithoutIndexer));
        assert!(failed
            .block_reasons
            .contains(&RailBlockReason::MissingRecoverySeed));
        assert!(failed
            .block_reasons
            .contains(&RailBlockReason::SacPoolFreezeOrClawbackHazard));
        assert!(failed
            .block_reasons
            .contains(&RailBlockReason::ExecutionDisabled));
    }
}
