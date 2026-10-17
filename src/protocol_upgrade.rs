//! Offline review of public Soroban upgrade proposal observations.
//! This module neither fetches RPC data nor authorizes changes. A valid
//! timelock is never equivalent to administrator signing, release or payment.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryTarget {
    CorridorRegistry,
    PolicyRegistry,
}

#[derive(Debug, Clone, Copy)]
pub struct UpgradeProposal {
    pub wasm_hash: [u8; 32],
    pub ready_at_ledger: u32,
    pub expires_at_ledger: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct UpgradeObservation {
    pub target: RegistryTarget,
    pub network_is_testnet: bool,
    pub current_ledger: u32,
    pub paused: bool,
    pub candidate_wasm_hash: [u8; 32],
    pub pending: Option<UpgradeProposal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowState {
    Invalid,
    NotProposed,
    Waiting,
    OpenUnverified,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeAssessment {
    pub state: WindowState,
    pub hash_matches: bool,
    /// A public ledger observation never grants signing authority.
    pub authorized_to_execute: bool,
    pub financial_execution_enabled: bool,
}

fn assessment(state: WindowState, hash_matches: bool) -> UpgradeAssessment {
    UpgradeAssessment {
        state,
        hash_matches,
        authorized_to_execute: false,
        financial_execution_enabled: false,
    }
}

/// Only intended for a separately verified testnet RPC adapter.
pub fn assess_upgrade(observation: &UpgradeObservation) -> UpgradeAssessment {
    if !observation.network_is_testnet
        || observation.current_ledger == 0
        || observation.candidate_wasm_hash == [0; 32]
    {
        return assessment(WindowState::Invalid, false);
    }
    let Some(pending) = observation.pending else {
        return assessment(WindowState::NotProposed, false);
    };
    if pending.wasm_hash == [0; 32]
        || pending.ready_at_ledger == 0
        || pending.expires_at_ledger.checked_sub(pending.ready_at_ledger) != Some(10_000)
        || pending.wasm_hash != observation.candidate_wasm_hash
    {
        return assessment(WindowState::Invalid, false);
    }
    if !observation.paused || observation.current_ledger < pending.ready_at_ledger {
        return assessment(WindowState::Waiting, true);
    }
    if observation.current_ledger > pending.expires_at_ledger {
        return assessment(WindowState::Expired, true);
    }
    assessment(WindowState::OpenUnverified, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> UpgradeObservation {
        UpgradeObservation {
            target: RegistryTarget::PolicyRegistry,
            network_is_testnet: true,
            current_ledger: 200,
            paused: true,
            candidate_wasm_hash: [11; 32],
            pending: Some(UpgradeProposal {
                wasm_hash: [11; 32],
                ready_at_ledger: 200,
                expires_at_ledger: 10_200,
            }),
        }
    }

    #[test]
    fn matching_upgrade_window_is_never_authority_to_execute() {
        let result = assess_upgrade(&sample());
        assert_eq!(result.state, WindowState::OpenUnverified);
        assert!(result.hash_matches);
        assert!(!result.authorized_to_execute);
        assert!(!result.financial_execution_enabled);
    }

    #[test]
    fn paused_hash_timing_and_network_guardrails_match_sdk() {
        let mut item = sample();
        item.network_is_testnet = false;
        assert_eq!(assess_upgrade(&item).state, WindowState::Invalid);
        item.network_is_testnet = true;
        item.paused = false;
        assert_eq!(assess_upgrade(&item).state, WindowState::Waiting);
        item.paused = true;
        item.current_ledger = 199;
        assert_eq!(assess_upgrade(&item).state, WindowState::Waiting);
        item.current_ledger = 10_201;
        assert_eq!(assess_upgrade(&item).state, WindowState::Expired);
        item.pending.as_mut().unwrap().wasm_hash = [8; 32];
        assert_eq!(assess_upgrade(&item).state, WindowState::Invalid);
        item.pending = None;
        assert_eq!(assess_upgrade(&item).state, WindowState::NotProposed);
    }

    #[test]
    fn hostile_proposal_window_is_invalid_even_with_syntactically_valid_hash() {
        let mut item = sample();
        item.pending.as_mut().unwrap().expires_at_ledger = 120_000;
        assert_eq!(assess_upgrade(&item).state, WindowState::Invalid);
        item.pending.as_mut().unwrap().expires_at_ledger = 10_200;
        item.candidate_wasm_hash = [0; 32];
        assert_eq!(assess_upgrade(&item).state, WindowState::Invalid);
    }
}
