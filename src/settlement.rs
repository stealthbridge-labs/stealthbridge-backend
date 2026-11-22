//! Pure settlement state machine. No chain or payout side effects.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementState {
    Draft,
    Quoted,
    Authorized,
    Submitted,
    ChainFinalized,
    PayoutPending,
    PayoutCompleted,
    Expired,
    Rejected,
    ChainFailed,
    PayoutFailed,
    RefundPending,
    Refunded,
    ManualReview,
}
impl SettlementState {
    pub fn as_str(self) -> &'static str {
        use SettlementState::*;
        match self {
            Draft => "draft",
            Quoted => "quoted",
            Authorized => "authorized",
            Submitted => "submitted",
            ChainFinalized => "chain_finalized",
            PayoutPending => "payout_pending",
            PayoutCompleted => "payout_completed",
            Expired => "expired",
            Rejected => "rejected",
            ChainFailed => "chain_failed",
            PayoutFailed => "payout_failed",
            RefundPending => "refund_pending",
            Refunded => "refunded",
            ManualReview => "manual_review",
        }
    }
    /// Final customer-visible outcomes. A chain-finalized event does NOT
    /// establish a delivered fiat payout; external confirmation is distinct.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::PayoutCompleted | Self::Expired | Self::Rejected | Self::Refunded
        )
    }
    /// These states require independent provider-level evidence before any
    /// eventual customer-facing assertion of payout completion.
    pub fn awaits_external_delivery_evidence(self) -> bool {
        matches!(
            self,
            Self::ChainFinalized | Self::PayoutPending | Self::PayoutFailed
        )
    }
    pub fn parse(value: &str) -> Option<Self> {
        use SettlementState::*;
        Some(match value {
            "draft" => Draft,
            "quoted" => Quoted,
            "authorized" => Authorized,
            "submitted" => Submitted,
            "chain_finalized" => ChainFinalized,
            "payout_pending" => PayoutPending,
            "payout_completed" => PayoutCompleted,
            "expired" => Expired,
            "rejected" => Rejected,
            "chain_failed" => ChainFailed,
            "payout_failed" => PayoutFailed,
            "refund_pending" => RefundPending,
            "refunded" => Refunded,
            "manual_review" => ManualReview,
            _ => return None,
        })
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum TransitionError {
    Invalid {
        from: SettlementState,
        to: SettlementState,
    },
}
pub fn transition(
    from: SettlementState,
    to: SettlementState,
) -> Result<SettlementState, TransitionError> {
    use SettlementState::*;
    let valid = matches!(
        (from, to),
        (Draft, Quoted)
            | (Draft, Rejected)
            | (Quoted, Authorized)
            | (Quoted, Expired)
            | (Quoted, Rejected)
            | (Authorized, Submitted)
            | (Authorized, Rejected)
            | (Submitted, ChainFinalized)
            | (Submitted, ChainFailed)
            | (Submitted, ManualReview)
            | (ChainFinalized, PayoutPending)
            | (ChainFinalized, ManualReview)
            | (PayoutPending, PayoutCompleted)
            | (PayoutPending, PayoutFailed)
            | (PayoutPending, ManualReview)
            | (PayoutFailed, PayoutPending)
            | (PayoutFailed, RefundPending)
            | (PayoutFailed, ManualReview)
            | (ChainFailed, RefundPending)
            | (ChainFailed, ManualReview)
            | (RefundPending, Refunded)
            | (RefundPending, ManualReview)
            | (ManualReview, PayoutPending)
            | (ManualReview, RefundPending)
    );
    if valid {
        Ok(to)
    } else {
        Err(TransitionError::Invalid { from, to })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn happy_path() {
        let mut state = SettlementState::Draft;
        for next in [
            SettlementState::Quoted,
            SettlementState::Authorized,
            SettlementState::Submitted,
            SettlementState::ChainFinalized,
            SettlementState::PayoutPending,
            SettlementState::PayoutCompleted,
        ] {
            state = transition(state, next).expect("valid transition");
        }
        assert_eq!(state, SettlementState::PayoutCompleted);
    }
    #[test]
    fn cannot_equate_ledger_finality_with_payout() {
        assert!(transition(
            SettlementState::ChainFinalized,
            SettlementState::PayoutCompleted
        )
        .is_err());
    }
    #[test]
    fn terminal_outcomes_and_delivery_evidence_are_separate() {
        use SettlementState::*;
        for state in [PayoutCompleted, Expired, Rejected, Refunded] {
            assert!(state.is_terminal());
            assert!(!state.awaits_external_delivery_evidence());
        }
        for state in [ChainFinalized, PayoutPending, PayoutFailed] {
            assert!(!state.is_terminal());
            assert!(state.awaits_external_delivery_evidence());
            assert!(transition(state, PayoutCompleted).is_err() || state == PayoutPending);
        }
        assert!(!Submitted.is_terminal());
        assert!(!ManualReview.is_terminal());
        assert!(transition(ChainFinalized, PayoutCompleted).is_err());
    }
    #[test]
    fn state_names_roundtrip() {
        for state in [
            SettlementState::Draft,
            SettlementState::ManualReview,
            SettlementState::Refunded,
            SettlementState::ChainFinalized,
        ] {
            assert_eq!(SettlementState::parse(state.as_str()), Some(state));
        }
        assert_eq!(SettlementState::parse("paid"), None);
    }
}
