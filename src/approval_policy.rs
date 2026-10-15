//! Pure business maker-checker review policy for future tenant-scoped requests.
//! No signatures are verified here, no persistence occurs, and policy consistency
//! is NEVER a wallet authorization or permission to execute a financial transfer.

use crate::authz::{permits, Permission, Role};
use std::collections::HashSet;
use uuid::Uuid;

const MAX_REVIEW_WINDOW_SECONDS: i64 = 86_400;
const MAX_REVIEW_RECORDS: usize = 8;

#[derive(Debug)]
pub struct ReviewPolicy {
    pub organization: Uuid,
    pub initiator: String,
    /// Hash of the canonical operation envelope; the caller must compute and verify it.
    pub intent_sha256: [u8; 32],
    pub required_reviewers: u8,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
}

#[derive(Debug)]
pub struct ReviewRecord {
    pub organization: Uuid,
    pub reviewer: String,
    pub role: Role,
    pub recorded_at_unix: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReviewError {
    InvalidPolicy,
    Expired,
    InvalidRecord,
    WrongOrganization,
    SameInitiator,
    ForbiddenRole,
    DuplicateReviewer,
    TooManyRecords,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReviewAssessment {
    pub distinct_reviewers: usize,
    pub remaining_reviewers: usize,
    /// Only a structural review count. Not evidence of signed approval.
    pub review_count_met: bool,
    /// Intentionally false even when every supplied record is structurally valid.
    pub financial_execution_authorized: bool,
}

fn valid_subject(s: &str) -> bool {
    (8..=128).contains(&s.len())
        && s.trim() == s
        && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Validate review constraints without trusting caller-supplied roles, subjects,
/// membership or signatures. Trusted orchestration must separately verify all
/// inputs in the same tenant-scoped database transaction as a future mutation.
pub fn assess_review(
    policy: &ReviewPolicy,
    records: &[ReviewRecord],
    now_unix: i64,
) -> Result<ReviewAssessment, ReviewError> {
    if policy.organization.is_nil()
        || !valid_subject(&policy.initiator)
        || policy.intent_sha256 == [0u8; 32]
        || !(2..=4).contains(&policy.required_reviewers)
        || policy.issued_at_unix <= 0
        || policy.expires_at_unix <= policy.issued_at_unix
        || policy.expires_at_unix - policy.issued_at_unix > MAX_REVIEW_WINDOW_SECONDS
    {
        return Err(ReviewError::InvalidPolicy);
    }
    if now_unix < policy.issued_at_unix || now_unix >= policy.expires_at_unix {
        return Err(ReviewError::Expired);
    }
    if records.len() > MAX_REVIEW_RECORDS {
        return Err(ReviewError::TooManyRecords);
    }
    let mut reviewers = HashSet::with_capacity(records.len());
    for entry in records {
        if entry.organization != policy.organization {
            return Err(ReviewError::WrongOrganization);
        }
        if !valid_subject(&entry.reviewer)
            || entry.recorded_at_unix < policy.issued_at_unix
            || entry.recorded_at_unix > now_unix
        {
            return Err(ReviewError::InvalidRecord);
        }
        if entry.reviewer == policy.initiator {
            return Err(ReviewError::SameInitiator);
        }
        if !permits(entry.role, Permission::ApproveIntent) {
            return Err(ReviewError::ForbiddenRole);
        }
        if !reviewers.insert(entry.reviewer.as_str()) {
            return Err(ReviewError::DuplicateReviewer);
        }
    }
    let distinct = reviewers.len();
    let required = usize::from(policy.required_reviewers);
    Ok(ReviewAssessment {
        distinct_reviewers: distinct,
        remaining_reviewers: required.saturating_sub(distinct),
        review_count_met: distinct >= required,
        financial_execution_authorized: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (ReviewPolicy, Vec<ReviewRecord>) {
        let org = Uuid::new_v4();
        let policy = ReviewPolicy {
            organization: org,
            initiator: "GTESTINITIATOR000001".into(),
            intent_sha256: [7; 32],
            required_reviewers: 2,
            issued_at_unix: 1_780_000_000,
            expires_at_unix: 1_780_003_600,
        };
        let entries = vec![
            ReviewRecord {
                organization: org,
                reviewer: "GTESTREVIEWER000001".into(),
                role: Role::Approver,
                recorded_at_unix: 1_780_000_100,
            },
            ReviewRecord {
                organization: org,
                reviewer: "GTESTREVIEWER000002".into(),
                role: Role::Admin,
                recorded_at_unix: 1_780_000_200,
            },
        ];
        (policy, entries)
    }

    #[test]
    fn policy_count_is_not_execution_authority() {
        let (policy, records) = setup();
        let result = assess_review(&policy, &records, 1_780_000_300).unwrap();
        assert!(result.review_count_met);
        assert!(!result.financial_execution_authorized);
        assert_eq!(result.remaining_reviewers, 0);
        let partial = assess_review(&policy, &records[..1], 1_780_000_300).unwrap();
        assert_eq!(partial.remaining_reviewers, 1);
        assert!(!partial.review_count_met);
    }

    #[test]
    fn cross_tenant_replay_self_approval_and_duplicate_records_fail() {
        let (policy, mut records) = setup();
        records[0].organization = Uuid::new_v4();
        assert_eq!(assess_review(&policy, &records, 1_780_000_300), Err(ReviewError::WrongOrganization));
        records[0].organization = policy.organization;
        records[0].reviewer = policy.initiator.clone();
        assert_eq!(assess_review(&policy, &records, 1_780_000_300), Err(ReviewError::SameInitiator));
        records[0].reviewer = records[1].reviewer.clone();
        assert_eq!(assess_review(&policy, &records, 1_780_000_300), Err(ReviewError::DuplicateReviewer));
    }

    #[test]
    fn invalid_roles_and_time_constraints_fail() {
        let (mut policy, mut records) = setup();
        records[0].role = Role::Operator;
        assert_eq!(assess_review(&policy, &records, 1_780_000_300), Err(ReviewError::ForbiddenRole));
        records[0].role = Role::Approver;
        assert_eq!(assess_review(&policy, &records, policy.expires_at_unix), Err(ReviewError::Expired));
        policy.intent_sha256 = [0; 32];
        assert_eq!(assess_review(&policy, &records, 1_780_000_300), Err(ReviewError::InvalidPolicy));
        policy.intent_sha256 = [7; 32];
        records[0].recorded_at_unix = 1_780_000_400;
        assert_eq!(assess_review(&policy, &records, 1_780_000_300), Err(ReviewError::InvalidRecord));
    }
}
