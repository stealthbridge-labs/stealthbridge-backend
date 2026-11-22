//! Tenant role-policy primitives, deliberately separate from authentication.
//! These helpers do not verify a wallet, session, organization membership,
//! proof, jurisdiction or a payment signature. Never call them as a substitute
//! for a trusted, signed identity and a tenant-scoped database lookup.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Owner,
    Admin,
    Operator,
    Approver,
    Viewer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    ReadSettlement,
    ReadAudit,
    CreateDraft,
    ApproveIntent,
    SubmitAuthorizedIntent,
    ManageMembers,
    ManageCorridors,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessError {
    Forbidden,
    SameInitiator,
    InvalidSubject,
}

impl Role {
    pub fn from_db(value: &str) -> Option<Self> {
        Some(match value {
            "owner" => Self::Owner,
            "admin" => Self::Admin,
            "operator" => Self::Operator,
            "approver" => Self::Approver,
            "viewer" => Self::Viewer,
            _ => return None,
        })
    }
}
pub fn permits(role: Role, permission: Permission) -> bool {
    use Permission::*;
    use Role::*;
    match permission {
        ReadSettlement | ReadAudit => true,
        CreateDraft | SubmitAuthorizedIntent => matches!(role, Owner | Admin | Operator),
        ApproveIntent => matches!(role, Owner | Admin | Approver),
        ManageMembers => matches!(role, Owner | Admin),
        ManageCorridors => matches!(role, Owner | Admin),
    }
}

/// A permission-only precondition, NOT a signed payment approval.
/// A real caller still must verify the member's identity, active DB role,
/// quote digest, proof validity and an independently approved settlement.
pub fn check_distinct_approver(
    role: Role,
    initiator_subject: &str,
    approver_subject: &str,
) -> Result<(), AccessError> {
    if initiator_subject.is_empty()
        || approver_subject.is_empty()
        || initiator_subject.len() > 256
        || approver_subject.len() > 256
    {
        return Err(AccessError::InvalidSubject);
    }
    if !permits(role, Permission::ApproveIntent) {
        return Err(AccessError::Forbidden);
    }
    if initiator_subject == approver_subject {
        return Err(AccessError::SameInitiator);
    }
    Ok(())
}

/// Internal data-bound authorization guard. Caller MUST already hold a
/// cryptographically verified subject identity for the selected organization;
/// untrusted HTTP headers/body fields must not be passed here as identity.
///
/// This guard is suitable for read-only or pre-flight decisions. Future
/// financial writes must lock the membership row and perform authorization
/// in the SAME transaction as the mutation to avoid revocation races.
#[derive(Debug)]
pub enum MembershipError {
    InvalidSubject,
    Denied,
    Database(sqlx::Error),
}
impl From<sqlx::Error> for MembershipError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

pub async fn authorize_member(
    pool: &sqlx::PgPool,
    organization: uuid::Uuid,
    verified_subject: &str,
    permission: Permission,
) -> Result<Role, MembershipError> {
    if verified_subject.len() < 8
        || verified_subject.len() > 256
        || verified_subject.trim() != verified_subject
        || verified_subject.chars().any(char::is_control)
    {
        return Err(MembershipError::InvalidSubject);
    }
    // Explicit tenant scope, active status, non-revocation. A missing org or
    // unrecognized role is DENIED (never converted to an admin permission).
    let role_name = sqlx::query_scalar::<_, String>(
        "SELECT m.role FROM organization_members m \
         JOIN organizations o ON o.id=m.organization_id \
         WHERE m.organization_id=$1 AND m.subject=$2 \
         AND m.revoked_at IS NULL AND o.status='active'",
    )
    .bind(organization)
    .bind(verified_subject)
    .fetch_optional(pool)
    .await?;
    let role = role_name
        .as_deref()
        .and_then(Role::from_db)
        .ok_or(MembershipError::Denied)?;
    if !permits(role, permission) {
        return Err(MembershipError::Denied);
    }
    Ok(role)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn role_policy_is_deny_by_default_for_sensitive_operations() {
        assert!(!permits(Role::Viewer, Permission::SubmitAuthorizedIntent));
        assert!(!permits(Role::Viewer, Permission::ApproveIntent));
        assert!(!permits(Role::Operator, Permission::ApproveIntent));
        assert!(!permits(Role::Approver, Permission::SubmitAuthorizedIntent));
        assert!(permits(Role::Operator, Permission::CreateDraft));
        assert!(permits(Role::Approver, Permission::ApproveIntent));
        assert!(permits(Role::Admin, Permission::ManageMembers));
        assert!(!permits(Role::Viewer, Permission::ManageCorridors));
        assert_eq!(Role::from_db("root"), None);
        assert_eq!(Role::from_db("owner"), Some(Role::Owner));
    }
    #[test]
    fn a_payment_initiator_cannot_self_approve() {
        assert_eq!(
            check_distinct_approver(Role::Admin, "member-123", "member-123"),
            Err(AccessError::SameInitiator)
        );
        assert_eq!(
            check_distinct_approver(Role::Operator, "member-a", "member-b"),
            Err(AccessError::Forbidden)
        );
        assert_eq!(
            check_distinct_approver(Role::Approver, "member-a", "member-b"),
            Ok(())
        );
        assert_eq!(
            check_distinct_approver(Role::Owner, "", "member-b"),
            Err(AccessError::InvalidSubject)
        );
    }
}
