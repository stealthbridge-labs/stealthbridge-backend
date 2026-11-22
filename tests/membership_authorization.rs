//! Tenant membership enforcement tests against CI PostgreSQL.
//! Identity strings and organizations in this file are synthetic fixtures.
use sqlx::PgPool;
use stealthbridge_backend::authz::{authorize_member, MembershipError, Permission, Role};
use uuid::Uuid;

#[tokio::test]
async fn active_membership_role_and_revocation_are_database_enforced() {
    let url = std::env::var("DATABASE_URL").expect("CI PostgreSQL required");
    let pool = PgPool::connect(&url).await.expect("connect");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrate");
    let alpha = Uuid::new_v4();
    let beta = Uuid::new_v4();
    let subject = "test-fixture-verified-identity-123";
    for (org, status) in [(alpha, "active"), (beta, "suspended")] {
        sqlx::query("INSERT INTO organizations(id,display_name,status) VALUES ($1,$2,$3)")
            .bind(org)
            .bind("TEST_ONLY_ORGANIZATION")
            .bind(status)
            .execute(&pool)
            .await
            .expect("org");
        sqlx::query("INSERT INTO organization_members(organization_id,subject,role) VALUES ($1,$2,'approver')")
            .bind(org).bind(subject).execute(&pool).await.expect("member");
    }
    let can_approve = authorize_member(&pool, alpha, subject, Permission::ApproveIntent)
        .await
        .expect("approved by active role");
    assert_eq!(can_approve, Role::Approver);
    assert!(matches!(
        authorize_member(&pool, alpha, subject, Permission::SubmitAuthorizedIntent).await,
        Err(MembershipError::Denied)
    ));
    assert!(matches!(
        authorize_member(&pool, beta, subject, Permission::ApproveIntent).await,
        Err(MembershipError::Denied)
    ));
    assert!(matches!(
        authorize_member(&pool, Uuid::new_v4(), subject, Permission::ReadAudit).await,
        Err(MembershipError::Denied)
    ));
    assert!(matches!(
        authorize_member(&pool, alpha, " unknown ", Permission::ReadAudit).await,
        Err(MembershipError::InvalidSubject)
    ));
    sqlx::query("UPDATE organization_members SET revoked_at=now() WHERE organization_id=$1")
        .bind(alpha)
        .execute(&pool)
        .await
        .expect("revoke");
    assert!(matches!(
        authorize_member(&pool, alpha, subject, Permission::ReadAudit).await,
        Err(MembershipError::Denied)
    ));
    // Re-activate a tenant does not override suspended/revoked member rows.
    sqlx::query("UPDATE organizations SET status='active' WHERE id=$1")
        .bind(beta)
        .execute(&pool)
        .await
        .expect("activate");
    assert!(
        authorize_member(&pool, beta, subject, Permission::ReadAudit)
            .await
            .is_ok()
    );
    for org in [alpha, beta] {
        sqlx::query("DELETE FROM organization_members WHERE organization_id=$1")
            .bind(org)
            .execute(&pool)
            .await
            .expect("clean membership");
        sqlx::query("DELETE FROM organizations WHERE id=$1")
            .bind(org)
            .execute(&pool)
            .await
            .expect("clean org");
    }
}
