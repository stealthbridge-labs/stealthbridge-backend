//! PostgreSQL-only role and tenant schema constraints. The records here are
//! synthetic CI fixtures, not onboarded people, financial entities or KYC.
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::test]
async fn member_roles_are_tenant_scoped_and_revocation_is_validated() {
    let url = std::env::var("DATABASE_URL").expect("CI PostgreSQL required");
    let pool = PgPool::connect(&url).await.expect("connection");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations");
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();

    for id in [first, second] {
        sqlx::query(
            "INSERT INTO organizations(id,display_name) VALUES ($1,'TEST_ONLY_ORGANIZATION')",
        )
        .bind(id)
        .execute(&pool)
        .await
        .expect("isolated organization fixture");
    }

    // Same opaque subject across distinct tenants is allowed; membership
    // must always be resolved against the authenticated selected tenant.
    for org in [first, second] {
        sqlx::query(
            "INSERT INTO organization_members(organization_id,subject,role) \
             VALUES ($1,'test-fixture-subject','viewer')",
        )
        .bind(org)
        .execute(&pool)
        .await
        .expect("fixture membership");
    }
    // Duplicate membership in one tenant is not a second role grant.
    assert!(sqlx::query(
        "INSERT INTO organization_members(organization_id,subject,role) \
         VALUES ($1,'test-fixture-subject','admin')"
    )
    .bind(first)
    .execute(&pool)
    .await
    .is_err());

    // Unknown roles, too-short identifiers, and cross-tenant FK failures
    // must be rejected by the DB itself, never accepted as valid sessions.
    assert!(sqlx::query(
        "INSERT INTO organization_members(organization_id,subject,role) \
         VALUES ($1,'another-fixture-subject','superuser')"
    )
    .bind(first)
    .execute(&pool)
    .await
    .is_err());
    assert!(sqlx::query(
        "INSERT INTO organization_members(organization_id,subject,role) \
         VALUES ($1,'short','admin')"
    )
    .bind(first)
    .execute(&pool)
    .await
    .is_err());
    assert!(sqlx::query(
        "INSERT INTO organization_members(organization_id,subject,role) \
         VALUES ($1,'another-fixture-subject','viewer')"
    )
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .is_err());

    // A pre-creation revocation is invalid.
    assert!(sqlx::query(
        "UPDATE organization_members SET revoked_at=created_at - INTERVAL '1 second' \
         WHERE organization_id=$1 AND subject='test-fixture-subject'"
    )
    .bind(first)
    .execute(&pool)
    .await
    .is_err());
    // A valid revocation persists and never removes the audit identity.
    sqlx::query(
        "UPDATE organization_members SET revoked_at=now() \
         WHERE organization_id=$1 AND subject='test-fixture-subject'",
    )
    .bind(first)
    .execute(&pool)
    .await
    .expect("revocation");
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM organization_members \
         WHERE organization_id=$1 AND revoked_at IS NULL",
    )
    .bind(first)
    .fetch_one(&pool)
    .await
    .expect("active memberships");
    assert_eq!(active, 0);
    let other: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM organization_members \
         WHERE organization_id=$1 AND revoked_at IS NULL",
    )
    .bind(second)
    .fetch_one(&pool)
    .await
    .expect("other tenant");
    assert_eq!(other, 1);

    // FK restriction prevents deleting tenant metadata while members exist.
    assert!(sqlx::query("DELETE FROM organizations WHERE id=$1")
        .bind(second)
        .execute(&pool)
        .await
        .is_err());
    for id in [first, second] {
        sqlx::query("DELETE FROM organization_members WHERE organization_id=$1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("member fixture cleanup");
        sqlx::query("DELETE FROM organizations WHERE id=$1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("organization fixture cleanup");
    }
}
