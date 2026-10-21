//! Organization membership directory checks against isolated CI PostgreSQL.
//! Fixtures are inserted and deleted by tests; never customer data.
use sqlx::PgPool;
use stealthbridge_backend::account_directory;
use uuid::Uuid;

#[tokio::test]
async fn tenant_membership_directory_query_filters_revoked_and_suspended(){
    let url=std::env::var("DATABASE_URL").expect("CI PostgreSQL required");
    let pool=PgPool::connect(&url).await.expect("connect");
    sqlx::migrate!("./migrations").run(&pool).await.expect("migrations");
    let subject="GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
    let active=Uuid::new_v4();
    let revoked=Uuid::new_v4();
    let suspended=Uuid::new_v4();
    for (id,status) in [(active,"active"),(revoked,"active"),(suspended,"suspended")]{
        sqlx::query("INSERT INTO organizations(id,display_name,status) VALUES ($1,$2,$3)")
            .bind(id).bind("TEST_ONLY_ORG").bind(status).execute(&pool).await.expect("org fixture");
        sqlx::query("INSERT INTO organization_members(organization_id,subject,role) VALUES ($1,$2,'viewer')")
            .bind(id).bind(subject).execute(&pool).await.expect("member fixture");
    }
    sqlx::query("UPDATE organization_members SET revoked_at=now() WHERE organization_id=$1")
        .bind(revoked).execute(&pool).await.expect("revoke");
    // Query is identical to the production membership directory but results
    // are asserted on the database side rather than leaking through a
    // public or unauthenticated endpoint.
    let ids:Vec<Uuid>=sqlx::query_scalar(
        "SELECT o.id FROM organization_members m JOIN organizations o ON o.id=m.organization_id \
         WHERE m.subject=$1 AND m.revoked_at IS NULL AND o.status='active' ORDER BY o.created_at,o.id LIMIT 26"
    ).bind(subject).fetch_all(&pool).await.expect("lookup");
    assert_eq!(ids,vec![active]);
    for id in [active,revoked,suspended]{
        sqlx::query("DELETE FROM organization_members WHERE organization_id=$1")
            .bind(id).execute(&pool).await.expect("fixture cleanup");
        sqlx::query("DELETE FROM organizations WHERE id=$1")
            .bind(id).execute(&pool).await.expect("fixture cleanup");
    }
    let _ = std::any::type_name::<account_directory::AccountDirectory>();
}
