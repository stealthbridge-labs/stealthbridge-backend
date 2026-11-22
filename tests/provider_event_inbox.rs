//! Synthetic test-only provider callback inbox and PostgreSQL deduplication.
use sqlx::PgPool;
use stealthbridge_backend::webhook::{record_event, InboxError, InboxResult, VerifiedEvent};
use uuid::Uuid;

#[tokio::test]
async fn provider_events_are_idempotent_and_collisions_fail_closed() {
    let url = std::env::var("DATABASE_URL").expect("CI database");
    let pool = PgPool::connect(&url).await.expect("connect");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations");
    let org = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO organizations(id,display_name,status) VALUES($1,'TEST_ONLY_ORG','active')",
    )
    .bind(org)
    .execute(&pool)
    .await
    .expect("fixture organization");
    let event = VerifiedEvent {
        event_id: "fixture_event_001".into(),
        event_type: "fixture.notice".into(),
        payload_sha256: "a".repeat(64),
    };
    assert_eq!(
        record_event(&pool, org, "test-provider", &event)
            .await
            .expect("insert"),
        InboxResult::Inserted
    );
    assert_eq!(
        record_event(&pool, org, "test-provider", &event)
            .await
            .expect("duplicate"),
        InboxResult::Duplicate
    );
    let conflicting = VerifiedEvent {
        payload_sha256: "b".repeat(64),
        ..event
    };
    assert!(matches!(
        record_event(&pool, org, "test-provider", &conflicting).await,
        Err(InboxError::Collision)
    ));
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM provider_event_inbox WHERE organization_id=$1")
            .bind(org)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(count, 1);
    sqlx::query("DELETE FROM provider_event_inbox WHERE organization_id=$1")
        .bind(org)
        .execute(&pool)
        .await
        .expect("cleanup inbox");
    sqlx::query("DELETE FROM organizations WHERE id=$1")
        .bind(org)
        .execute(&pool)
        .await
        .expect("cleanup tenant");
}
