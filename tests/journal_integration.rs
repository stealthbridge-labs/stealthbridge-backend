//! Real PostgreSQL integration tests; use isolated GitHub Actions service.
//! No fiat providers, wallet secrets, testnet accounts or funded transfers.

use sqlx::{postgres::PgPoolOptions, Row};
use stealthbridge_backend::{
    settlement::SettlementState,
    store::{advance_intent, register_intent, JournalError},
};
use uuid::Uuid;

/// CI checks actual database payloads with the independently built SDK.
fn verify_sdk_notifications(payloads: &[serde_json::Value]) {
    let Ok(entry) = std::env::var("STEALTHBRIDGE_SDK_ENTRY") else {
        return; // The dedicated cross-repository CI step supplies this path.
    };
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let mut child = Command::new("node")
        .args(["--input-type=module", "-e", r#"
            import {readFileSync} from 'node:fs';
            import {pathToFileURL} from 'node:url';
            import assert from 'node:assert/strict';
            const {parseSettlementNotification}=await import(pathToFileURL(process.env.STEALTHBRIDGE_SDK_ENTRY).href);
            const events=JSON.parse(readFileSync(0,'utf8'));
            assert.equal(events.length,2);
            for(const event of events)assert.deepEqual(parseSettlementNotification(event),event);
            console.log('Verified actual PostgreSQL outbox payloads with the built SDK');
        "#])
        .env("STEALTHBRIDGE_SDK_ENTRY", entry)
        .stdin(Stdio::piped()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .spawn().expect("Node.js consumer");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(payloads).unwrap())
        .unwrap();
    assert!(child.wait().expect("SDK consumer exit").success());
}

#[tokio::test]
async fn outbox_failure_rolls_back_registration_and_transition() {
    let url = std::env::var("DATABASE_URL").expect("isolated test database required");
    // One connection keeps the injected TEMP table private to this test.
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let corridor = Uuid::new_v4();
    let organization = Uuid::new_v4();
    let key = format!("rollback-test-{}", Uuid::new_v4());
    let digest = "c".repeat(64);
    sqlx::query("INSERT INTO corridors (id,origin_country,destination_country,asset_code,privacy_rail) VALUES ($1,'AA','BB','ROLLBACK_TEST','confidential-token')")
        .bind(corridor).execute(&pool).await.unwrap();
    let reject_notifications = "CREATE TEMP TABLE settlement_outbox (LIKE public.settlement_outbox INCLUDING ALL, CHECK (current_setting('stealthbridge.test_outbox_failure', true) IS DISTINCT FROM 'on'))";
    sqlx::query(reject_notifications)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("SET stealthbridge.test_outbox_failure = 'on'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        register_intent(&pool, organization, corridor, &key, &digest).await,
        Err(JournalError::Database(_))
    ));
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM settlement_intents WHERE organization_id=$1")
            .bind(organization)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count, 0,
        "a failed notification cannot leave an intent behind"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM settlement_transition_log WHERE organization_id=$1",
    )
    .bind(organization)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
    sqlx::query("SET stealthbridge.test_outbox_failure = 'off'")
        .execute(&pool)
        .await
        .unwrap();
    let intent = register_intent(&pool, organization, corridor, &key, &digest)
        .await
        .unwrap();
    sqlx::query("SET stealthbridge.test_outbox_failure = 'on'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        advance_intent(&pool, organization, intent.id, 0, SettlementState::Quoted).await,
        Err(JournalError::Database(_))
    ));
    let record: (String, i64) = sqlx::query_as(
        "SELECT state,version FROM settlement_intents WHERE organization_id=$1 AND id=$2",
    )
    .bind(organization)
    .bind(intent.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(record, ("draft".into(), 0));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM settlement_transition_log WHERE organization_id=$1",
    )
    .bind(organization)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1, "failed transition cannot append history");
    sqlx::query("SET stealthbridge.test_outbox_failure = 'off'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        advance_intent(&pool, organization, intent.id, 0, SettlementState::Quoted)
            .await
            .unwrap(),
        1
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM settlement_outbox WHERE organization_id=$1")
            .bind(organization)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count, 2,
        "retry emits exactly the initial and successful transition events"
    );
    for table in [
        "settlement_outbox",
        "settlement_transition_log",
        "settlement_intents",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE organization_id=$1"))
            .bind(organization)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM corridors WHERE id=$1")
        .bind(corridor)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn idempotency_is_organization_scoped_and_history_is_append_only() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for integration test");
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect(&url)
        .await
        .expect("postgres");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("schema migration");

    // Synthetic values are limited to this isolated integration test.
    let corridor = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO corridors (id,origin_country,destination_country,asset_code,privacy_rail) \
                 VALUES ($1,'AA','BB','INTEGRATION_TEST','confidential-token')",
    )
    .bind(corridor)
    .execute(&pool)
    .await
    .expect("fixture corridor");

    let organization = Uuid::new_v4();
    let another_organization = Uuid::new_v4();
    let key = format!("integration-test-{}", Uuid::new_v4());
    let digest = "a".repeat(64);

    let (first, second) = tokio::join!(
        register_intent(&pool, organization, corridor, &key, &digest),
        register_intent(&pool, organization, corridor, &key, &digest)
    );
    let first = first.expect("first registration");
    let second = second.expect("second registration");
    assert_eq!(first.id, second.id);
    assert_ne!(first.created, second.created);

    assert!(matches!(
        register_intent(&pool, organization, corridor, &key, &"b".repeat(64)).await,
        Err(JournalError::PayloadConflict)
    ));

    let other = register_intent(&pool, another_organization, corridor, &key, &digest)
        .await
        .expect("different tenant is independent");
    assert_ne!(other.id, first.id);
    assert!(other.created);

    assert!(matches!(
        advance_intent(
            &pool,
            another_organization,
            first.id,
            0,
            SettlementState::Quoted
        )
        .await,
        Err(JournalError::NotFound)
    ));
    assert_eq!(
        advance_intent(&pool, organization, first.id, 0, SettlementState::Quoted)
            .await
            .expect("transition"),
        1
    );
    assert!(matches!(
        advance_intent(
            &pool,
            organization,
            first.id,
            0,
            SettlementState::Authorized
        )
        .await,
        Err(JournalError::VersionConflict)
    ));
    assert!(matches!(
        advance_intent(
            &pool,
            organization,
            first.id,
            1,
            SettlementState::PayoutCompleted
        )
        .await,
        Err(JournalError::InvalidTransition)
    ));

    let rows=sqlx::query("SELECT previous_state,next_state,version \
        FROM settlement_transition_log WHERE organization_id=$1 AND settlement_id=$2 ORDER BY version")
        .bind(organization).bind(first.id).fetch_all(&pool).await.expect("history");
    assert_eq!(rows.len(), 2);
    let initial: Option<String> = rows[0].try_get("previous_state").expect("initial state");
    let draft: String = rows[0].try_get("next_state").expect("initial state");
    let second: String = rows[1].try_get("next_state").expect("later state");
    assert_eq!(initial, None);
    assert_eq!(draft, "draft");
    assert_eq!(second, "quoted");

    let notifications = sqlx::query("SELECT payload, processed FROM settlement_outbox WHERE organization_id=$1 AND settlement_id=$2 ORDER BY id")
        .bind(organization).bind(first.id).fetch_all(&pool).await.expect("outbox");
    assert_eq!(
        notifications.len(),
        2,
        "retries and failed transitions cannot duplicate notifications"
    );
    verify_sdk_notifications(
        &notifications
            .iter()
            .map(|row| row.try_get::<serde_json::Value, _>("payload").unwrap())
            .collect::<Vec<_>>(),
    );
    for (index, row) in notifications.iter().enumerate() {
        let payload: serde_json::Value = row.try_get("payload").unwrap();
        assert_eq!(payload["schema_version"], 1);
        assert_eq!(payload["version"], index.to_string());
        assert_eq!(payload["financial_execution_authorized"], false);
        assert!(!row.try_get::<bool, _>("processed").unwrap());
        assert!(payload.get("request_sha256").is_none());
    }
    assert_eq!(
        notifications[0]
            .try_get::<serde_json::Value, _>("payload")
            .unwrap()["previous_state"],
        serde_json::Value::Null
    );

    // Competing transitions at the same expected version have one winner.
    let (a, b) = tokio::join!(
        advance_intent(
            &pool,
            organization,
            first.id,
            1,
            SettlementState::Authorized
        ),
        advance_intent(&pool, organization, first.id, 1, SettlementState::Rejected)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert!(matches!(
        if a.is_err() { a } else { b },
        Err(JournalError::VersionConflict)
    ));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM settlement_outbox WHERE organization_id=$1 AND settlement_id=$2",
    )
    .bind(organization)
    .bind(first.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 3);

    // The database in CI is disposable. These cleanups are scoped to fixtures.
    sqlx::query("DELETE FROM settlement_outbox WHERE settlement_id IN ($1,$2)")
        .bind(first.id)
        .bind(other.id)
        .execute(&pool)
        .await
        .expect("outbox cleanup");
    sqlx::query("DELETE FROM settlement_transition_log WHERE settlement_id IN ($1,$2)")
        .bind(first.id)
        .bind(other.id)
        .execute(&pool)
        .await
        .expect("fixture cleanup");
    sqlx::query("DELETE FROM settlement_intents WHERE id IN ($1,$2)")
        .bind(first.id)
        .bind(other.id)
        .execute(&pool)
        .await
        .expect("fixture cleanup");
    sqlx::query("DELETE FROM corridors WHERE id=$1")
        .bind(corridor)
        .execute(&pool)
        .await
        .expect("fixture cleanup");
}
