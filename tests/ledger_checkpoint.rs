//! Isolated CI PostgreSQL test for a durable read-only Testnet ledger cursor.
//! Synthetic hashes/ledgers below are solely fixtures, never runtime responses.
use sqlx::PgPool;
use stealthbridge_backend::ledger::{
    last_head, record_head, CheckpointChange, LedgerError, VerifiedHead,
};
#[tokio::test]
async fn checkpoint_cannot_rewind_or_silently_replace_a_ledger_hash() {
    let database = std::env::var("DATABASE_URL").expect("isolated CI DB");
    let pool = PgPool::connect(&database)
        .await
        .expect("connect PostgreSQL");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations");
    let base = VerifiedHead {
        passphrase: "Test SDF Network ; September 2015".into(),
        ledger_sequence: 500,
        ledger_hash: "a".repeat(64),
        ledger_closed_at_unix: "1760000000".into(),
    };
    // The CI database is disposable. The singleton observer record is used
    // only by this test; no actual RPC is contacted.
    sqlx::query("DELETE FROM stellar_ledger_observer WHERE network='testnet'")
        .execute(&pool)
        .await
        .expect("clear test-only checkpoint");
    assert_eq!(
        record_head(&pool, &base).await.expect("insert"),
        CheckpointChange::Inserted
    );
    assert_eq!(
        record_head(&pool, &base).await.expect("same"),
        CheckpointChange::Unchanged
    );
    let mut older = base.clone();
    older.ledger_sequence = 499;
    assert_eq!(
        record_head(&pool, &older).await.expect("stale"),
        CheckpointChange::Stale
    );
    let mut conflict = base.clone();
    conflict.ledger_hash = "b".repeat(64);
    assert!(matches!(
        record_head(&pool, &conflict).await,
        Err(LedgerError::ConflictingHash)
    ));
    let mut next = base.clone();
    next.ledger_sequence = 501;
    next.ledger_hash = "c".repeat(64);
    assert_eq!(
        record_head(&pool, &next).await.expect("advance"),
        CheckpointChange::Advanced
    );
    let stored = last_head(&pool)
        .await
        .expect("read")
        .expect("checkpoint exists");
    assert_eq!(stored.ledger_sequence, 501);
    assert_eq!(stored.ledger_hash, "c".repeat(64));
    assert_eq!(stored.source, "stellar-rpc");
    sqlx::query("DELETE FROM stellar_ledger_observer WHERE network='testnet'")
        .execute(&pool)
        .await
        .expect("test-only cleanup");
    assert!(last_head(&pool).await.expect("empty").is_none());
}
