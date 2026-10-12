//! Dedicated, session-scoped PostgreSQL advisory lease for the read-only
//! Stellar Testnet ledger observer. No tenant data or transaction writes.
use sqlx::postgres::PgConnection;

const LEDGER_OBSERVER_LEASE: i64 = 0x5354_425f_4c45_4447;

/// A second observer must not poll concurrently with the session that owns
/// this advisory lock. Session disconnect/crash releases the lock automatically.
pub async fn try_acquire(conn: &mut PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
        .bind(LEDGER_OBSERVER_LEASE)
        .fetch_one(conn)
        .await
}

/// Never mark a worker as active if its dedicated lease connection is lost.
/// Heartbeat checks the same PostgreSQL backend PID and lock ownership.
pub async fn still_held(conn: &mut PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' \
         AND pid = pg_backend_pid() AND granted AND objsubid = 1 \
         AND classid = (($1::bigint >> 32) & 4294967295)::oid \
         AND objid = ($1::bigint & 4294967295)::oid)"
    )
    .bind(LEDGER_OBSERVER_LEASE)
    .fetch_one(conn)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;

    #[tokio::test]
    async fn lease_rejects_parallel_worker_and_survives_restart() {
        let url = std::env::var("DATABASE_URL").expect("CI Postgres DATABASE_URL");
        let mut first = PgConnection::connect(&url).await.expect("worker 1 connection");
        let mut second = PgConnection::connect(&url).await.expect("worker 2 connection");
        assert!(try_acquire(&mut first).await.expect("first lease"));
        assert!(still_held(&mut first).await.expect("first heartbeat"));
        assert!(!try_acquire(&mut second).await.expect("reject parallel worker"));
        assert!(!still_held(&mut second).await.expect("second not lease holder"));
        first.close().await.expect("disconnect first worker");
        assert!(try_acquire(&mut second).await.expect("restart lease"));
        assert!(still_held(&mut second).await.expect("restart heartbeat"));
        second.close().await.expect("disconnect restarted worker");
    }
}
