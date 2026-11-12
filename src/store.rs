//! Transactional, organization-scoped settlement journal.
//! Internal database operations only: no external payouts or on-chain writes.

use crate::settlement::{self, SettlementState};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug)]
pub enum JournalError {
    Database(sqlx::Error),
    PayloadConflict,
    NotFound,
    VersionConflict,
    InvalidTransition,
}

impl From<sqlx::Error> for JournalError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredIntent {
    pub id: Uuid,
    /// True only if this call inserted the intent and its initial journal event.
    pub created: bool,
}

/// The journal and its notification are one transaction. Notifications contain
/// state metadata only; consumers must re-read scoped authoritative state and
/// must never treat an outbox message as permission to move funds.
async fn append_transition(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    intent_id: Uuid,
    previous: Option<SettlementState>,
    next: SettlementState,
    version: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO settlement_transition_log
         (organization_id, settlement_id, previous_state, next_state, version)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(organization_id)
    .bind(intent_id)
    .bind(previous.map(SettlementState::as_str))
    .bind(next.as_str())
    .bind(version)
    .execute(&mut **tx)
    .await?;
    let payload = serde_json::json!({
        "schema_version": 1,
        "previous_state": previous.map(SettlementState::as_str),
        "next_state": next.as_str(),
        // Preserve the full PostgreSQL BIGINT range for JavaScript consumers.
        "version": version.to_string(),
        "financial_execution_authorized": false,
    });
    sqlx::query(
        "INSERT INTO settlement_outbox
         (organization_id, settlement_id, event_type, payload)
         VALUES ($1, $2, 'settlement.state_changed', $3)",
    )
    .bind(organization_id)
    .bind(intent_id)
    .bind(payload)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Register a canonical request once per organization and idempotency key.
/// The database unique constraint arbitrates races; replays never append events.
pub async fn register_intent(
    pool: &PgPool,
    organization_id: Uuid,
    corridor_id: Uuid,
    idempotency_key: &str,
    request_sha256: &str,
) -> Result<RegisteredIntent, JournalError> {
    let mut tx = pool.begin().await?;
    let id = Uuid::new_v4();
    let inserted: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO settlement_intents
         (id, organization_id, corridor_id, idempotency_key, request_sha256)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (organization_id, idempotency_key) DO NOTHING
         RETURNING id",
    )
    .bind(id)
    .bind(organization_id)
    .bind(corridor_id)
    .bind(idempotency_key)
    .bind(request_sha256)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some((id,)) = inserted {
        append_transition(
            &mut tx,
            organization_id,
            id,
            None,
            SettlementState::Draft,
            0,
        )
        .await?;
        tx.commit().await?;
        return Ok(RegisteredIntent { id, created: true });
    }

    // After the conflicting INSERT waits for the winner to commit,
    // SELECT sees the winning row and locks it before checking its payload.
    let existing = sqlx::query(
        "SELECT id, corridor_id, request_sha256 FROM settlement_intents
         WHERE organization_id = $1 AND idempotency_key = $2 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(JournalError::NotFound)?;

    let existing_id: Uuid = existing.try_get("id")?;
    let existing_corridor: Uuid = existing.try_get("corridor_id")?;
    let digest: String = existing.try_get("request_sha256")?;
    if digest != request_sha256 || existing_corridor != corridor_id {
        return Err(JournalError::PayloadConflict);
    }
    tx.commit().await?;
    Ok(RegisteredIntent {
        id: existing_id,
        created: false,
    })
}

/// Lock the scoped row, enforce expected version and valid transition,
/// then persist the state and append-only history in one DB transaction.
pub async fn advance_intent(
    pool: &PgPool,
    organization_id: Uuid,
    intent_id: Uuid,
    expected_version: i64,
    next_state: SettlementState,
) -> Result<i64, JournalError> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT state, version FROM settlement_intents
         WHERE organization_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(intent_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(JournalError::NotFound)?;

    let version: i64 = row.try_get("version")?;
    if version != expected_version {
        return Err(JournalError::VersionConflict);
    }
    let old_name: String = row.try_get("state")?;
    let old_state = SettlementState::parse(&old_name).ok_or(JournalError::InvalidTransition)?;
    settlement::transition(old_state, next_state).map_err(|_| JournalError::InvalidTransition)?;
    let new_version = version
        .checked_add(1)
        .ok_or(JournalError::VersionConflict)?;

    sqlx::query(
        "UPDATE settlement_intents SET state = $1, version = $2,
         updated_at = now() WHERE organization_id = $3 AND id = $4",
    )
    .bind(next_state.as_str())
    .bind(new_version)
    .bind(organization_id)
    .bind(intent_id)
    .execute(&mut *tx)
    .await?;

    append_transition(
        &mut tx,
        organization_id,
        intent_id,
        Some(old_state),
        next_state,
        new_version,
    )
    .await?;
    tx.commit().await?;
    Ok(new_version)
}
