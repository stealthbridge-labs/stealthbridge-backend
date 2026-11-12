# Settlement Intent Journal — Internal Domain Infrastructure

The SQL migration and Rust store are internal components only. There is **no authenticated command endpoint, wallet signature verification, quote signer, private-payment proof or provider disbursement**. The existing external POST remains HTTP 501.

## Tables and invariants

- settlement_intents: per-organization intent with public corridor reference, immutable canonical request SHA-256, scoped idempotency key, explicit state and revision number.
- settlement_transition_log: append-only record of initial state and each successful transition. Recommended DB principal must not possess UPDATE/DELETE permissions on this table.
- Unique (organization_id, idempotency_key) prevents independent same-key intents; a different payload or corridor returns conflict.
- register_intent does an INSERT ... ON CONFLICT DO NOTHING, then locks the resulting row with FOR UPDATE and compares request digest. Only new rows receive the initial log event.
- advance_intent acquires the row lock, validates expected_version and the pure state machine, updates one state, appends its history and outbox notification, and commits atomically. Registration also emits its initial notification in the same transaction.
- All database lookups and mutations here scope by organization_id. No generic admin bypass function exists.
- Amounts, recipients, provider references and real payout statuses are not stored by this skeleton.

## Important boundaries

- Only a trusted, authenticated service workflow may invoke these internal library functions after tenant and policy checks; do not expose them directly as HTTP handlers.
- Request hashes must be computed from an unambiguous canonical payload representation with domain separation, not from loosely ordered JSON fields. That full canonicalization implementation is future work.
- A client-supplied organization_id alone is **not** authorization.
- The SQL migration must be applied by an approved deployment process; the app will not auto-apply schema changes.
- The current journal is not yet a financial double-entry ledger or cryptographic proof registry.
- Real PostgreSQL tests verify concurrent idempotency, competing transitions, and rollback of both registration and transitions when notification insertion fails. This does not replace future signed authorization or process-crash testing.
- Never equate chain_finalized with payout_completed.

## Implementation contract

See src/store.rs and src/settlement.rs. Each step must validate its caller's role, immutable quote/payload digest, wallet authorization, privacy proof and provider policy before allowing further state transitions in a real payment system.

## Transactional notification format

Each newly committed history row emits one `settlement.state_changed` outbox row.
Replayed registration, payload conflicts, stale versions and invalid transitions
emit nothing. Notification insertion failure rolls back the intent and history.
The payload contains exactly `schema_version: 1`, `previous_state` (null only
for initial registration), `next_state`, decimal-string `version`, and
`financial_execution_authorized: false`. It contains no recipient, amount,
request digest, wallet signature or ciphertext. Tenant and settlement IDs remain
in the existing scoped outbox columns. Version strings preserve BIGINT precision.

The SDK's `parseSettlementNotification` validates this actual format. To verify
real PostgreSQL output with a locally built SDK in an isolated test database:

```bash
# Build the sibling SDK first with npm ci --ignore-scripts && npm run build.
# DATABASE_URL must point to a disposable test database, never the customer DB.
STEALTHBRIDGE_SDK_ENTRY=/absolute/path/stealthbridge-sdk/dist/index.js \
  cargo test --test journal_integration -- --nocapture
```

The dedicated compatibility CI step requires this path. Ordinary backend tests
also validate the database behavior independently. A dispatcher is not enabled:
future consumers must authenticate tenant scope, deduplicate deliveries, and
re-read authoritative state. Notifications never authorize funds movement. No
schema migration or production database modification is needed for this fix.
