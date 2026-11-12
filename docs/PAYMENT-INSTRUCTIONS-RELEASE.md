# Prepared instruction storage release — 2026-11-12

Status: tested in an isolated Neon branch; **not applied to production**. Both
feature flags remain false/unset. No customer data or money movement is enabled.

- Backend migration: `migrations/202611120001_customer_payment_instructions.sql`
- SQLx SHA-384: `874eb2ee548e019a9fcea2154392f33673e534d5fc6a4ebb8b29c3c6b1e1efd0b1b540df7127fa5e6e73edf178466f8b`
- Project: `late-resonance-01145687` (`stealthbridge-backend`)
- Database: `neondb`
- Parent: `br-fragrant-night-b7s83g65` (`main`)
- Prepared branch: `br-proud-wave-b7mqny4y`
- Prepared migration ID: `8a274819-007d-42b8-bb90-093301f92074`

The prepared SQL contains the exact migration text, followed by this SQLx registry
entry so later normal SQLx migration runs recognize the reviewed source checksum:

```sql
INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time)
VALUES (202611120001,'customer payment instructions',true,
 decode('874eb2ee548e019a9fcea2154392f33673e534d5fc6a4ebb8b29c3c6b1e1efd0b1b540df7127fa5e6e73edf178466f8b','hex'),0);
```

Neon branch inspection verified account-scoped primary/foreign keys, replay nonce
uniqueness, state/revision checks, ciphertext size and bounded-expiry constraints.
The source checksum marker matched. No unrelated optional vault migration is part
of this prepared release. Existing production readiness still uses its 12 core
migrations; this optional feature fails closed until released.

Applying this prepared migration to the parent and enabling
`STEALTHBRIDGE_PAYMENT_INSTRUCTIONS_ENABLED=true` in backend and frontend require
explicit approval. The migration completion operation also removes the temporary
branch. The shared BFF secret is reused, never printed or placed in client code.
No payment, mainnet, payout or confidential-token flag should be enabled.

Rollback: disable both instruction flags, retain customer records and migration
history, and revert application commits if necessary. No data deletion is required.
