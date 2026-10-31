# Production SQLx release handoff — 31 October 2026

## Evidence: isolated branch, not production

- Neon project late-resonance-01145687; database neondb; primary br-fragrant-night-b7s83g65 (main).
- Primary SQLx versions: 7 successful of 12 expected.
- Clone: br-flat-lake-b7ujsj0b (stealthbridge-sqlx-preflight-20261031), created directly from primary.
- SQLx CLI 0.8.6 successfully applied the five pending repository migrations to that isolated branch. All 12 versions registered with correct checksums through SQLx.
- All eight new relations exist, including account challenge, contract event journal, business reviewer, customer profile and team invitation tables.
- Repository source validator and its six tests passed. Production remained unchanged.
- Production live GET /v1/observer/schema still reports migrations-pending and GET /ready returns HTTP 503.

## Protected production GitHub workflow

The GitHub environment production-db now exists with a custom branch policy, but its public rules on 31 October showed no required reviewer. Before any production DDL, an operator must:

1. Confirm the custom branch restriction explicitly permits ONLY main.
2. Configure a required production-database reviewer if supported.
3. Confirm the protected environment secret PRODUCTION_DATABASE_URL points to the DIRECT Neon main connection, not pooled and not the validation branch.
4. Confirm the Neon restore/snapshot window and recovery procedure.
5. Manually dispatch GitHub Actions -> Protected SQLx production migration gate -> mode=inspect on main. Expect seven installed and five pending; stop on checksum mismatch.
6. Following approval, dispatch mode=apply with confirmation APPLY_PRODUCTION_REVIEWED_SQLX. The existing workflow runs sqlx migrate run --source migrations and checks versions. Do not manually insert migration receipts.
7. Verify SQLx 12/12 on primary, /v1/observer/schema=current, and /ready=200. If still degraded, inspect runtime and database configuration; do not mask the failure.

This document does not itself approve production database writes.

## Preview isolation and safety

The backend Vercel project prj_pRmNqa5zPfP9EQCMRieGf0H4Yi3n has POSTGRES_URL, DATABASE_URL and DATABASE_URL_UNPOOLED records targeting both Preview and Production. Preview must NOT be assumed isolated. Do not enable preview customer onboarding before separate preview branch targeting is verified. Do not rewrite production secrets automatically.

A successful SQL migration does not enable settlement, confidential payments, Testnet smart account signing, fiat payouts, fee collection or team-invitation feature flags. All remain separately gated.

Source: migrations/*.sql, docs/PRODUCTION-SQLX-MIGRATION-RUNBOOK.md and .github/workflows/production-sqlx-migrations.yml.
