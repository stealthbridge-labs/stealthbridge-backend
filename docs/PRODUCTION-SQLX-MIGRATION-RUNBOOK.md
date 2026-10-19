# Production SQLx migration runbook

## Verified incident

On 19 October 2026 the public read-only `GET /v1/observer/schema` endpoint reported `migrations-pending`: **7 of 10** expected SQLx migration versions registered. The Neon primary was checked independently and likewise contained only seven successful entries. This prevents the contract event journal from being queried. A temporary Neon branch successfully created the missing relations; it did not change production or register SQLx checksums.

The pending additive migrations, kept in `migrations/`:

| Version | Purpose | Tables |
| --- | --- | --- |
| `202610130001` | Wallet login challenge digests | `organization_login_challenges` |
| `202610130002` | Public Testnet contract event metadata | `stellar_contract_event_cursors`, `stellar_contract_event_journal` |
| `202610150001` | Tenant-bound review records | `business_review_requests`, `business_review_records` |

No customer data, event rows, transfers, or wallet keys are seeded. The migration code is additive and reviewed by `scripts/validate_migrations.py`. **Do not** manually insert rows in `_sqlx_migrations` or copy/paste DDL against primary; only a reviewed SQLx migration run records the correct checksums.

## Operator release procedure

1. In GitHub **Settings → Environments** create or check `production-db`, restrict deployment branches to `main`, set required reviewers and add a `PRODUCTION_DATABASE_URL` environment secret pointing to the approved Neon primary. Do not paste the credential into logs, PRs or chat.
2. Verify the Neon project, branch and restore plan, and review the exact three SQL files.
3. Manually dispatch **Actions → Protected SQLx production migration gate** on `main` with `mode=inspect`. It runs read-only SQLx inspection and source tests.
4. **After approval**, dispatch it again with `mode=apply` and the exact confirmation `APPLY_PRODUCTION_REVIEWED_SQLX`. GitHub's protected `production-db` environment should require a reviewer. It calls `sqlx migrate run --source migrations` and then reads the registered versions.
5. Check `GET /v1/observer/schema` → `current` and `GET /ready` → database connected. A schema-current result alone is **not** proof of a running observer process.
6. Deploy one supervised `ledger-observer` process **outside Vercel Functions** with an explicit Stellar Testnet C-address allowlist, start-ledger retention review and dedicated database lease. Confirm real cursor advancement before stating that observation history is active.

The workflow is `workflow_dispatch` only. Normal Git commits never apply production DDL. StealthBridge payments, privacy verification, fee collection and wallet signing remain disabled.
