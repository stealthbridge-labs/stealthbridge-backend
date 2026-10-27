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

## Added customer-profile migration (21 October 2026)

The source tree now additionally contains
`202610210001_customer_profiles.sql`, creating optional
`customer_profiles` and replay-guarding `customer_profile_update_receipts`.
The readiness manifest expects eleven migration versions once this source is
merged. It does **not** seed data, create wallet accounts, authorize payments,
or bypass the three previously pending migrations.

**Never execute it directly against primary Neon.** The approved
`production-db` SQLx workflow must run the three earlier migrations and this
new migration in exact sorted order after inspecting checksums, backup
procedures, and branch identity. An apparent 503 from the customer profile
service before approval is the correct failure mode; do not conceal that
state with browser-local fake "saved" profiles.

For a scoped Testnet user, the profile stores only a chosen display name,
a declared interest in personal/business/both, and an optional self-reported
two-letter country code. No KYC/legal identity, email, bank instruction,
payout provider, membership, cryptographic key or balance is retained.
An authenticated Next.js session signs requests through a private HMAC
bridge and Rust validates path, HTTP method, 30-second freshness, exact
SHA-256 body digest and a unique UUID. PostgreSQL commits one-use receipts
and the profile change in a single transaction; replay cannot rewrite a
profile. Sensitive production and preview secrets are already separate.
Approval and retention policies for update receipts remain required before
broad customer onboarding.

## Added consent-based team invitations (27 October 2026)

New source `202610270001_organization_invitations.sql` is a fifth pending
migration beyond the seven previously applied to the production primary.
The readiness manifest now expects **12 total** migration versions. Existing
historical sections above describe the older requirements, not a claim that
those migrations have been applied.

This is an additive invitation-audit table with single-use viewer-only
acceptance, expiry, revocation, and organization foreign-key restrictions.
Its presence **does not activate invitations**: `STEALTHBRIDGE_TEAM_INVITES_ENABLED`
must remain unset in both Vercel projects until approved SQLx migration,
staging verification and supervised real Freighter two-account acceptance.

Review SQLx checksums and confirm protected staging and production approval
using the workflow above; do not execute DDL directly or enable invite
controls while production remains on seven migrations. A safe rollout
includes a tested disable/recovery plan and retains invitation audit rows.
