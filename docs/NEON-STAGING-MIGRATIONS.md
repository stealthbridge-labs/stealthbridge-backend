# Neon staging SQLx migration acceptance — October 2026

**Operational boundary:** This procedure prepares a **non-production** Neon branch. It does not execute or authorize changes on the project's default/production database. Never connect GitHub's staging migration secret to the production connection string, even temporarily.

## Verified source and database checkpoint

The backend service currently requires nine migrations and the corresponding relations, including `organization_login_challenges`, `stellar_contract_event_cursors` and `stellar_contract_event_journal`. A read-only query on the existing default Neon branch showed **seven successful SQLx migration records** as of 2026-10-13, explaining why the new backend could correctly return `/ready` = degraded.

The additive SQL in `202610130001_login_challenges.sql` and `202610130002_contract_event_journal.sql` was replayed successfully on an isolated Neon copy named `staging-nine-migrations-validation-20261013` (branch `br-rough-queen-b7ny6h64`). Queries confirmed the new three relations exist with the expected column counts. **This only validates PostgreSQL DDL syntax and relationship creation.** The branch still has seven `_sqlx_migrations` bookkeeping rows because the SQL was applied directly for the syntax check, not using the SQLx CLI. Do not point Vercel preview/production at this branch and claim migration readiness until the exact CLI has applied and recorded the missing migration versions.

## Two-person operator-controlled staging procedure

1. Verify that the intended Neon project and staging branch are separate from the production/default branch. Create a point-in-time branch snapshot as needed. Use a least-privileged migration role with PostgreSQL DDL rights **only** in the staging branch, not Vercel's request-scoped API role. Obtain a sanitized `SELECT current_database(), current_schema(), inet_server_addr(), current_user` target identity and review it with a second operator. Do not store connection strings in PRs or Actions logs.
2. In GitHub repository Settings → Environments → `staging`, configure required reviewers. Set `STAGING_DATABASE_URL` only for the staging branch. Do **not** repurpose the production `DATABASE_URL` or Vercel Neon integration's shared default branch.
3. From default branch `main`, manually dispatch `Protected SQLx staging migration gate` with mode **inspect**. It verifies file/readiness parity and prints pending migration versions, not database secrets. Check exactly the seven installed plus two pending versions.
4. Get a second operator's explicit approval for **apply**, then dispatch with mode `apply` and confirmation `APPLY_STAGING_ONLY`. The protected Action installs pinned `sqlx-cli 0.8.6` and runs the source-only audited migrations using the protected staging secret. Do not bypass a dirty migration, delete `_sqlx_migrations`, truncate a table, run rollback DDL or set `DATABASE_URL` in a public shell.
5. Verify **all nine successful SQLx migration versions**, the required three tables and actual backend `GET /ready` through a protected staging deployment. The Vercel preview database environment must point to this **separate staged Neon branch** if it is used for testing; do not point preview at production just to make the smoke gate green.
6. Only after those checks, run `Protected Testnet staging smoke` on the backend and `Protected Vercel marketing and Testnet preview release gate` on the frontend with operator-approved precise HTTPS deployment URLs. Attach successful run links, deployed source SHA, Testnet ledger hash and fresh ledger time to backend #9 and frontend #13.
7. To promote a schema change to production, obtain an **independent production change approval**, execute fresh backups/restore drill and revalidate under the production team's controlled migration pipeline. This staging workflow **cannot** be used for production. No CLI success attests cryptographic confidentiality, bank payouts or merchant eligibility.

## Failure policy

Any CLI checksum mismatch, dirty migration, missing reviewer, mismatched branch, failed Testnet passphrase check, Vercel SSO/protection redirect, unexpected response/POST, expired ledger or regression test failure means **stop**, preserve logs and keep the relevant issue open. Never insert synthetic customer, corridor or settlement data to make readiness pass.

The pull-request CI checks migration-to-readiness source parity and rejects new unreviewed destructive or permission-changing SQL in the two pending migration files. The manual workflow additionally reruns the static safety checks before invoking the SQLx CLI. It does **not** provision a deployment and must not use a wallet, signing or payout secret.
