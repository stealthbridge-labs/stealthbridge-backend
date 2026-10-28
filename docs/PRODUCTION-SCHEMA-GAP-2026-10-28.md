# Production database schema reconciliation — October 28, 2026

Read-only Neon inspection of the production main branch returned seven successful SQLx migrations through version 202610100001 and nine public tables (including _sqlx_migrations). Live backend diagnostics reported the database as schema-incomplete, while Testnet RPC was connected. This is a confirmed schema gap, not a loss of PostgreSQL transport.

Five migration files in the backend repository remain absent from production SQLx history:
- 202610130001_login_challenges.sql
- 202610130002_contract_event_journal.sql
- 202610150001_business_review_requests.sql
- 202610210001_customer_profiles.sql
- 202610270001_organization_invitations.sql

The invitation, account-profile and onboarding capabilities must not be presented as operational until migrations and associated access controls are validated.

## Safe release procedure

1. Review the five SQL migrations, ordering and checksums against production history and application code.
2. Confirm retention/backup and capture a pre-change schema report. Use an isolated staging/validation branch with a fresh copy of the production schema; apply missing migrations in SQLx order and execute the full DB integration suite.
3. Review transaction locks, RLS/tenant isolation, unique indexes, repeat application behavior and rollback plan.
4. Only with an approved production change window use the existing dispatch-only migration gate in scripts/ and .github workflows. Do not invoke implicit server startup migrations or paste database credentials into CI logs.
5. Verify all twelve SQLx migrations have success=true, verify all core relations, run GET /v1/diagnostics and GET /ready, then run signed customer onboarding and invitation acceptance tests against the expected deployment and isolated accounts. Do not automatically enable financial execution or privacy claims.

No SQL changes were applied to the Neon production database as part of this source milestone.
