# Pending business application lifecycle: corrections and withdrawal

These are **private account-management** operations, never public payment APIs. Existing live Neon tables `organizations` and `organization_members` are used, with **no new migration, seeded data, or enablement of settlement/fee collection**.

## Workflows

- `GET /v1/account/business-onboarding`: read the signed-in account's real pending owner applications.
- `POST /v1/account/business-onboarding`: create a new pending application (existing behavior, maximum three).
- `PATCH /v1/account/business-onboarding`: `{organization_id,expected_display_name,display_name}`; compares the existing name under a database row lock and changes **only** a pending application owned by the authenticated account, with exactly one member. Stale edits return 409.
- `DELETE /v1/account/business-onboarding`: `{organization_id,confirm_display_name}`; user-confirmed irreversible withdrawal of an **unused, pending, single-owner** application only. Foreign-key protected review/provider records or any settlement-intent activity block removal. Related rows are removed atomically in one transaction; repeat withdrawal returns 404. This is not deleting an active organization.

All state-changing requests require the Next.js session and same-origin check before they reach the Rust backend. The Next.js backend bridge signs exact method/path/account/timestamp/request UUID/SHA-256 body using a server-only HMAC key; signatures expire in 30 seconds. The Rust server validates the Stellar G-address checksum, strict JSON fields, short body, requested UUID, and signature. Client-provided role or approval flags are rejected.

An advisory lock serializes create/amend/withdraw by signed account and PostgreSQL row locks protect the organization and member. No browser may upgrade tenant status, approve a business, invite members, transfer funds, or impersonate the operator.

## Constraints

Withdrawal removes only an unused pending registration with no known related financial or review records. It does **not** provide a legal records-retention solution for later regulated customer onboarding. Once compliance evidence, onboarding audit trails, or invitation records are introduced, withdrawal/retention policy must be reviewed and updated; PostgreSQL RESTRICT foreign keys prevent casual loss of linked records.

Idempotency: withdrawals are at-most-once by organization existence; stale amendment checks prevent ordinary repeated writes. Historical **ABA renames** are not fully prevented until a persistent amendment receipt ledger is introduced by a separately approved migration. Neither behavior is financial write authorization.

## Validation

Rust unit tests check strict input parsing, method/digest-bound HMAC, stale names and active/foreign-owner denial. Isolated CI PostgreSQL integration tests check correction, repeated submission, other-member blocking, active-state protection, and permitted withdrawal. Browser/SDK tests verify the exact payloads and fail-closed response schemas. Public OpenAPI contract continues to document **no executable financial writes**.
