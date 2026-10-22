# Self-service business registration — pending, not verified

This vertical slice uses the **already-deployed** `organizations` and
`organization_members` tables created by SQLx migration
`202610080004_org_roles.sql`. No new migration or fake company/customer
row is required. The primary Neon environment currently has those
tables even though the later profile and observer migration versions are
still awaiting protected approval.

A customer first proves control of their Testnet G-address using
Freighter's SEP-53 sign-in. `POST /api/account/business-onboarding` checks
the signed session, same-origin HTTP POST and strictly one display name.
It generates an opaque UUID and signs method/path/account/timestamp/UUID/
SHA-256 body for the Rust service with the private shared
`STEALTHBRIDGE_ACCOUNT_BRIDGE_SECRET`. The secret never reaches the
browser. Rust verifies account checksum, HMAC, 30-second time window,
nonce and exact body.

Within a single PostgreSQL transaction, Rust obtains a per-account
advisory lock, checks the count of pending applications, rejects more
than three, and inserts `organizations(status='pending')` and a member
row `role='owner'`. The signed UUID is also the DB primary key and
repeated writes fail with 409. All write errors must fail closed.
The customer can read their real pending applications with a similarly
signed `GET`. Suspended/revoked records are never represented as pending.

**Pending-owner role does not grant rights to transfer money.** Existing
`authz::authorize_member` requires an `active` tenant, so an on-boarded
pending owner has no financial authority; operator-controlled compliance,
account recovery, actual organization verification and controlled
activation are future independent release gates. API responses have
literal false flags for `organization_verified`,
`payment_execution_enabled` and
`organization_payment_authorized`.

Risks and next stage: a user can create at most three pending businesses
per signing key, but distinct Stellar keys are cheap and can still
produce abuse. Add verified human/business enrollment, proof-of-consent,
rate limits at a trusted edge, organization-unique identifiers, manual
triage and authenticated administrator onboarding controls before
scaling registration. Never offer self-service promotion to `active`
or issue invites granting financial permissions under this endpoint.
