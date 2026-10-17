# Authenticated Business Review Read Boundary

StealthBridge has an internal, persistent PostgreSQL business-review ledger and a strictly read-only endpoint:

`GET /v1/business/reviews/{organization}/{request_id}`

No write HTTP route for review requests, wallet login, token minting, payment or contract execution is available. The internal review writers are **not** directly callable over HTTP.

## Trust and authentication

The endpoint requires both trusted backend runtime settings:

- `STEALTHBRIDGE_AUTH_DOMAIN`: the exact reviewed app hostname, **not** a caller-supplied Host header.
- `STEALTHBRIDGE_SESSION_SECRET`: unpredictable, unique secret of at least 32 bytes; configure through your deployment secret manager, never source control.

Both settings are optional as a group; without them this endpoint returns 503. Partial or weak configuration fails backend initialization.

A valid short-lived HMAC read session is accepted in `Authorization: Bearer <session>` only after independent wallet-signature login verification via the existing Rust `org_auth` code. The server checks Testnet domain binding, session expiry, selected tenant, and active database membership on **each request**. The browser proxy intentionally does not relay this header; use a trusted backend client. Never place the session in a URL, query parameter, log, localStorage, analytics event, or repo.

**Important:** the wallet login challenge and session-issuance workflow exists as an internal Rust service, but no production HTTP session issuance is available. Do not claim an end-to-end login product until real Freighter acceptance tests and origin protections pass.

## Stored review status

A 200 response contains only `organization`, `request_id`, `review_count`, `remaining_reviewers`, `review_count_met`, `financial_execution_authorized: false`, `signatures_verified: false` and `source: tenant-review-journal`. It never includes reviewers, secrets, private witnesses or payment instructions. Responses carry `Cache-Control: no-store`.

403-style cross-tenant access is represented by authentication failure. Missing review records return 404. Missing migrations or database failure return 503, not fabricated counts.

## Deployment and schema readiness

Backend `/ready` requires all **ten** reviewed SQLx migrations. The new migration is `202610150001_business_review_requests.sql`. No application bootstrapping runs DDL and no API handler automatically upgrades Neon. Operator-approved staging migration checks must precede any separate main-branch migration. Staging completion does not imply that the current main database has been migrated.

## Before production use

Complete signed origin- and network-bound Freighter login, challenge replay tests, per-tenant rate limits across instances, managed secret rotation and session revocation, database role append-only protections, audit exports with lawful retention, cross-tenant access tests against deployed environments, and a full independent security review. Reviewer counts are **not signed approvals or transfer authority**.
