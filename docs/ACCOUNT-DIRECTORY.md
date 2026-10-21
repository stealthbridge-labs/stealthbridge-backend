# Private customer organization directory — Stellar Testnet

This is the first account-aware product integration beyond wallet sign-in. It exposes **actual**, active, non-revoked organizational memberships that already exist in Neon's `organizations` and `organization_members` tables. It never creates demo organizations, grants roles, assumes KYC approval, or allows settlement. The seven existing primary schema migrations are sufficient for this read-only feature.

## Trust boundary

Browser → Next.js same-origin `GET /api/account/directory` → cryptographically validated *HttpOnly* StealthBridge wallet session → server-to-server signed request → Rust `GET /v1/account/directory` → PostgreSQL memberships filtered by **the validated account**.

The browser never receives the bridge secret, server-side attestation signature or unrestricted database URL. A caller cannot supply a different account in a query string or HTTP body. Rust accepts these exact request headers only:

- `x-stealthbridge-account`: checksum-valid Stellar G account
- `x-stealthbridge-issued-at`: short decimal Unix timestamp
- `x-stealthbridge-signature`: lowercase hex HMAC-SHA256 of the precise message `stealthbridge-account-directory-v1\nGET\n/v1/account/directory\n<account>\n<timestamp>\n`

The backend rejects missing/weak secrets, invalid signatures, tampering, foreign addresses, timestamps older than 30 seconds, or future timestamps more than 5 seconds ahead. It only exposes the first 25 ACTIVE memberships (with `has_more`) and excludes revoked or suspended membership/organizations at the SQL boundary. Secrets must be distinct across Vercel production and preview and configured as `STEALTHBRIDGE_ACCOUNT_BRIDGE_SECRET` in both projects. The Rust route fails with 503 until configured and with 401 on invalid attestation, without echoing identities.

The response contains only schema version, network, authenticated account address, publicly named organization and role records, a pagination indicator, and `false` financial-execution flags. There is no payment history, identity verification, transaction submission, team invitation, or administrative session issuance. **Possession of a wallet signing key is not evidence of business authorization**; any future write/approval needs independently reviewed organization authentication, role checks and a strongly protected, replay-resistant transaction-specific signature.

## Operational release boundary

- The directory uses tables installed by `202610080004` and requires no production schema changes.
- Neon's primary still lacks `202610130001`, `202610130002` and `202610150001`. Release those only through the existing protected SQLx migration gate in `docs/PRODUCTION-SQLX-MIGRATION-RUNBOOK.md`, with reviewer approval, not a Vercel request or ad-hoc SQL.
- Return an honest empty membership list if none exists. A database error returns 503 and must **not** be mapped to an empty list.
- A read-only directory doesn't onboard an organization or persist a user profile; those are subsequent independently reviewed features.
