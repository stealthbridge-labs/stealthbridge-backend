# Organization team access and status

The `GET /v1/account/organizations/{id}/team` endpoint provides **private, read-only membership metadata**, not regulated-business verification, payment authorization, or a team-invitation endpoint.

## Verified trust boundaries

1. A customer signs in to the Next.js workspace using their Stellar Testnet account. The server validates its HttpOnly signed session.
2. The same-origin Next.js BFF rejects unknown or repeated query parameters, validates the organization UUID and optional G-address cursor, and signs `stealthbridge-organization-team-v1\nGET\n<canonical path + cursor>\n<verified account>\n<Unix timestamp>\n` using the server-only `STEALTHBRIDGE_ACCOUNT_BRIDGE_SECRET`.
3. Rust verifies the HMAC in constant time and checks Stellar StrKey checksum, tenant ID binding, clock freshness (30 seconds), and the exact cursor. An unconfigured secret fails closed.
4. PostgreSQL first requires a non-revoked membership. A **pending** organization grants only its owner a view of their own row. For **active** organizations, only recorded owners and admins can read a member directory. Viewers, operators, approvers, outsiders, and suspended organizations cannot list members.
5. Keyset pagination is bounded to 25 member records per page. Rows are sorted by subject, validated as Stellar G-addresses, and filtered to omit revoked identities. No personal email, financial quote, signing secret, bank details or settlement activity is returned.
6. The response explicitly asserts `business_verified:false`, `invitation_issuance_enabled:false`, `payment_execution_enabled:false` and `organization_payment_authorized:false` regardless of tenant status.

**Important:** An internally `active` tenant is *not* evidence of legal or regulatory business approval. Membership visibility is not equivalent to permission to initiate or approve payments. An operator-reviewed verification case, validated legal identity, invitation flow, and secure member management are independent milestones.

## Operational policy

This endpoint uses the existing `202610080004_org_roles.sql` schema and requires no production DDL changes. It is safe to deploy without applying still-protected SQLx migrations. No users, organizations, payments, or migrations are seeded.

Tests: Rust HMAC tampering/tenant/cursor/expiry cases, and CI PostgreSQL tests for pending-owner isolation, active-owner directory access, viewer denial, revocation and suspension. The frontend/SDK strictly verify all returned fields and reject forged authority or incorrectly paginated records.

Known limit: member addresses are pseudonymous public identifiers, not real human identities, and HMAC-secured BFF calls remain bound to the customer's existing wallet session. Add broader KYC/compliance, invite acceptance, key recovery and operator approval through separately reviewed workflows—never activate those through this reader.
