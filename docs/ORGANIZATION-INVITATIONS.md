# Consent-based organization viewer invitations

## Release status
New SQLx migration `202610270001_organization_invitations.sql` is **source code only** until the protected staging/production release procedure approves and applies it. Neither the backend nor frontend should set `STEALTHBRIDGE_TEAM_INVITES_ENABLED=true` until the full migration chain, secrets, real Freighter acceptance test and authorized operational review have passed. The default is **off**; missing schema with the gate on fails closed (503).

The workflow does not activate pending organizations, verify legal entities, authorize settlements or issue custody/contract permissions. Existing platform and fiat payout execution remain disabled.

## Customer flow
An authenticated owner/admin of an internally active organization can invite a specific classic Stellar G-address with the **only currently supported role, viewer**. No emails, names, wallet secrets, signing requests or transfer data are collected. An invitation expires seven days after creation; at most ten open invitations can exist per organization. The invited account must sign into its own session to see and accept. Sending an invitation never creates membership. A viewer can read permitted organizational records only; the existing role-policy module must be consulted before exposing more privileged data.

The owner/admin can revoke a pending invitation, but **cannot use this endpoint to revoke an already accepted member**. A separate, audited member-revocation flow is required. Revoked inviter access, expired invitations, suspended/pending organizations, duplicate invites, impersonated recipients and pre-existing/revoked members all fail closed.

## Authentication and concurrency
The Next.js BFF validates the HttpOnly wallet session and same-origin POST. It signs this canonical server-to-server message using the private `STEALTHBRIDGE_ACCOUNT_BRIDGE_SECRET`:

```
stealthbridge-team-invites-v1
METHOD
/v1/account/team-invites
verified-G-address
Unix-seconds
request-UUID-for-POST-or-empty
SHA256-of-exact-POST-body-or-empty

```

Rust checks the exact method/path/account/timestamp/body digest/nonce with constant-time HMAC and 30-second expiry. Request IDs are used as invitation primary keys on creation. Account G-address checksum and exact JSON variant fields are checked. No untrusted asserted caller identity or role passes through.

PostgreSQL checks the active organization and inviter membership under row locks. An accepted invite locks the organization and invite in a consistent order, re-checks the inviter's current owner/admin role, then inserts viewer membership and marks acceptance atomically. Acceptance and revocation are one-time transactions; duplicate membership or revocation history blocks restoration. The invitation table retains created, accepted and revoked timestamps, with a partial unique index to prevent concurrent open duplicates. Expired records are marked revoked only on reissue; the API still classifies them as expired using their timestamps.

## Limits and rollout
The private GET returns up to twenty received and twenty sent records; `received_more`/`sent_more` disclose truncation. It does not expose raw tokens or payment data. Outgoing records are visible only to active organization owners/admins; incoming offers are visible only to the named signer, subject to the inviter still being an active owner/admin.

Release sequence: test migrations and HMAC/role/replay cases in isolated CI PostgreSQL, verify staging on a protected Neon branch, independently approve production migration with SQLx checksum checks, enable the paired **server-side** release flag in both apps, deploy, and complete real two-account Freighter acceptance. Do not use synthetic rows in production. Rollback is disabling the feature flag; database rollback is not automatic and must preserve invitation audit records.
