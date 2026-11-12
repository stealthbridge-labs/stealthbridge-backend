# StealthBridge engineering audit — 2026-11-12

Scope: four main-branch repositories and read-only checks of the connected Vercel
projects/public service. This is an engineering review, not an independent
security audit. Desktop Commander reported both registered devices offline.
No production secrets, customer rows, schema migrations or signing keys were used.

## Evidence and capability boundary

| System | Evidence | Actual capability / gap |
| --- | --- | --- |
| Contracts | `stealthbridge-contracts/Cargo.toml` workspace members; `contracts/{corridor-registry,policy-registry,governance-gate}/src/lib.rs` | Three governance contracts are compiled. The fee vault directory is outside the workspace; settlement adapter is documentation. Governance flags do not implement confidential payment execution. |
| Privacy | Backend `src/privacy_commitment.rs`; SDK `src/private-review-commitment.ts`; frontend `src/lib/private-draft-vault.ts` | Salted review fingerprints and client-encrypted drafts provide specific local integrity/storage protections. Neither proves hidden amounts, unlinkability, ZK verification or confidential settlement. |
| Backend | `src/store.rs`, `src/settlement.rs`, `migrations/202610080002_settlement_journal.sql`, `migrations/202610080006_settlement_outbox_and_amount.sql` | Tenant-scoped internal state/history existed, but transitions never populated the already-created outbox. No public settlement command is enabled. |
| Identity | Backend `src/org_auth.rs`, `src/account_directory.rs`; frontend `src/lib/wallet-auth.ts`, account BFF routes | Wallet sessions and account-bound business views exist. Backend organizational scoped-read sessions are a separate identity boundary; no assumption of interchangeable sessions is justified. |
| SDK | `src/client.ts`, `tests/package.test.mjs` | Read-only client and installable tarball consumer tests exist. Transaction lookup previously accepted a different valid transaction hash. Package is private, not a published npm release. |
| Frontend | `src/components/customer-payment-workspace.tsx`, `src/components/transaction-explorer.tsx` | Payment preparation, encrypted drafts and business management exist. Transfers remain disabled. An outstanding transaction lookup could restore obsolete results after input changed. |
| Upgrades | Both registry `accept_admin` implementations; backend `src/protocol_upgrade.rs`; SDK/frontend `upgrade-review.ts` | Administrator handover retained an outgoing administrator's mature proposal. Offline review also classified expired, unpaused proposals as merely waiting. |
| Dependencies | Frontend lockfile; SDK `tests/fixtures/next-app` lockfile | Next.js frontend 16.4.3 and consumer fixture 16.4.0 required security patches. Updated to 16.4.6; remaining frontend audit findings are in the development lint dependency chain. |

Public checks before changes: customer homepage HTTP 200; backend `/health`
HTTP 200; `/ready` HTTP 200 with database/RPC connected and payments disabled;
`/v1/capabilities` reported all four financial/privacy capability flags false.
Vercel's latest frontend/backend production records were READY at the inspected
base commits. This is a point-in-time service check, not continuous monitoring
or evidence of confidential settlement.

## First implemented foundation milestone

1. Commit state, append-only history and sanitized outbox notification atomically.
   Exercise real PostgreSQL concurrent retries, competing transitions, and
   injected outbox failure rollback. Preserve decimal BIGINT versions.
2. Add an SDK notification parser and test actual PostgreSQL-emitted payloads
   against the separately built SDK. Reject impossible transitions, extra private
   fields and authority claims. No dispatcher or new execution API is exposed.
3. Bind SDK transaction responses to requested hashes; reject malformed Rust
   inclusion metadata; cancel frontend lookups on edit and unmount.
4. Cancel inherited upgrades atomically on accepted administrator handover;
   preserve pause, ABI and storage layout. Verify cancellation event, failed
   unauthorized acceptance, and fresh successor timelock. This changes source
   only; historical on-chain bytecode is untouched.
5. Commit the tested backend dependency lockfile and enforce locked CI resolution.
6. Classify expired upgrade proposals consistently across Rust, SDK and frontend,
   regardless of pause. Upgrade frontend and isolated consumer Next.js patches.

## Execution order after this milestone

1. Define one durable, authenticated **non-executing payment instruction** domain
   joining customer drafts, business authorization and settlement journal. Bind
   canonical instruction identity, expiry and recipient/asset/corridor changes;
   never accept an arbitrary browser digest as authorization.
2. Integrate that domain through a versioned backend/SDK/BFF contract and personal
   and business workspaces. Add real empty/error/history states and tenant access
   tests. Keep quotable amounts/rates unavailable without a legitimate provider.
3. Implement a settlement adapter only after choosing a technically demonstrated
   privacy construction and establishing trusted quote, authorization and ledger
   evidence. Public Stellar inclusion alone cannot certify instruction semantics
   or off-chain payout. Add a durable observer/dispatcher with replay recovery.
4. Redesign the customer website/dashboard around the verified domain, with
   responsive visual review and accessibility checks. Do not expose operator
   tools or deployer addresses as the customer journey.
5. Independently review privacy, protocol economics, smart-account recovery,
   release/rollback and provider boundaries before any financial enablement.

## Trust and release limits

The backend journal APIs remain internal trusted-code primitives: caller-supplied
organization IDs, outbox metadata and state-machine validity are not signatures,
policy decisions or verified payment evidence. A future worker must authenticate
scope and enforce those missing prerequisites; replaying an event must never move
funds. No public mutation route, customer payment, fiat payout or mainnet action
was enabled. No live Testnet transaction or contract upgrade was submitted.

Local browser execution is blocked by the workspace's Chromium socket policy;
new desktop/mobile regression cases are included in the existing preview CI
suite. Local TypeScript checks and builds cannot substitute for those browser
results. Frontend lint has existing warnings. Production deployability and CI
status must be checked on the new commit SHAs, separately from local results.
