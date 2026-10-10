# StealthBridge Backend — Settlement Platform Roadmap

> **Engineering status: active, Testnet-first development.** This is a living implementation roadmap, not a feature announcement. No real funds, fabricated corridors, invented prices, alleged issuer partnerships or unsupported privacy guarantees. Work is complete only when code, tests, interface documentation and verifiable operational evidence exist.

**Cross-repository contract:** [Frontend](https://github.com/stealthbridge-labs/stealthbridge-frontend/blob/main/ROADMAP.md) · [Backend](https://github.com/stealthbridge-labs/stealthbridge-backend/blob/main/ROADMAP.md) · [Contracts](https://github.com/stealthbridge-labs/stealthbridge-contracts/blob/main/ROADMAP.md) · [SDK](https://github.com/stealthbridge-labs/stealthbridge-sdk/blob/main/ROADMAP.md)

## October 2026 implementation checkpoint and next delivery slices

See [architecture and delivery](docs/ARCHITECTURE-AND-DELIVERY.md) for a full Rust/Axum ↔ Neon ↔ Stellar ↔ SDK/frontend boundary map.

**Verified code/CI baseline:** Stellar Testnet RPC reader and freshness-aware `/ready`; managed PostgreSQL migrations; disabled candidate corridor onboarding and enabled-only reads; bounded public transaction observation; internal tenant-scoped journal, role helpers and webhook primitives; source-only three-contract ABI and `not-deployed` manifest. Remote PostgreSQL requires explicit TLS. These are not a live financial service.

**Priority sequence (with evidence gates):**

| Order | Owner deliverable | Evidence required |
| --- | --- | --- |
| B1 | Deployment runtime acceptance and operational Postgres posture | Actual fresh ledger and `SELECT 1` over HTTPS `/ready`, schema verification, monitoring, restore plan |
| B2 | Continuous dedicated ledger observer / recovery | Checkpoint monotonicity, stale RPC, failover, worker lifecycle and duplicate handling |
| B3 | Signed wallet challenge and tenant authorization | Nonce replay, origin/network binding, role revocation and cross-tenant negative tests |
| B4 | Attested Testnet governance read adapter | Real C-address/WASM/admin/dependency attestation, contract protocol compatibility |
| B5 | Real approved quote + settlement orchestration | Operator-verified partner sandbox, distinct approval, idempotency, payout callback signature, reconciliation and failure drills |
| B6 | Approved value-moving Testnet rail | Independent privacy/security/compliance verification; narrow rollout and rollback before any Mainnet consideration |

**No shortcuts:** a database row, `200 /ready`, wallet G-address or `public_flags_allow=true` is **not** a payment authorization. The public settlement POST must stay disabled until there is actual independently verified cryptographic signing and policy enforcement.

## Platform mission

Implement a reliable, multi-tenant Rust/Axum orchestration layer connecting verified Stellar privacy primitives with appropriately licensed liquidity and fiat partners. The backend is **not** a ZK wallet or a substitute for financial regulation. It owns durable workflow state, authenticated policy decisions, ledger observations, provider adapters and settlement reconciliation. Money movement cannot be enabled merely by exposing a submit API.

## Current baseline (code, not production claims)

- Live Stellar Testnet RPC verification and ledger-head endpoint; PostgreSQL-backed, unseeded corridor catalog; truthfully disabled fund-moving routes.
- Transaction observation endpoint that whitelists inclusion/status and avoids raw XDR/events.
- Pure settlement lifecycle state machine and internal organization-scoped PostgreSQL intent journal with stable idempotency/payload validation, versioned transitions and append-only history.
- CI runs Rust tests and Clippy; live database migrations and external provider operations require operator approval.

## Domain modeling and financial correctness

Define organization, tenant, user, policy, asset, issuer, corridor, eligibility, quote, quote revision, settlement intent, ledger attempt, payout attempt, reconciliation item, fee item, balance/liability, audit evidence and recovery case. Every ID and reference is tenant-scoped; preserve a canonical on-chain vs off-chain state taxonomy. Persist minor units as checked integer or exact decimal with explicit asset scale; never use floating point for money. Record fees, slippage tolerances, minimum received, quote expiration, asset identities, network passphrase and contract version in accepted intents. Add migrations with rollback guidance and immutability guarantees.

## Authentication, organizational access and compliance controls

Introduce wallet challenge-response login with nonce, origin, network binding and replay/expiry protection; multi-role organization membership, least-privileged service accounts and separate issuer/operator actions. Enforce tenant authorization in every database access, with PostgreSQL row-security review. Distinguish user authorization, compliance review and issuer-level restriction. Store only necessary KYC references (ideally with licensed partners), with encryption, retention/deletion policy and audited selective-disclosure access. Build documented legal/compliance requirements per operating jurisdiction before live payout.

## Settlement workflow and idempotency

Expand the transactional journal into authenticated orchestration: incoming request validation → quote binding and expiry → policy/role approval → wallet intent and signature verification → privacy proof or committed token transfer → chain submission confirmation → independent payout scheduling → payout acknowledgement → reconciliation. Use a transactional outbox and retry-safe inbox; no duplicate settlement or payout from retries or webhook reorder. Implement optimistic-locking/version guards, explicit unrecoverable states, compensating transactions and human review with role-specific decision audit. Confirm cancellation and refund semantics against the actual underlying asset/protocol before enabling them.

## Stellar infrastructure and observation

Run a reliable indexer/read model for contract IDs, ledger sequences and transaction inclusion with checkpointed cursors, retention handling, duplicate-event detection, failover RPC, history backfill and protocol upgrade support. Untrusted RPC requests must be bounded, rate-limited and network-pinned. Build deployment-aware contract ABI/event decoding only for public signals whose privacy properties have been verified. Retain indexed traces with clear source timestamps and avoid exposing confidential XDR or tenant-specific transaction relationships. Separate liveness, readiness, RPC availability and lag metrics.

## Corridor / FX / liquidity platform

A corridor is an **eligibility and settlement contract**, not a country pair alone. Persist jurisdiction, origin/destination asset, issuer, settlement network, eligibility, limits, supported rails, provider settlement account reference, disclosure requirements, FX quote protocol and operator approval. Integrate only verified on/off-ramp partners. Use signed, expiring quotes, authenticated callbacks, finite retry policy, liquidity exhaustion behavior, float-safe precision normalization and reconciliation across all legs. Implement sandbox/contract tests separately from actual regulated processing. No sample rate or invented payout partner in runtime data.

## Protocol adapters and stablecoin issuer model

Separate Confidential Tokens from Stellar Private Payments with different methods, proof inputs, state models and trust assumptions. Support issuer-controlled confidential stablecoins only after specifying mint/burn supply accounting, authorization, freeze/unfreeze, legally scoped viewing and redemption/audit policy. A pool deposit is not a secret issuance or guaranteed FX exchange. Never store consumer proving witnesses or shielded spend keys in ordinary backend logs. Optional relayers and cross-chain bridges require threat models and version-pinned contracts before deployment.

## Reliability, performance and observability

Start as modular Rust services with bounded asynchronous concurrency; split workers only after performance data. Add timeouts, backoff+jitter, per-tenant rate limits, provider circuit breakers, queue dead-letter recovery, connection pool metrics, idempotency key retention, zero-downtime schema migrations, backups and restore drills. Instrument ledger lag, settlement stage latency, payout exception rates, HTTP request volume and RPC health without protected amounts or identifiers in public logs. Establish SLOs only after load and production-like tests, including delayed provider callbacks and partial outages.

## Security and engineering validation

Build negative tests for cross-tenant reads, invalid wallet challenge, replayed quote, double-submission, version race, forged partner webhook, incorrect contract ABI, ledger rollback, proof substitution, unauthorized operator actions and payout refund races. Include isolated PostgreSQL tests for same-key concurrency and immutable audit rows; protect deployment secrets through managed secret storage. Release only after successful CI, contract/SDK compatibility tests, signed deployment manifest, load/fault tests and documented operator runbooks. No automated use of mainnet credentials or real funds.

## Contributor scope and completion gates

Initial issues: [State persistence](https://github.com/stealthbridge-labs/stealthbridge-backend/issues/1), [Ledger observer](https://github.com/stealthbridge-labs/stealthbridge-backend/issues/2), [Organization authentication](https://github.com/stealthbridge-labs/stealthbridge-backend/issues/3). The first release gate is an authenticated, persistent **Testnet-only** settlement with independent on-chain evidence and a non-production provider, not a claim of fiat settlement. A backend feature is complete when storage, tests, OpenAPI, failure/retry semantics, security analysis, monitoring and frontend/SDK consumers agree.
