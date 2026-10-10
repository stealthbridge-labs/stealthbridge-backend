<div align="center"><img src="assets/stealthbridge-logo.svg" alt="StealthBridge — Confidential payments. Without borders." width="760" /></div>

# StealthBridge Backend

**Engineering roadmap:** [View the repository-specific plan](ROADMAP.md).

## End-to-end platform architecture and delivery priorities

**Full engineering guide:** [Backend architecture, managed PostgreSQL, trust boundaries and delivery gates](docs/ARCHITECTURE-AND-DELIVERY.md).

```text
Next.js preview / typed SDK
      │ read-only HTTP + explicit typed errors
      ▼
Rust/Axum Testnet API ───► Stellar RPC (network identity, ledger, tx status)
      │
      ├──► Neon PostgreSQL (organizations, corridors, journal, checkpoints)
      ├──► source-only Soroban ABI + not-deployed manifest
      └──x financial execution (returns disabled)
Future: authenticated sessions → signed approval → verified privacy rail
      → actual on-chain finality → independent provider payout → reconciliation
```

**Implemented vs operational:** real SQLx migrations have been applied to managed Neon; code queries real enabled-corridor rows, and the CLI records new candidate corridors as **disabled**. Runtime reachability, credentials and production recovery must still be independently verified after deployments. A `GET /ready` response is infrastructure readiness only; even `200` must still report `payments=disabled`. The journal, exact-value arithmetic, role helpers and webhook protections are internal foundations, **not** authenticated public fund-moving services.

**Next engineering milestones:** preserve evidence of a fresh Testnet RPC + Neon staging acceptance; establish a designated always-on observer rather than polling on every Vercel function; introduce challenge-based wallet authentication with short-lived nonce, origin/network binding and revocation; enforce tenant roles in database transactions; and consume independently attested three-contract addresses only after on-chain review.

**Later gates:** signed expiring quote and exact asset identity; workflow drafts and distinct approvals; durable outbox/inbox and idempotent provider callbacks; verified Confidential Tokens or Stellar Private Payments adapters; audited wallet/chain execution; reconciliation of chain finality with partner payout; observability and recovery drills. A payout-provider callback can never be inferred from a chain transaction hash.

**Security constraints:** all off-chain provider secrets remain server-side; remote PostgreSQL requires secure `sslmode`; bounded requests and sanitized logs; no fabricated FX, partners, customer records or liquidity. The canonical testnet contract manifest stays `not-deployed` until independent evidence and a reviewed manifest revision exist. Never enable `POST /v1/settlements` just because the database and RPC work.

Real-time, **read-only** Stellar Testnet observation API, a real transaction hash lookup, a tenant-scoped internal settlement journal, and an unseeded operator-managed corridor catalog. Rust, Axum, PostgreSQL, Stellar RPC.

**Live data, not demo records.** `GET /v1/network` makes actual `getNetwork` and `getLatestLedger` RPC requests. `GET /v1/corridors` reads enabled corridors from PostgreSQL; if no database is configured it clearly returns 503 instead of making them up. `POST /v1/settlements` is disabled (501) until cryptographic proof and custody requirements are satisfied.

## Run
Requires Rust and dependencies. No account secret or key required for RPC reads.

```sh
cargo test
cargo run
curl http://127.0.0.1:8080/v1/network
```

For real corridor records, set a PostgreSQL `DATABASE_URL` and apply `migrations/` through your approved deployment environment. No example corridor data is inserted.

## Architecture
- [API specification](api/openapi.yaml)
- [Deployment and environment](docs/DEPLOYMENT.md)
- [Settlement state machine](src/settlement.rs)
- [Transactional journal](docs/SETTLEMENT-JOURNAL.md)
- [Public transaction observation](docs/TRANSACTION-OBSERVATION.md)
- [Service architecture](docs/ARCHITECTURE.md)

*Status:* no confidential transfers, stablecoin issuance, FX rates, wallet signing, fiat payouts or proof generation wired yet. Do not process real money. Network is restricted to Testnet passphrase.

## Other repositories
[Frontend](https://github.com/stealthbridge-labs/stealthbridge-frontend) · [Contracts](https://github.com/stealthbridge-labs/stealthbridge-contracts) · [SDK](https://github.com/stealthbridge-labs/stealthbridge-sdk)

## Exact asset amounts and readiness

- `src/amount.rs` provides checked fixed-precision `i128` minor-unit arithmetic, explicit asset/network identity and strict decimal parsing. It uses no floating-point financial math. Asset decimals must come from verified issuer/chain metadata; this module does not discover or trust a stablecoin by itself.
- `GET /health` reports process liveness only.
- `GET /ready` probes actual Stellar RPC **and** configured PostgreSQL with bounded upstream calls; 200 requires both, otherwise 503 with a non-sensitive error envelope and dependency details. It distinguishes an unconfigured database from a configured but unavailable one and **always** reports `payments=disabled`.
- Failed requests return stable JSON error codes with a generated `trace_id` and `X-Request-ID` header. Logs contain only the trace ID and status.
- Optional `/internal/metrics` exports bounded readiness/RPC aggregates. Set `STEALTHBRIDGE_METRICS_TOKEN` to enable it; without a token the route returns 404. The endpoint never labels metrics with wallets, transaction hashes, tenants or request IDs.
- Backend internal settlement state transitions are still not public payment APIs and require policy, authentication and privacy-proof verification before money movement.

See [service readiness and exact asset value notes](docs/ENGINEERING-FOUNDATIONS.md).

### Corridor lookup

`GET /v1/corridors/{id}` selects one **enabled** operator-configured record by UUID with a parameterized PostgreSQL query. Invalid UUIDs return 400, unavailable/disabled records 404 and a missing database 503. No country, asset identity, rate, issuer relationship or payout availability is synthesized. The SDK exposes the same typed read.

## Detailed integration guide

[Deployment and API integration reference](docs/INTEGRATION-GUIDE.md) documents every read-only route, failure status, database boundary and release precondition.

## Bounded corridor keyset discovery

\`GET /v1/corridors/page?limit=25&after=<UUID>\` returns \`{items, next_cursor}\` from **real enabled operator records** in PostgreSQL. Limits range 1–100, default 25; malformed UUID or out-of-range count returns 400. The query fetches one extra row to determine whether a cursor should be returned, so the service never reads the full table to produce a page. Stable UUID ordering avoids OFFSET scans at larger tables. A missing database returns 503, an empty configured database gives an empty page with null cursor, and no partner/FX details are synthesized.

Page boundaries are not a long-running database snapshot: concurrent operator enable/disable changes can affect later pages. Cursors must be treated as opaque pagination tokens; a future authenticated and signed cursor scheme will be needed if customer-specific filters appear. \`/v1/corridors\` is retained for backwards compatibility with existing read-only clients; new integrations should use the bounded endpoint.

## Opt-in durable Stellar observer

Set \`STEALTHBRIDGE_ENABLE_LEDGER_OBSERVER=true\` **only** on a designated backend worker with a real PostgreSQL database. This starts a 15-second read-only Stellar Testnet ledger-head poller; each response must contain the exact Testnet passphrase, positive ledger sequence, a 64-character hexadecimal ledger hash and a valid close-time. A transactionally monotonic cursor is persisted in \`stellar_ledger_observer\`. A same-sequence hash conflict is rejected and flagged; stale responses cannot rewind the cursor. **No transaction XDR, wallet identity, customer or payment data is stored.**

\`GET /v1/observer\` exposes the last persisted public ledger checkpoint; 404 means no observation has been recorded, and 503 means no database service. This record **may be stale** and is not a settlement receipt, indexer backlog, account balance or regulated payout confirmation.

Operate **one designated observer per environment**; multiple replicas can safely contend on row locks but cause needless RPC load. Production worker leases, chain history backfill, event indexing, failure metrics and replay protection remain future work. The opt-in worker never signs or submits transactions.

## Tenant access-control foundations

The backend now includes a role and separation-of-duties model with a minimal organization/member schema. These are **internal building blocks**, not authentication endpoints or financial permissions. See [organization authorization and missing controls](docs/ORGANIZATION-AUTHORIZATION.md).

### Bounded ledger freshness

The readiness probe verifies not just a valid Testnet RPC network passphrase and database but a ledger **closed within 180 seconds of the current server clock**. An old ledger, invalid timestamp, or timestamp more than 30 seconds ahead of the server clock makes \`GET /ready\` report degraded (503), even if \`getNetwork\` and \`getLatestLedger\` return HTTP success. \`GET /v1/network\` still reports actual metadata without changing or fabricating it.

Keep host clocks synchronized; slow networks can require explicit operator investigation. A fresh ledger is only an infrastructure-readiness condition and **does not enable payments**.

## Future provider webhook inbox

A provider-neutral authenticated-notification verifier and PostgreSQL idempotent inbox are available as internal building blocks. They do not enable provider integrations, public callback endpoints, payouts or settlement transitions. See src/webhook.rs and its unit/integration tests.

## Inter-repository Testnet contract discovery

`GET /v1/contracts` serves the exact **undeployed** contract manifest from the Soroban repository as a read-only build snapshot, with `on_chain_verified=false` and `payment_execution_enabled=false`. CI compares the snapshot to the canonical upstream file; it fails on drift or an unverified deployment claim. The Vercel Rust adapter in `api/axum.rs` uses the same Axum routes as the local server. See [deployment notes](docs/DEPLOYMENT.md).

The backend also includes the source-verified public registry method inventory, synchronized from `stealthbridge-contracts/integrations/public-soroban-interface.v1.json`. `GET /v1/contracts` returns this metadata as `public_interface`. It is documentation of public Soroban **source methods**, not confirmation that a contract ID exists or that its methods can currently be invoked.
