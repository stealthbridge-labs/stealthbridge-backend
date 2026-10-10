# StealthBridge Backend — Integration and Operating Guide

## 1. Purpose and trust boundaries

This Rust/Axum service provides reliable public Testnet observation and an **internal, tenant-scoped settlement journal**. It does **not** hold wallet keys, custody assets, issue tokens, quote fiat FX, or execute a payout. Never infer financial readiness from a successful HTTP response or passing CI.

```text
Frontend / TypeScript SDK
      │ HTTPS read-only metadata
      ▼
Rust API (network passphrase enforced)
      ├── Stellar RPC: getNetwork, getLatestLedger, getTransaction
      │    └─ Projection only: ledger/hash/status, no raw XDR or contract events
      └── PostgreSQL: enabled corridors and internal settlement state journal
           ├─ tenant-scoped idempotent intents
           └─ append-only transition log (not a double-entry ledger)
```

## 2. Current API surface

| Route | Input | Result | Operational caveat |
|---|---|---|---|
| `GET /health` | None | 200 process liveness | Not chain readiness |
| `GET /ready` | None | 200 ready / 503 degraded | Separates an unconfigured DB from a failed DB probe; payment flags remain disabled |
| `GET /internal/metrics` | `Authorization: Bearer …` | 200 metrics / 401 unauthorized / 404 disabled | Aggregate internal metrics; enabled only when `STEALTHBRIDGE_METRICS_TOKEN` is set |
| `GET /v1/network` | None | Live protocol/ledger and passphrase | 502 on bad/unavailable RPC |
| `GET /v1/capabilities` | None | Explicit boolean capability flags | Privacy and payment flags remain false |
| `GET /v1/corridors` | None | Enabled database records, maybe empty | 503 without PostgreSQL |
| `GET /v1/corridors/{id}` | UUID | Single enabled operator record | 400 invalid, 404 missing, 503 database unavailable |
| `GET /v1/transactions/{hash}` | 64 hex | Public execution status and ledger | 404 includes old/nonretained tx; no fiat payout claim |
| `POST /v1/settlements` | — | 501 | No fund submission allowed |

All public reads return live observation or persisted configuration, **never synthetic rates/partners/success messages**. See [OpenAPI](../api/openapi.yaml) for response schemas.

## 3. Local startup and migrations

Configure `STELLAR_RPC_URL=https://soroban-testnet.stellar.org` and optionally `DATABASE_URL` with an operator-managed PostgreSQL instance. Run migrations using an approved SQLx migration process; startup itself does not mutate the database.

```sh
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo run
curl -i http://127.0.0.1:8080/health
curl -i http://127.0.0.1:8080/ready
curl -i http://127.0.0.1:8080/v1/network
```

A database is intentionally not seeded with example corridors. An unconfigured instance may serve `/v1/network` while `/ready` and `/v1/corridors` correctly report degraded/unavailable. Error responses include a stable `error.code`, a safe message and a generated `trace_id`; the same ID is returned in `X-Request-ID` for log correlation. Do not echo arbitrary request values into logs or error bodies.

## 4. Financial domain foundations

`src/amount.rs` provides exact checked i128 minor-unit arithmetic tied to asset identity and decimals. Identity and scale must be validated externally against an actual issuer or on-chain token. No floating-point amounts should enter durable settlement logic.

`src/settlement.rs` holds the pure transition rules. `src/store.rs` holds organization-scoped idempotent registration with payload digests, row locking, revision checks and an atomic append-only history. These functions are deliberately not exposed as public HTTP writes. A future caller must verify tenant identity, wallet authorization, quote signatures, proof validity, issuer permissions, compliance eligibility, and external provider obligations first.

## 5. Privacy and operational safety

- Never return raw transaction XDR or contract events through the public observation API.
- Do not log secret inputs, payment witnesses or personal financial identifiers.
- Deploy behind TLS, request rate limits, managed secrets and database credentials with minimum privileges.
- The current readiness endpoint is *dependency status*, not a settlement certification.
- CI's PostgreSQL service uses synthetic isolated test data; these are **not production corridor registrations**.

## 6. Release sequence

First verify API/SDK schema agreement and remote endpoint data, then authenticated organization identity, then proof/asset compatibility, then signed quotes and structured settlement attempts, then provider-specific payout reconciliation. Review security, licensing and local compliance requirements before anything fund-moving. The [backend roadmap](../ROADMAP.md) describes full exit criteria.

## RPC hardening (concurrent-reader protection)

The read-only Stellar upstream client has an 8-second HTTP timeout, **16 simultaneous RPC request permits**, and a **2 MiB maximum streamed response**. Responses are not deserialized until their bounded content is collected. Unexpected JSON-RPC versions, mismatched response IDs, error objects, null results and untrusted ledger hashes fail closed as upstream errors. Correctness tests cover malformed response envelopes.

The configured RPC URL must be HTTPS without embedded credentials, fragment or query string. Readiness probes execute network and database checks concurrently, with a two-second DB timeout. These are service-capacity safeguards, **not per-user/IP rate limits**; public deployment still needs an ingress limiter, trusted proxy policy and monitoring.

## Bounded corridor keyset discovery

\`GET /v1/corridors/page?limit=25&after=<UUID>\` returns \`{items, next_cursor}\` from **real enabled operator records** in PostgreSQL. Limits range 1–100, default 25; malformed UUID or out-of-range count returns 400. The query fetches one extra row to determine whether a cursor should be returned, so the service never reads the full table to produce a page. Stable UUID ordering avoids OFFSET scans at larger tables. A missing database returns 503, an empty configured database gives an empty page with null cursor, and no partner/FX details are synthesized.

Page boundaries are not a long-running database snapshot: concurrent operator enable/disable changes can affect later pages. Cursors must be treated as opaque pagination tokens; a future authenticated and signed cursor scheme will be needed if customer-specific filters appear. \`/v1/corridors\` is retained for backwards compatibility with existing read-only clients; new integrations should use the bounded endpoint.

### Local integration test coverage

CI's PostgreSQL service now runs `tests/corridor_pagination.rs`: it creates five isolated, synthetic **test-only** corridor records, boots the Axum router on a local ephemeral port, verifies two successive keyset pages and malformed query failures, checks that provider/FX fields are absent, and cleans up. This is not a deployment or an authorization to onboard a real corridor.

## Opt-in durable Stellar observer

Set \`STEALTHBRIDGE_ENABLE_LEDGER_OBSERVER=true\` **only** on a designated backend worker with a real PostgreSQL database. This starts a 15-second read-only Stellar Testnet ledger-head poller; each response must contain the exact Testnet passphrase, positive ledger sequence, a 64-character hexadecimal ledger hash and a valid close-time. A transactionally monotonic cursor is persisted in \`stellar_ledger_observer\`. A same-sequence hash conflict is rejected and flagged; stale responses cannot rewind the cursor. **No transaction XDR, wallet identity, customer or payment data is stored.**

\`GET /v1/observer\` exposes the last persisted public ledger checkpoint; 404 means no observation has been recorded, and 503 means no database service. This record **may be stale** and is not a settlement receipt, indexer backlog, account balance or regulated payout confirmation.

Operate **one designated observer per environment**; multiple replicas can safely contend on row locks but cause needless RPC load. Production worker leases, chain history backfill, event indexing, failure metrics and replay protection remain future work. The opt-in worker never signs or submits transactions.

### Bounded ledger freshness

The readiness probe verifies not just a valid Testnet RPC network passphrase and database but a ledger **closed within 180 seconds of the current server clock**. An old ledger, invalid timestamp, or timestamp more than 30 seconds ahead of the server clock makes \`GET /ready\` report degraded (503), even if \`getNetwork\` and \`getLatestLedger\` return HTTP success. \`GET /v1/network\` still reports actual metadata without changing or fabricating it.

Keep host clocks synchronized; slow networks can require explicit operator investigation. A fresh ledger is only an infrastructure-readiness condition and **does not enable payments**.

## Signed callback inbox (future provider integration)

The internal HMAC verifier and tenant-scoped PostgreSQL inbox now reject unauthenticated, stale, duplicated and conflicting callback inputs. These remain separate from public APIs and money movements. See [provider callback verification](PROVIDER-CALLBACK-SECURITY.md).

## Real HTTP contract integration regression

`tests/contracts_http_integration.rs` now starts the actual Axum router on an ephemeral local port. It verifies `GET /v1/contracts` exposes the canonical empty Testnet deployment manifest and source-level read-method inventory; `POST /v1/settlements` stays HTTP 501; and payment/privacy capability flags remain false. No Stellar RPC calls, real payment data, private witnesses or on-chain deployments are part of this test.


## Wallet public-account trust boundary

The backend now provides `wallet::decode_account_address`, a pure Rust
validator for **classic Stellar `G...` StrKeys** with a version byte and
CRC16-XModem checksum. It returns an Ed25519 public-key byte array but **does
not prove ownership**. The corresponding frontend and SDK validators enforce
the same checksum for local watch-only inputs.

StealthBridge does not offer a public endpoint for registering or authenticating
wallet addresses, and the preview never uploads watched addresses to the
backend. A Freighter connection exposes a public key to the browser only after
the user grants access; it is neither an organization login nor a transaction
signature. Any future authenticated write path must verify a challenge signature,
bind the authenticated account to an active organization role, enforce replay
protection and confirm the exact Testnet passphrase.

Soroban governance writes remain authorized on-chain by `require_auth()` in
the registry contracts; nothing in this Rust utility signs or submits them.
Current `POST /v1/settlements` remains disabled. A verified contract deployment,
working privacy rail, and compliance/audit gates are required before new
financial APIs can be enabled.

