# Backend deployment — noncustodial observation service

## Environment
- `HOST=0.0.0.0` only inside a trusted reverse-proxy or PaaS network.
- `PORT` platform-provided listener port.
- `STELLAR_RPC_URL` HTTPS RPC for **Stellar Testnet only**.
- `DATABASE_URL` optional secure PostgreSQL; without it `GET /v1/corridors` responds 503 (no fabricated corridors).
- Do not set signing secrets; service has no signing code.

## Migration and startup
Run `sqlx migrate run` with operator-selected database credentials *as a separate approved deployment step*. The service does not create or mutate external resources by itself. Start using `cargo run --release`.

## Smoke tests
```bash
curl -fsS "$API_URL/health"
curl -fsS "$API_URL/v1/network"
curl -fsS "$API_URL/v1/capabilities"
curl -i "$API_URL/v1/corridors"
curl -i -X POST "$API_URL/v1/settlements"
```
Expected: `/v1/network` returns the actual ledger head and protocol. Settlements always 501 until private transfers work and are verified. A healthy process with broken RPC will still answer `/health` but `/v1/network` returns 502.

## Scale/security
Serve behind TLS, managed DDoS controls and request limits. Add service-level auth and tenant-aware settlement reads *before enabling write endpoints*. Do not publish KYC records or private witnesses to this API. Do not expose a database administrative operation publicly.


## Public Stellar RPC capacity protection

`GET /v1/network` and `GET /v1/transactions/{hash}` share a fixed-window quota of **60 reads per minute per directly verified TCP peer** (configurable via `STEALTHBRIDGE_RPC_READS_PER_MINUTE`, integer 1–120). Requests exceeding quota return **429**, a structured `RATE_LIMITED` error with a request ID and `Retry-After: 60`. Other public metadata routes keep their existing availability semantics. There are no fee or transfer-success claims.

The native Rust listener attaches peer `SocketAddr` from the actual connection. Forwarding headers (`X-Forwarded-For`, `CF-Connecting-IP`, client-ID claims) are **never trusted** as identity, preventing easy spoofing. In Vercel Functions, where direct TCP peer identity is not supplied, requests use a **shared anonymous per-function-instance quota**. Multiple function instances **do not share quotas**; configure global identity-aware rate limiting at a trusted upstream gateway or WAF, stripping untrusted forwarding headers and protecting the direct origin. The per-instance limiter bounds IP buckets to 1,024 entries and shares a fallback quota under saturation.

Outbound Stellar RPC uses an eight-second timeout, a strict two-MiB streamed-response limit, redirect denial and a 16-request **non-waiting concurrency budget**. Saturation returns a classified upstream-unavailable error without unbounded waiting. Transaction hashes and RPC Testnet passphrases are validated before interpreting transaction observations. No request body, wallet data or financial event payload is logged.

## Vercel Rust Functions adapter

The repository contains `api/axum.rs` and `vercel.json`, adapting the **same Axum router** through the official `vercel_runtime` Rust Functions runtime (currently beta). A Vercel project can import `stealthbridge-labs/stealthbridge-backend` with the Rust/Axum preset. The adapter creates a request-handling service, not an always-on listener.

- No permanent background ledger observer runs inside Vercel Functions; run it on a separate supervised persistent worker.
- With no `DATABASE_URL`, network and capability reads remain available, but corridors/observer return explicit 503 and `/ready` remains degraded. Migrations are never applied at startup.
- A configured `DATABASE_URL` is connected lazily so an unavailable database does not prevent process startup; `/health` remains liveness and `/ready` reports `database=unavailable`.
- Set `STEALTHBRIDGE_METRICS_TOKEN` only for an internal monitoring deployment. `/internal/metrics` returns 404 when unset and requires `Authorization: Bearer <token>` when enabled. Keep the route behind a private network or authenticated gateway as well.

### Readiness and monitoring probes

```sh
curl -i "$API_URL/health"
curl -i "$API_URL/ready"
curl -fsS -H "Authorization: Bearer $STEALTHBRIDGE_METRICS_TOKEN" "$API_URL/internal/metrics"
```

Alert when `/ready` stays degraded, the observed ledger age exceeds 180 seconds, the RPC probe error ratio rises above the service's normal baseline, or PostgreSQL is configured but unavailable. During an outage, keep the process live for diagnostics, stop treating observer checkpoints as current payment evidence, and leave all payment execution disabled. Never attach wallet, transaction, tenant or customer identifiers as metric labels.
- `GET /v1/contracts` exposes the canonical undeployed Testnet manifest snapshot and **always reports on-chain verification false**. It returns 503 if someone incorrectly inserts an unverified deployment record.
- If the Vercel build or runtime cannot support the deployed Rust dependencies, inspect actual logs and do not claim functionality from a build alone.

To connect an engineering staging frontend, set the `STEALTHBRIDGE_API_URL` on a **separate Vercel preview project** pointing to the actual backend HTTPS URL, with `STEALTHBRIDGE_SITE_MODE=preview`. Keep the production marketing site on `landing`.

**Deploying the API cannot enable payments or contract transactions.** The `POST /v1/settlements` handler remains disabled.

## Post-deployment acceptance gate

From CI or an operator-approved staging environment, run:

```sh
python3 scripts/smoke_testnet_http.py --url "https://your-staging-backend.example"
# Strict launch gate: require a fresh, actual Testnet ledger
python3 scripts/smoke_testnet_http.py --url "https://your-staging-backend.example" --require-live-network --max-ledger-age-seconds 180
```

The script fails on non-JSON responses, wrong Testnet metadata, accidentally enabled capabilities, unexpected RPC errors, unverified contract deployment or a settlement write that is not disabled. A 502 from network or a 503 degraded readiness result is accepted only when a structured dependency failure explains the outage; do not interpret these as a successful ledger observation. Run on every approved staging deployment, and after configuring the actual deployed API URL, not against a mocked production endpoint. CI does not require staging credentials or automatically deploy. Do not run smoke probes against a URL containing a token.


## Separate runtime ownership: HTTP Functions vs Testnet observer

The **only Vercel deployable Rust binary** is `main` at `api/axum.rs`; it creates an Axum request handler, does not poll, does not run migrations and does not start a task that outlives a request. The native local HTTP binary is `api-server`; it refuses `STEALTHBRIDGE_ENABLE_LEDGER_OBSERVER=true` instead of silently launching a background task.

A separately supervised durable process must be launched explicitly:

```bash
# With operator-configured, secure DATABASE_URL and Testnet-only STELLAR_RPC_URL:
STEALTHBRIDGE_WORKER_MODE=readonly-testnet-observer cargo run --locked --release --bin ledger-observer
```

Only use a supervised continuously running worker platform (VM, managed worker or container with restart policy); **do not deploy this binary as a Vercel Function or cron**. Ensure a single reviewed release/config owner is assigned to the worker and a different release owner for the public API. The operator provisions migrations outside both processes; the observer starts only after required tables exist. The `DATABASE_URL` credentials are limited to the necessary Testnet observation tables and read-only RPC access. Neither binary holds a wallet secret or can move funds.

### Lease and restart invariants

The worker takes a PostgreSQL **session advisory lock** with a dedicated `PgConnection`, never a connection from the request-handler SQLx pool; competing worker processes back off without polling RPC or modifying the checkpoint. The worker checks a fresh `SELECT 1` heartbeat before each 15-second observation. A failed heartbeat closes the session, releases the lock, and triggers a safe retry. On process crash or explicit session close, PostgreSQL releases the lock automatically. Restart resumes from the same PostgreSQL monotonic `stellar_ledger_observer` checkpoint. Equal observations are idempotent, older observations ignored, and same-sequence conflicting hashes reported and never overwritten. Tests run with isolated CI PostgreSQL sessions and assert exclusive lease, release and restart acquisition.

Supervisor health should check the process, PostgreSQL lock ownership, `GET /v1/observer` freshness and metrics. No connection should idle silently while appearing healthy. The current checkpoint is **public ledger metadata, not a private transfer observer or fiat reconciliation receipt**. Configured contract event reconciliation and retention upgrades remain distinct future work in issue #2.


## Operator-triggered live staging verification (GitHub Actions)

Use GitHub Actions → **Protected Testnet staging smoke** → **Run workflow** **after** reviewing an actual Vercel backend staging deployment and its immutable commit SHA. The job uses the protected GitHub `staging` environment and requires `STEALTHBRIDGE_STAGING_API_URL` as an **environment variable** (only the clean HTTPS backend origin, no credentials, path, query or fragment). For deployment protection, set the optional `STEALTHBRIDGE_VERCEL_BYPASS_TOKEN` as a **secret**, never put it in the URL, PR, issue, log or command line. Have a reviewer approve the exact staging commit and workflow run; use a dedicated staging project/environment isolated from public marketing. This is an authorized operator acceptance step, **not** automatic deployment or release promotion.

The workflow runs Python's bounded JSON checks against the actual API: /health, capabilities, canonical **not-deployed** contract discovery, readiness, fresh real Testnet network head, rejected settlement POST 501, and malformed transaction hash rejection. It fails closed on a stale/mismatched network, unsafe capabilities, JSON drift or protected-deployment redirects; it never signs or sends actual settlements. Successful local fixture tests do **not** count as a post-Vercel live test. Retain the GitHub run URL and associated Vercel staging deployment commit as release evidence.

At the time this workflow was added, **Vercel environment-variable inspection was not authorized** under the connected project's team scope. The workflow is not proof that a protected staging URL has been configured or that an actual Vercel deployment has been accepted. Issue #9 remains open until a real strict workflow run succeeds.

## Opt-in contract event journal — Testnet public identifiers only

Official API reference: [Stellar RPC `getEvents`](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getEvents) and [pagination](https://developers.stellar.org/docs/data/apis/rpc/api-reference/structure/pagination). The node has a bounded recent history (commonly ~7 days, measured by `oldestLedger`); the worker **never silently skips a pruned checkpoint**.

After independently verifying a deployed contract ID and applying **all nine** reviewed SQLx migrations, operators may opt in up to five trusted contract IDs by setting:

```text
STEALTHBRIDGE_WORKER_MODE=readonly-testnet-observer
STEALTHBRIDGE_OBSERVER_CONTRACTS=<one-to-five-comma-separated-C-StrKeys>
STEALTHBRIDGE_OBSERVER_START_LEDGER=<actual-source-ledger-at-or-before-contract-activation>
```

Do not copy placeholder contract IDs into deployment configuration. `deployments/testnet/manifest.json` remains **not-deployed**, so **no StealthBridge contract event observation is active by default**. Startup **fails closed** when IDs are malformed/duplicated, configuration requests more than five contracts, or the initial ledger is missing/non-positive. The env-selected ledger must be inside RPC retention; if `getEvents.oldestLedger` exceeds the saved cursor window, observation stops and requires a **manually reviewed gap-recovery plan** (alternative archival source with independent verification). Never jump forward and label data reconciled.

The supervised worker first verifies live Testnet network/passphrase/head under an exclusive PostgreSQL advisory lease, then queries **one contract per RPC call**, with a fixed `limit=25`, a JSON-RPC network timeout, 2 MiB streamed-body cap and nonwaiting 16-request shared semaphore. Requests use a filter by exact StrKey C-address and `type=contract`, `xdrFormat=base64`. The opaque RPC pagination cursor is kept durable **without** a `startLedger` argument on cursor pages. Empty pages advance to the RPC-reported latest ledger plus one; records and cursor advance in the **same SQL transaction**, preventing crash/restart duplicate application. Concurrent replay, duplicate public event IDs and conflicting transaction hashes are rejected or deduplicated.

The new `stellar_contract_event_journal` stores **only** public `contract_id`, `event_id`, transaction hash, ledger sequence, fixed observation-state label and insertion time. It **does not** persist `topic`, `value`, encrypted balances, ciphertext, memo, payer/recipient personal data, proof witnesses, account keys, or private payments. **Event inclusion is not an assertion of execution success, finality, private transfer validity or fiat payout**; no settlement transition is ever triggered. Deployed protocol verifiers require a separate reviewed source+proof/audit chain.

Retention and operations: preserve the journal for the organization's approved audit period (proposed 90 days, **not automatically enforced**). Define archive/export and exact retention SQL with security/compliance before adopting deletion. Track RPC `oldestLedger`, `latestLedger`, observer checkpoint lag, cursor age, duplicate event rates and rejected conflicting IDs. SQL migrations are never applied by the Vercel handler or the worker automatically. Replaying a gap requires explicit operator evidence and resync approval, not environment-variable edits that impersonate settlement history.
