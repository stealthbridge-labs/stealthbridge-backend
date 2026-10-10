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
