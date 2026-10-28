# Customer route preflight (public metadata only)

GET /v1/corridors/{uuid}/preflight returns one currently enabled operator-configured corridor with a fresh Testnet RPC observation and a protected SQLx schema-readiness check.

- Exact route ID and catalog data come from PostgreSQL, not suggestions or inferred markets.
- A missing/disabled corridor returns HTTP 404, malformed UUID returns 400, database failures return 503.
- network_fresh requires a Testnet ledger closed in the previous 180 seconds. ledger_sequence is null if the ledger is unavailable or stale.
- database_schema_ready means all twelve required SQLx versions and essential tables exist. It is separate from DB connectivity.
- read_only_dependencies_ready is not payment authorization; it is true only when the RPC and the schema are ready.
- Execution, fee quotes, liquidity, issuer eligibility, privacy proofs and fiat payouts are all explicitly false. Nothing about sender/recipient/amount is sent; no financial write route is added.
- The request is bounded by the existing public read limiter and Cache-Control: no-store.

The frontend and SDK validate the exact v1 schema and refuse stale, forged or inconsistent responses. The endpoint is not intended to be cached or used to sign any transfer. Existing Testnet contract deployments are not changed.

The additive GET endpoint is specified in api/openapi.yaml and enforced by scripts/verify_readonly_openapi.py. The protected financial-write route remains an HTTP 501-only reservation.
