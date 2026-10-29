# Batch live read-only readiness

GET /v1/corridors/batch/preflight?ids=(1-8 canonical public lowercase UUIDs) returns an ordered current operator catalog snapshot, missing IDs and independently measured operational checks.

- network_fresh: Stellar Testnet observation closed within 180 seconds; stale observations erase the ledger sequence.
- database_schema_ready: SQLx versions and core relations pass the existing backend readiness check.
- read_only_dependencies_ready: both pass; NOT permission to sign, transfer, settle, quote FX, verify privacy, deliver fiat, collect fees or claim issuer/liquidity eligibility.
- Six explicit financial flags always false even when all IDs are configured and read-only dependencies pass.

Public responses contain no account, recipient, amount or reference. Existing /v1/corridors/batch contract remains unchanged. Database errors return 503; no fabricated route is substituted. Preflight is rate-limited and no-store. Frontend and SDK validate exact schema and a 120-second lifetime; mismatched batch records fail closed. No contract upgrade or financial operation.
