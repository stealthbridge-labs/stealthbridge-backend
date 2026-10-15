# Testnet Activity workspace — product integration contract

The user-facing technical-preview endpoint `GET /v1/observer/activity` returns **public event identifiers already stored** by the dedicated observer worker. It never polls Stellar RPC on an HTTP request, invents deployments, reads privacy witnesses, produces FX quotes, or submits transactions. It is not a payment explorer.

## Contract and boundaries

The canonical backend API remains `api/openapi.yaml` **v0.3**. The new read-only observer API has a separately reviewed additive `api/observer-activity.v0.1.yaml` extension, mirrored by the SDK under `specs/observer-activity.v0.1.yaml`. Both must be synchronized before any v0.4 canonical OpenAPI release. Unknown HTTP methods return 405 via Axum/Next.js route protections; the request contains **no wallet address or payment data**.

Read-only parameters: `limit` 1–25 (default 15), optional checksum-valid Stellar contract `contract_id`, optional `before` opaque pair of numeric event ID and contract C-address. The cursor is an ordering key, **not an access token**; never infer deployment/finality from it. Sorting is `(event_id,contract_id) DESC` for cross-contract stable pagination; PostgreSQL applies the tuple keyset predicate. Queries are prepared, bounded to 26 potential rows and at most six tracked cursors, with a three-second handler timeout.

Response fields `network=testnet`, `source=stored-public-testnet-metadata`, `observation_status=no-checkpoint|checkpoint-present`, `payment_execution_enabled=false`, `contracts`, `items`, `next_cursor` are intentionally explicit. `checkpoint-present` means **historical DB metadata exists**: it does not mean worker freshness or cryptographic proof succeeded. No database: 503; database without configured contracts: 200 with empty arrays and status `no-checkpoint`; DB query corruption: fail closed. No synthetic success data is returned.

The underlying journal stores `event_id`, `contract_id`, `transaction_hash`, `ledger_sequence`, observed UTC timestamp, and a fixed `observed` label only. No raw topics, values, private amounts, recipient identities, proof bytes, or fiat payout evidence. UI and SDK should link an event only to the **public Stellar Testnet transaction explorer**, clearly marked unverified inclusion until independently observed.

## Integration release

- Backend: public event route, migrations previously reviewed, PostgreSQL idempotent worker and CI.
- SDK: `observerActivity()` with strict JSON response boundaries and safe GET-only retry/abort controls; no signing interface.
- Frontend: isolated `/preview/activity` page and same-origin `/api/bridge/v1/observer/activity` proxy, visible empty/disabled/error states, no connection to public marketing.
- Contracts: canonical Testnet deployment manifest stays `not-deployed` until independently verified. The activity UI may therefore legitimately display zero rows.

Never label an activity entry a private transfer, verified confidential amount, settlement, fiat payout, or proof of on-chain executed StealthBridge contract while the manifest is undeployed.
