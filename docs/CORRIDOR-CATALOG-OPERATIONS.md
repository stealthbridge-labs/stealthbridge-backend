# Real Testnet corridor catalog — Rust API and Neon PostgreSQL

The StealthBridge backend now provides **filtered, paginated, read-only**
access to corridor *configuration records*. This is an operator-approved
catalog, **not** a quote engine or evidence of usable confidential payments,
FX liquidity, available banks, a verified issuer, or fiat settlement.

## API

`GET /v1/corridors/page` accepts these optional parameters:

| Parameter | Allowed values | Meaning |
| --- | --- | --- |
| `after` | UUID returned as `next_cursor` | Continue stable UUID-keyset pagination |
| `limit` | 1–100, default 25 | Maximum returned records |
| `origin_country` | Two uppercase ASCII letters such as `NG` | Exact origin-country metadata filter |
| `destination_country` | Two uppercase ASCII letters such as `GH` | Exact destination-country metadata filter |
| `privacy_rail` | `confidential-token` or `private-payments` | Operator-declared research classification |

For example:

```http
GET /v1/corridors/page?origin_country=NG&destination_country=GH&privacy_rail=confidential-token&limit=25
```

The response is `{ "items": [], "next_cursor": null }` when no **enabled**
records match. This empty result is expected until an operator independently
reviews and enables real configuration entries. Never fabricate listings to
fill the UI. Individual enabled entries can also be looked up via
`GET /v1/corridors/{id}`.

The backend also revalidates each public corridor record **after reading
from PostgreSQL**. Invalid country/rail/asset metadata or a non-checksummed
Stellar issuer G-address causes the affected public catalog request to
fail closed (503) instead of publishing an unsafe record. This protects
against direct SQL updates that bypass the operator CLI, but it does not
verify that a checksum-valid issuer actually owns or authorizes an asset.

All filters are validated before the database query and passed to SQLx as
**bound parameters**, not SQL fragments. Pagination is ordered by the immutable
UUID; invalid country/rail/limit/cursor values return HTTP 400. A cursor only
has meaning within the same filter set. Because the catalog can change between
pages, this is a bounded operational listing, not a serializable snapshot.

## Register a candidate

```sh
cargo run --bin corridor-admin -- register NG GH USDC STELLAR_PUBLIC_ISSUER_G_ADDRESS confidential-token
```

Use `-` instead of the issuer only when an issuer is legitimately
unspecified. The CLI validates exact Stellar classic G-address **CRC16-XModem**
checksums, uppercase country codes and the research rail classification.
It inserts `enabled=false` exclusively. A valid issuer address does **not**
prove the account exists, issued an asset, delegated trust or has liquidity.

## Database and deployment readiness

`GET /ready` now checks all seven expected SQLx migration success markers and
the presence of eight required relations: corridors, organizations,
organization_members, stellar_ledger_observer, settlement_intents,
settlement_transition_log, provider_event_inbox, and settlement_outbox.

If SQLx migration tracking is incomplete or a required relation is unavailable
to the configured database role, the result is degraded (HTTP 503). This
check is bounded to two seconds and **does not** apply migrations from a
request handler. Operators still run the migration CLI separately after
confirming the target Neon environment.

A healthy database alone never enables payments: `payments=disabled`
remains mandatory, and Stellar RPC readiness requires a fresh Testnet ledger.
For network reads, the backend now refuses HTTP redirects from the configured
RPC provider and validates the exact network passphrase, nonzero ledger
sequence/protocol, numeric close time and a full 64-digit ledger hash.

## Security and operational acceptance

- Backend credentials and any provider key are server-only; the frontend
  uses a same-origin allowlisted read proxy.
- Remote PostgreSQL URLs require TLS; local test databases may use loopback.
- Operator-entered corridors remain disabled unless a separately reviewed
  activation path exists. There is no public POST to add or activate them.
- CI covers a real ephemeral PostgreSQL instance, bounded filtering, invalid
  metadata, issuer checksum, incomplete RPC envelopes, and redirect rejection.
- Before production acceptance, inspect the live `/ready`, query the actual
  Neon schema, confirm the newest deployment SHA, and independently observe
  ledger freshness. A passing mock/browser test is not a live-system proof.

Next: version the API/SDK filter compatibility, add signed wallet identity
and tenant permissions, and introduce independently verified on-chain Soroban
governance reads **only after** an administrator-approved Testnet deployment.
Do not promote configuration to funding, signing or settlement authority.
