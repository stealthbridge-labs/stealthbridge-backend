# Managed PostgreSQL and real Testnet corridor onboarding

StealthBridge uses a managed PostgreSQL database for **operator-maintained corridor
configuration**, ledger checkpoints and the internal settlement journal. The
current release has **no confidential payment execution, live partner quotes,
liquidity commitments or fiat payout rails**.

## 1. Provision Neon for the Rust API

1. In Vercel, choose the `stealthbridge-backend` project, then Storage /
   Marketplace -> Neon -> **Create Database**. If Neon is already installed
   on the Vercel team, create/connect a *new resource* to this project.
2. Choose a deployment region close to the backend Function region (currently
   `iad1`); use a separate database/branch for staging instead of sharing
   production credentials across feature previews.
3. Connect the Neon database to the **backend only**, enabling its production
   environment (and a separately isolated preview environment if needed).
   Do not expose PostgreSQL credentials to the frontend, public browser,
   wallet extension, SDK, or Soroban contracts.
4. Confirm the backend has `DATABASE_URL` from the Neon integration.
   The PostgreSQL connection must enforce TLS (`sslmode=require` or stronger);
   use the pooled Neon connection host for request-driven Vercel Functions.
   Make sure the database access role supports migrations during controlled
   bootstrap; afterwards prefer a least-privilege runtime role.
5. Redeploy the backend once Vercel has applied the environment variables:
   changes to settings do not retroactively change already-built deployments.

Use Vercel/Neon interfaces for credentials. Never paste connection URLs in
GitHub, ChatGPT, CI logs or issue comments.

## 2. Apply the schema **as a separate operator step**

Use a controlled workstation / one-time runner with network access and the
correct backend `DATABASE_URL`, verify the target host and database in the
provider console, then run:

```sh
cargo run --bin migrate -- --apply
```

This is deliberately **not** called from a Vercel Function at startup. The
versioned SQLx migrations create the corridors, organization authorization,
journal, ledger observer and provider inbox tables. Migration errors abort
without emitting the database URL. Back up and review any existing production
schema before rerunning after a failure.

## 3. Register real operator-reviewed corridor *candidates*

Only after verifying the actual counterparties, geography, selected Stellar
asset issuer, privacy-rail feasibility, and compliance constraints, an operator
may store a candidate (example fields below are **placeholders, not a live
approved corridor**):

```sh
cargo run --bin corridor-admin -- register \
  ORIGIN_COUNTRY DESTINATION_COUNTRY ASSET_CODE STELLAR_ISSUER_OR_DASH privacy-rail
```

Replace every placeholder with verified facts. Countries use uppercase ISO
alpha-2; asset code is 1-64 ASCII letters/numbers/underscore/dash/colon; the
issuer field is `-` for absent or a syntactically formatted Stellar public
account address. `privacy-rail` must be `private-payments` or
`confidential-token`. The CLI **only checks syntax**, not asset existence,
issuer authorization, available liquidity, KYC eligibility or private transfer
proofs. It always inserts `enabled=false`. There is deliberately no CLI
`enable` command.

```sql
-- Operator-safe read-only review; query with controlled database credentials.
SELECT id, origin_country, destination_country, asset_code,
       privacy_rail, enabled
FROM corridors ORDER BY created_at DESC LIMIT 25;
```

A new candidate will **not** appear in `GET /v1/corridors` or
`GET /v1/corridors/page` because only enabled records are advertised. Do
not enable a candidate until an independently reviewed activation workflow
verifies real integration capabilities. A record's existence never implies
exchange-rate or payout availability.

## 4. Verify live runtime, not just a successful build

```sh
python3 scripts/smoke_testnet_http.py \
  --url "https://YOUR_BACKEND_DOMAIN" \
  --require-live-network --max-ledger-age-seconds 180
```

After the schema migration, `GET /ready` should report
`database=connected` and a fresh `stellar_rpc=connected`, while
`payments=disabled` remains mandatory. `GET /v1/corridors/page?limit=25`
should return a real empty `items` array until approved records are
activated—never seeded or fabricated corridors.

## 5. Configure the private RPC endpoint

The backend supports a Stellar JSON-RPC HTTPS endpoint in
`STELLAR_RPC_URL`. Configure your provider's **newly rotated key** as a
sensitive server-side Vercel variable, not in Git, the SDK, frontend, or browser
source. The API checks `getNetwork` for the exact Testnet network passphrase,
then obtains `getLatestLedger`; setting the wrong network fails closed.

The API's `STELLAR_RPC_URL` default is the public Stellar Testnet endpoint.
The provider key supplied in a previous chat should be rotated before use in
any environment. An API `READY` build is not proof of a reachable RPC, secure
database, a deployed Soroban contract, or actual settlement.
