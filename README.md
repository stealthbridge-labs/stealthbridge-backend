<div align="center"><img src="assets/stealthbridge-logo.svg" alt="StealthBridge — Confidential payments. Without borders." width="760" /></div>

# StealthBridge — Rust Platform API

**A fail-closed Testnet backend for a privacy-conscious cross-border payment product.**

[Customer app](https://stealthbridge.vercel.app) · [OpenAPI specification](api/openapi.yaml) · [Architecture](docs/ARCHITECTURE-AND-DELIVERY.md) · [Roadmap](ROADMAP.md)

## Current operational boundary

The Rust/Axum backend serves real, bounded **Stellar Testnet RPC observations** and **Neon PostgreSQL** records consumed by the product. The frontend has working signed-in profiles, pending business onboarding, organization membership/invitation reads and strictly read-only corridor/recipient planning. The TypeScript SDK validates independently pinned response contracts.

**Production SQLx as of the verified October 31, 2026 release:** all **12 of 12** expected migrations applied to the Neon primary. The protected GitHub Actions SQLx workflow recorded successful apply and post-deployment checks. This is a historical verification, not a perpetual assertion; check `/ready` and `/v1/observer/schema` before each release. The backend last returned `ready` with connected database/RPC and **payments disabled**.

[Protected migration release evidence](docs/PRODUCTION-DB-RELEASE-2026-10-31.md) · [Schema change runbook](docs/PRODUCTION-SQLX-MIGRATION-RUNBOOK.md).

### What the APIs actually serve

| Domain | Examples | Guarantee and limitation |
| --- | --- | --- |
| Runtime | `GET /health`, `GET /ready`, `GET /v1/diagnostics` | Actual dependency checks; not payment authorization |
| Account | `GET /v1/account/profile` and authenticated account updates | HMAC-bound frontend server identity; self-reported nonfinancial preferences |
| Business | `/v1/account/business-onboarding`, `/v1/account/directory`, `/v1/account/organizations/{id}/team`, `/v1/account/team-invites` | Database-backed tenant boundaries; pending applications are not KYC approval |
| Route discovery | `GET /v1/corridors/page`, `/v1/corridors/{id}` | Actual enabled operator-configured records, bounded filtering/pagination, no FX or payout quote |
| Live preflight | `GET /v1/corridors/{id}/preflight`, `/v1/corridors/batch/preflight` | Fresh RPC and SQL schema state with all finance flags false |
| Public recipient | `GET /v1/wallet/classic-recipient/{address}` and `/v1/wallet/recipient/{address}` | Public account/contract presence only, not ownership or asset acceptance |
| Observer | `GET /v1/observer`, `/v1/observer/activity`, `/v1/observer/schema` | Public ledger observations, not settlement or bank delivery |
| Governance | `GET /v1/governance/release`, `/code`, `/admin`, `/snapshot` | Public deployment records and current readbacks, not private-payment evidence |

`POST /v1/settlements` is **disabled**. Fee collection, custody, private transfers, signed transactions, FX execution and fiat payouts are not available.

The [API specification](api/openapi.yaml) is the read-only HTTP source of truth. [Customer privacy boundary](docs/CUSTOMER-RECIPIENT-PRIVACY.md) and [Business authorization](docs/ORGANIZATION-AUTHORIZATION.md) describe consent and role constraints.

## Service architecture

```text
Customer browser ── Next.js same-origin account/public BFF
                                |
                 signed, nonce-bound read/write requests
                                v
                   Rust/Axum Testnet API ───► Stellar RPC
                                |             network / ledger / public Soroban
                                v
                        Neon PostgreSQL
                profiles / pending businesses / teams
                public corridor configuration / journals
                                |
                      financial writes disabled

TypeScript SDK → reviewed read-only API protocol + safe local operations
Soroban Rust → three separately deployed public governance contracts
```

The browser's login signature **only establishes a customer session**. The Next.js server sends limited authenticated identity evidence to Rust using server-only shared secrets. An organization membership never authorizes a payment. The backend does not accept arbitrary signed client claims as permissions.

## Run and verify locally

Requires the repository's Rust toolchain and `cargo`. Public Testnet RPC checks do not need a signing key. Database-backed tests require a dedicated isolated PostgreSQL environment; never point automated tests to the primary production database.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo run
# In a separate terminal, after local runtime configuration
curl http://127.0.0.1:8080/ready
curl http://127.0.0.1:8080/v1/network
```

Use the [environment deployment guide](docs/DEPLOYMENT.md). Never paste SQL credentials, account bridge secrets, signing identities, provider keys or production tokens into issues or logs. Configure isolated database URLs in the applicable deployment environments, not in source. Production/preview URLs must **not** be treated as isolated without checking Vercel variable targets and Neon branch identity.

### Database migrations: controlled release only

The repository contains **12 SQLx migrations** under `migrations/`, including login challenges, the contract event journal, business reviews, profiles and invitations. Treat modifications as reviewed, forward-only schema changes.

1. Test migrations on a **Neon branch cloned from the correct primary**, with checksum and table-invariant verification.
2. Confirm a backup/restore window, protected GitHub environment, authorized reviewer and **direct** production database connection.
3. Dispatch protected `production-sqlx-migrations.yml` in inspect mode; examine pending versions.
4. Only after approval, dispatch the explicit apply mode and verify all migrations through SQLx and the deployed `/ready` and `/v1/observer/schema`.
5. Keep financial execution disabled regardless of schema outcome.

Do not infer that a schema is current from a Vercel deployment badge. The [production handoff](docs/PRODUCTION-DB-RELEASE-2026-10-31.md) records the successful historical 12/12 application and remaining environment-isolation checks.

## Read-only safety controls

- Strict Testnet network passphrase, fresh ledger timestamps, bounded upstream requests and sanitized errors with trace IDs.
- SQLx parameterized queries, strict UUIDs, organization roles, replay-resistant account updates and one-time request receipts where relevant.
- A bounded corridor catalog with explicit 400/404/503 states, **no seeded liquidity, currencies, rates, partners or fake balances**.
- Public Soroban governance receipts and verified source code observations, **not** an authorization to call fund-moving contracts.
- Private amount/recipient/reference fields in product drafts are browser-local; opt-in public recipient checks intentionally reach the Testnet network.
- Protected deployment workflows. No migration or smart-account deployment should run implicitly from a frontend change.

## Soroban and wallet scope

Three **public governance contracts** were deployed on Stellar Testnet on **October 17, 2026**. Actual receipts and current observations are linked in the [Contracts release record](https://github.com/stealthbridge-labs/stealthbridge-contracts/blob/main/deployments/testnet/VERIFIED-GOVERNANCE-RELEASE-2026-10-17.md). Current source includes additional governance methods **not automatically deployed** to those historical instances. The legacy canonical v1 integration manifest still reads `not-deployed` and must not be mistaken for an on-chain verdict.

Smart-account Testnet artifact verification and TTL checks are conducted in the contracts repository. A successful hash preflight is not deployed customer custody or recoverable passkey access.

## Next engineering work

Reliable ledger observer operations and retention, exact provider evidence and replay protection, verifiable issuer support and confidentiality proofs, guarded smart-account authorization/recovery, separately approved money movement, and reconciliation across chain and payout partner ledgers. This is a **Testnet-only infrastructure and planning system**, not an authorized live payments service.

### Repository map

[Frontend](https://github.com/stealthbridge-labs/stealthbridge-frontend) · [SDK](https://github.com/stealthbridge-labs/stealthbridge-sdk) · [Contracts](https://github.com/stealthbridge-labs/stealthbridge-contracts) · [Integration guide](docs/INTEGRATION-GUIDE.md) · [Security](SECURITY.md)

**Infrastructure readiness ≠ financial authorization. No customer funds.**
