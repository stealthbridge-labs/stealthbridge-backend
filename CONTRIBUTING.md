# Contributing to StealthBridge Backend

Welcome to `stealthbridge-backend`, the Rust / Axum orchestration API, SQLx / Neon PostgreSQL persistence layer, and Stellar Testnet RPC observer for StealthBridge.

> **Security & privacy rule:** Never log or commit database URLs, `STEALTHBRIDGE_ACCOUNT_BRIDGE_SECRET`, wallet recovery phrases, raw plaintext payment notes, or ZK proof witnesses. Only store encrypted envelopes inside bounded vault tables or strictly non-custodial metadata.

---

## 1. Repository Architecture

- **Framework:** Rust (`edition 2021`), Axum, SQLx (`postgres`, `rustls`), `stellar-strkey`, HMAC-SHA256 / Ed25519 verification.
- **Cross-repo map:** [CROSS-REPO-INTEGRATION-MAP.md](https://github.com/stealthbridge-labs/stealthbridge-contracts/blob/main/docs/CROSS-REPO-INTEGRATION-MAP.md)
- **Key source directories:**
  - `src/` — Axum router (`server.rs`), `account_*` BFF-authenticated services (`account_profile.rs`, `account_beneficiaries.rs`, `customer_ciphertext_vault.rs`, `payment_instructions.rs`, `settlement_lifecycle.rs`), organization RBAC (`org_auth.rs`, `organization_team.rs`, `team_invites.rs`), Protocol 30/privacy validators (`wallet.rs`, `privacy_rails.rs`), ledger observation (`ledger.rs`, `ledger_events.rs`).
  - `migrations/` — strictly additive SQLx migrations checked by `scripts/validate_migrations.py`.
  - `api/openapi.yaml` — canonical read-only public API specification synchronized with `stealthbridge-sdk` and `stealthbridge-frontend`.
  - `tests/` — Rust integration tests requiring a live PostgreSQL instance (`DATABASE_URL`).

---

## 2. Local Setup & Verification

### Prerequisites
- Rust stable toolchain (`rustfmt`, `clippy`)
- PostgreSQL 16 (local or Docker: `docker run -d --name sb-pg -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=stealthbridge -p 5432:5432 postgres:16-alpine`)
- `sqlx-cli` (`0.8.6`), Python `3.11+`

### Run Full Suite

```bash
export DATABASE_URL="postgres://postgres:postgres@127.0.0.1:5432/stealthbridge"
sqlx migrate run
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --test journal_integration --locked -- --test-threads=1
cargo test --test payment_instruction_http --locked -- --test-threads=1
cargo test --test settlement_lifecycle_e2e --locked -- --test-threads=1

# Offline safety & cross-repo parity checks
python3 scripts/validate_migrations.py
python3 scripts/verify_readonly_openapi.py
python3 -m unittest discover -s scripts -p 'test_*.py'
```

---

## 3. Practical Contributor Walkthroughs

### How to Add a New SQLx Migration & Rust API Endpoint
1. **Create an additive migration:** Name it `migrations/YYYYMMDDNNNN_<feature>.sql`. Use `CREATE TABLE IF NOT EXISTS`, `CHECK` bounds on string lengths/StrKeys/states, and avoid destructive DDL (`DROP`/`TRUNCATE`/`DELETE`/`UPDATE` in migration SQL).
2. **Register bounds in validator:** Update `OPTIONAL_MIGRATIONS` (or `REQUIRED_SCHEMA_VERSIONS` in `src/server.rs` when ratified for `/ready`) inside `scripts/validate_migrations.py` so CI verifies structural invariants.
3. **Implement the Rust handler:**
   - For account-scoped writes, verify requests with `customer_ciphertext_vault::authorize_account_request(...)`, require single-use `UUID` nonces in a receipt table (`409 CONFLICT` on replay), wrap multi-row checks in `db.begin()` with `pg_advisory_xact_lock`, and use `#[serde(deny_unknown_fields)]`.
   - Enforce `DefaultBodyLimit::max(...)` when registering the route in `src/server.rs`.
4. **Update OpenAPI & SDK when public:** If modifying `/v1/` public routes in `api/openapi.yaml`, coordinate corresponding updates in `stealthbridge-sdk/specs/backend-openapi.v0.3.yaml` and update pinned commits in `.github/workflows/ci.yml` after SDK/Frontend pushes.
5. **Write integration tests:** Add unit + PostgreSQL tests covering auth failures (`401`), bad input (`400`), nonce replay (`409`), and cleanup.

---

## 4. Security Review Policy

Changes to authentication, HMAC verification, tenant RBAC, SQLx readiness checks, settlement state transitions, or OpenAPI safety gates require maintainer security review. Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and report vulnerabilities privately via [SECURITY.md](SECURITY.md).
