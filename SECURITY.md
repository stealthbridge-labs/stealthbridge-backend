# Security Policy — StealthBridge (backend)

## Scope
This repository contains the backend orchestration API, PostgreSQL persistence layer, and Stellar Testnet RPC observer for StealthBridge. It is experimental **Stellar Testnet-only** financial infrastructure software and has not completed an independent third-party cryptographic audit. Real funds, production KYC data, private payment spend notes, zero-knowledge witness secrets, wallet recovery phrases, relayer credentials, and actual fiat banking/custody secrets must never be used.

## Responsible reporting
Do not disclose critical vulnerabilities, authentication bypasses, or zero-day exploits in public GitHub issues, pull requests, or discussions.

If the repository's GitHub private vulnerability reporting is enabled, please submit reports directly via **Security → Report a vulnerability**. Otherwise, contact the organization maintainers privately to coordinate confidential evaluation and patching.

Please include in your report:
- Impacted endpoint, route handler, or background service (e.g., `/v1/account/*`, `/v1/settlement/*`, ledger observer)
- Deterministic, non-destructive reproduction steps or script
- Expected vs. observed security property
- Assessment of impact (e.g., authorization bypass, replay attack, data leakage, denial of service)

Do not include private keys, real customer credentials, or live network exploits.

## Backend Security Commitments & Architectural Invariants
- **Non-Custodial Data Boundaries:** The backend never holds, generates, logs, or persists user wallet private keys, mnemonic seed phrases, or unencrypted private payment notes. Customer ciphertext envelopes are stored as opaque encrypted blobs inside authenticated vault records.
- **BFF Authentication & Anti-Tampering:** All account-scoped endpoints require constant-time HMAC-SHA256 signature verification (`STEALTHBRIDGE_ACCOUNT_BRIDGE_SECRET`) with monotonic millisecond timestamps to prevent request forgery and replay.
- **SQL Injection Prevention:** All database operations utilize parameterized queries and compile-time checked SQLx queries against PostgreSQL schema, eliminating SQL injection vulnerabilities.
- **Idempotency & Double-Execution Protection:** Payment instructions and settlement records enforce strict uniqueness constraints and cryptographic digest hashing (`instruction_digest`) to prevent duplicate processing.
- **Re-org Resilience:** The Stellar Testnet ledger observer enforces bounded block confirmations before updating settlement state to terminal success.
- **Strict Protocol 30 Address Parsing:** All Stellar addresses are strictly validated via canonical `stellar-strkey` decoding (`G...`, `M...`, `C...`, `W...`) without permissive regex.
- **Role-Based Access Control (RBAC):** Organization routes strictly enforce organization membership, role privileges (`Owner`, `Admin`, `Member`), and tenant isolation.

## Important
No guarantee of financial finality or transaction settlement is made until formal verification, independent cryptographic audit, and mainnet governance deployment are complete. All deployments remain strictly restricted to Stellar Testnet (`mainnet_enabled: false`, `fiat_payouts_enabled: false`, `live_fx_enabled: false`).
