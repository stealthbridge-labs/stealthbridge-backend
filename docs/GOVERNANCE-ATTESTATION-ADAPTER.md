# Governance attestation adapter — fail-closed specification

The contracts repository now contains **historical evidence** for three real Testnet governance contracts, but its legacy canonical manifest is not yet trusted for consumers. No live-attested adapter is implemented by this document.

## Read-only adapter acceptance

- Read canonical **approved** schema-v2 release metadata only after an out-of-band operator approval. Treat the existing deployment observation as an input to verification, not a trusted allowlist.
- Require exact network passphrase `Test SDF Network ; September 2015`, three unique contract IDs and expected code hashes, approved release signature/trust anchor, and bounded validity.
- Fetch fresh Stellar RPC state for every contract, verify executable hash, current administrator, pause state, registry pointers in GovernanceGate, TTL and ledger freshness. Cache successes only within an explicitly bounded period, invalidating on upgrades, governance changes and stale RPC.
- Fail closed on missing data, wrong network, malformed RPC results, timeout, mismatched ABI/WASM, admin rotation, paused registry, expired contract storage or unknown schema.
- A future public `GET /v1/governance/status` should return an explicit `unavailable` / `unverified` / `verified` state, observed ledger/time, sanitized reasons and immutable `payments_enabled: false`, `fees_enabled: false` until *separate* audited execution releases.
- Never return operator signing material, RPC auth tokens, private witnesses or internal reconciliation secrets.

## Integration tests to implement before any status rollout

A success fixture must come from captured and independently checked real Testnet responses; include negative cases for wrong passphrase, swapped contract addresses, altered hashes, mismatched gate bindings, stale ledgers, paused registries, changed admins, TTL expiry and replayed observations. Do not insert fake live data into production endpoints.

**Release blocker:** no code path should accept the observation JSON alone as an authority for transactions or payment permission.
