# Smart-account-kit upstream artifact observation

`GET /v1/wallet/smart-account-kit` returns public Stellar Testnet infrastructure
health for `stellar/smart-account-kit` **0.10.0**, reference commit
`768ac041dad01b94a750b768fc650e67930afd28`. No customer smart account currently
exists, and the customer smart-account factory is not deployed. Upstream
artifact health is **not payment readiness**.

The exact local release inventory is
[`assets/smart-account-kit-release.json`](../assets/smart-account-kit-release.json).
It records the four WASM hashes, three validator instance IDs, all seven base64
LedgerKey XDR constants, and the account WASM size of **48273 bytes**. Pins were
copied from the explicitly authorized read-only contracts preflight
`tools/smart-account-preflight/src/manifest.mjs`; key construction and TTL semantics
follow its `src/audit-helpers.mjs`. The backend compiles this inventory into the
binary and does not read the sibling repository at runtime. Changes to pins
require review and an operator release.

The endpoint requires `getNetwork` to report the Testnet passphrase and
`getLatestLedger` to provide a valid head. The head must have closed within
180 seconds of observation and cannot be in the future. All seven keys are
then read with **one** `getLedgerEntries` request, without fetching customer
addresses, balances, credentials, instance storage or authorization details into
the response. Its `latestLedger` must be within 15 ledgers of the verified head.
Freshness is checked again after the batch completes. Existing bounded RPC body,
concurrency, timeout and public read rate limits apply. Responses, including
errors and rate limits, carry `Cache-Control: no-store`.

Rows always appear in this order: `account_code`, `webauthn_instance`,
`webauthn_code`, `threshold_instance`, `threshold_code`,
`spendingLimit_instance`, `spendingLimit_code`. The wire contract is in
[`api/openapi.yaml`](../api/openapi.yaml). No customer address or raw XDR is
returned. Canonical XDR decoding validates the entire entry, including extensions,
padding and the instance storage tail. Instance verification also checks the
contract identity, persistent instance key and WASM executable. Code verification
independently hashes the actual WASM bytes and compares both their SHA256 and
the entry's embedded hash to the release pin. The account code must also have
the pinned byte length.

- `live`: identity matches and remaining live TTL is **greater than 120960** ledgers.
- `low_ttl`: identity matches and remaining live TTL is **0 through 120960** ledgers.
  The expiration ledger itself is still live, matching the preflight semantics.
- `unavailable`: missing entry, zero TTL sentinel, or reported expiration before
  the observation ledger. Absence cannot distinguish archival from nonexistence.
- `mismatch`: code or executable hash divergence, or account byte-size divergence.
  A mismatch takes precedence over TTL availability.

Absent entries have null observed hash, expiration and remaining TTL. A zero TTL
has null expiration and remaining TTL; a positive expired TTL is preserved but
remaining TTL is null. A present entry with missing or malformed TTL is an error,
never an invented lifetime. `observed_wasm_hash` is the computed byte digest for
code and the executable hash for instances. Duplicate or unexpected RPC keys,
malformed XDR or metadata, wrong network and excessive ledger distance return
502. Stale heads return 503. Missing live entries are represented in a 200
observation with `all_entries_healthy: false`.

`all_entries_healthy` is true only when every one of the seven rows is `live`.
It does not establish signer control, security review, current administrator,
credential enrollment, recovery, privacy proofs or settlement capability.
`customer_smart_account_factory_deployed`, `customer_smart_account_created`,
`credential_recovery_verified`, `privacy_proofs_verified`, `mainnet_enabled`,
and `financial_execution_enabled` always remain false;
`operator_managed_deployment` is always true. SDK and frontend consumers must
retain these distinctions even when upstream artifacts are healthy.

Deployment belongs to startup/operator infrastructure. Users never deploy.
This endpoint does not deploy, extend TTL, restore, sign, simulate authorization,
broadcast, access keys, or enable funds. The runtime remains read-only and
Testnet-only. It does not automatically repair unavailable or low-TTL artifacts.
