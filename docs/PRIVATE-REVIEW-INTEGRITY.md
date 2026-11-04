# Offline customer review fingerprint parity (Rust)

`src/privacy_commitment.rs` is a **pure offline** SHA-256 implementation that
pins the browser/SDK review format. It has no HTTP endpoint, database writes,
ledger writes, key material, fees or permission to authorize transfers.

Input is the exact operator-configured Testnet corridor ID/countries/asset,
issuer, privacy rail, public sender/recipient, decimal amount and optional
internal reference. The caller uses an unpredictable 32-byte *secret* nonce.
The digest domain binds the Testnet passphrase and all fields. A changed amount,
route, recipient, asset or reference yields a different digest. Cross-language
fixtures pin the result for `a1` repeated 32 bytes to:

`4f1d1a8cbf79a6d8b8d6780034de12339983540d836e9879ce1a3e03bd38f571`

The fixed nonce is a **test vector only**; live clients use Web Crypto randomness.
Neither the random nonce nor a draft preimage should be sent through public
StealthBridge APIs, observability, logs or telemetry. Published fingerprints
cannot be validated without the secret and original details. This is **not**
a signature, password, zero-knowledge proof, privacy-pool commitment or payment
receipt. Backend payment execution, ZK verification, compliance approvals and
fiat payouts remain disabled.

Run: `cargo test --lib privacy_commitment`.
