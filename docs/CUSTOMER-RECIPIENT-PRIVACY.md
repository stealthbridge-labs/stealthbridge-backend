# Customer recipient evidence, not protocol introspection

GET /v1/wallet/recipient/{C-address} returns a fresh (server time), exact-address public Soroban contract-instance *presence* observation. It uses the existing RPC getLedgerEntries validation, Testnet passphrase check, TTL, and ledger freshness. The response deliberately omits executable WASM hashes, contract IDs other than the recipient the user supplied, deployment administrator addresses, signers, raw XDR, authorizations, and operator details.

An observed contract instance is **not** proof of a smart wallet, ownership, recoverability, asset support, a signed authorization, liquidity, confidentiality or permission to pay. All such flags are false. No private payment data is submitted. A consumer proxy checks the exact schema, timestamp and requested address before display.

The original /v1/wallet/contracts/{C-address} remains a research diagnostic API and should be separately access-controlled before production trust certification. Do not enable account creation or payment execution based on presence.
