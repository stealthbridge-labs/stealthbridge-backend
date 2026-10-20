# Read-only compatibility gates

Canonical inputs:
- `api/openapi.yaml` defines HTTP responses.
- `stealthbridge-contracts/integrations/public-soroban-interface.v1.json` defines source-only registry methods.
- `stealthbridge-contracts/deployments/testnet/manifest.json` remains undeployed.

Release checks:
1. Pin an audited contracts commit SHA and compare local manifest and interface snapshots.
2. Validate `/v1/network`, `/v1/capabilities`, `/v1/contracts`, `/v1/corridors/page`, and `/ready` against the OpenAPI contract.
3. Exercise malformed JSON, 502/503 dependency failures and rejected write methods.
4. Check SDK runtime decoders and frontend same-origin proxy against the same schema revision.
5. Fail the release if payment execution becomes enabled or deployment evidence is absent.

Matching source files do not establish on-chain deployment. This document does not claim CI automation or live staging acceptance.

Related issues: #9, #10, #13.

## Consent-based C-address recipient preflight

The existing `GET /v1/wallet/contracts/{address}` is a public instance-presence
read, not a counterparty attestation. It requires checksum-valid StrKey input,
a fresh Testnet head, a matching `getLedgerEntries` ledger/key, nonexpired TTL,
and a parsed executable WASM hash when present. The endpoint now forces
`Cache-Control: no-store` for both success and error responses. Consumers
must never substitute a cached observation or infer smart-account authority,
compatible token handling, private-payment capability or permission to settle.
No schema, signing API, state transition or payment handler was added.
