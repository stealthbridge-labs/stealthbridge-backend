# Observability source-to-interface integration gate

StealthBridge's Testnet observability workspace is now a connected three-repository feature, not a visual mock:

| Boundary | Pinned source | Responsibility |
|---|---|---|
| Backend Rust / Axum | Current PR `api/openapi.yaml`, `src/server.rs` | Public **GET only** Testnet RPC, database checkpoint, dependency readiness, undeployed contract source metadata, disabled capabilities |
| SDK | `3bf69c478461958026839832627042bc3f1b9577` | Strict comparison of public ledger sequence **and hash**, observer lag, missing/stale readings, source-only capability invariants, sanitized bounded evidence |
| Frontend | `733f6ee73c1b00d568f8904c46975f79fe060a80` | Same-origin GET proxy, five independently guarded runtime requests, accessible in-session timeline, deliberate user-triggered evidence copy |
| Soroban contracts | Canonical `not-deployed` Testnet manifest and source-only public ABI | No falsely claimed contract deployment or private transfers |

GitHub Actions `.github/workflows/observability-parity.yml` uses pinned, immutable **public** Git source references, not mutable `main` URLs or non-reviewable downloads. The Python source-only gate validates that the frontend's assessment module is byte-for-byte identical to SDK source, that its UI invokes all five typed backend read routes, that Rust has GET handlers for all five API paths and that `/v1/settlements` remains `post(disabled)`. It explicitly fails a frontend proxy POST, missing or mutating routes, altered SDK source, missing hash comparison or omitted observer read.

**Security and provenance limits:** This check does not deploy services, execute an RPC query, verify a Soroban WASM, confirm a private token proof, connect Freighter, or authorize a bank payout. An API schema or source-code parity badge cannot change `payments_enabled=false`. For live release validation use the independently protected Vercel/Testnet workflows, operator database migrations and separate audited confidentiality verification.

If the frontend or SDK changes, review the changed source and functional tests, update the exact pinned source SHA in this workflow in a new PR, and require the full regression suite to pass. Never silently switch to a floating branch to avoid drift failures.
