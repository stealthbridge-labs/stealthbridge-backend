# StealthBridge Platform Expansion Charter

**Status: architecture and SDK foundation only.** No payments, privacy proofs, payout providers, Testnet contract deployments, mainnet readiness, licensed operations or external partnerships are implied by this proposal.

## Product thesis
StealthBridge evolves from a cross-border private-payment prototype into a **configurable confidential-finance platform** on Stellar. Privacy is a deliberate, disclosed capability, not an unconditional marketing claim. Business workflows are multi-tenant; developer APIs are versioned; local fiat payout depends on separately approved providers and jurisdictions.

## Product surfaces
| Audience | Products | First independently testable slice | Gated future capability |
|---|---|---|---|
| Individuals | Send, receive, self-custody wallet links, payment status, recoverability | Watch-only Testnet discovery, wallet network status, corridor eligibility | Private transfers, recipient claims, regulated fiat payout |
| Businesses | Treasury, payable/receivable requests, batch payroll, counterparty book, maker-checker approvals | Read-only org dashboard, review queues and exact-value journal | Signed batches, partner payout, privacy-aware reconciliation |
| Developers | Typed TS SDK, server APIs, sandbox, webhook signatures, idempotent requests | Read-only SDK, strict release capability gates, API examples | Versioned write APIs, managed attestations, operational SLAs |
| Partners | Corridor operators, licensed off-ramps, issuers, compliance partners | Disabled corridor onboarding and evidence inventory | Approval-gated routing, policy attestation, signed callbacks |

## Core services and responsibility boundaries
1. **Identity and authorization:** Wallet-origin/network-bound challenge, organization roles, workload API keys and scoped service accounts. Wallet connection alone is not permission to move assets.
2. **Corridor registry and routing:** Currency/asset/chain identification, supported countries, quote-source provenance, residency and license restrictions, freshness and fee disclosure. Never fabricate quotes or exchange partners.
3. **Payment orchestration:** Exact minor-unit accounting, client-provided idempotency key, signed expiring quote, durable outbox/inbox, approval graph, cancellation semantics and retry-safety.
4. **Privacy adapter interface:** Explicit `public`, `amount-confidential`, or `counterparty-private` mode with independent proof capability/evidence. The browser or wallet owns private witnesses and keys; server stores the minimum required evidence.
5. **Compliance and disclosures:** Regulated partner verification, local legal analysis, sanctions/AML screening where applicable, recorded access to selective disclosure, retention and privacy impact assessment. Never call a hash a substitute for compliance.
6. **Operations:** Dedicated ledger observer, reconciliation against *both* final chain status and independent partner payout acknowledgement, trace IDs, metric alerts, disaster recovery and staged rollout controls.

## Release capability model
A module is accessible only if its audience is authorized, the requested network is supported, and an evidence reference is present. Missing or duplicated entries fail closed. The SDK's `assertModuleAvailable` is a **client guardrail**, not an authentication, on-chain authorization or proof verification system; all safety checks must be repeated on trusted services.

**Mainnet requires additional independent release decision**: formal threat modeling, cryptography review, audited contracts and dependencies, third-party review of upgrades, verified deployment bytecode and keys, on-chain and partner operational tests, funds-flow legal analysis, compliance controls, penetration tests, custody/key recovery analysis, monitoring, incident response, governance sign-off and guarded gradual rollout. A Testnet badge is never automatically promoted to Mainnet.

## Engineering sequencing
- **P0:** Capability manifests and negative tests; authenticated organization model; truthful feature-disabled UI; environment isolation; documentation of evidence.
- **P1:** Wallet challenge + account switching, business role checks and read-only reconciliation views; SDK runtime schemas and public sandbox; independent Testnet deployments.
- **P2:** Explicit approvals/batches with no public execution; privacy adapter feasibility using audited or reviewable upstream primitives; exact quote bindings; webhook replay protection.
- **P3:** Approved Testnet execution only after independent proof/issuer/partner evidence. Mainnet release is a separate human authorization milestone.

## Scale constraints
Tenant-bound IDs and queries; partitioned journal/event tables with bounded retention; monotonic observer checkpoints; event-driven durable queues with deduplication; idempotent workers; rate limits per client/tenant; keyed pagination; backpressure; horizontal stateless API replicas; database connection budgets; encrypted secrets; region-specific data storage and privacy-by-design metrics that never expose witnesses. Test 10x concurrency, RPC degradation, duplicate and out-of-order callbacks, and restoration from backups before launch.

## Anti-goals
No homegrown unaudited ZK circuits presented as secure; no synthetic success claims, anonymous transfer guarantees, unlicensed fiat payout, support for unrestricted arbitrary tokens, or cross-border fund movement from frontend state alone.

## Source references
- Stellar privacy implementation cautions: https://developers.stellar.org/docs/build/apps/privacy
- Stellar ZK primitives: https://developers.stellar.org/docs/build/apps/zk
- Soroban upgrades and safeguards: https://developers.stellar.org/docs/build/guides/conventions/upgrading-contracts
