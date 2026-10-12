# Serverless API and observer worker boundaries

The HTTP API is request-scoped. A serverless invocation must not start a durable ledger observer, retry worker, provider callback consumer, or database migration.

A separately supervised worker is required for any future observer. It must use an exclusive checkpoint lease, bounded batch size, restart-safe cursor, and deterministic duplicate-observation tests. No such worker is declared production-ready by this document.

Deployment operators must independently validate Testnet RPC reachability, PostgreSQL migration readiness, source-only contract discovery, and disabled settlement writes. HTTP readiness is not proof of privacy or payout capability.

Never add signing keys, transfer execution, mainnet endpoints, or real-money movement to this acceptance path.

Related issues: #9, #11.
