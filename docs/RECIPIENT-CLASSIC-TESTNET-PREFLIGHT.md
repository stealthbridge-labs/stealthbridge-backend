# Classic G-account recipient preflight: read-only

A valid StrKey checksum and the existence of a live classic account are different facts. The new GET /v1/wallet/classic-recipient/{G-address} rejects malformed checksums, verifies a fresh Testnet RPC head and calls fixed https://horizon-testnet.stellar.org/accounts/{G-address} with no redirects and a capped 64 KiB response. A Horizon 404 means the account was not found; unexpected errors fail closed. Both id and account_id must match the exact requested account.

The minimal response omits balances, signer metadata, trustlines and other public account data. Client validation binds exact address, network, source, fresh timestamp and false ownership, asset acceptance and payment execution flags. A successful account lookup does not verify ownership, supported assets, usable custody, liquidity, confidentiality or payout ability.

No live payments, signing, database writes or recipient names enter this endpoint. Independent issuer, payment partner, account policy and compliance gates remain.
