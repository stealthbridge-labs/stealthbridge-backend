# Organization authentication RFC — Testnet-only, no financial capabilities

**Status:** library and CI fixture only. There is no public login or tenant endpoint, no session cookies, wallet signing request, payout authorization, mainnet or money transfer. Deployment requires a separate protocol and multi-signature review.

## Threat model and architecture

1. **Untrusted client asserts only a classic Stellar G-address.** The backend validates the StrKey CRC16-XModem checksum but never treats address validity as authentication. A verified *active* organization member can obtain an expiring challenge for a trusted configured domain. This lookup reveals membership existence, so a future public challenge endpoint must use uniform errors, abuse throttles, and monitoring.
2. A challenge is bound to **domain, Stellar Testnet passphrase, organization UUID, public account address, a 256-bit non-repeating UUID-v4-derived nonce, issued timestamp and expiry**. Format is UTF-8 with exact line breaks and `StealthBridge organizational login v1\n` prefix. Lifetime: **300 seconds**. Do not sign a challenge generated for any other origin. The provided `now_unix` must be a **trusted server time**, never an HTTP field.
3. The client signs the exact challenge bytes using the corresponding **Ed25519 classic account key**. This library verifies a strict Ed25519 signature using `ed25519-dalek` and the account's decoded 32-byte key. **It does not support Stellar multisignature threshold accounts, contract wallets, delegated signers, muxed addresses, SEP-10 transaction-challenge semantics, hardware-wallet-specific message transformations or Freighter-specific message preimages.** Those must be researched/implemented before exposing sign-in as a real user feature. This custom challenge is not advertised as SEP-10 compliant.
4. Only a **SHA-256 nonce digest** is stored in `organization_login_challenges`, with tenant/account/domain, issuance and expiry. No signed message, signature, private key or proof witness is persisted. Wrong/forged signatures cannot consume a legitimate challenge. The successful verified signer atomically consumes its one-use row with conditional SQL UPDATE, so racing requests never authenticate twice. PostgreSQL migration `202610130001_login_challenges.sql` enforces a fixed 300-second validity period. Periodic controlled pruning after the retention window will be required before public launch.
5. The verified identity is converted to a **separate short-lived, HMAC-SHA256 authenticated 15-minute token**, bound to `organization_read_only`, trusted domain and Testnet. Tokens are not wallet signatures or payment authorizations. Session signing secrets must be generated server-side with ≥32 bytes of entropy and stored only in a managed secret vault; never derive from wallet seed material or echo into logs. All session claims are **untrusted until MAC verification**. A token remains visible to its holder (bearer credential): never put it in a URL or expose it to marketing routes.
6. `require_read_session` verifies the MAC, expiry, route's trusted expected organization, required permission **and current PostgreSQL organization/member status on every request**. Revoked or suspended members cannot continue using otherwise-valid tokens. Authorization for any future financial operation would additionally require transactional row locks, separation of duties, proof/quote validation, a reviewed step-up signature and independent partner controls. **No such operation exists here.**

## Actor and attack matrix

| Threat | Defensive property | CI evidence |
| --- | --- | --- |
| Account enumeration | Membership queried only in an unexposed library; future public boundary needs uniform errors + throttling | Interface remains non-routable |
| Wrong chain/network | Canonical Testnet passphrase is inside signed message and session | Unit signed-message assertion |
| Wrong tenant | Organization UUID inside signed challenge and session; SQL queries scoped to organization | Cross-tenant PostgreSQL fixture |
| Phishing domain | Exact server-configured domain inside signed bytes and MAC; domain format restricted | Wrong-domain signature/session fixtures |
| Modified challenge or wrong signer | Strict Ed25519 public account key verification | Tampered-signature test |
| Nonce replay, concurrent requests | Unique UUID + one-use SQL UPDATE with `consumed_at_unix IS NULL` predicate | Rejected second use; DB conditional update |
| Expired challenge or session | Fixed 300/900-second windows and trusted server clock | Expired fixture tests |
| Forged session / session theft | Server HMAC secret and short-lived bearer; never log or serialize secret | Wrong-secret/tampered-token test |
| Cross-tenant role confusion | DB tenant-specific `authorize_member` after cryptographic checks | Revoked/wrong-tenant/insufficient-role tests |
| Lost/revoked wallet/member | Revalidate membership on each authenticated request | Mid-session revocation fixture |
| Multisig and unsupported wallet semantics | Fail closed: this is **single-key classic account** only; no public endpoint | Not covered by real Freighter devices; release blocker |

## Frontend/SDK contract before public integration

A future operator-approved sign-in interface should use an audited, standardized protocol (prefer Stellar [SEP-10](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md) where applicable) or a jointly reviewed byte-for-byte Freighter `signMessage` message profile. Do not make the UI request a private key/seed phrase. An authorization response should never grant payments based on wallet connection alone. Future frontend code must show network change, user denial, expiry/replay and disconnected states; never silently change the tenant from a user-supplied HTTP header. SDK package can only expose the verified canonical challenge after its compatibility tests and official-wallet signature verification succeed.

## Run the tests and release criteria

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
# CI supplies an isolated PostgreSQL 16 DATABASE_URL
cargo test --test organization_login_integration
```

**Not yet production-ready:** no public auth endpoint or auth cookie middleware, no wallet-device acceptance, no account multisig semantics, no global abuse throttling, no retention/pruning worker, no compliance/identity verification and no live tenant session. Any of these absent means issue #3 should remain open if its acceptance explicitly requires live organization sign-in.
