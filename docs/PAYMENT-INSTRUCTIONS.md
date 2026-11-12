# Encrypted payment instruction foundation

This is an account-owned **planning** lifecycle, not a quote, approval, settlement,
financial ledger or confidential on-chain rail. The wallet's signed sign-in grants
access to workspace records only. Business-kind instructions remain personal
account records; organizational approval and money-moving authority are separate.

## Integrated boundary

Authenticated Next.js cookie session → same-origin account BFF → domain-separated
HMAC request → Rust policy checks → PostgreSQL record + revision event + one-use
receipt → strict SDK/GUI response validation. Existing public settlement POST
continues to return disabled. No on-chain contract, fee or smart account is changed.

| Request | Implemented behavior |
| --- | --- |
| `GET /v1/account/instructions` | Returns up to 50 encrypted account-owned records; expiry derived at observation time. No read mutation. |
| `PUT /v1/account/instructions` | Creates an immutable record by caller-generated UUID. Same canonical payload/ID retries succeed without duplicate rows/events. Different payload conflicts. |
| `POST /v1/account/instructions` | Explicit cancellation `{id, expected_revision: 1}`. Scoped row lock, expiry/version check, atomic event. Repeated cancellation with a fresh request nonce is idempotent. |

The browser calls `/api/account/instructions`, not the private Rust bridge directly.
Every write needs a valid wallet session, matching Origin/Host, JSON and a bounded
body. BFF/backend both require `STEALTHBRIDGE_PAYMENT_INSTRUCTIONS_ENABLED=true`.
No query parameters are accepted by the BFF. Responses are private/no-store.

## Authentication and authorization

Rust accepts only the configured server-side account bridge secret (at least 32
bytes). HMAC-SHA256 signs the following UTF-8 text, including its trailing newline:

```
stealthbridge-payment-instructions-v1
METHOD
/v1/account/instructions
CANONICAL_G_ADDRESS
ISSUED_AT_UNIX
NONCE
BODY_SHA256
```

GET uses empty nonce and digest lines. PUT/POST require a canonical, non-nil UUID
nonce. Timestamp age is at most 30 seconds with at most 5 seconds future skew.
An already-consumed mutation nonce conflicts. Receipts are inserted only for real
state changes, bounding receipt growth to two per instruction. Fresh-nonce retries
of unchanged state do not append receipts/events. Nonce uniqueness also arbitrates
cross-account races. Public G-address syntax alone never establishes identity.

The bridge secret is a service trust boundary, not an external developer API key.
Never distribute it to users or SDK consumers. Browser identity/session verification
is performed by the existing BFF wallet-signature implementation. The existing
cookie sessions expire after two hours; global server-side session revocation and
non-wallet identity options remain separate authentication work.

## Privacy, policy and persistence

Client-side AES-256-GCM, PBKDF2-HMAC-SHA256 (600,000 iterations), random salt/IV and
account/UUID associated data reuse the existing reviewed draft envelope format.
The server enforces envelope bounds and schema, not decryption or payment validity.
It cannot validate a hidden recipient or amount. Passphrases cannot be reset.
A compromised browser/frontend delivery can compromise plaintext and keys.

The server sees public account, selected corridor, route fingerprint, creation and
expiry times, status, ciphertext and its size. This is not traffic unlinkability.
The route fingerprint binds the UUID, country pair, asset, issuer and rail through
an unambiguous public SHA-256 format, pinned by a shared SDK/Rust vector. Enabled
catalog metadata is locked against changes during initial registration. It is not
liquidity, an FX quote, issuer approval, KYC or verified privacy. Every future
financial operation must independently revalidate these prerequisites.

Account advisory locks serialize creation/cancellation, prevent quota races and
bind each lookup to account + instruction ID. Row/history/receipt writes commit
or roll back together. Records cannot be edited or resurrected after cancellation;
expiry is checked server-side. Never infer bank delivery from these states.

## Release and rollback

Migration `202611120001_customer_payment_instructions.sql` adds three tables only.
It is optional to existing readiness, so unrelated catalog/observer routes continue
to work before this feature is released. Production does not auto-run migrations.
See [the prepared release record](PAYMENT-INSTRUCTIONS-RELEASE.md).

Deploy code with flags false, apply the reviewed migration after explicit approval,
then enable the matching backend/BFF flags with their existing bridge secret. Verify
an unauthenticated request is refused and a real customer sign-in can read its own
empty directory. A real instruction needs a legitimately configured corridor; never
seed fictional production corridors or create test customer payments to claim readiness.
Rollback by disabling the two flags and reverting code if needed. Retain tables,
SQLx marker and encrypted records; no destructive rollback is prescribed.

## Validation

Real PostgreSQL tests cover concurrent saves, account isolation, replay, payload
conflict, expired cancellation, changed route configuration, event-write rollback
and bounded retry receipts. A real HTTP test exercises signed Rust requests through
PostgreSQL; with `STEALTHBRIDGE_SDK_ENTRY` it validates actual responses in the built
SDK. Browser fixtures use real ephemeral Ed25519 sign-in and real encryption but
intercept storage/catalog responses. They are not a deployed end-to-end payment test.
