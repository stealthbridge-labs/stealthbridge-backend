# Provider-neutral webhook authentication and inbox operations

**Status: foundation only — no live callback endpoint, partner credentials, fiat payout or settlement transition enabled.** An HTTP request must **never** select its own trusted organization/provider identity. Configure the tenant UUID, provider slug, signing keyring and allowed webhook deployment origin outside the incoming body/header, in reviewed secret-bearing operator configuration. The current Rust library does not expose an inbound payout route.

## Signed envelope and replay boundary

`verify_scoped_event(raw,timestamp,signature_hex,tenant,provider,key_id,keyring,now_unix)` uses **HMAC-SHA256** and `Mac::verify_slice` over exact bytes:

```text
"stealthbridge-provider-callback-v2\n"
+ 16-byte organization UUID + "\n"
+ trusted provider ASCII slug + "\n"
+ trusted key id + "\n"
+ decimal UTC timestamp + "\n"
+ exact raw JSON request body
```

The provided `key_id` only selects a **reviewed configured key**; it is not itself an authentication factor. The handler must select trusted tenant and provider from its authorized routing configuration, not from a body field. A valid signature for tenant A or provider X cannot authenticate tenant B or provider Y, even if both tenants mistakenly share a secret. The signed envelope allows only `event_id` and `event_type`; an embedded `tenant`, `provider`, `payout_reference`, arbitrary instructions or identity payload is rejected.

Verify before deserializing. Cap raw body at **64 KiB**; accept numeric timestamps of at most 20 characters, within **±300 seconds** of server UTC. Require a **32-byte minimum secret**, keyring size at most **8**, unique reviewed key IDs, strict key validity interval and explicit key retirement. Do not echo signatures, HMAC keys, callback URLs with secrets or notification bodies into logs. Use HTTPS, an upstream body-size cap and request timeout.

An accepted `ScopedVerifiedEvent` binds the trusted tenant/provider/key to a content SHA-256 digest; pass that exact struct into `record_scoped_event`, not a caller-provided organization ID. The database unique key **(organization_id,provider,event_id)** means duplicates return `Duplicate` only when the digest and event type also match. A collision with different authenticated payload is rejected. A repeated message from a different tenant must verify under that tenant's own scoped signature before it could enter that tenant's inbox.

**No event consumption or out-of-order payout transition is performed.** A `payout.completed` arriving before `payout.pending` is merely an authenticated metadata receipt, not evidence to mark a transfer complete. When real providers are approved, a separate consumer must bind each event to a verified payout reference and expected prior state, use row locks plus tenant-scoped transactional state transitions, document retention, archive/dedup windows and rebuild the idempotent event journal. No such consumer runs here.

## Key rotation and operations

Provision one active key and, during planned rotation, one previous key with explicit `valid_from_unix`/`valid_until_unix` for a short overlap. The key ID is part of the authenticated MAC input; rewriting it invalidates the signature. A delivery timestamp outside that key's valid period fails. A key past its not-after time fails **even for an old delayed callback**; have a manually reviewed replay process rather than extending expired keys automatically. Record key ID and opaque security metrics without recording the secret. Revoke compromised keys immediately; purge from every instance's configuration and audit previously received event IDs/digests.

## Required tests and deployment gates

Run backend Rust tests and isolated PostgreSQL integration suites. Negative fixtures cover: bad signature, tampered raw body, weak key, timestamp skew, wrong tenant/provider/key, duplicated key IDs, expired rotation key, invalid callback envelope, duplicate event ID and conflicting event ID content. CI must show failing cases are **rejected** and an accepted identical retry is not applied twice. Configure the inbox table with scoped retention/backup privileges; a final provider-specific threat review is required before introducing a live HTTP endpoint.

Signing or delivering a notification in this test library is **not** authorization to debit funds, mutate payout state, create an external remittance or claim proof of private asset settlement.
