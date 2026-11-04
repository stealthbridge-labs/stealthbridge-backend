# Customer-owned encrypted payment drafts — guarded rollout

This is an optional, **ciphertext-only** storage feature for customer-owned
payment planning. It is not custody, financial execution, confidential settlement,
asset support, proof verification, compliance approval or a deployed smart wallet.

## Storage contract

`202611040001_customer_ciphertext_vault.sql` adds `customer_ciphertext_drafts`
(max eight per classic wallet account, bounded 4 KB JSON envelope per record)
and `customer_ciphertext_draft_receipts` (one-use mutation nonces). The only
cleartext database identifiers are the signing G-address, random draft UUID,
revision, timestamps and a one-use audit nonce; no corridor, recipient, amount,
reference, passphrase, verifier witness, ZK key or decrypted draft exists in
PostgreSQL columns. The browser uses AES-256-GCM and PBKDF2-HMAC-SHA256 with
600,000 iterations, independently random salt and IV per draft.

`GET /v1/account/drafts` returns only bounded encrypted records. `PUT` and
`DELETE` require an exact method/path/account/timestamp/body-digest HMAC signed
by StealthBridge's authenticated Next.js BFF, fresh 30-second window and one-use
UUID nonce. Mutations use per-account advisory-locked transactions and optimistic
revision checks. A second account cannot access another account's rows. No
password crosses the BFF, and no backend function decrypts stored bytes.

The API is **503 by default**. Both frontend and backend must explicitly set
`STEALTHBRIDGE_CUSTOMER_DRAFTS_ENABLED=true` after the protected migration is
reviewed and applied. The shared account bridge secret (at least 32 bytes)
remains server-only. Use existing restricted TLS/database and signer session
gates. Never enable this feature from a public URL or an unauthenticated client.

## Deployment without breaking existing Testnet services

1. Run `python3 scripts/validate_migrations.py` and unit tests. Review the
   migration as additive. Do **not** apply it automatically on request handling.
2. Apply the SQLx migration in a protected, isolated staging database after
   review and verify `customer_ciphertext_drafts` exists. Test account isolation,
   replay, CAS revision, bounded response, backup recovery and backup deletion.
3. Verify the existing 12-migration readiness contract remains green. This
   thirteenth migration is **optional** until release, so absence of the vault
   cannot take down unrelated `/ready`, public corridors and observer reads.
4. After successful staging and security review, apply the migration through the
   protected production SQLx workflow, then enable both matching feature flags.
5. Verify GET, PUT, DELETE from a real signed-in account, and confirm disabled
   financial capability flags. Retention/DSAR procedures for encrypted blobs,
   receipts and user deletion need operator review before rollout.

Until all steps are verified, `503` is the expected ciphertext-sync state;
customers can still create encrypted backup files entirely in their browser.

## Known limitations

No mainnet or wallet transaction is allowed. A customer must retain a strong,
unique passphrase: loss prevents recovery, and weak passphrases remain vulnerable
to offline guessing if ciphertext leaks. JavaScript browser security and third-
party scripts are in the threat model; malicious code loaded into the tab can
read plaintext during local editing. Passkey/WebAuthn PRF wrapping, more scalable
multi-device recovery, encryption key rotation, incident procedures and external
cryptographic review remain future work. Ciphertext authenticated integrity does
not establish ZK confidentiality of any future on-chain payment.
