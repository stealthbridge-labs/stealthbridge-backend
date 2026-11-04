-- Optional, operator-migrated Testnet-only opaque customer draft vault.
-- Ciphertexts are generated client-side; never collect password, recipient,
-- amount, corridor, private witness, or smart-account credential columns.
CREATE TABLE IF NOT EXISTS customer_ciphertext_drafts (
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 draft_id UUID NOT NULL,
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 envelope JSONB NOT NULL CHECK(jsonb_typeof(envelope)='object' AND octet_length(envelope::text)<=4096),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(account_address,draft_id)
);
CREATE INDEX IF NOT EXISTS customer_ciphertext_drafts_recent
 ON customer_ciphertext_drafts(account_address,updated_at DESC,draft_id);
CREATE TABLE IF NOT EXISTS customer_ciphertext_draft_receipts (
 nonce UUID PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 operation VARCHAR(8) NOT NULL CHECK(operation IN('PUT','DELETE')),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS customer_ciphertext_draft_receipts_account
 ON customer_ciphertext_draft_receipts(account_address,recorded_at DESC);
COMMENT ON TABLE customer_ciphertext_drafts IS
 'Opaque browser-encrypted Testnet payment planning drafts; no keys or plaintext. Not an executed payment, provider quote, compliance decision or smart account.';
COMMENT ON TABLE customer_ciphertext_draft_receipts IS
 'Single-use signed BFF mutation receipts; retention/replay policy must be reviewed before enabling customer draft sync.';
