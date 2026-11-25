-- Passkey-authorized smart-account payments. A row records what the customer
-- was asked to authorize (the exact auth entry and its payload) and what the
-- chain later proved. `confirmed` is written only after the executed envelope
-- matched the authorized transfer and RPC reported SUCCESS.
CREATE TABLE IF NOT EXISTS account_smart_account_payments (
 id UUID PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 contract_address VARCHAR(56) NOT NULL CHECK(contract_address ~ '^C[A-Z2-7]{55}$'),
 destination VARCHAR(56) NOT NULL CHECK(destination ~ '^[GC][A-Z2-7]{55}$'),
 asset VARCHAR(69) NOT NULL CHECK(length(asset) BETWEEN 3 AND 69),
 asset_contract VARCHAR(56) NOT NULL CHECK(asset_contract ~ '^C[A-Z2-7]{55}$'),
 amount_stroops BIGINT NOT NULL CHECK(amount_stroops > 0),
 network_passphrase VARCHAR(64) NOT NULL,
 auth_entry_xdr TEXT NOT NULL CHECK(length(auth_entry_xdr) BETWEEN 8 AND 16384),
 signature_payload CHAR(64) NOT NULL CHECK(signature_payload ~ '^[0-9a-f]{64}$'),
 auth_nonce BIGINT NOT NULL,
 expiration_ledger BIGINT NOT NULL CHECK(expiration_ledger > 0),
 fee_estimate_stroops BIGINT NOT NULL CHECK(fee_estimate_stroops >= 0),
 status VARCHAR(16) NOT NULL CHECK(status IN('prepared','submitting','submitted','confirmed','failed','expired')),
 tx_hash CHAR(64) UNIQUE CHECK(tx_hash IS NULL OR tx_hash ~ '^[0-9a-f]{64}$'),
 ledger BIGINT CHECK(ledger IS NULL OR ledger > 0),
 error_code VARCHAR(48),
 created_at_unix BIGINT NOT NULL CHECK(created_at_unix > 0),
 updated_at_unix BIGINT NOT NULL CHECK(updated_at_unix >= created_at_unix),
 UNIQUE(contract_address, auth_nonce),
 FOREIGN KEY(account_address, contract_address)
   REFERENCES account_smart_account_deployments(account_address, contract_address) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS account_smart_account_payments_by_account
 ON account_smart_account_payments(account_address, created_at_unix DESC);

CREATE TABLE IF NOT EXISTS account_smart_account_payment_receipts (
 nonce UUID PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
