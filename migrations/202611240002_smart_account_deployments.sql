-- Relayed smart-account deployments: a row exists only after the relayer
-- submitted a factory create_account, and status becomes 'deployed' only
-- after Stellar RPC reports SUCCESS. Unlike account_smart_accounts (a
-- customer-asserted binding), these rows are backed by an on-chain tx.
CREATE TABLE IF NOT EXISTS account_smart_account_deployments (
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 contract_address VARCHAR(56) NOT NULL CHECK(contract_address ~ '^C[A-Z2-7]{55}$'),
 label VARCHAR(48) NOT NULL CHECK(length(btrim(label)) BETWEEN 1 AND 48),
 owner_public_key CHAR(130) NOT NULL CHECK(owner_public_key ~ '^04[0-9a-f]{128}$'),
 credential_id VARCHAR(256) NOT NULL CHECK(length(credential_id) BETWEEN 16 AND 256 AND credential_id ~ '^[A-Za-z0-9_-]+$'),
 rp_id VARCHAR(253) NOT NULL CHECK(length(rp_id) BETWEEN 3 AND 253),
 guardian_address VARCHAR(56) CHECK(guardian_address IS NULL OR guardian_address ~ '^G[A-Z2-7]{55}$'),
 factory_address VARCHAR(56) NOT NULL CHECK(factory_address ~ '^C[A-Z2-7]{55}$'),
 network VARCHAR(16) NOT NULL CHECK(network = 'testnet'),
 tx_hash CHAR(64) NOT NULL UNIQUE CHECK(tx_hash ~ '^[0-9a-f]{64}$'),
 status VARCHAR(16) NOT NULL CHECK(status IN('submitted','deployed','failed')),
 ledger BIGINT CHECK(ledger IS NULL OR ledger > 0),
 created_at_unix BIGINT NOT NULL CHECK(created_at_unix > 0),
 updated_at_unix BIGINT NOT NULL CHECK(updated_at_unix >= created_at_unix),
 PRIMARY KEY(account_address, contract_address)
);
CREATE INDEX IF NOT EXISTS account_smart_account_deployments_by_account
 ON account_smart_account_deployments(account_address, created_at_unix DESC);

CREATE TABLE IF NOT EXISTS account_smart_account_deploy_receipts (
 nonce UUID PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
