-- Additive tables for Smart Account bindings and Business Invoices, Webhooks, and API Credentials.
-- Preserves non-custodial boundaries and never stores plaintext API secrets or webhook keys.

CREATE TABLE IF NOT EXISTS account_smart_accounts (
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 contract_address VARCHAR(56) NOT NULL CHECK(contract_address ~ '^C[A-Z2-7]{55}$'),
 label VARCHAR(48) NOT NULL CHECK(length(btrim(label)) BETWEEN 1 AND 48),
 guardian_address VARCHAR(56) CHECK(guardian_address IS NULL OR guardian_address ~ '^G[A-Z2-7]{55}$'),
 recovery_delay_ledgers INTEGER NOT NULL CHECK(recovery_delay_ledgers BETWEEN 100 AND 100000),
 webauthn_credential_id VARCHAR(128) CHECK(webauthn_credential_id IS NULL OR length(btrim(webauthn_credential_id)) BETWEEN 16 AND 128),
 created_at_unix BIGINT NOT NULL CHECK(created_at_unix > 0),
 updated_at_unix BIGINT NOT NULL CHECK(updated_at_unix >= created_at_unix),
 PRIMARY KEY(account_address, contract_address)
);

CREATE TABLE IF NOT EXISTS account_smart_account_receipts (
 nonce UUID PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 operation VARCHAR(8) NOT NULL CHECK(operation IN('PUT','DELETE')),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS business_invoices (
 organization_id UUID NOT NULL,
 id UUID NOT NULL,
 invoice_number VARCHAR(48) NOT NULL CHECK(length(btrim(invoice_number)) BETWEEN 2 AND 48),
 counterparty_name VARCHAR(64) NOT NULL CHECK(length(btrim(counterparty_name)) BETWEEN 2 AND 64),
 recipient_address VARCHAR(69) NOT NULL CHECK(length(recipient_address) BETWEEN 56 AND 69),
 asset_code VARCHAR(12) NOT NULL CHECK(asset_code IN('XLM','USDC','EURC')),
 amount_stroops BIGINT NOT NULL CHECK(amount_stroops > 0),
 due_at_unix BIGINT NOT NULL CHECK(due_at_unix > 0),
 status VARCHAR(24) NOT NULL CHECK(status IN('draft','issued','settled_testnet','cancelled')),
 privacy_mode VARCHAR(32) NOT NULL CHECK(privacy_mode IN('public-testnet','private-payments-groth16','confidential-token')),
 created_by VARCHAR(56) NOT NULL CHECK(created_by ~ '^G[A-Z2-7]{55}$'),
 created_at_unix BIGINT NOT NULL CHECK(created_at_unix > 0),
 updated_at_unix BIGINT NOT NULL CHECK(updated_at_unix >= created_at_unix),
 PRIMARY KEY(organization_id, id),
 UNIQUE(organization_id, invoice_number)
);

CREATE INDEX IF NOT EXISTS business_invoices_org_updated_idx
 ON business_invoices(organization_id, updated_at_unix DESC, id DESC);

CREATE TABLE IF NOT EXISTS business_invoice_receipts (
 nonce UUID PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 operation VARCHAR(8) NOT NULL CHECK(operation IN('PUT','DELETE')),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS business_webhooks (
 organization_id UUID NOT NULL,
 id UUID NOT NULL,
 endpoint_url VARCHAR(256) NOT NULL CHECK(endpoint_url ~ '^https://[^/[:space:]]+'),
 subscribed_events VARCHAR(256) NOT NULL CHECK(length(btrim(subscribed_events)) BETWEEN 3 AND 256),
 secret_prefix VARCHAR(16) NOT NULL CHECK(length(secret_prefix) BETWEEN 8 AND 16),
 secret_sha256 CHAR(64) NOT NULL CHECK(secret_sha256 ~ '^[a-f0-9]{64}$'),
 enabled BOOLEAN NOT NULL DEFAULT true,
 created_by VARCHAR(56) NOT NULL CHECK(created_by ~ '^G[A-Z2-7]{55}$'),
 created_at_unix BIGINT NOT NULL CHECK(created_at_unix > 0),
 updated_at_unix BIGINT NOT NULL CHECK(updated_at_unix >= created_at_unix),
 PRIMARY KEY(organization_id, id)
);

CREATE TABLE IF NOT EXISTS business_webhook_receipts (
 nonce UUID PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 operation VARCHAR(8) NOT NULL CHECK(operation IN('PUT','POST','DELETE')),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS business_api_credentials (
 organization_id UUID NOT NULL,
 id UUID NOT NULL,
 label VARCHAR(48) NOT NULL CHECK(length(btrim(label)) BETWEEN 2 AND 48),
 scopes VARCHAR(128) NOT NULL CHECK(length(btrim(scopes)) BETWEEN 4 AND 128),
 key_prefix VARCHAR(20) NOT NULL CHECK(length(key_prefix) BETWEEN 8 AND 20),
 secret_sha256 CHAR(64) NOT NULL CHECK(secret_sha256 ~ '^[a-f0-9]{64}$'),
 created_by VARCHAR(56) NOT NULL CHECK(created_by ~ '^G[A-Z2-7]{55}$'),
 created_at_unix BIGINT NOT NULL CHECK(created_at_unix > 0),
 revoked_at_unix BIGINT CHECK(revoked_at_unix IS NULL OR revoked_at_unix >= created_at_unix),
 PRIMARY KEY(organization_id, id)
);

CREATE TABLE IF NOT EXISTS business_api_credential_receipts (
 nonce UUID PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 operation VARCHAR(8) NOT NULL CHECK(operation IN('POST','DELETE')),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
