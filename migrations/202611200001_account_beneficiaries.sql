-- Account-owned saved recipients / beneficiaries for Personal and Business planning.
-- Never implies on-chain verification, KYB/KYC approval, or financial execution authority.
CREATE TABLE IF NOT EXISTS account_beneficiaries (
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 id UUID NOT NULL,
 recipient_address VARCHAR(69) NOT NULL CHECK(length(recipient_address) BETWEEN 56 AND 69),
 recipient_kind VARCHAR(32) NOT NULL CHECK(recipient_kind IN('classic','muxed-classic','contract','muxed-contract')),
 label VARCHAR(48) NOT NULL CHECK(length(btrim(label)) BETWEEN 1 AND 48),
 flow VARCHAR(16) NOT NULL CHECK(flow IN('personal','business')),
 created_at_unix BIGINT NOT NULL CHECK(created_at_unix > 0),
 updated_at_unix BIGINT NOT NULL CHECK(updated_at_unix >= created_at_unix),
 PRIMARY KEY(account_address, id),
 UNIQUE(account_address, recipient_address, flow)
);

CREATE INDEX IF NOT EXISTS account_beneficiaries_account_updated_idx
 ON account_beneficiaries(account_address, updated_at_unix DESC, id DESC);

CREATE TABLE IF NOT EXISTS account_beneficiary_receipts (
 nonce UUID PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 operation VARCHAR(8) NOT NULL CHECK(operation IN('PUT','DELETE')),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE account_beneficiaries IS
 'Account-owned beneficiary labels and canonical G/M/C/W addresses stored in PostgreSQL. Never implies ownership or payment readiness.';
