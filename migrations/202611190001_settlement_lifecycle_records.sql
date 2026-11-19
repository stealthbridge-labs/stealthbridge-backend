-- Account-owned controlled Testnet settlement lifecycle journal and outbox.
-- Never activates Mainnet, live FX pricing, unverified privacy rails or fiat payouts.
CREATE TABLE IF NOT EXISTS account_settlement_lifecycles (
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 id UUID NOT NULL,
 organization_id UUID,
 instruction_id UUID,
 corridor_id UUID NOT NULL REFERENCES corridors(id) ON DELETE RESTRICT,
 route_fingerprint CHAR(64) NOT NULL CHECK(route_fingerprint ~ '^[0-9a-f]{64}$'),
 idempotency_key VARCHAR(128) NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),
 request_sha256 CHAR(64) NOT NULL CHECK(request_sha256 ~ '^[0-9a-f]{64}$'),
 asset_code VARCHAR(32) NOT NULL CHECK(length(asset_code) BETWEEN 1 AND 32),
 asset_issuer VARCHAR(56) CHECK(asset_issuer IS NULL OR asset_issuer ~ '^G[A-Z2-7]{55}$'),
 amount_minor_units BIGINT NOT NULL CHECK(amount_minor_units > 0),
 recipient_address VARCHAR(69) NOT NULL CHECK(length(recipient_address) BETWEEN 56 AND 69),
 recipient_kind VARCHAR(32) NOT NULL CHECK(recipient_kind IN('classic','muxed-classic','contract','muxed-contract')),
 privacy_rail VARCHAR(32) NOT NULL CHECK(privacy_rail IN('private-payments','confidential-token')),
 privacy_rail_verified BOOLEAN NOT NULL DEFAULT FALSE,
 quote_status VARCHAR(32) NOT NULL DEFAULT 'unavailable' CHECK(quote_status IN('unavailable','provider_verified')),
 quote_sha256 CHAR(64) CHECK(quote_sha256 IS NULL OR quote_sha256 ~ '^[0-9a-f]{64}$'),
 policy_commitment_sha256 CHAR(64) CHECK(policy_commitment_sha256 IS NULL OR policy_commitment_sha256 ~ '^[0-9a-f]{64}$'),
 customer_auth_sha256 CHAR(64) CHECK(customer_auth_sha256 IS NULL OR customer_auth_sha256 ~ '^[0-9a-f]{64}$'),
 state VARCHAR(32) NOT NULL CHECK(state IN(
  'instruction_created','corridor_verified','asset_recipient_verified','quote_unavailable','quoted',
  'policy_verified','customer_authorized','privacy_proof_pending','privacy_proof_verified',
  'tx_submitted','chain_finalized','chain_failed','payout_pending','payout_completed',
  'payout_failed','dispute_open','reversal_pending','reversed','reconciled','expired','cancelled'
 )),
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision >= 1),
 expires_at_unix BIGINT NOT NULL CHECK(expires_at_unix > created_at_unix),
 testnet_tx_hash CHAR(64) CHECK(testnet_tx_hash IS NULL OR testnet_tx_hash ~ '^[0-9a-f]{64}$'),
 observed_ledger BIGINT CHECK(observed_ledger IS NULL OR observed_ledger > 0),
 observed_at_unix BIGINT CHECK(observed_at_unix IS NULL OR observed_at_unix > 0),
 chain_status VARCHAR(16) CHECK(chain_status IS NULL OR chain_status IN('SUCCESS','FAILED')),
 provider_event_id VARCHAR(128),
 payout_status VARCHAR(32) NOT NULL DEFAULT 'unavailable' CHECK(payout_status IN('unavailable','pending','completed','failed','reversed')),
 reconciliation_status VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK(reconciliation_status IN('pending','matched','disputed','reversed')),
 last_error_code VARCHAR(64),
 created_at_unix BIGINT NOT NULL CHECK(created_at_unix > 0),
 updated_at_unix BIGINT NOT NULL CHECK(updated_at_unix >= created_at_unix),
 CHECK(expires_at_unix - created_at_unix BETWEEN 300 AND 86400),
 PRIMARY KEY(account_address,id),
 UNIQUE(account_address,idempotency_key)
);

CREATE TABLE IF NOT EXISTS account_settlement_events (
 account_address VARCHAR(56) NOT NULL,
 settlement_id UUID NOT NULL,
 revision INTEGER NOT NULL CHECK(revision >= 1),
 previous_state VARCHAR(32),
 next_state VARCHAR(32) NOT NULL,
 reason_code VARCHAR(64) NOT NULL,
 tx_hash CHAR(64) CHECK(tx_hash IS NULL OR tx_hash ~ '^[0-9a-f]{64}$'),
 recorded_at_unix BIGINT NOT NULL CHECK(recorded_at_unix > 0),
 PRIMARY KEY(account_address,settlement_id,revision),
 FOREIGN KEY(account_address,settlement_id) REFERENCES account_settlement_lifecycles(account_address,id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS account_settlement_outbox (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL,
 settlement_id UUID NOT NULL,
 revision INTEGER NOT NULL CHECK(revision >= 1),
 event_type VARCHAR(64) NOT NULL CHECK(length(event_type) > 0),
 payload JSONB NOT NULL,
 processed BOOLEAN NOT NULL DEFAULT FALSE,
 created_at_unix BIGINT NOT NULL CHECK(created_at_unix > 0),
 FOREIGN KEY(account_address,settlement_id) REFERENCES account_settlement_lifecycles(account_address,id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS account_settlement_outbox_pending_idx
 ON account_settlement_outbox(account_address, created_at_unix) WHERE processed = FALSE;

CREATE TABLE IF NOT EXISTS account_settlement_receipts (
 nonce UUID PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 operation VARCHAR(8) NOT NULL CHECK(operation IN('PUT','POST')),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
