-- Account-owned, encrypted planning instructions. No financial execution.
CREATE TABLE IF NOT EXISTS customer_payment_instructions (
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 id UUID NOT NULL,
 corridor_id UUID NOT NULL REFERENCES corridors(id) ON DELETE RESTRICT,
 route_fingerprint CHAR(64) NOT NULL CHECK(route_fingerprint ~ '^[0-9a-f]{64}$'),
 request_sha256 CHAR(64) NOT NULL CHECK(request_sha256 ~ '^[0-9a-f]{64}$'),
 envelope JSONB NOT NULL CHECK(jsonb_typeof(envelope)='object' AND octet_length(envelope::text)<=4096),
 state VARCHAR(16) NOT NULL DEFAULT 'saved' CHECK(state IN('saved','cancelled')),
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision IN(1,2)),
 created_at_unix BIGINT NOT NULL CHECK(created_at_unix>0),
 expires_at_unix BIGINT NOT NULL,
 CHECK(expires_at_unix-created_at_unix BETWEEN 300 AND 86400),
 CHECK((state='saved' AND revision=1) OR (state='cancelled' AND revision=2)),
 PRIMARY KEY(account_address,id)
);
CREATE TABLE IF NOT EXISTS customer_payment_instruction_events (
 account_address VARCHAR(56) NOT NULL,
 instruction_id UUID NOT NULL,
 revision INTEGER NOT NULL CHECK(revision IN(1,2)),
 state VARCHAR(16) NOT NULL CHECK(state IN('saved','cancelled')),
 recorded_at_unix BIGINT NOT NULL CHECK(recorded_at_unix>0),
 PRIMARY KEY(account_address,instruction_id,revision),
 FOREIGN KEY(account_address,instruction_id) REFERENCES customer_payment_instructions(account_address,id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS customer_payment_instruction_receipts (
 nonce UUID PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL CHECK(account_address ~ '^G[A-Z2-7]{55}$'),
 operation VARCHAR(8) NOT NULL CHECK(operation IN('PUT','POST')),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE customer_payment_instructions IS
 'Browser-encrypted Testnet planning instructions. Public account, route and timing metadata remain visible to service operators. No quote, payment authorization, compliance decision or settlement.';
