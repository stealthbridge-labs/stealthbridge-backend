-- Public Testnet contract event metadata only; no event payloads or private proof data.
CREATE TABLE IF NOT EXISTS stellar_contract_event_cursors (
 network TEXT NOT NULL CHECK(network='testnet'),
 contract_id VARCHAR(56) NOT NULL CHECK(contract_id ~ '^C[A-Z2-7]{55}$'),
 next_start_ledger BIGINT NOT NULL CHECK(next_start_ledger>0),
 pagination_cursor VARCHAR(256),
 observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(network,contract_id)
);
CREATE TABLE IF NOT EXISTS stellar_contract_event_journal (
 network TEXT NOT NULL CHECK(network='testnet'),
 contract_id VARCHAR(56) NOT NULL CHECK(contract_id ~ '^C[A-Z2-7]{55}$'),
 event_id VARCHAR(30) NOT NULL CHECK(event_id ~ '^[0-9]{19}-[0-9]{10}$'),
 transaction_hash CHAR(64) NOT NULL CHECK(transaction_hash ~ '^[a-f0-9]{64}$'),
 ledger_sequence BIGINT NOT NULL CHECK(ledger_sequence>0),
 observation_state TEXT NOT NULL DEFAULT 'observed'
   CHECK(observation_state='observed'),
 observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(network,contract_id,event_id)
);
CREATE INDEX IF NOT EXISTS stellar_contract_event_ledger_lookup
 ON stellar_contract_event_journal(network,contract_id,ledger_sequence,event_id);
COMMENT ON TABLE stellar_contract_event_journal IS
 'Public RPC metadata only; events do not prove wallet identity, confidential amounts, transaction finality or off-chain payouts';
