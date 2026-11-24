-- Audit C-5: one on-chain transaction may evidence at most one settlement.
-- Additive only. Fails to apply if duplicate hashes already exist; resolve
-- those manually before running the protected migration gate.
CREATE UNIQUE INDEX IF NOT EXISTS account_settlement_lifecycles_tx_hash_unique
 ON account_settlement_lifecycles(testnet_tx_hash)
 WHERE testnet_tx_hash IS NOT NULL;
