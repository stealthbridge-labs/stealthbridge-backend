-- Replay-resistant login challenges only. No auth HTTP routes or payment commands.
-- Wallet private keys, signed messages and original nonces are never persisted.
CREATE TABLE IF NOT EXISTS organization_login_challenges (
 id UUID PRIMARY KEY,
 organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
 subject VARCHAR(56) NOT NULL,
 domain VARCHAR(253) NOT NULL,
 nonce_sha256 CHAR(64) NOT NULL,
 issued_at_unix BIGINT NOT NULL,
 expires_at_unix BIGINT NOT NULL,
 consumed_at_unix BIGINT,
 CONSTRAINT org_login_subject_length CHECK (length(subject)=56 AND left(subject,1)='G'),
 CONSTRAINT org_login_nonce_digest CHECK (nonce_sha256 ~ '^[a-f0-9]{64}$'),
 CONSTRAINT org_login_ttl CHECK (expires_at_unix=issued_at_unix+300),
 CONSTRAINT org_login_consumption CHECK (consumed_at_unix IS NULL OR
  (consumed_at_unix>=issued_at_unix AND consumed_at_unix<=expires_at_unix))
);
CREATE INDEX IF NOT EXISTS org_login_expiry_idx
 ON organization_login_challenges(expires_at_unix);
CREATE INDEX IF NOT EXISTS org_login_subject_idx
 ON organization_login_challenges(organization_id,subject,issued_at_unix DESC);
COMMENT ON TABLE organization_login_challenges IS
 'One-use, short-lived Testnet challenge digests; no wallet keys, identities beyond public G addresses, or payment execution.';
