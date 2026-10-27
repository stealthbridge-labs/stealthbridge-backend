-- Account-consented viewer-only team membership invitations.
-- Applies through the protected SQLx runbook. Never grant payment execution.
CREATE TABLE IF NOT EXISTS organization_invitations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    invited_account VARCHAR(56) NOT NULL CHECK (length(invited_account) = 56),
    invited_by VARCHAR(56) NOT NULL CHECK (length(invited_by) = 56),
    role VARCHAR(16) NOT NULL DEFAULT 'viewer' CHECK (role = 'viewer'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT invite_cannot_target_inviter CHECK (invited_account <> invited_by),
    CONSTRAINT invite_valid_lifetime CHECK (
        expires_at > created_at AND expires_at <= created_at + INTERVAL '7 days'
    ),
    CONSTRAINT invite_accept_before_expiry CHECK (
        accepted_at IS NULL OR (accepted_at >= created_at AND accepted_at < expires_at)
    ),
    CONSTRAINT invite_revocation_after_create CHECK (
        revoked_at IS NULL OR revoked_at >= created_at
    ),
    CONSTRAINT invite_single_terminal_state CHECK (
        accepted_at IS NULL OR revoked_at IS NULL
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS organization_invitations_one_open
 ON organization_invitations (organization_id, invited_account)
 WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS organization_invitations_for_recipient
 ON organization_invitations (invited_account, created_at DESC)
 WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS organization_invitations_for_organization
 ON organization_invitations (organization_id, created_at DESC);
COMMENT ON TABLE organization_invitations IS
 'Explicit single-use Testnet team viewer invitations; not KYC, payment eligibility, or contract authority.';
