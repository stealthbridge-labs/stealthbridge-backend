-- Internal, tenant-bound maker-checker audit storage. This is NOT a payout,
-- financial settlement, or publicly exposed approval API.
-- No organizations, members, draft requests or fictional payments are seeded.
CREATE TABLE IF NOT EXISTS business_review_requests (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    initiator VARCHAR(128) NOT NULL,
    request_key VARCHAR(128) NOT NULL CHECK (length(request_key) BETWEEN 16 AND 128),
    intent_sha256 CHAR(64) NOT NULL CHECK (intent_sha256 ~ '^[0-9a-f]{64}$' AND intent_sha256 <> repeat('0', 64)),
    required_reviewers SMALLINT NOT NULL CHECK (required_reviewers BETWEEN 2 AND 4),
    issued_at_unix BIGINT NOT NULL CHECK (issued_at_unix > 0),
    expires_at_unix BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT review_window CHECK (expires_at_unix > issued_at_unix AND expires_at_unix - issued_at_unix BETWEEN 300 AND 86400),
    CONSTRAINT review_initiator_membership FOREIGN KEY (organization_id, initiator)
        REFERENCES organization_members (organization_id, subject) ON DELETE RESTRICT,
    UNIQUE (organization_id, request_key),
    UNIQUE (organization_id, id)
);

CREATE TABLE IF NOT EXISTS business_review_records (
    organization_id UUID NOT NULL,
    request_id UUID NOT NULL,
    reviewer VARCHAR(128) NOT NULL,
    recorded_at_unix BIGINT NOT NULL CHECK (recorded_at_unix > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, request_id, reviewer),
    CONSTRAINT review_request_scope FOREIGN KEY (organization_id, request_id)
        REFERENCES business_review_requests (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT review_record_membership FOREIGN KEY (organization_id, reviewer)
        REFERENCES organization_members (organization_id, subject) ON DELETE RESTRICT
);
CREATE INDEX business_reviews_by_tenant ON business_review_requests
 (organization_id, created_at DESC, id);
CREATE INDEX business_records_by_tenant ON business_review_records
 (organization_id, request_id, created_at);

COMMENT ON TABLE business_review_requests IS
 'Internal organization review configuration only. No authorization to execute financial settlement.';
COMMENT ON TABLE business_review_records IS
 'Append-only independent reviewer observations; application database role must enforce append-only permissions.';
