-- Align persisted corridor identities with the public SDK's strict wire schema.
-- Existing invalid rows must be corrected by an operator before this migration.
-- This does not enable any corridor or establish a real payout capability.
ALTER TABLE corridors
    ADD CONSTRAINT corridors_asset_code_format
        CHECK (asset_code ~ '^[A-Za-z0-9_:-]{1,64}$'),
    ADD CONSTRAINT corridors_asset_issuer_format
        CHECK (asset_issuer IS NULL OR asset_issuer ~ '^G[A-Z2-7]{55}$');

COMMENT ON CONSTRAINT corridors_asset_issuer_format ON corridors IS
    'Basic Stellar public issuer account syntax only; not authorization or on-chain verification.';
