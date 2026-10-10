-- Persisted identities must obey the same bounds as the public SDK wire model.
-- This intentionally does not certify issuer ownership, token provenance or liquidity.
-- Existing invalid rows must be reviewed before applying the migration.
ALTER TABLE corridors
    ADD CONSTRAINT corridors_asset_code_format
        CHECK (asset_code ~ '^[A-Za-z0-9_:-]{1,64}$'),
    ADD CONSTRAINT corridors_asset_issuer_length
        CHECK (asset_issuer IS NULL OR char_length(asset_issuer) BETWEEN 1 AND 128);

COMMENT ON CONSTRAINT corridors_asset_issuer_length ON corridors IS
    'Issuer text length only; this constraint does not verify a Stellar issuer or contract.';
