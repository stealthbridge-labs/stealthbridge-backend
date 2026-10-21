-- Customer-controlled, non-financial profile preferences only.
-- Sign-in alone never creates profile rows. No email, legal identity, KYC,
-- payment instruction, private key, organization role, or synthetic data.
CREATE TABLE IF NOT EXISTS customer_profiles (
 account_address VARCHAR(56) PRIMARY KEY
   CHECK (account_address ~ '^G[A-Z2-7]{55}$'),
 display_name VARCHAR(80) NOT NULL
   CHECK (length(btrim(display_name)) BETWEEN 1 AND 80
          AND display_name = btrim(display_name)),
 use_case VARCHAR(10) NOT NULL
   CHECK (use_case IN ('personal','business','both')),
 residence_country CHAR(2)
   CHECK (residence_country IS NULL OR residence_country ~ '^[A-Z]{2}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS customer_profile_update_receipts (
 nonce UUID PRIMARY KEY,
 account_address VARCHAR(56) NOT NULL
   REFERENCES customer_profiles(account_address) ON DELETE RESTRICT,
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS customer_profile_receipts_by_account
 ON customer_profile_update_receipts(account_address, recorded_at DESC);
COMMENT ON TABLE customer_profiles IS
 'Optional user-saved profile preferences. Not KYC, identity assurance, onboarding approval, or a payment account.';
COMMENT ON TABLE customer_profile_update_receipts IS
 'Server-side replay defense for customer-only nonfinancial preference changes. Receipts should be retained according to an approved privacy retention policy.';
