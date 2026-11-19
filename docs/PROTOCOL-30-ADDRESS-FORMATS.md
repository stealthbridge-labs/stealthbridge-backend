# Stellar Protocol 30 & Smart-Account Compatibility Notes

StealthBridge backend uses `stellar-xdr = "=30.0.0"` and `stellar-strkey = "=1.0.0"` for Protocol 30 XDR (`ScAddress::MuxedContract`, `LedgerHeader`) and CAP-84 / SEP-23 StrKey validation (`G`, `C`, `M`, `W`).

## Database & endpoint boundaries

- **Owner-scoped / SEP-53 login tables** (`customer_profiles`, `customer_ciphertext_drafts`, `customer_payment_instructions`, `organization_login_challenges`, `organization_invitations`) remain strictly constrained to 56-character Ed25519 `G...` addresses.
- **Contract journal tables** (`stellar_contract_event_cursors`, `stellar_contract_event_journal`) and `/v1/wallet/contracts/{address}` remain strictly constrained to 56-character `C...` contract IDs (`^C[A-Z2-7]{55}$`).
- **Actor / metadata / ciphertext storage** (`organization_members.subject`, `business_review_requests.initiator`, `business_review_records.reviewer`, `corridors.asset_issuer`, and client-encrypted draft/instruction envelopes) accommodates 69-character `M...` and CAP-84 `W...` strings.
- **`/v1/wallet/classic-recipient/{address}`** accepts canonical `G...` and `M...` (querying Horizon against the decoded `G...` Ed25519 account; Horizon returns HTTP 400 for raw `M...` strings).
- **`/v1/wallet/recipient/{address}`** accepts canonical `C...` and CAP-84 `W...` (querying Soroban RPC `getLedgerEntries` for the decoded underlying `C...` contract instance).
- All presence responses keep `ownership_verified`, `smart_account_verified`, `signer_authority_verified`, and `payment_execution_enabled` set to `false` and never claim mux ID routing support.
