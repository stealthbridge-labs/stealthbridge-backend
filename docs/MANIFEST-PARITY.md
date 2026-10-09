# Canonical deployment manifest parity

CI pins `STEALTHBRIDGE_CONTRACTS_REF` to a reviewed 40-character commit SHA from `stealthbridge-labs/stealthbridge-contracts`. The verifier compares both local deployment snapshots against canonical paths at that immutable revision, rejecting mismatched JSON, non-Testnet schema versions, missing source method metadata, or any claim that contracts or assets have been deployed. Never treat matching JSON as proof of an on-chain deployment.

When upstream contracts change, review the commit and manifest/source-interface changes, synchronize the backend snapshots, and update the pinned revision together in `.github/workflows/ci.yml`. A manifest marking live contracts must fail until an independent on-chain attestation workflow is reviewed. Never add fabricated contract IDs or testnet addresses just to pass CI.
