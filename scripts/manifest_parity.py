"""Pure cross-repository manifest and source-interface parity validation.

Equality of source snapshots is not evidence of on-chain deployment.
"""
def verify_manifest(snapshot, canonical):
    if snapshot != canonical:
        raise ValueError("Contract manifest mismatch with canonical Soroban repository")
    if not isinstance(snapshot, dict) or snapshot.get("schemaVersion") != 1 or snapshot.get("network") != "testnet":
        raise ValueError("Invalid Testnet manifest metadata")
    if snapshot.get("status") != "not-deployed" or snapshot.get("verified") is not False:
        raise ValueError("Unsupported Testnet deployment claim")
    for field, value in (("contractAddresses", {}), ("assetIssuers", {}), ("txHashes", [])):
        if snapshot.get(field) != value:
            raise ValueError(f"Manifest must not advertise {field}")
    return True

def verify_public_interface(local, upstream):
    if local != upstream:
        raise ValueError("Public Soroban interface snapshot drifted from contracts repository")
    if not isinstance(local, dict) or local.get("schemaVersion") != 1 or local.get("network") != "testnet":
        raise ValueError("Invalid source-interface metadata")
    if local.get("status") != "source-interface-only" or not isinstance(local.get("contracts"), dict):
        raise ValueError("Source-only interface contract required")
    if set(local["contracts"]) != {"corridor-registry","policy-registry","governance-gate"}:
        raise ValueError("Missing or unexpected Soroban public contract")
    return True
