#!/usr/bin/env python3
"""Compare the API's local read-only snapshot with canonical public Soroban data.

No generated claims or contract deployment; the GitHub API is a read-only
cross-repository check. CI fails if either repository gets out of sync.
"""
import json
import os
import re
from pathlib import Path
from urllib.request import urlopen
REF = os.environ.get("STEALTHBRIDGE_CONTRACTS_REF", "")
if not re.fullmatch(r"[a-fA-F0-9]{40}", REF):
    raise SystemExit("STEALTHBRIDGE_CONTRACTS_REF must be an audited 40-character commit SHA")
CANONICAL = f"https://raw.githubusercontent.com/stealthbridge-labs/stealthbridge-contracts/{REF}/deployments/testnet/manifest.json"
snapshot=json.loads(Path("deployments/testnet/manifest.json").read_text())
with urlopen(CANONICAL,timeout=15) as response:
    origin=json.load(response)
if snapshot!=origin:
    raise SystemExit("Contract manifest mismatch: sync from stealthbridge-contracts and verify before release")
if snapshot.get("schemaVersion")!=1 or snapshot.get("network")!="testnet" or snapshot.get("status")!="not-deployed" or snapshot.get("verified") is not False or snapshot.get("contractAddresses")!={} or snapshot.get("assetIssuers")!={} or snapshot.get("txHashes")!=[]:
    raise SystemExit("Unverified contract deployment must not be advertised by read-only backend")
print("Cross-repository contract deployment snapshot matches canonical un-deployed manifest.")

INTERFACE=f"https://raw.githubusercontent.com/stealthbridge-labs/stealthbridge-contracts/{REF}/integrations/public-soroban-interface.v1.json"
local=json.loads(Path("deployments/testnet/public-soroban-interface.v1.json").read_text())
with urlopen(INTERFACE,timeout=15) as response:
    upstream=json.load(response)
if local!=upstream:
    raise SystemExit("Soroban source-interface snapshot drifted from canonical contracts repository")
if local.get("schemaVersion")!=1 or local.get("network")!="testnet" or local.get("status")!="source-interface-only" or not isinstance(local.get("contracts"),dict):
    raise SystemExit("Public Soroban source interface must remain testnet and source-only")
print("Public registry interface snapshot matches source; no on-chain contract read implied.")
