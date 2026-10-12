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
from manifest_parity import verify_manifest, verify_public_interface
REF = os.environ.get("STEALTHBRIDGE_CONTRACTS_REF", "")
if not re.fullmatch(r"[a-fA-F0-9]{40}", REF):
    raise SystemExit("STEALTHBRIDGE_CONTRACTS_REF must be an audited 40-character commit SHA")
CANONICAL = f"https://raw.githubusercontent.com/stealthbridge-labs/stealthbridge-contracts/{REF}/deployments/testnet/manifest.json"
snapshot=json.loads(Path("deployments/testnet/manifest.json").read_text())
with urlopen(CANONICAL,timeout=15) as response:
    origin=json.load(response)
verify_manifest(snapshot, origin)
print("Cross-repository contract deployment snapshot matches canonical un-deployed manifest.")

INTERFACE=f"https://raw.githubusercontent.com/stealthbridge-labs/stealthbridge-contracts/{REF}/integrations/public-soroban-interface.v1.json"
local=json.loads(Path("deployments/testnet/public-soroban-interface.v1.json").read_text())
with urlopen(INTERFACE,timeout=15) as response:
    upstream=json.load(response)
verify_public_interface(local, upstream)
print("Public registry interface snapshot matches source; no on-chain contract read implied.")
