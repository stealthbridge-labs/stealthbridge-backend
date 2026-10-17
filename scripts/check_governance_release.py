#!/usr/bin/env python3
"""Pin the backend governance release JSON to the reviewed contracts repo.

This checks byte-for-byte source parity, NOT new signatures, current code,
current administrator, confidential payments or fresh on-chain RPC reads.
"""
import json
from pathlib import Path
from urllib.request import urlopen

SOURCE_REF="930fcdff5898abcd1e3f75704c4429f4b7ec4881"
PATH="deployments/testnet/governance-deployment-evidence.v2.json"
URI=f"https://raw.githubusercontent.com/stealthbridge-labs/stealthbridge-contracts/{SOURCE_REF}/{PATH}"
def verify(local:bytes,original:bytes)->None:
    if len(local)>16_384 or len(original)>16_384 or len(original)<100:
        raise ValueError("Governance release evidence exceeds reviewed byte bounds")
    if local!=original:
        raise ValueError("Governance release differs from pinned verified contract evidence")
    record=json.loads(local)
    if record["schemaVersion"]!=2 or record["network"]!="testnet" or len(record["contracts"])!=3:
        raise ValueError("Invalid three-contract Testnet release envelope")
    for field in ("privacyVerified","paymentExecutionEnabled","platformFeesEnabled","fiatPayoutEnabled"):
        if record["scope"].get(field) is not False:
            raise ValueError("Release is not authorized for financial execution")
if __name__=="__main__":
    with urlopen(URI,timeout=15) as r:
        upstream=r.read(16_385)
    verify(Path(PATH).read_bytes(),upstream)
    print("PASS: backend published governance release matches pinned contracts evidence")
