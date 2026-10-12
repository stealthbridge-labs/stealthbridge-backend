import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from manifest_parity import verify_manifest, verify_public_interface

M = {"schemaVersion":1,"network":"testnet","status":"not-deployed","verified":False,
     "contractAddresses":{},"assetIssuers":{},"txHashes":[]}
I = {"schemaVersion":1,"network":"testnet","status":"source-interface-only",
     "contracts":{x:{"reads":{},"writes":[]} for x in ("corridor-registry","policy-registry","governance-gate")}}

class CanonicalSorobanParityTests(unittest.TestCase):
    def test_equal_empty_testnet_snapshot(self):
        self.assertTrue(verify_manifest(M,M.copy()))
        self.assertTrue(verify_public_interface(I,I.copy()))
    def test_canonical_manifest_drift(self):
        with self.assertRaisesRegex(ValueError,"mismatch"):
            verify_manifest(M,{**M,"notes":"modified canonical version"})
    def test_forged_deployment_flags_and_addresses(self):
        for mutation in ({"verified":True},{"status":"deployed"},
                         {"contractAddresses":{"corridor-registry":"fake"}},
                         {"txHashes":["f"*64]},{"network":"public"}):
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                verify_manifest({**M,**mutation},{**M,**mutation})
    def test_source_contract_inventory_and_revision_drift(self):
        with self.assertRaisesRegex(ValueError,"drifted"):
            verify_public_interface(I,{**I,"status":"deployed"})
        with self.assertRaisesRegex(ValueError,"Missing"):
            verify_public_interface({**I,"contracts":{}},{**I,"contracts":{}})

if __name__=="__main__":unittest.main()
