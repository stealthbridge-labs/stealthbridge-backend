import unittest
from pathlib import Path
from scripts.check_governance_release import verify
class TestGovernanceParity(unittest.TestCase):
    def test_pinned_release_is_self_consistent(self):
        source=Path("deployments/testnet/governance-deployment-evidence.v2.json").read_bytes()
        verify(source,source)
    def test_mutated_source_fails(self):
        source=Path("deployments/testnet/governance-deployment-evidence.v2.json").read_bytes()
        with self.assertRaisesRegex(ValueError,"differs"):
            verify(source,source.replace(b'"privacyVerified": false',b'"privacyVerified": true'))
    def test_oversized_evidence_fails(self):
        with self.assertRaises(ValueError):verify(b"x"*17_000,b"x"*17_000)
if __name__=="__main__":unittest.main()
