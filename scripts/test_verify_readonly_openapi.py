"""No network, Rust process, or real payment submission; mutate the actual spec."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_readonly_openapi import PATH, verify

class ReadOnlyApiSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = PATH.read_text()
    def test_documented_routes_include_only_disabled_post(self):
        self.assertEqual(verify(self.schema), 16)
    def test_duplicate_component_block_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            verify(self.schema + "\ncomponents:\n  schemas:\n    Forged: {}\n")
    def test_payment_post_in_new_endpoint_rejected(self):
        forged = self.schema.replace("\ncomponents:\n", "\n  /v1/payout:\n    post:\n      responses:\n        \"200\": {}\ncomponents:\n")
        with self.assertRaises(ValueError): verify(forged)
    def test_settlement_must_fail_without_enabled_write(self):
        bad = self.schema.replace('        "501": {$ref: "#/components/responses/ApiError"}',
                                  '        "200": {description: transfer completed}')
        with self.assertRaisesRegex(ValueError, "HTTP 501"):
            verify(bad)
    def test_wrong_corrupted_corridor_pattern_rejected(self):
        with self.assertRaisesRegex(ValueError, "country filter patterns"):
            verify(self.schema.replace('pattern: "^[A-Z]{2}$"', 'pattern: ".*"', 1))
    def test_new_delete_operation_rejected(self):
        bad = self.schema.replace("  /v1/network:\n    get:", "  /v1/network:\n    delete:\n    get:")
        with self.assertRaisesRegex(ValueError, "unexpected method"):
            verify(bad)

if __name__ == "__main__":
    unittest.main()
