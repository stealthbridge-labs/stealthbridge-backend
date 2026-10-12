import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from verify_consumer_contracts import CONSUMERS, required_fields, verify_contracts

YAML=(Path(__file__).resolve().parents[1]/"api/openapi.yaml").read_text()
def frontend_fixture():
    source=""
    for schema,client in CONSUMERS.items():
        fields=required_fields(YAML,schema)
        source+=f"export interface {client} "+"{"+ "".join(f"{x}:unknown;" for x in fields)+"}\n"
    return source+"function networkResponse(){} function capabilitiesResponse(){} function readFilteredCorridorPage(){}"

class ConsumerContractTests(unittest.TestCase):
    def test_matching_generated_schema_and_client_fields(self):
        self.assertEqual(verify_contracts(YAML,YAML,frontend_fixture()),5)
    def test_backend_edit_without_sdk_pin_fails(self):
        with self.assertRaisesRegex(ValueError,"Breaking API drift"):
            verify_contracts(YAML.replace("0.3.0","0.4.0"),YAML,frontend_fixture())
    def test_removed_frontend_required_key_fails(self):
        modified=frontend_fixture().replace("ledger_hash:unknown;","")
        with self.assertRaisesRegex(ValueError,"ledger_hash"):
            verify_contracts(YAML,YAML,modified)
    def test_removed_decoder_fails(self):
        modified=frontend_fixture().replace("networkResponse(", "ignoredNetwork(")
        with self.assertRaisesRegex(ValueError,"runtime response guards"):
            verify_contracts(YAML,YAML,modified)

if __name__=="__main__":unittest.main()
