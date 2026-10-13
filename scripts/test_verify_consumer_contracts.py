import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from verify_consumer_contracts import CONSUMERS,required_fields,verify_contracts

YAML=(Path(__file__).resolve().parents[1]/"api/openapi.yaml").read_text()
def sdk_fixture():
    source=""
    for schema in CONSUMERS:
        fields=required_fields(YAML,schema)
        source+="export interface Api"+schema+" {\n"
        source+="".join(f"  {field}: unknown;\n" for field in fields)
        source+="}\n"
    return source
def frontend_fixture():
    source='import type { ApiReadiness } from "./sdk-api-wire.v0.2";\n'
    for schema,client in CONSUMERS.items():
        source+=f"export interface {client} extends Api{schema} "+"{}\n"
    return source+("function networkResponse(){} function capabilitiesResponse(){} "
                   "function readFilteredCorridorPage(){} function checkpointResponse(){} "
                   "function transactionResponse(){}")

class ConsumerContractTests(unittest.TestCase):
    def test_sdk_derived_frontend_types_and_runtime_guards(self):
        sdk=sdk_fixture()
        self.assertEqual(verify_contracts(YAML,YAML,frontend_fixture(),sdk,sdk),5)
    def test_backend_openapi_edit_without_sdk_update_fails(self):
        sdk=sdk_fixture()
        with self.assertRaisesRegex(ValueError,"Breaking API drift"):
            verify_contracts(YAML.replace("0.3.0","0.4.0"),YAML,frontend_fixture(),sdk,sdk)
    def test_removed_sdk_required_key_fails(self):
        sdk=sdk_fixture().replace("  ledger_hash: unknown;\n","")
        with self.assertRaisesRegex(ValueError,"ledger_hash"):
            verify_contracts(YAML,YAML,frontend_fixture(),sdk,sdk)
    def test_missing_frontend_sdk_inheritance_fails(self):
        sdk=sdk_fixture()
        altered=frontend_fixture().replace("NetworkStatus extends ApiNetworkStatus",
                                            "NetworkStatus")
        with self.assertRaisesRegex(ValueError,"no longer inherits"):
            verify_contracts(YAML,YAML,altered,sdk,sdk)
    def test_frontend_sdk_mirror_drift_fails(self):
        sdk=sdk_fixture()
        with self.assertRaisesRegex(ValueError,"mirror"):
            verify_contracts(YAML,YAML,frontend_fixture(),sdk+"\n//tampered\n",sdk)
    def test_unverified_runtime_decoder_fails(self):
        sdk=sdk_fixture()
        altered=frontend_fixture().replace("networkResponse(", "ignoredNetwork(")
        with self.assertRaisesRegex(ValueError,"runtime response guards"):
            verify_contracts(YAML,YAML,altered,sdk,sdk)

if __name__=="__main__":unittest.main()
