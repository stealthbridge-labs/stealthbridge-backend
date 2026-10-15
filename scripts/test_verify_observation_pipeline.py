import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from verify_observation_pipeline import check

API=(ROOT/"api/openapi.yaml").read_text()
ROUTER=(ROOT/"src/server.rs").read_text()
PROXY='''export async function GET() {} method:"GET"; export const allowed =
new Set(["ready","v1/network","v1/observer","v1/capabilities","v1/contracts"]);'''
SDK='''export function assessPublicObservations(x) { const observerComparison = 
 x.ledger_hash.toLowerCase(); return {paymentExecutionEnabled:false}; }
export function appendPublicEvidence() {}
export function publicEvidenceReceipt() {}'''
CLIENT='''"use client";
readBridge<NetworkStatus>("network"
readBridge<ObservedLedgerCheckpoint>("observer"
readBridge<ServiceReadiness>("ready"
readBridge<Capabilities>("capabilities"
readBridge<ContractDiscovery>("contracts"
assessPublicObservations()
appendPublicEvidence()
publicEvidenceReceipt()'''

class ObservabilityContractTests(unittest.TestCase):
 def test_current_backend_gets_and_pinned_source_fixture_match(self):
    self.assertEqual(check(API,ROUTER,SDK,SDK,CLIENT,PROXY),5)
 def test_sdk_frontend_drift_is_blocked(self):
    with self.assertRaisesRegex(ValueError,"differs from reviewed SDK"):
      check(API,ROUTER,SDK,SDK+"//changed",CLIENT,PROXY)
 def test_missing_or_mutable_backend_read_endpoint_is_blocked(self):
    altered=ROUTER.replace('.route("/v1/observer",get(observer_head))',
      '.route("/v1/observer",post(observer_head))')
    with self.assertRaisesRegex(ValueError,"GET-only"):
      check(API,altered,SDK,SDK,CLIENT,PROXY)
 def test_unauthorized_proxy_write_endpoint_is_blocked(self):
    with self.assertRaisesRegex(ValueError,"write methods"):
      check(API,ROUTER,SDK,SDK,CLIENT,PROXY+'\nexport async function POST() {}')
 def test_settlement_post_cannot_be_enabled(self):
    altered=ROUTER.replace('.route("/v1/settlements",post(disabled))',
      '.route("/v1/settlements",post(submit_payment))')
    with self.assertRaisesRegex(ValueError,"must remain disabled"):
      check(API,altered,SDK,SDK,CLIENT,PROXY)
 def test_missing_hash_verification_is_blocked(self):
    altered=SDK.replace("ledger_hash.toLowerCase()","ledger_hash.toString()")
    with self.assertRaisesRegex(ValueError,"hash checks"):
      check(API,ROUTER,altered,altered,CLIENT,PROXY)
 def test_client_cannot_omit_persisted_checkpoint(self):
    altered=CLIENT.replace('readBridge<ObservedLedgerCheckpoint>("observer"', "")
    with self.assertRaisesRegex(ValueError,"missing guarded"):
      check(API,ROUTER,SDK,SDK,altered,PROXY)
if __name__=="__main__":unittest.main()
