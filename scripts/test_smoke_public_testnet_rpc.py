import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from smoke_public_testnet_rpc import (
    OFFICIAL_TESTNET,NATIVE_XLM_SAC,UnsafeTestnetResponse,
    validate_network,validate_public_events,call_rpc,
)
NOW=1_760_000_000
HEAD={"sequence":1000,"hash":"a"*64,"closeTime":str(NOW-5)}
def page(**overrides):
    value={"latestLedger":1000,"oldestLedger":900,"events":[]}
    value.update(overrides)
    return value
def event(**overrides):
    value={"type":"contract","contractId":NATIVE_XLM_SAC,
      "id":"0000000000000000999-0000000001","txHash":"b"*64,
      "ledger":999}
    value.update(overrides)
    return value
class PublicRpcReadOnlyTests(unittest.TestCase):
 def test_fresh_testnet_ledger_and_official_contract(self):
    self.assertEqual(validate_network({"passphrase":OFFICIAL_TESTNET},HEAD,NOW),(1000,5))
    self.assertEqual(validate_public_events(page(events=[event()]),995),(1000,900,1))
 def test_wrong_network_or_stale_head_fails(self):
    for network in ["Public Global Stellar Network ; September 2015","",None]:
      with self.subTest(network=network),self.assertRaisesRegex(UnsafeTestnetResponse,"Wrong Stellar"):
        validate_network({"passphrase":network},HEAD,NOW)
    with self.assertRaisesRegex(UnsafeTestnetResponse,"Stale"):
      validate_network({"passphrase":OFFICIAL_TESTNET},{**HEAD,"closeTime":str(NOW-360)},NOW)
    with self.assertRaisesRegex(UnsafeTestnetResponse,"future"):
      validate_network({"passphrase":OFFICIAL_TESTNET},{**HEAD,"closeTime":str(NOW+90)},NOW)
 def test_corrupted_ledger_hash_or_time_fails(self):
    for altered in [{"hash":"0"*63},{"sequence":0},{"closeTime":"nan"},{"closeTime":"0"*30}]:
      with self.subTest(altered=altered),self.assertRaises(UnsafeTestnetResponse):
       validate_network({"passphrase":OFFICIAL_TESTNET},{**HEAD,**altered},NOW)
 def test_pruned_retention_or_unbounded_public_events_fails(self):
    for altered,start in [(page(oldestLedger=999),990),
      (page(latestLedger=980),990),
      (page(events=[event()]*26),990),
      (page(oldestLedger=0),990)]:
      with self.subTest(altered=altered,start=start),self.assertRaises(UnsafeTestnetResponse):
       validate_public_events(altered,start)
 def test_wrong_contract_and_hash_fails(self):
    for altered in [{"contractId":"C"+"A"*55},{"type":"system"},
                    {"txHash":"a"*63}]:
      with self.subTest(altered=altered),self.assertRaises(UnsafeTestnetResponse):
       validate_public_events(page(events=[event(**altered)]),995)
 def test_mutable_json_rpc_is_not_exposed(self):
    for method in ["sendTransaction","simulateTransaction","getTransaction"]:
      with self.subTest(method=method),self.assertRaises(UnsafeTestnetResponse):
       call_rpc(method)
if __name__=="__main__":unittest.main()
