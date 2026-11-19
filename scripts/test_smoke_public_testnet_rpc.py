import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from smoke_public_testnet_rpc import (
    MAX_BYTES,
    MAX_LEDGER_STREAM_BYTES,
    NATIVE_XLM_SAC,
    OFFICIAL_TESTNET,
    DenyRedirects,
    RpcUnavailableError,
    UnsafeTestnetResponse,
    call_rpc,
    read_bounded_rpc_json,
    run_cli,
    validate_network,
    validate_public_events,
)
NOW=1_760_000_000
HEAD={"id":"a"*64,"protocolVersion":30,"sequence":1000,"closeTime":str(NOW-5)}
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

class FakeResponse:
    def __init__(self,body_bytes,*,status=200,headers=None):
        self._stream=io.BytesIO(body_bytes)
        self.status=status
        self.headers=headers or {}
    def read(self,n=-1):
        return self._stream.read(n)
    def __enter__(self):
        return self
    def __exit__(self,*_args):
        return False

class FakeOpener:
    def __init__(self,factory):
        self._factory=factory
    def open(self,_request,timeout=None):
        return self._factory(timeout)

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
    for altered in [
        {"id":"0"*63},
        {"id":None,"hash":"a"*64},
        {"sequence":0},
        {"protocolVersion":0},
        {"closeTime":"nan"},
        {"closeTime":"0"*30},
    ]:
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
    for method in ["sendTransaction","simulateTransaction","getTransaction","getLedgers"]:
      with self.subTest(method=method),self.assertRaises(UnsafeTestnetResponse):
       call_rpc(method)
 def test_get_latest_ledger_streams_past_large_metadata_xdr_within_retained_budget(self):
    large_meta=("AAAA"+'\\"\\u0041'+"B"*520_000).encode("utf-8")
    payload=(
        b'{"jsonrpc":"2.0","id":"public-readonly-testnet","result":{'
        b'"id":"'+(b"c"*64)+b'","protocolVersion":30,"sequence":5810418,'
        b'"closeTime":"1795075730","headerXdr":"AAAA","metadataXdr":"'
        +large_meta+b'"}}'
    )
    self.assertGreater(len(payload),MAX_BYTES*4)
    # Chunk at 17 bytes to exercise escape/boundary handling across reads.
    parsed=read_bounded_rpc_json(
        FakeResponse(payload),allow_skip_metadata_xdr=True,chunk_size=17
    )
    self.assertEqual(parsed["result"]["id"],"c"*64)
    self.assertEqual(parsed["result"]["sequence"],5810418)
    self.assertEqual(parsed["result"]["metadataXdr"],"")
 def test_oversized_non_ledger_or_non_metadata_payloads_fail_closed(self):
    oversized_events=(
        b'{"jsonrpc":"2.0","id":"public-readonly-testnet","result":{"padding":"'
        +(b"x"*MAX_BYTES)+b'"}}'
    )
    with self.assertRaisesRegex(UnsafeTestnetResponse,"Unbounded"):
      read_bounded_rpc_json(FakeResponse(oversized_events),allow_skip_metadata_xdr=False)
    oversized_header=(
        b'{"jsonrpc":"2.0","id":"public-readonly-testnet","result":{"id":"'
        +(b"a"*64)+b'","headerXdr":"'+(b"x"*MAX_BYTES)+b'","metadataXdr":"AA=="}}'
    )
    with self.assertRaisesRegex(UnsafeTestnetResponse,"128000"):
      read_bounded_rpc_json(FakeResponse(oversized_header),allow_skip_metadata_xdr=True)
    top_level_meta=(
        b'{"jsonrpc":"2.0","id":"public-readonly-testnet","metadataXdr":"'
        +(b"x"*MAX_BYTES)+b'","result":{}}'
    )
    with self.assertRaisesRegex(UnsafeTestnetResponse,"128000"):
      read_bounded_rpc_json(FakeResponse(top_level_meta),allow_skip_metadata_xdr=True)
    object_meta=(
        b'{"jsonrpc":"2.0","id":"public-readonly-testnet","result":{"metadataXdr":{"k":"'
        +(b"x"*MAX_BYTES)+b'"}}}'
    )
    with self.assertRaisesRegex(UnsafeTestnetResponse,"128000"):
      read_bounded_rpc_json(FakeResponse(object_meta),allow_skip_metadata_xdr=True)
    duplicate_meta=(
        b'{"jsonrpc":"2.0","id":"public-readonly-testnet","result":'
        b'{"metadataXdr":"AA==","metadataXdr":"BB=="}}'
    )
    with self.assertRaisesRegex(UnsafeTestnetResponse,"Duplicate"):
      read_bounded_rpc_json(FakeResponse(duplicate_meta),allow_skip_metadata_xdr=True)
 def test_ledger_stream_wire_and_content_length_caps_are_enforced(self):
    with self.assertRaisesRegex(UnsafeTestnetResponse,"Content-Length"):
      read_bounded_rpc_json(
          FakeResponse(b"{}",headers={"Content-Length":str(MAX_BYTES+1)}),
          allow_skip_metadata_xdr=False,
      )
    with self.assertRaisesRegex(UnsafeTestnetResponse,"Content-Length"):
      read_bounded_rpc_json(
          FakeResponse(b"{}",headers={"Content-Length":str(MAX_LEDGER_STREAM_BYTES+1)}),
          allow_skip_metadata_xdr=True,
      )
    class InfiniteMetadataStream:
      headers={}
      def __init__(self):
        self.sent_prefix=False
      def read(self,n=-1):
        if not self.sent_prefix:
          self.sent_prefix=True
          return b'{"jsonrpc":"2.0","id":"public-readonly-testnet","result":{"metadataXdr":"'
        return b"A"*(n if n>0 else 16_384)
    with self.assertRaisesRegex(UnsafeTestnetResponse,"4194304"):
      read_bounded_rpc_json(InfiniteMetadataStream(),allow_skip_metadata_xdr=True)
 def test_error_after_skipped_metadata_xdr_is_still_rejected(self):
    payload=(
        b'{"jsonrpc":"2.0","id":"public-readonly-testnet","result":{"id":"'
        +(b"a"*64)+b'","sequence":1000,"closeTime":"1795075730","metadataXdr":"'
        +(b"A"*200_000)+b'"},"error":{"code":-32000,"message":"bad"}}'
    )
    with patch("smoke_public_testnet_rpc.build_opener",
               return_value=FakeOpener(lambda _t: FakeResponse(payload))):
      with self.assertRaisesRegex(UnsafeTestnetResponse,"error or invalid"):
        call_rpc("getLatestLedger")
 def test_redirects_and_upstream_unavailability_are_distinctly_classified(self):
    with self.assertRaisesRegex(UnsafeTestnetResponse,"redirected"):
      DenyRedirects().redirect_request(None,None,302,"Found",{},"https://evil.example")
    http_err=HTTPError(
        "https://soroban-testnet.stellar.org",503,"Unavailable",{},io.BytesIO(b"")
    )
    self.addCleanup(http_err.close)
    for err in [
        http_err,
        URLError("dns failure"),
        TimeoutError("timed out"),
    ]:
      def raise_err(_t,exc=err):
        raise exc
      with self.subTest(err=type(err).__name__),patch(
          "smoke_public_testnet_rpc.build_opener",return_value=FakeOpener(raise_err)
      ),self.assertRaises(RpcUnavailableError):
        call_rpc("getNetwork")
    with patch("smoke_public_testnet_rpc.build_opener",
               return_value=FakeOpener(lambda _t: FakeResponse(b""))), \
         self.assertRaises(RpcUnavailableError):
      call_rpc("getNetwork")
    stderr_unavail=io.StringIO()
    with patch("smoke_public_testnet_rpc.main",side_effect=RpcUnavailableError("HTTP 503")), \
         patch("sys.stderr",stderr_unavail):
      self.assertEqual(run_cli(),1)
    self.assertIn("upstream unavailable",stderr_unavail.getvalue())
    stderr_policy=io.StringIO()
    with patch("smoke_public_testnet_rpc.main",side_effect=UnsafeTestnetResponse("oversized")), \
         patch("sys.stderr",stderr_policy):
      self.assertEqual(run_cli(),1)
    self.assertIn("response policy rejected",stderr_policy.getvalue())
if __name__=="__main__":unittest.main()
