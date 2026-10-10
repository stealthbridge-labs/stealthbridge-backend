"""Unit checks for deployment smoke freshness without network access."""
import importlib.util
import pathlib
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("smoke_testnet_http", pathlib.Path(__file__).with_name("smoke_testnet_http.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

HASH = "ab" * 32

def fake_probe(age=10, degraded=False):
    def probe(_origin, path, method="GET"):
        if path == "/health":
            return 200, {"status": "ok"}
        if path == "/v1/capabilities":
            return 200, {k: False for k in ("payments_enabled", "confidential_token_verified", "private_payments_verified", "fiat_payouts_enabled")}
        if path == "/v1/contracts":
            return 200, {"network": "testnet", "on_chain_verified": False, "payment_execution_enabled": False, "manifest": {"status": "not-deployed"}}
        if path == "/ready":
            return 200, {"status": "ready", "payments": "disabled"}
        if path == "/v1/network":
            if degraded:
                return 502, {"error": {"code": "UPSTREAM_UNAVAILABLE"}, "trace_id": "test"}
            return 200, {"network": "testnet", "passphrase": "Test SDF Network ; September 2015",
                         "ledger_sequence": 123, "ledger_hash": HASH, "protocol_version": 23,
                         "ledger_closed_at_unix": str(int(time.time()) - age)}
        if path == "/v1/settlements" and method == "POST":
            return 501, {"error": {"code": "FEATURE_DISABLED"}, "trace_id": "test"}
        if path == "/v1/transactions/not-a-hash":
            return 400, {"error": {"code": "INVALID_REQUEST"}, "trace_id": "test"}
        raise AssertionError(path)
    return probe

class SmokeVerificationTests(unittest.TestCase):
    def test_fresh_live_ledger_passes(self):
        with patch.object(smoke, "probe", fake_probe()):
            smoke.verify("https://api.example", require_live_network=True)

    def test_stale_ledger_fails(self):
        with patch.object(smoke, "probe", fake_probe(age=400)):
            with self.assertRaisesRegex(AssertionError, "stale"):
                smoke.verify("https://api.example", require_live_network=True)

    def test_rpc_outage_only_allowed_in_diagnostic_mode(self):
        with patch.object(smoke, "probe", fake_probe(degraded=True)):
            smoke.verify("https://api.example")
            with self.assertRaisesRegex(AssertionError, "live Testnet RPC is required"):
                smoke.verify("https://api.example", require_live_network=True)

if __name__ == "__main__":
    unittest.main()
