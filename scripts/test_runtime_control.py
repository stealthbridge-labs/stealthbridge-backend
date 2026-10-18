"""Static routing and safety regression tests for the *diagnostic-only* Node probe."""
from pathlib import Path
import json
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]

class RuntimeControlTests(unittest.TestCase):
    def test_dedicated_probe_precedes_axum_catch_all(self):
        config=json.loads((ROOT/"vercel.json").read_text())
        rewrites=config["rewrites"]
        self.assertEqual(rewrites[0],{
            "source":"/__runtime_node_probe","destination":"/api/runtime-node-probe"})
        self.assertEqual(rewrites[1],{
            "source":"/__runtime_probe","destination":"/api/runtime-probe"})
        self.assertEqual(rewrites[-1],{
            "source":"/(.*)","destination":"/api/axum"})
    def test_control_never_launders_readiness_or_secrets(self):
        content=(ROOT/"api/runtime-node-probe.mjs").read_text()
        for forbidden in ("process.env","fetch(","DATABASE_URL","STELLAR_RPC_URL",
                          "payment_execution_enabled:true","fee_collection_enabled:true",
                          "backend_ready:true","network_verified:true"):
            self.assertNotIn(forbidden,content)
        for required in ("request.method!==\"GET\"","node_invocation_healthy:true",
                         "backend_ready:false","payment_execution_enabled:false",
                         "fee_collection_enabled:false","response.status(405)"):
            self.assertIn(required,content)

if __name__=="__main__":
    unittest.main()
