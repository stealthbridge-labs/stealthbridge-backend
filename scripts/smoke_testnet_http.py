#!/usr/bin/env python3
"""Read-only post-deploy HTTP smoke validation; no transaction is submitted."""
import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

def probe(origin, path, method="GET"):
    request = Request(origin + path, method=method, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=12) as response:
            code, raw = response.status, response.read(65537)
    except HTTPError as error:
        code, raw = error.code, error.read(65537)
    if len(raw) > 65536:
        raise ValueError(f"{path}: response exceeds 64 KiB")
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError(f"{path}: expected JSON ({error})") from error
    if not isinstance(body, dict):
        raise ValueError(f"{path}: expected JSON object")
    return code, body

def error_is(body, allowed):
    error = body.get("error")
    return isinstance(error, dict) and error.get("code") in allowed and isinstance(body.get("trace_id"), str)

def verify(origin):
    status, health = probe(origin, "/health")
    assert status == 200 and health.get("status") == "ok", "liveness failed"
    status, cap = probe(origin, "/v1/capabilities")
    assert status == 200, "capabilities unavailable"
    for flag in ("payments_enabled", "confidential_token_verified",
                 "private_payments_verified", "fiat_payouts_enabled"):
        assert cap.get(flag) is False, f"unsafe capability flag: {flag}"
    status, contract = probe(origin, "/v1/contracts")
    assert status == 200 and contract.get("network") == "testnet", "contract discovery invalid"
    assert contract.get("on_chain_verified") is False
    assert contract.get("payment_execution_enabled") is False
    assert contract.get("manifest", {}).get("status") == "not-deployed"
    status, ready = probe(origin, "/ready")
    if status == 200:
        assert ready.get("status") == "ready" and ready.get("payments") == "disabled"
    else:
        assert status == 503 and error_is(ready, {"DEPENDENCY_UNAVAILABLE"}), "unexpected readiness error"
        assert ready.get("details", {}).get("status") == "degraded"
    status, network = probe(origin, "/v1/network")
    if status == 200:
        assert network.get("network") == "testnet"
        assert network.get("passphrase") == "Test SDF Network ; September 2015"
        assert isinstance(network.get("ledger_sequence"), int) and network["ledger_sequence"] > 0
        assert isinstance(network.get("ledger_hash"), str) and len(network["ledger_hash"]) == 64
    else:
        assert status == 502 and error_is(network, {"UPSTREAM_UNAVAILABLE"}), "network RPC failure not classified"
    status, write = probe(origin, "/v1/settlements", method="POST")
    assert status == 501 and error_is(write, {"FEATURE_DISABLED"}), "settlement write unexpectedly enabled"
    status, invalid = probe(origin, "/v1/transactions/not-a-hash")
    assert status == 400 and error_is(invalid, {"INVALID_REQUEST"}), "invalid hash not rejected"
    print("PASS: liveness, capabilities, undeployed contracts, readiness, Testnet RPC, disabled writes, invalid hash")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Deployed HTTPS staging API origin")
    args = parser.parse_args()
    origin = args.url.rstrip("/")
    if not origin.startswith("https://") or "/" in origin[8:]:
        parser.error("Only HTTPS staging API origins (without a path) are accepted")
    try:
        verify(origin)
    except (AssertionError, URLError, ValueError, TimeoutError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
