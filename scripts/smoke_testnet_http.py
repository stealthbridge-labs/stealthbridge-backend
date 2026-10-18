#!/usr/bin/env python3
"""Read-only post-deploy HTTP smoke validation; no transaction is submitted."""
import argparse
import json
import os
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.parse import urlsplit

class BlockRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Staging API redirected instead of returning its own JSON response")

def protected_headers():
    headers={"Accept":"application/json"}
    token=os.environ.get("STEALTHBRIDGE_VERCEL_BYPASS_TOKEN")
    if token:
        if len(token)>512 or not re.fullmatch(r"[A-Za-z0-9._~-]+",token):
            raise ValueError("Invalid protected-deployment bypass secret format")
        headers["x-vercel-protection-bypass"]=token
    return headers

def probe(origin, path, method="GET"):
    request = Request(origin + path, method=method, headers=protected_headers())
    try:
        with build_opener(BlockRedirect()).open(request, timeout=12) as response:
            code, raw = response.status, response.read(65537)
    except HTTPError as error:
        code, raw = error.code, error.read(65537)
        # Distinguish a platform-level failure from our JSON API errors.
        # NEVER treat Vercel's "READY" build as proof of a healthy invocation.
        platform_code = error.headers.get("x-vercel-error")
        if platform_code:
            if not re.fullmatch(r"[A-Z_]{2,100}",platform_code):
                platform_code="VERCEL_PLATFORM_ERROR"
            raise RuntimeError(
                f"{path}: Vercel function invocation failed (HTTP {code}, "
                f"{platform_code}); inspect deployment Functions/Logs and runtime settings"
            )
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

def verify(origin, require_live_network=False, max_ledger_age_seconds=180, require_governance_snapshot=False):
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
        assert all(c in "0123456789abcdefABCDEF" for c in network["ledger_hash"]), "ledger hash must be hexadecimal"
        assert isinstance(network.get("protocol_version"), int) and network["protocol_version"] > 0
        closed = network.get("ledger_closed_at_unix")
        assert isinstance(closed, str) and closed.isdecimal(), "ledger close time invalid"
        age = time.time() - int(closed)
        assert -60 <= age <= max_ledger_age_seconds, f"stale or future Testnet ledger ({age:.0f}s)"
        print(f"PASS: live Testnet ledger {network['ledger_sequence']} ({age:.0f}s old)")
    else:
        assert status == 502 and error_is(network, {"UPSTREAM_UNAVAILABLE"}), "network RPC failure not classified"
        if require_live_network:
            raise AssertionError("live Testnet RPC is required; degraded network is not deployment-ready")
        print("DEGRADED: Stellar RPC unavailable; live ledger not observed")
    if require_governance_snapshot:
        status, snapshot = probe(origin, "/v1/governance/snapshot")
        assert status == 200, "atomic public governance snapshot is unavailable"
        assert snapshot.get("network") == "testnet"
        assert snapshot.get("state") == "consistent-observations", "governance observations disagree"
        assert snapshot.get("source") == "stellar-rpc+stellar-horizon"
        assert snapshot.get("schema_version") == 1
        assert isinstance(snapshot.get("observed_ledger_sequence"), int)
        assert snapshot["observed_ledger_sequence"] > 5244293
        for field in ("canonical_manifest_attested", "signer_possession_verified",
                      "trusted_for_execution", "privacy_verified",
                      "payment_execution_enabled", "fee_collection_enabled"):
            assert snapshot.get(field) is False, f"unsafe governance assertion: {field}"
        for field in ("release", "code", "administrators"):
            assert isinstance(snapshot.get(field), dict), f"missing {field} observation"
            assert snapshot[field].get("network") == "testnet"
            assert snapshot[field].get("observed_ledger_sequence") == snapshot["observed_ledger_sequence"]
        assert len(snapshot["release"].get("contracts", [])) == 3
        assert len(snapshot["code"].get("contracts", [])) == 3
        assert len(snapshot["administrators"].get("contracts", [])) == 3
        print("PASS: public single-ledger governance observations agree; execution remains disabled")
    status, write = probe(origin, "/v1/settlements", method="POST")
    assert status == 501 and error_is(write, {"FEATURE_DISABLED"}), "settlement write unexpectedly enabled"
    status, invalid = probe(origin, "/v1/transactions/not-a-hash")
    assert status == 400 and error_is(invalid, {"INVALID_REQUEST"}), "invalid hash not rejected"
    print("PASS: liveness, capabilities, undeployed contracts, readiness, Testnet RPC, disabled writes, invalid hash")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Deployed HTTPS staging API origin")
    parser.add_argument("--require-live-network", action="store_true", help="Require a fresh Stellar Testnet ledger")
    parser.add_argument("--require-governance-snapshot", action="store_true", help="Require same-ledger public governance agreement")
    parser.add_argument("--max-ledger-age-seconds", type=int, default=180, help="Max observed ledger age in seconds")
    args = parser.parse_args()
    if not 1 <= args.max_ledger_age_seconds <= 3600:
        parser.error("--max-ledger-age-seconds must be between 1 and 3600")
    origin = args.url.rstrip("/")
    parsed=urlsplit(origin)
    if (parsed.scheme!="https" or not parsed.hostname or parsed.username is not None or
            parsed.password is not None or parsed.path or parsed.query or parsed.fragment or
            not parsed.port in (None,443)):
        parser.error("Only HTTPS staging API origins without credentials, port, path or query are accepted")
    try:
        verify(origin, args.require_live_network, args.max_ledger_age_seconds, args.require_governance_snapshot)
    except (AssertionError, URLError, ValueError, TimeoutError, RuntimeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
