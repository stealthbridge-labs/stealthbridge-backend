#!/usr/bin/env python3
"""Strict offline contract guard for StealthBridge's intentionally disabled write API.

A reserved POST /v1/settlements is documented as HTTP 501 only; this is not
a public settlement capability. No network access, credentials, or submissions.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "api/openapi.yaml"
METHOD = re.compile(r"^    (get|post|put|patch|delete):\s*$")
ROUTE = re.compile(r"^  (/[^\s:]+):\s*$")
ALLOWED = {"/health", "/ready", "/internal/metrics", "/v1/observer",
           "/v1/network", "/v1/wallet/contracts/{address}", "/v1/governance/snapshot", "/v1/contracts", "/v1/capabilities", "/v1/platform/modules",
           "/v1/business/reviews/{organization}/{request_id}",
           "/v1/corridors", "/v1/corridors/page", "/v1/corridors/{id}",
           "/v1/corridors/{id}/preflight", "/v1/corridors/batch",
           "/v1/transactions/{hash}", "/v1/settlements"}


def verify(text: str) -> int:
    if not re.search(r"(?m)^openapi: 3\.1\.0\s*$", text):
        raise ValueError("OpenAPI 3.1.0 required")
    if text.count("\npaths:\n") != 1 or text.count("\ncomponents:\n") != 1:
        raise ValueError("OpenAPI must contain exactly one paths and components mapping")
    if "Confidential settlement submission is disabled" not in text:
        raise ValueError("missing disabled-settlement disclosure")
    prefix, rest = text.split("\npaths:\n", 1)
    paths_text, schemas = rest.split("\ncomponents:\n", 1)
    if not prefix.startswith("openapi:") or "  schemas:\n" not in schemas:
        raise ValueError("missing API metadata or component schemas")
    routes = {}
    active = None
    for line in paths_text.splitlines():
        route = ROUTE.fullmatch(line)
        if route:
            active = route.group(1)
            if active in routes or active not in ALLOWED:
                raise ValueError(f"unknown or duplicate route: {active}")
            routes[active] = []
        operation = METHOD.fullmatch(line)
        if operation:
            if active is None:
                raise ValueError("operation without route")
            routes[active].append(operation.group(1))
    if set(routes) != ALLOWED:
        raise ValueError("documented routes do not match reviewed API inventory")
    for path, methods in routes.items():
        if methods != (["post"] if path == "/v1/settlements" else ["get"]):
            raise ValueError(f"unexpected method on {path}: {methods}")
    settlement = paths_text.split("  /v1/settlements:\n", 1)[1]
    if not re.search(r"(?m)^      operationId: disabledSettlement$", settlement):
        raise ValueError("settlement operation must be explicitly disabled")
    if not re.search(r'(?m)^        "501":', settlement):
        raise ValueError("disabled settlement must return HTTP 501")
    if re.search(r'(?m)^        "(?:2\d\d|3\d\d)":', settlement):
        raise ValueError("settlement route must not advertise successful writes")
    for field in ("origin_country", "destination_country", "privacy_rail"):
        if f"        - name: {field}\n" not in paths_text:
            raise ValueError(f"missing validated page filter {field}")
    if paths_text.count('pattern: "^[A-Z]{2}$"') != 2:
        raise ValueError("country filter patterns must be exact")
    preflight=paths_text.split("  /v1/corridors/{id}/preflight:\n",1)[1].split("\n  /v1/",1)[0]
    if "operationId: corridorMetadataPreflight" not in preflight or "CorridorPreflight" not in preflight:
        raise ValueError("missing reviewed, non-execution corridor preflight")
    for name in ("payment_execution_enabled","fee_quote_available","liquidity_verified",
                 "issuer_verified","privacy_verified","fiat_payouts_enabled"):
        if f"        {name}: {{type: boolean, const: false}}" not in schemas:
            raise ValueError("corridor preflight is missing hardcoded no-execution flag: "+name)
    return len(routes)


if __name__ == "__main__":
    try:
        count = verify(PATH.read_text(encoding="utf-8"))
    except (ValueError, OSError) as error:
        raise SystemExit(f"FAIL: {error}") from error
    print(f"PASS: {count} documented Testnet routes; no executable financial writes")
