#!/usr/bin/env python3
"""Fail-closed offline OpenAPI release guard. No network or financial calls."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
schema = (ROOT / "api/openapi.yaml").read_text()
if not re.search(r"(?m)^openapi:\s*3\.1\.0\s*$", schema):
    sys.exit("FAIL: OpenAPI version must be 3.1.0")
if "Confidential settlement submission is disabled" not in schema:
    sys.exit("FAIL: disabled settlement disclosure missing")
paths = re.findall(r"(?m)^  (/[^\s:]+):\s*$", schema.split("\ncomponents:", 1)[0].split("\npaths:", 1)[-1])
if not paths:
    sys.exit("FAIL: no documented paths")
for path in paths:
    if not path.startswith(("/v1/", "/health", "/ready", "/internal/")):
        sys.exit(f"FAIL: unexpected route {path}")
for verb in ("post", "put", "patch", "delete"):
    if re.search(rf"(?m)^    {verb}:\s*$", schema):
        sys.exit(f"FAIL: forbidden {verb.upper()} operation")
print(f"PASS: {len(paths)} read-only API paths; no mutating operations")
