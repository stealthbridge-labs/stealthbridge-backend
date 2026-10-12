#!/usr/bin/env python3
"""Fail CI on breaking backend OpenAPI drift from pinned SDK/frontend consumers.

Only audited source text is fetched. This is NOT live deployment or on-chain proof.
"""
import os
import re
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
SDK_REPO = "stealthbridge-labs/stealthbridge-sdk"
FRONTEND_REPO = "stealthbridge-labs/stealthbridge-frontend"
CONSUMERS = {
    "Capabilities": "Capabilities",
    "NetworkStatus": "NetworkStatus",
    "Corridor": "Corridor",
    "CorridorPage": "CorridorPage",
    "Readiness": "ServiceReadiness",
}
def reviewed_ref(value):
    if not re.fullmatch(r"[a-f0-9]{40}",value or ""):
        raise ValueError("Cross-repo refs must be immutable 40-character Git SHAs")
    return value

def load_remote(repo, sha, path):
    ref = reviewed_ref(sha)
    url = f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"
    with urlopen(url, timeout=20) as response:
        raw = response.read(131073)
    if len(raw)>131072:
        raise ValueError("Consumer source response exceeded 128 KiB")
    return raw.decode("utf-8")

def required_fields(yaml, name):
    if yaml.count("\ncomponents:\n")!=1 or yaml.count("\n  schemas:\n")!=1:
        raise ValueError("Ambiguous OpenAPI schema components")
    content=yaml.split("\n  schemas:\n",1)[1]
    match=re.search(rf"(?m)^    {re.escape(name)}:\s*$",content)
    if not match:
        raise ValueError(f"Missing schema {name}")
    next_match=re.search(r"(?m)^    [A-Z][A-Za-z0-9]+:\s*$",content[match.end():])
    block=content[match.end():match.end()+next_match.start() if next_match else None]
    required=re.search(r"(?m)^      required: \[([^\]]+)\]$",block)
    if not required:
        raise ValueError(f"Required fields missing in {name}")
    keys=[item.strip() for item in required.group(1).split(",")]
    actual=set(re.findall(r"(?m)^        ([a-z_]+):",block))
    if set(keys)-actual:
        raise ValueError(f"Missing OpenAPI property for {name}")
    return keys

def verify_contracts(backend_yaml, pinned_sdk_yaml, frontend_types):
    if backend_yaml!=pinned_sdk_yaml:
        raise ValueError("Breaking API drift: SDK pinned OpenAPI snapshot differs from backend")
    if not all(symbol in frontend_types for symbol in
               ("networkResponse(", "capabilitiesResponse(", "readFilteredCorridorPage(")):
        raise ValueError("Missing frontend runtime response guards")
    for backend, frontend in CONSUMERS.items():
        if not re.search(rf"(?m)^export interface {frontend} ",frontend_types):
            raise ValueError(f"Frontend missing {frontend} wire interface")
        required=required_fields(backend_yaml, backend)
        # The TypeScript component must declare every backend-required key.
        snippet=frontend_types.split(f"export interface {frontend} ",1)[1].split("}",1)[0]
        for field in required:
            if not re.search(rf"\b{re.escape(field)}\??\s*:",snippet):
                raise ValueError(f"Frontend {frontend} missing required API property {field}")
    return len(CONSUMERS)

def main():
    api=(ROOT/"api/openapi.yaml").read_text()
    sdk=load_remote(SDK_REPO, os.environ.get("STEALTHBRIDGE_SDK_REF"),
                    "specs/backend-openapi.v0.3.yaml")
    frontend=load_remote(FRONTEND_REPO, os.environ.get("STEALTHBRIDGE_FRONTEND_REF"),
                         "src/lib/bridge-api.ts")
    count=verify_contracts(api,sdk,frontend)
    print(f"PASS: backend API matches pinned SDK source and {count} frontend response interfaces")

if __name__=="__main__":
    main()
