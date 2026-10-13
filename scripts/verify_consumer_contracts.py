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

def generated_fields(generated, interface):
    match=re.search(rf"(?m)^export interface {re.escape(interface)} \{{\s*$",generated)
    if not match:
        raise ValueError(f"Missing SDK-generated interface {interface}")
    body=generated[match.end():].split("\n}",1)[0]
    return set(re.findall(r"(?m)^  ([a-z_]+)\??:",body))

def verify_contracts(backend_yaml, pinned_sdk_yaml, frontend_types,
                     frontend_mirror, canonical_sdk_generated):
    if backend_yaml!=pinned_sdk_yaml:
        raise ValueError("Breaking API drift: SDK pinned OpenAPI snapshot differs from backend")
    if frontend_mirror!=canonical_sdk_generated:
        raise ValueError("Frontend SDK wire type mirror differs from pinned reviewed SDK source")
    if '"./sdk-api-wire.v0.2"' not in frontend_types:
        raise ValueError("Frontend must import the reviewed SDK-generated API models")
    if not all(symbol in frontend_types for symbol in
               ("networkResponse(", "capabilitiesResponse(", "readFilteredCorridorPage(",
                "checkpointResponse(", "transactionResponse(")):
        raise ValueError("Missing frontend runtime response guards")
    for backend, frontend in CONSUMERS.items():
        model="Api"+backend
        if not re.search(
            rf"(?m)^export interface {re.escape(frontend)} extends {re.escape(model)} \{{",frontend_types
        ):
            raise ValueError(f"Frontend {frontend} no longer inherits its SDK wire interface {model}")
        required=required_fields(backend_yaml, backend)
        actual=generated_fields(canonical_sdk_generated,model)
        for field in required:
            if field not in actual:
                raise ValueError(f"Generated SDK {model} missing required API property {field}")
    return len(CONSUMERS)

def main():
    api=(ROOT/"api/openapi.yaml").read_text()
    sdk=load_remote(SDK_REPO, os.environ.get("STEALTHBRIDGE_SDK_REF"),
                    "specs/backend-openapi.v0.3.yaml")
    frontend=load_remote(FRONTEND_REPO, os.environ.get("STEALTHBRIDGE_FRONTEND_REF"),
                         "src/lib/bridge-api.ts")
    frontend_mirror=load_remote(FRONTEND_REPO, os.environ.get("STEALTHBRIDGE_FRONTEND_REF"),
                                "src/lib/sdk-api-wire.v0.2.ts")
    sdk_generated=load_remote(SDK_REPO, os.environ.get("STEALTHBRIDGE_SDK_REF"),
                              "src/generated/api-wire.ts")
    count=verify_contracts(api,sdk,frontend,frontend_mirror,sdk_generated)
    print(f"PASS: backend API matches pinned SDK source and {count} frontend response interfaces")

if __name__=="__main__":
    main()
