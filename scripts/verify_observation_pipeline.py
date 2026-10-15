#!/usr/bin/env python3
"""Fail closed if the public Testnet observability layers drift.

This gate fetches *only* reviewed, pinned public Git source files. It does NOT
call deployed APIs, hold secrets, sign, inspect wallets or attest transactions.
"""
import os
import re
from pathlib import Path
from urllib.request import Request, urlopen

ROOT=Path(__file__).resolve().parents[1]
PATHS=("ready","v1/network","v1/observer","v1/capabilities","v1/contracts")
SDK_REPO="stealthbridge-labs/stealthbridge-sdk"
FRONT_REPO="stealthbridge-labs/stealthbridge-frontend"
MAX_SOURCE_BYTES=96_000

def require(value,reason):
    if not value:raise ValueError(reason)

def source_at(repo,sha,path):
    require(re.fullmatch(r"[a-f0-9]{40}",sha or "") is not None,
            "Reviewed source references must be exact 40-character Git commit IDs")
    require(repo in (SDK_REPO,FRONT_REPO),"Unsupported source repository")
    require(not path.startswith("/") and ".." not in path,
            "Untrusted source path")
    url=f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
    request=Request(url,headers={"user-agent":"StealthBridge-source-contract-check/1.0"})
    with urlopen(request,timeout=15) as handle:
        require(handle.status==200 and handle.url==url,"Source was redirected or unavailable")
        data=handle.read(MAX_SOURCE_BYTES+1)
    require(0<len(data)<=MAX_SOURCE_BYTES,"Cross-repo source exceeds bounded size")
    return data.decode("utf-8")

def check(backend_openapi,backend_router,sdk_logic,frontend_logic,workspace,proxy):
    require(sdk_logic==frontend_logic,
            "Frontend public evidence evaluator differs from reviewed SDK implementation")
    # These exact API GETs must remain backed by read-only Rust handlers.
    for path in PATHS:
        entry="/"+path
        require(re.search(r"(?m)^  "+re.escape(entry)+r":\s*$",backend_openapi) is not None,
                "Missing public OpenAPI route "+entry)
        require(re.search(r"(?m)^\s+\.route\(\""+re.escape(entry)+
                          r"\",get\([a-z_]+\)\)",backend_router) is not None,
                "Missing GET-only backend route "+entry)
        require(f'\"{path}\"' in proxy or path=="ready" and '\"ready\"' in proxy,
                "Preview proxy must explicitly allow "+entry)
    require(re.search(r'\.route\("/v1/settlements",post\(disabled\)\)',backend_router) is not None,
            "Settlement write route must remain disabled")
    require("export async function GET" in proxy and
            "export async function POST" not in proxy and
            'method:"GET"' in proxy,
            "Frontend proxy unexpectedly permits write methods")
    for method in ("assessPublicObservations","appendPublicEvidence","publicEvidenceReceipt"):
        require(method in sdk_logic and method in workspace,
                "Missing canonical SDK / client observability method: "+method)
    for symbol in ("ledger_hash.toLowerCase()","observerComparison","paymentExecutionEnabled:false"):
        require(symbol in sdk_logic,
                "SDK observation lacks hash checks or fails to explicitly disable transfers: "+symbol)
    for symbol in ('readBridge<NetworkStatus>("network"',
                   'readBridge<ObservedLedgerCheckpoint>("observer"',
                   'readBridge<ServiceReadiness>("ready"',
                   'readBridge<Capabilities>("capabilities"',
                   'readBridge<ContractDiscovery>("contracts"'):
        require(symbol in workspace,
                "Frontend missing guarded read-only observation: "+symbol)
    require("wallet" not in workspace.lower().split("import",1)[0] and
            '"use client"' in workspace and "transfer" not in sdk_logic.lower().split(
                "export function assessPublicObservations",1)[0],
            "This read-only cross-repo source check cannot include wallet/payment handling")
    return len(PATHS)

def main():
    backend_api=(ROOT/"api/openapi.yaml").read_text()
    backend_router=(ROOT/"src/server.rs").read_text()
    sdk=source_at(SDK_REPO,os.environ.get("STEALTHBRIDGE_OBS_SDK_REF"),
                  "src/observation-health.ts")
    frontend_ref=os.environ.get("STEALTHBRIDGE_OBS_FRONTEND_REF")
    browser=source_at(FRONT_REPO,frontend_ref,"src/lib/observation-health.ts")
    workspace=source_at(FRONT_REPO,frontend_ref,"src/components/observability-workspace.tsx")
    proxy=source_at(FRONT_REPO,frontend_ref,"src/app/api/bridge/[...parts]/route.ts")
    count=check(backend_api,backend_router,sdk,browser,workspace,proxy)
    print(f"PASS: {count} backend GET routes, reviewed SDK classifier and frontend observation UI match")
    print("SOURCE PARITY ONLY — no live network, wallet, proof, contract deployment or payment evidence")

if __name__=="__main__":main()
