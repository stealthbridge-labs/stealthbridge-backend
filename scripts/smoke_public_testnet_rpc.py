#!/usr/bin/env python3
"""Operator-independent, entirely READ-ONLY live public Stellar Testnet RPC probe.

The contract is the official native-XLM SAC from Stellar's docs, NOT a
StealthBridge deployment, proof, wallet or payment confirmation.
No transaction submission or private payload recording is possible here.
"""
import json
import re
import sys
import time
from datetime import datetime, timezone
from urllib.request import Request, build_opener, HTTPRedirectHandler

OFFICIAL_TESTNET="Test SDF Network ; September 2015"
PUBLIC_RPC="https://soroban-testnet.stellar.org"
NATIVE_XLM_SAC="CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
MAX_BYTES=128_000
MAX_AGE=180

class UnsafeTestnetResponse(ValueError):
    pass

class DenyRedirects(HTTPRedirectHandler):
    def redirect_request(self,*_args,**_kwargs):
        raise UnsafeTestnetResponse("Public RPC redirected to another endpoint")

def require(ok,reason):
    if not ok:
        raise UnsafeTestnetResponse(reason)

def call_rpc(method,params=None):
    require(method in ("getNetwork","getLatestLedger","getEvents"),
            "Unsupported or potentially mutable Stellar RPC method")
    request=Request(PUBLIC_RPC,
        data=json.dumps({"jsonrpc":"2.0","id":"public-readonly-testnet",
                         "method":method,"params":params or {}},
                        separators=(",",":")).encode(),
        headers={"content-type":"application/json","accept":"application/json",
                 "user-agent":"StealthBridge-public-Testnet-smoke/1.0"},
        method="POST")
    # JSON-RPC's HTTP POST transports *read-only methods*: it is not a
    # Soroban transaction POST or a StealthBridge settlement request.
    with build_opener(DenyRedirects()).open(request,timeout=12) as response:
        require(response.status==200,"Public Testnet RPC not reachable")
        body=response.read(MAX_BYTES+1)
    require(0<len(body)<=MAX_BYTES,"Unbounded public RPC response")
    obj=json.loads(body)
    require(type(obj) is dict and obj.get("jsonrpc")=="2.0" and
            obj.get("id")=="public-readonly-testnet" and
            "error" not in obj and type(obj.get("result")) is dict,
            "Stellar Testnet RPC error or invalid JSON-RPC envelope")
    return obj["result"]

def validate_network(network,head,now_unix):
    require(type(network) is dict and network.get("passphrase")==OFFICIAL_TESTNET,
            "Wrong Stellar passphrase: must fail closed")
    require(type(head) is dict and
            type(head.get("sequence")) is int and head["sequence"]>1 and
            type(head.get("hash")) is str and
            re.fullmatch(r"[a-f0-9]{64}",head["hash"],re.I) is not None,
            "Unverified Testnet ledger head")
    # Stellar getLatestLedger includes closeTime as a decimal unix string.
    close=head.get("closeTime")
    require(type(close) in (str,int) and
            re.fullmatch(r"[0-9]{1,20}",str(close)) is not None,
            "Missing Testnet ledger close time")
    age=now_unix-int(close)
    require(-30<=age<=MAX_AGE,"Stale or future Testnet ledger head")
    return head["sequence"],age

def validate_public_events(response,start,contract=NATIVE_XLM_SAC):
    require(type(response) is dict and
            type(response.get("latestLedger")) is int and
            type(response.get("oldestLedger")) is int and
            type(response.get("events")) is list,
            "Missing public RPC ledger retention envelope")
    newest=response["latestLedger"];oldest=response["oldestLedger"]
    require(oldest>0 and oldest<=start<=newest and len(response["events"])<=25,
            "RPC history pruned or event page unbounded")
    for event in response["events"]:
        require(type(event) is dict and event.get("type")=="contract" and
                event.get("contractId")==contract and
                isinstance(event.get("id"),str) and
                isinstance(event.get("txHash"),str) and
                re.fullmatch(r"[a-f0-9]{64}",event["txHash"],re.I) is not None,
                "Public contract event mismatched the official C-address")
    return newest,oldest,len(response["events"])

def main():
    network=call_rpc("getNetwork")
    head=call_rpc("getLatestLedger")
    sequence,age=validate_network(network,head,int(time.time()))
    start=max(1,sequence-5)
    params={
       "startLedger":start,
       "filters":[{"type":"contract","contractIds":[NATIVE_XLM_SAC]}],
       "pagination":{"limit":25},
       "xdrFormat":"base64",
    }
    newest,oldest,count=validate_public_events(
       call_rpc("getEvents",params),start)
    print(json.dumps({
        "network":"testnet","passphrase":OFFICIAL_TESTNET,
        "source":"public-Stellar-RPC","headSequence":sequence,
        "headHash":head["hash"],"headAgeSeconds":age,
        "observedContract":"official-native-XLM-asset-contract-only",
        "eventsInBoundedPage":count,"oldestLedger":oldest,
        "latestLedger":newest,"privateTransferProofVerified":False,
        "stealthbridgeContractsDeployed":False,
        "paymentsEnabled":False,
    },sort_keys=True))
    print("PASS read-only live public Testnet RPC; NO StealthBridge contract-event or private-transfer claim")

if __name__=="__main__":
    try:
        main()
    except (UnsafeTestnetResponse,TimeoutError,ValueError,OSError) as exc:
        print("FAIL public Testnet RPC smoke: "+str(exc),file=sys.stderr)
        sys.exit(1)
