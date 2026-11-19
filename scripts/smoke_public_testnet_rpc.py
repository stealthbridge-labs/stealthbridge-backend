#!/usr/bin/env python3
"""Operator-independent, entirely READ-ONLY live public Stellar Testnet RPC probe.

The contract is the official native-XLM SAC from Stellar's docs, NOT a
StealthBridge deployment, proof, wallet or payment confirmation.
No transaction submission or private payload recording is possible here.
"""
import codecs
import json
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

OFFICIAL_TESTNET="Test SDF Network ; September 2015"
PUBLIC_RPC="https://soroban-testnet.stellar.org"
NATIVE_XLM_SAC="CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
MAX_BYTES=128_000
# getLatestLedger includes an unrequested base64 LedgerCloseMeta blob (`metadataXdr`)
# that routinely exceeds 128 KB on active Testnet ledgers. Stream-skip only that
# string value up to a hard wire cap while keeping retained bytes <= MAX_BYTES.
MAX_LEDGER_STREAM_BYTES=4*1024*1024
READ_CHUNK_BYTES=16_384
MAX_JSON_DEPTH=32
MAX_AGE=180

class UnsafeTestnetResponse(ValueError):
    pass

class RpcUnavailableError(OSError):
    pass

class DenyRedirects(HTTPRedirectHandler):
    def redirect_request(self,*_args,**_kwargs):
        raise UnsafeTestnetResponse("Public RPC redirected to another endpoint")

def require(ok,reason):
    if not ok:
        raise UnsafeTestnetResponse(reason)

def _reject_json_constant(token):
    raise UnsafeTestnetResponse(f"Unsupported non-finite JSON constant: {token}")

def _advance_container(stack):
    if not stack:
        return
    state,key=stack[-1]
    if state=="obj_val":
        stack[-1]=["obj_comma_or_end",key]
    elif state in ("arr_val","arr_val_or_end"):
        stack[-1]=["arr_comma_or_val",None]

def _check_content_length(response,max_wire):
    headers=getattr(response,"headers",None)
    if not headers:
        return
    raw_len=headers.get("Content-Length")
    if raw_len is None:
        return
    value=raw_len.strip()
    require(re.fullmatch(r"\d+",value) is not None,
            "Invalid Content-Length header from public RPC")
    require(int(value)<=max_wire,
            f"Public RPC Content-Length exceeds {max_wire}-byte safety limit")

def read_bounded_rpc_json(response,*,allow_skip_metadata_xdr=False,chunk_size=READ_CHUNK_BYTES):
    max_wire=MAX_LEDGER_STREAM_BYTES if allow_skip_metadata_xdr else MAX_BYTES
    _check_content_length(response,max_wire)
    if not allow_skip_metadata_xdr:
        body=response.read(MAX_BYTES+1)
        if len(body)==0:
            raise RpcUnavailableError("Public Testnet RPC returned an empty response")
        require(len(body)<=MAX_BYTES,"Unbounded public RPC response")
        try:
            text=body.decode("utf-8")
            return json.loads(text,parse_constant=_reject_json_constant)
        except (UnicodeDecodeError,json.JSONDecodeError) as exc:
            raise UnsafeTestnetResponse("Malformed JSON from public RPC") from exc

    retained=bytearray()
    def emit(b):
        if len(retained)>=MAX_BYTES:
            raise UnsafeTestnetResponse("Retained public RPC ledger metadata exceeded 128000-byte limit")
        retained.append(b)

    stack=[]
    in_string=None
    escaped=False
    key_buf=bytearray()
    in_primitive=False
    skipped_metadata=False
    root_done=False
    total_wire_bytes=0
    skip_utf8=codecs.getincrementaldecoder("utf-8")("strict")

    try:
        while True:
            chunk=response.read(chunk_size)
            if not chunk:
                break
            total_wire_bytes+=len(chunk)
            require(total_wire_bytes<=MAX_LEDGER_STREAM_BYTES,
                    "Public RPC ledger stream exceeded 4194304-byte wire safety limit")
            i=0
            n=len(chunk)
            while i<n:
                if in_string=="skip":
                    start=i
                    closed=False
                    while i<n:
                        b=chunk[i]
                        if escaped:
                            require(b in b'"\\/bfnrtu',
                                    "Invalid JSON escape in public RPC metadataXdr")
                            escaped=False
                            i+=1
                        elif b==92:  # '\'
                            escaped=True
                            i+=1
                        elif b==34:  # '"'
                            skip_utf8.decode(chunk[start:i],final=True)
                            skip_utf8.reset()
                            emit(34)
                            in_string=None
                            _advance_container(stack)
                            i+=1
                            closed=True
                            break
                        else:
                            require(b>=0x20,"Unescaped control character in public RPC metadataXdr")
                            i+=1
                    if not closed:
                        skip_utf8.decode(chunk[start:n],final=False)
                    continue

                b=chunk[i]
                i+=1
                if in_string is not None:
                    emit(b)
                    if in_string=="key":
                        if escaped:
                            escaped=False
                            key_buf.append(b)
                        elif b==92:
                            escaped=True
                            key_buf.append(b)
                        elif b==34:
                            key=json.loads((b'"'+bytes(key_buf)+b'"').decode("utf-8"))
                            require(stack and stack[-1][0] in ("obj_key_or_end","obj_key"),
                                    "Malformed object key in public RPC JSON")
                            stack[-1]=["obj_colon",key]
                            in_string=None
                            escaped=False
                        else:
                            key_buf.append(b)
                    else:  # in_string == "retain"
                        if escaped:
                            escaped=False
                        elif b==92:
                            escaped=True
                        elif b==34:
                            in_string=None
                            _advance_container(stack)
                    continue

                if in_primitive:
                    if b in (32,9,10,13,123,125,91,93,58,44,34):
                        in_primitive=False
                        _advance_container(stack)
                    else:
                        emit(b)
                        continue

                if b in (32,9,10,13):
                    emit(b)
                    continue
                require(not root_done,"Trailing data after public RPC JSON root")
                if b==123:  # '{'
                    require(len(stack)<MAX_JSON_DEPTH,"Public RPC JSON nesting exceeds policy limit")
                    stack.append(["obj_key_or_end",None])
                    emit(b)
                elif b==125:  # '}'
                    require(stack and stack[-1][0] in ("obj_key_or_end","obj_comma_or_end"),
                            "Malformed object end in public RPC JSON")
                    stack.pop()
                    if not stack:
                        root_done=True
                    else:
                        _advance_container(stack)
                    emit(b)
                elif b==91:  # '['
                    require(len(stack)<MAX_JSON_DEPTH,"Public RPC JSON nesting exceeds policy limit")
                    stack.append(["arr_val_or_end",None])
                    emit(b)
                elif b==93:  # ']'
                    require(stack and stack[-1][0] in ("arr_val_or_end","arr_comma_or_val"),
                            "Malformed array end in public RPC JSON")
                    stack.pop()
                    if not stack:
                        root_done=True
                    else:
                        _advance_container(stack)
                    emit(b)
                elif b==58:  # ':'
                    require(stack and stack[-1][0]=="obj_colon",
                            "Unexpected ':' in public RPC JSON")
                    stack[-1][0]="obj_val"
                    emit(b)
                elif b==44:  # ','
                    require(stack and stack[-1][0] in ("obj_comma_or_end","arr_comma_or_val"),
                            "Unexpected ',' in public RPC JSON")
                    if stack[-1][0]=="obj_comma_or_end":
                        stack[-1]=["obj_key",None]
                    else:
                        stack[-1]=["arr_val",None]
                    emit(b)
                elif b==34:  # '"'
                    if stack and stack[-1][0] in ("obj_key_or_end","obj_key"):
                        in_string="key"
                        escaped=False
                        key_buf.clear()
                        emit(b)
                    elif (len(stack)==2 and stack[0]==["obj_val","result"]
                          and stack[1]==["obj_val","metadataXdr"]):
                        require(not skipped_metadata,"Duplicate metadataXdr key in public RPC response")
                        skipped_metadata=True
                        in_string="skip"
                        escaped=False
                        skip_utf8.reset()
                        emit(b)
                    else:
                        in_string="retain"
                        escaped=False
                        emit(b)
                else:
                    in_primitive=True
                    emit(b)
    except (UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise UnsafeTestnetResponse("Malformed JSON from public RPC") from exc

    if total_wire_bytes==0:
        raise RpcUnavailableError("Public Testnet RPC returned an empty response")
    if in_primitive:
        _advance_container(stack)
    require(in_string is None and not stack,"Truncated JSON from public RPC")
    try:
        return json.loads(retained.decode("utf-8"),parse_constant=_reject_json_constant)
    except (UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise UnsafeTestnetResponse("Malformed JSON from public RPC") from exc

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
    try:
        with build_opener(DenyRedirects()).open(request,timeout=12) as response:
            if response.status!=200:
                raise RpcUnavailableError(f"Public Testnet RPC returned HTTP {response.status}")
            obj=read_bounded_rpc_json(response,allow_skip_metadata_xdr=(method=="getLatestLedger"))
    except HTTPError as exc:
        raise RpcUnavailableError(f"Public Testnet RPC HTTP {exc.code}") from exc
    except (URLError,TimeoutError,OSError) as exc:
        if isinstance(exc,RpcUnavailableError):
            raise
        raise RpcUnavailableError(f"Public Testnet RPC unreachable: {exc}") from exc
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
            type(head.get("id")) is str and
            re.fullmatch(r"[a-f0-9]{64}",head["id"],re.I) is not None,
            "Unverified Testnet ledger head")
    if "protocolVersion" in head:
        require(type(head["protocolVersion"]) is int and head["protocolVersion"]>0,
                "Invalid Testnet protocolVersion")
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
        "headHash":head["id"],"headAgeSeconds":age,
        "observedContract":"official-native-XLM-asset-contract-only",
        "eventsInBoundedPage":count,"oldestLedger":oldest,
        "latestLedger":newest,"privateTransferProofVerified":False,
        "stealthbridgeContractsDeployed":False,
        "paymentsEnabled":False,
    },sort_keys=True))
    print("PASS read-only live public Testnet RPC; NO StealthBridge contract-event or private-transfer claim")

def run_cli():
    try:
        main()
        return 0
    except RpcUnavailableError as exc:
        print("FAIL public Testnet RPC smoke (upstream unavailable): "+str(exc),file=sys.stderr)
        return 1
    except (UnsafeTestnetResponse,TimeoutError,ValueError,OSError) as exc:
        print("FAIL public Testnet RPC smoke (response policy rejected): "+str(exc),file=sys.stderr)
        return 1

if __name__=="__main__":
    sys.exit(run_cli())
