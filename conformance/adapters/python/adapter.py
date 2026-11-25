#!/usr/bin/env python3
"""EHBP conformance adapter (Python). See conformance/adapters/README.md.

Reads one fixture on stdin, runs it through the public ehbp API, prints one
normalized result. All native-error translation lives in map_error.
"""

from __future__ import annotations

import json
import os
import resource
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

from ehbp import Client, Discover, code_of, core, discover, self_check
from ehbp.errors import InvalidInputError

HEADER_SUBSET = ("ehbp-response-nonce", "content-length", "transfer-encoding", "content-type")


def main() -> None:
    fx = json.load(sys.stdin)
    res = {"fixture_id": fx["id"], "outcome": "ok", "error_code": None, "status": None,
           "body_hex": None, "passthrough": False, "plaintext_emitted_before_error": False,
           "bytes_emitted_before_error": 0, "native_error": None, "runner": "python"}
    try:
        run(fx, res)
    except Exception as err:  # a non-EHBP failure is still the adapter reporting honestly
        res["outcome"] = "error"
        res["error_code"] = map_error(err)
        res["body_hex"] = None
        res["native_error"] = str(err)
    json.dump(res, sys.stdout)


def map_error(err: Exception) -> str:
    """The canonical code the library attached (code_of); anything uncoded is a caller/adapter input error."""
    code = code_of(err)
    return code.value if code else "INVALID_INPUT"


def run(fx: dict, res: dict) -> None:
    op = fx["operation"]
    if op == "derive_keys":
        key, nonce_base = core.derive_keys(hex_in(fx, "exportedSecret"), hex_in(fx, "requestEnc"), hex_in(fx, "responseNonce"))
        res["body_hex"] = (key + nonce_base).hex()
    elif op == "decrypt_response":
        decrypt(fx, res, False)
    elif op == "decrypt_response_streaming":
        decrypt(fx, res, True)
    elif op == "compute_nonce":
        res["body_hex"] = core.nonce_for(hex_in(fx, "nonceBase"), int(str_in(fx, "seqHex"), 16)).hex()
    elif op == "token_roundtrip":
        tok = core.parse_token(str_in(fx, "json"))
        res["body_hex"] = (tok.exported_secret + tok.request_enc).hex()
    elif op == "parse_config":
        res["body_hex"] = core.parse_config(hex_in(fx, "config")).hex()
    elif op == "marshal_config":
        res["body_hex"] = core.marshal_config(hex_in(fx, "publicKey")).hex()  # keyId is opaque: always 0
    elif op == "request":
        exchange(fx, res, "bytes", False, False, False, False)
    elif op == "discover":
        discover(discover_target(fx))  # raises on a bad key configuration
    elif op == "reject_reserved_header":
        hardening(fx, "header")
    elif op == "reject_cross_origin":
        hardening(fx, "cross")
    elif op == "residue_selfcheck":
        lines = self_check()  # the core's shared vectors through this language's bindings
        res["body_hex"] = "\n".join(lines).encode().hex()
        res["native_error"] = "; ".join(lines) or None
    elif op == "reject_url_credentials":
        hardening(fx, "credentials")
    elif op == "large_body":
        exchange(fx, res, "pattern", False, False, False, True)
    elif op == "request_stream":
        exchange(fx, res, "stream", False, False, False, False)
    elif op == "close_response_early":
        exchange(fx, res, "bytes", False, True, False, False)
    elif op == "token_before_response":
        exchange(fx, res, "bytes", True, False, False, False)
    elif op == "token_after_exchange":
        exchange(fx, res, "bytes", False, False, True, False)
    else:
        raise InvalidInputError(f"unknown operation {op}")


def oracle() -> tuple[str, Client]:
    """A Client over the oracle, discovering its key through the library."""
    base = os.environ["ORACLE_URL"]
    return base, Client(base, Discover, http_client=httpx.Client(follow_redirects=False, timeout=600))


def decrypt(fx: dict, res: dict, streaming: bool) -> None:
    """The token-only response path over the framed body, fed whole or split at
    the fixture's byte offsets; reports the plaintext delivered."""
    framed = hex_in(fx, "encryptedResponse")
    segments = split_at(framed, fx.get("chunking")) if streaming else [framed]
    out = bytearray()
    try:
        for chunk in core.decrypt(hex_in(fx, "exportedSecret"), hex_in(fx, "requestEnc"), hex_in(fx, "responseNonce"), segments):
            out += chunk
    except Exception:
        record_partial(res, out)
        raise
    res["body_hex"] = bytes(out).hex()


def exchange(fx: dict, res: dict, body: str, hold: bool, early: bool, after: bool, rss: bool) -> None:
    """Sends the fixture request to the oracle and reads the reply. body is how
    the fixture body is supplied (bytes, stream: unknown length, pattern: the
    lazy large body); hold reads the token while the oracle holds its reply;
    early reads one byte and closes; after reads the token once the exchange
    ended, also on error; rss reports peak RSS."""
    base, client = oracle()
    req = fx["request"]
    if body == "pattern":
        content = pattern(int_in(fx, "size_bytes"), int_in(fx, "block_seed"))
    elif req.get("body_hex") is None:
        content = None
    elif body == "stream":
        content = iter([bytes.fromhex(req["body_hex"])])
    else:
        content = bytes.fromhex(req["body_hex"])  # "" is a zero-length body, not absent
    out = bytearray()
    try:
        with ThreadPoolExecutor(1) as pool:
            pending = pool.submit(client.request, req["method"], req["path"], headers=req.get("headers") or {}, body=content)
            if hold:
                time.sleep(500 / 1000)  # the oracle holds 5 s
                res["token_before_response"] = client.session_recovery_token() is not None
            r = pending.result()
        res["status"] = r.status_code
        res["response_headers"] = subset_headers(r.headers)
        chunks = iter(r)
        if early:
            out += next(chunks)[:1]
            res["token_before_close"] = client.session_recovery_token() is not None
            r.close()
            res["token_after_close"] = client.session_recovery_token() is not None
        else:
            for chunk in chunks:
                out += chunk
            # No nonce on a non-2xx is a sanctioned unauthenticated pass-through.
            res["passthrough"] = "Ehbp-Response-Nonce".lower() not in res["response_headers"] and not 200 <= r.status_code < 300
        if rss:
            res["peak_rss_bytes"] = peak_rss_bytes()
        res["body_hex"] = bytes(out).hex()
    except Exception:
        record_partial(res, out)
        raise
    finally:
        if after:
            res["token_after_exchange"] = client.session_recovery_token() is not None
        client.close()


def hardening(fx: dict, target: str) -> None:
    """Sends a request the library must refuse before it reaches the wire; a reply from the oracle is the divergent result."""
    base, client = oracle()
    url = base + "/probe"
    if target == "cross":
        url = "http://other.invalid/probe"
    elif target == "credentials":
        url = base.replace("://", "://user:pass@", 1) + "/probe"
    headers = {}
    if target == "header":
        name = str_in(fx, "header")
        headers[name] = "attacker.invalid" if name.lower() == "host" else "0000000000000000000000000000000000000000000000000000000000000000"
    client.request("POST", url, headers=headers, body=b"x").read()


def discover_target(fx: dict) -> str:
    """The oracle listener the harness exposes as ORACLE_<TARGET>_URL (the main oracle for anything else)."""
    target = str_in(fx, "target")
    return (target != "ORACLE_URL" and os.environ.get(f"ORACLE_{target.upper()}_URL")) or os.environ["ORACLE_URL"]


# --- helpers ---

def record_partial(res: dict, out: bytes) -> None:
    """Fail-closed bookkeeping: plaintext delivered before the error, if any."""
    res["bytes_emitted_before_error"] = len(out)
    res["plaintext_emitted_before_error"] = len(out) > 0


def split_at(data: bytes, offsets) -> list[bytes]:
    segs, prev = [], 0
    for o in offsets or []:
        if prev < o < len(data):
            segs.append(data[prev:o])
            prev = o
    return segs + [data[prev:]]


def pattern(size: int, seed: int):
    """1 MiB block with block[i] = (i + seed) & 0xff, repeated to size, lazily."""
    block = bytes((i + seed) & 0xFF for i in range(1 << 20))
    while size > 0:
        n = min(size, len(block))
        yield block if n == len(block) else block[:n]
        size -= n


def peak_rss_bytes() -> int:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss if sys.platform == "darwin" else rss * 1024


def subset_headers(headers) -> dict:
    return {name: headers[name] for name in HEADER_SUBSET if name in headers}


# Fixture inputs are repository-controlled; a missing field is a broken fixture, so fail loudly (ADAPTER_CRASH).
def hex_in(fx: dict, key: str) -> bytes:
    return bytes.fromhex(str_in(fx, key))


def str_in(fx: dict, key: str) -> str:
    return fx["inputs"][key]


def int_in(fx: dict, key: str) -> int:
    return int(fx["inputs"][key])


if __name__ == "__main__":
    main()
