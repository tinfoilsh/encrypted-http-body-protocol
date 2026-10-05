#!/usr/bin/env python3
"""EHBP conformance adapter (Python). See conformance/adapters/README.md.

Reads one fixture on stdin, runs it through the public ehbp API, prints one
normalized result. All native-error translation lives in map_error.
"""

from __future__ import annotations

import json
import os
import sys

import httpx

from ehbp import (
    Client,
    EHBPTransport,
    ServerIdentity,
    SessionRecoveryToken,
    code_of,
    compute_nonce,
    derive_response_keys,
)
from ehbp.errors import EHBPError, InvalidInputError
from ehbp.protocol import ENCAPSULATED_KEY_HEADER, KEYS_PATH, RESPONSE_NONCE_HEADER

HEADER_SUBSET = ("ehbp-response-nonce", "content-length", "transfer-encoding", "content-type")


def main() -> None:
    fx = json.load(sys.stdin)
    res = {"fixture_id": fx["id"], "outcome": "ok", "error_code": None, "status": None,
           "body_hex": None, "passthrough": False, "plaintext_emitted_before_error": False,
           "bytes_emitted_before_error": 0, "native_error": None, "runner": "python"}
    try:
        run(fx, res)
    except EHBPError as err:
        res["outcome"] = "error"
        res["error_code"] = map_error(fx["operation"], err)
        res["body_hex"] = None
        res["native_error"] = str(err)
    except Exception as err:  # non-EHBP failure is still the adapter reporting honestly
        res["outcome"] = "error"
        res["error_code"] = map_error(fx["operation"], err)
        res["native_error"] = str(err)
    json.dump(res, sys.stdout)


def run(fx: dict, res: dict) -> None:
    op = fx["operation"]
    ins = fx.get("inputs", {})
    if op == "derive_keys":
        km = derive_response_keys(b(ins, "exportedSecret"), b(ins, "requestEnc"), b(ins, "responseNonce"))
        res["body_hex"] = (km.key + km.nonce_base).hex()
    elif op == "compute_nonce":
        res["body_hex"] = compute_nonce(b(ins, "nonceBase"), int(ins["seqHex"], 16)).hex()
    elif op in ("decrypt_response", "decrypt_response_streaming"):
        decrypt(fx, res)
    elif op == "token_roundtrip":
        tok = SessionRecoveryToken.from_json(ins["json"])
        res["body_hex"] = (tok.exported_secret + tok.request_enc).hex()
    elif op == "parse_config":
        res["body_hex"] = ServerIdentity.unmarshal_public_config(b(ins, "config")).public_key_bytes().hex()
    elif op == "marshal_config":
        res["body_hex"] = ServerIdentity(b(ins, "publicKey"), int(ins.get("keyId", 0))).marshal_public_config().hex()
    elif op == "request":
        request(fx, res)
    elif op == "large_body":
        large_body(fx, res)
    elif op == "token_before_response":
        token_before_response(fx, res)
    elif op == "discover":
        Client.discover(discover_target(ins))  # raises on bad content type / status
    elif op in ("reject_reserved_header", "reject_cross_origin", "reject_url_credentials"):
        hardening(op)
    else:
        raise InvalidInputError(f"unknown operation {op}")


def record_partial(res: dict, out: bytes) -> None:
    """Fail-closed bookkeeping: plaintext delivered before the error, if any."""
    res["bytes_emitted_before_error"] = len(out)
    res["plaintext_emitted_before_error"] = len(out) > 0


def discover_target(ins: dict) -> str:
    return {"bad_ct": os.environ.get("ORACLE_BAD_CT_URL", ""),
            "non200": os.environ.get("ORACLE_NON200_URL", "")}.get(
        ins.get("target"), os.environ["ORACLE_URL"])


def hardening(op: str) -> None:
    base = os.environ["ORACLE_URL"]
    client = Client.discover(base)
    if op == "reject_reserved_header":
        client.request("POST", "/s/echo", body=b"x", headers={ENCAPSULATED_KEY_HEADER: "x"})
    elif op == "reject_cross_origin":
        client.request("GET", "http://other.example/x")
    else:  # reject_url_credentials
        client.request("GET", base.replace("http://", "http://user:pass@") + "/x")


def decrypt(fx: dict, res: dict) -> None:
    ins = fx["inputs"]
    token = SessionRecoveryToken(b(ins, "exportedSecret"), b(ins, "requestEnc"))
    decryptor = token.create_response_decryptor(b(ins, "responseNonce"))
    framed = b(ins, "encryptedResponse")
    segments = split_at(framed, fx.get("chunking")) if fx["operation"].endswith("streaming") else [framed]

    out = bytearray()
    try:
        for seg in segments:
            for chunk in decryptor.push(seg):
                out += chunk
        decryptor.finish()
    except EHBPError:
        record_partial(res, out)
        raise
    res["body_hex"] = bytes(out).hex()


def oracle() -> tuple[str, ServerIdentity]:
    """(base URL, discovered identity): the one bootstrap for every oracle-bound op."""
    base = os.environ["ORACLE_URL"].rstrip("/")
    return base, ServerIdentity.unmarshal_public_config(httpx.get(base + KEYS_PATH).content)


def request(fx: dict, res: dict) -> None:
    base, identity = oracle()
    req = fx["request"]
    content = bytes.fromhex(req["body_hex"]) if req.get("body_hex") else None

    client = httpx.Client(transport=EHBPTransport(identity), base_url=base)
    out = bytearray()
    try:
        with client.stream(req["method"], req["path"], content=content,
                           headers=req.get("headers") or {}) as r:
            res["status"] = r.status_code
            res["response_headers"] = subset_headers(r.headers)
            for chunk in r.iter_bytes():
                out += chunk
        res["body_hex"] = bytes(out).hex()
        no_nonce = RESPONSE_NONCE_HEADER.lower() not in {k.lower() for k in (res.get("response_headers") or {})}
        res["passthrough"] = no_nonce and not (200 <= (res["status"] or 0) < 300)
    except EHBPError:
        record_partial(res, out)
        raise
    finally:
        client.close()


def token_before_response(fx: dict, res: dict) -> None:
    """Read the session recovery token while the oracle still holds its reply (SPEC 6)."""
    import threading
    import time

    base, identity = oracle()
    client = Client(base, identity)
    req = fx["request"]
    done: list = []  # [Response] or [BaseException]

    def send() -> None:
        try:
            done.append(client.post(req["path"], body=bytes.fromhex(req["body_hex"])))
        except BaseException as err:  # noqa: BLE001 - re-raised on the main thread below
            done.append(err)

    worker = threading.Thread(target=send)
    worker.start()
    time.sleep(0.5)  # oracle holds 5 s: 10x margin
    res["token_before_response"] = client.get_session_recovery_token() is not None
    worker.join()
    r = done[0]
    if isinstance(r, BaseException):
        raise r
    res["status"] = r.status_code
    res["body_hex"] = r.content.hex()


def pattern(size: int, seed: int):
    """1 MiB block with block[i] = (i + seed) & 0xff, repeated to size, lazily."""
    block = bytes((i + seed) & 0xFF for i in range(1 << 20))
    while size > 0:
        n = min(size, len(block))
        yield block if n == len(block) else block[:n]
        size -= n


def large_body(fx: dict, res: dict) -> None:
    import resource
    import sys as _sys

    base, identity = oracle()
    ins = fx["inputs"]
    client = httpx.Client(transport=EHBPTransport(identity), base_url=base, timeout=600)
    try:
        r = client.post(fx["request"]["path"], content=pattern(int(ins["size_bytes"]), int(ins["block_seed"])))
        res["status"] = r.status_code
        res["body_hex"] = r.content.hex()
    finally:
        client.close()
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    res["peak_rss_bytes"] = rss if _sys.platform == "darwin" else rss * 1024


# map_error reads the canonical code the library attached (code_of). Anything
# uncoded is a caller/adapter input error.
def map_error(op: str, err: Exception) -> str:
    code = code_of(err)
    return code.value if code else "INVALID_INPUT"


# --- helpers ---

def b(ins: dict, key: str) -> bytes:
    return bytes.fromhex(ins[key])


def split_at(data: bytes, offsets):
    if not offsets:
        return [data]
    segs, prev = [], 0
    for o in offsets:
        if prev < o < len(data):
            segs.append(data[prev:o])
            prev = o
    segs.append(data[prev:])
    return segs


def subset_headers(headers) -> dict:
    out = {}
    for name in HEADER_SUBSET:
        if name in headers:
            out[name] = headers[name]
    return out


if __name__ == "__main__":
    main()
