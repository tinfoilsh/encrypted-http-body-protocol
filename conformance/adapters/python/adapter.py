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
    compute_nonce,
    derive_response_keys,
)
from ehbp.protocol import ENCAPSULATED_KEY_HEADER
from ehbp.errors import (
    CryptoError,
    EHBPError,
    HPKEError,
    InvalidConfigError,
    InvalidInputError,
    KeyConfigMismatchError,
    ProtocolError,
)
from ehbp.protocol import KEYS_PATH, RESPONSE_NONCE_HEADER

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
        res["native_error"] = f"{type(err).__name__}: {err}"
    except Exception as err:  # non-EHBP failure is still the adapter reporting honestly
        res["outcome"] = "error"
        res["error_code"] = map_error(fx["operation"], err)
        res["native_error"] = f"{type(err).__name__}: {err}"
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
        res["body_hex"] = ServerIdentity.from_public_key_bytes(b(ins, "publicKey")).marshal_public_config().hex()
    elif op == "request":
        request(fx, res)
    elif op == "discover":
        Client.discover(discover_target(ins))  # raises on bad content type / status
    elif op in ("reject_reserved_header", "reject_cross_origin", "reject_url_credentials"):
        hardening(op)
    else:
        raise InvalidInputError(f"unknown operation {op}")


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
        res["bytes_emitted_before_error"] = len(out)
        res["plaintext_emitted_before_error"] = len(out) > 0
        raise
    res["body_hex"] = bytes(out).hex()


def request(fx: dict, res: dict) -> None:
    base = os.environ["ORACLE_URL"].rstrip("/")
    keys = httpx.get(base + KEYS_PATH).content
    identity = ServerIdentity.unmarshal_public_config(keys)
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
        res["bytes_emitted_before_error"] = len(out)
        res["plaintext_emitted_before_error"] = len(out) > 0
        raise
    finally:
        client.close()


# map_error is the sole native-error -> canonical-code translation.
def map_error(op: str, err: Exception) -> str:
    msg = str(err)
    if isinstance(err, KeyConfigMismatchError):
        return "KEY_CONFIG_MISMATCH"
    if isinstance(err, CryptoError):
        return "AEAD_DECRYPT_FAILED"
    if isinstance(err, HPKEError):
        return "HPKE_SETUP_FAILED"
    if isinstance(err, InvalidConfigError):
        return "UNSUPPORTED_SUITE" if "unsupported" in msg.lower() else "INVALID_KEY_CONFIG"
    if isinstance(err, InvalidInputError):
        return "INVALID_TOKEN" if op == "token_roundtrip" else "INVALID_INPUT"
    if isinstance(err, ProtocolError):
        low = msg.lower()
        if "content type" in low or "returned status" in low:
            return "INVALID_KEY_CONFIG"
        if "missing" in low and "nonce" in low:
            return "MISSING_RESPONSE_NONCE"
        if "multiple" in low:
            return "DUPLICATE_RESPONSE_NONCE"
        if "nonce" in low:
            return "INVALID_RESPONSE_NONCE"
        if "truncated" in low:
            return "FRAMING_TRUNCATED"
        if "exceeds maximum" in low:
            return "CHUNK_TOO_LARGE"
        if "overflow" in low:
            return "SEQUENCE_OVERFLOW"
    return "INVALID_INPUT"


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
