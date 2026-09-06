#!/usr/bin/env python3
"""Generate the crypto and config conformance fixtures.

Derived values (config bytes, concatenations, malformed variants) are computed
here so the committed fixtures cannot drift from a typo. Run from anywhere:

    python3 conformance/tools/gen_fixtures.py

It reads the three existing golden vectors under test-vectors/ and writes
test-vectors/conformance/crypto.json and config.json. The written files are the
source of truth the harness consumes; this script is the reproducible authoring aid.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test-vectors"
OUT = VECTORS / "conformance"

KEM_X25519 = "0020"
KDF_HKDF_SHA256 = "0001"
AEAD_AES_256_GCM = "0002"


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text())


def config(key_id="00", kem=KEM_X25519, pubkey=None, suites_len=None,
           kdf=KDF_HKDF_SHA256, aead=AEAD_AES_256_GCM) -> str:
    pubkey = pubkey if pubkey is not None else "07" * 32
    body = "".join([kdf, aead])
    if suites_len is None:
        suites_len = f"{len(body) // 2:04x}"
    return key_id + kem + pubkey + suites_len + body


def main() -> None:
    derive = load("derive.json")
    resp = load("response-decryption.json")
    token = load("session-recovery-token.json")

    enc = resp["encryptedResponse"]
    tampered = enc[:-2] + f"{int(enc[-2:], 16) ^ 0x01:02x}"     # flip last byte
    truncated = enc[:-2]                                        # drop last byte
    oversized = "ffffffff" + "00" * 16                          # length prefix > 64 MiB

    # Multi-frame bodies are sealed by the reference library so they are valid by
    # construction (correct per-frame nonce sequence and tags).
    from ehbp import derive_response_keys, encrypt_chunk, frame_chunk
    km = derive_response_keys(bytes.fromhex(resp["exportedSecret"]),
                              bytes.fromhex(resp["requestEnc"]),
                              bytes.fromhex(resp["responseNonce"]))

    def frame(seq, pt):
        return frame_chunk(encrypt_chunk(km, seq, pt))

    mf = frame(0, b"one") + frame(1, b"two") + frame(2, b"three")   # 3 valid frames
    mf_hex = mf.hex()
    f0 = frame(0, b"first")
    f1 = bytearray(frame(1, b"second"))
    f1[-1] ^= 0x01                                                  # tamper frame 1's tag
    partial_hex = (f0 + bytes(f1)).hex()
    f0_len = len(f0)

    # A zero-length frame (bare 0x00000000 prefix) must be ignored without
    # advancing the sequence number (SPEC 4.3).
    zero_frame_hex = (frame(0, b"before") + bytes(4) + frame(1, b"after")).hex()

    valid_pubkey = "07" * 32
    token_json = json.dumps({"exportedSecret": token["exportedSecret"],
                             "requestEnc": token["requestEnc"]})

    crypto = [
        {
            "id": "derive-keys-vector",
            "description": "Derive response key material from the shared vector.",
            "category": "crypto", "operation": "derive_keys",
            "inputs": {"exportedSecret": derive["exportedSecret"],
                       "requestEnc": derive["requestEnc"],
                       "responseNonce": derive["responseNonce"]},
            "expect": {"outcome": "ok",
                       "body_hex": derive["derivedKey"] + derive["derivedNonceBase"]},
        },
        {
            "id": "derive-keys-bad-secret-length",
            "description": "Exported secret is not 32 bytes.",
            "category": "crypto", "operation": "derive_keys",
            "inputs": {"exportedSecret": "00" * 16,
                       "requestEnc": derive["requestEnc"],
                       "responseNonce": derive["responseNonce"]},
            "expect": {"outcome": "error", "error_code": "INVALID_INPUT"},
        },
        {
            "id": "decrypt-response-vector",
            "description": "Decrypt the single-frame response from the shared vector.",
            "category": "crypto", "operation": "decrypt_response",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": enc},
            "expect": {"outcome": "ok", "body_hex": resp["plaintext"]},
        },
        {
            "id": "decrypt-response-streaming-fragmented",
            "description": "Same body fed in 3-byte fragments across the frame boundary.",
            "category": "crypto", "operation": "decrypt_response_streaming",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": enc},
            "chunking": [3, 6, 20],
            "expect": {"outcome": "ok", "body_hex": resp["plaintext"]},
        },
        {
            "id": "decrypt-response-tampered-tag",
            "description": "Final ciphertext byte flipped; AEAD auth must fail closed.",
            "category": "crypto", "operation": "decrypt_response",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": tampered},
            "expect": {"outcome": "error", "error_code": "AEAD_DECRYPT_FAILED",
                       "plaintext_emitted_before_error": False,
                       "bytes_emitted_before_error": 0},
        },
        {
            "id": "decrypt-response-truncated-frame",
            "description": "Frame ciphertext one byte short of its length prefix.",
            "category": "crypto", "operation": "decrypt_response",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": truncated},
            "expect": {"outcome": "error", "error_code": "FRAMING_TRUNCATED",
                       "plaintext_emitted_before_error": False,
                       "bytes_emitted_before_error": 0},
        },
        {
            "id": "decrypt-response-oversized-chunk",
            "description": "Length prefix 0xffffffff exceeds the 64 MiB cap.",
            "category": "crypto", "operation": "decrypt_response",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": oversized},
            "expect": {"outcome": "error", "error_code": "CHUNK_TOO_LARGE",
                       "plaintext_emitted_before_error": False,
                       "bytes_emitted_before_error": 0},
        },
        {
            "id": "decrypt-response-multiframe",
            "description": "Three valid frames; sequence advances across frames.",
            "category": "crypto", "operation": "decrypt_response",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": mf_hex},
            "expect": {"outcome": "ok", "body_hex": b"onetwothree".hex()},
        },
        {
            "id": "decrypt-response-multiframe-streaming",
            "description": "Three frames fed in fragments that cross frame boundaries.",
            "category": "crypto", "operation": "decrypt_response_streaming",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": mf_hex},
            "chunking": [10, 30, 50],
            "expect": {"outcome": "ok", "body_hex": b"onetwothree".hex()},
        },
        {
            "id": "decrypt-response-partial-then-fail",
            "description": "Frame 0 authenticates and is emitted; frame 1's tag is bad.",
            "category": "crypto", "operation": "decrypt_response_streaming",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": partial_hex},
            "chunking": [f0_len],
            "expect": {"outcome": "error", "error_code": "AEAD_DECRYPT_FAILED",
                       "plaintext_emitted_before_error": True,
                       "bytes_emitted_before_error": len(b"first")},
        },
        {
            "id": "decrypt-response-zero-length-frame",
            "description": "A zero-length frame between two frames is ignored; sequence does not advance.",
            "category": "crypto", "operation": "decrypt_response",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": zero_frame_hex},
            "expect": {"outcome": "ok", "body_hex": b"beforeafter".hex()},
        },
        {
            "id": "compute-nonce-seq-1",
            "description": "Base of zeros XOR sequence 1.",
            "category": "crypto", "operation": "compute_nonce",
            "inputs": {"nonceBase": "00" * 12, "seqHex": "0000000000000001"},
            "expect": {"outcome": "ok", "body_hex": "000000000000000000000001"},
        },
        {
            "id": "compute-nonce-seq-large",
            "description": "Sequence above 2^32 to expose 32-bit-only clients.",
            "category": "crypto", "operation": "compute_nonce",
            "inputs": {"nonceBase": "00" * 12, "seqHex": "0102030405060708"},
            "expect": {"outcome": "ok", "body_hex": "000000000102030405060708"},
        },
        {
            "id": "token-roundtrip-vector",
            "description": "Decode the shared session recovery token.",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": token_json},
            "expect": {"outcome": "ok",
                       "body_hex": token["exportedSecret"] + token["requestEnc"]},
        },
        {
            "id": "token-bad-hex",
            "description": "Token field contains non-hex characters.",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": json.dumps({"exportedSecret": "zz" * 32,
                                           "requestEnc": token["requestEnc"]})},
            "expect": {"outcome": "error", "error_code": "INVALID_TOKEN"},
        },
        {
            "id": "token-missing-field",
            "description": "Token is missing requestEnc.",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": json.dumps({"exportedSecret": token["exportedSecret"]})},
            "expect": {"outcome": "error", "error_code": "INVALID_TOKEN"},
        },
        {
            "id": "token-wrong-length",
            "description": "exportedSecret decodes to 16 bytes, not 32.",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": json.dumps({"exportedSecret": "00" * 16,
                                           "requestEnc": token["requestEnc"]})},
            "expect": {"outcome": "error", "error_code": "INVALID_TOKEN"},
        },
    ]

    cfg = [
        {
            "id": "parse-config-valid",
            "description": "Parse a well-formed single key config.",
            "category": "config", "operation": "parse_config",
            "inputs": {"config": config(pubkey=valid_pubkey)},
            "expect": {"outcome": "ok", "body_hex": valid_pubkey},
        },
        {
            "id": "marshal-config",
            "description": "Marshal a config and compare bytes.",
            "category": "config", "operation": "marshal_config",
            "inputs": {"publicKey": valid_pubkey, "keyId": 0},
            "expect": {"outcome": "ok", "body_hex": config(pubkey=valid_pubkey)},
        },
        {
            "id": "parse-config-multiple-takes-first",
            "description": "Two configs concatenated; the first public key wins.",
            "category": "config", "operation": "parse_config",
            "inputs": {"config": config(pubkey="07" * 32) + config(pubkey="08" * 32)},
            "expect": {"outcome": "ok", "body_hex": "07" * 32},
        },
        {
            "id": "parse-config-truncated-pubkey",
            "description": "Public key cut to 16 bytes.",
            "category": "config", "operation": "parse_config",
            "inputs": {"config": "00" + KEM_X25519 + "07" * 16},
            "expect": {"outcome": "error", "error_code": "INVALID_KEY_CONFIG"},
        },
        {
            "id": "parse-config-no-suites",
            "description": "Cipher suites length is zero.",
            "category": "config", "operation": "parse_config",
            "inputs": {"config": "00" + KEM_X25519 + "07" * 32 + "0000"},
            "expect": {"outcome": "error", "error_code": "INVALID_KEY_CONFIG"},
        },
        {
            "id": "parse-config-suites-len-not-multiple-of-4",
            "description": "Cipher suites length is 3.",
            "category": "config", "operation": "parse_config",
            "inputs": {"config": "00" + KEM_X25519 + "07" * 32 + "0003" + "000100"},
            "expect": {"outcome": "error", "error_code": "INVALID_KEY_CONFIG"},
        },
        {
            "id": "parse-config-unsupported-kem",
            "description": "KEM id is P-256, not X25519.",
            "category": "config", "operation": "parse_config",
            "inputs": {"config": config(kem="0010", pubkey="07" * 32)},
            "expect": {"outcome": "error", "error_code": "UNSUPPORTED_SUITE"},
        },
        {
            "id": "parse-config-unsupported-aead",
            "description": "AEAD id is ChaCha20-Poly1305, not AES-256-GCM.",
            "category": "config", "operation": "parse_config",
            "inputs": {"config": config(pubkey="07" * 32, aead="0003")},
            "expect": {"outcome": "error", "error_code": "UNSUPPORTED_SUITE"},
        },
    ]

    def e2e(fid, scenario, expect, desc, body="hello", method="POST", browser=None):
        fx = {
            "id": fid, "description": desc, "category": "e2e", "operation": "request",
            "server_scenario": scenario,
            "request": {"method": method, "path": f"/s/{scenario}",
                        "body_hex": body.encode().hex() if body else None, "headers": {}},
            "expect": expect,
        }
        if browser is not None:
            fx["browser"] = browser
        return fx

    e2e_list = [
        e2e("e2e-echo-roundtrip", "echo",
            {"outcome": "ok", "status": 200, "body_hex": b"hello".hex(),
             "response_headers_absent": ["content-length", "transfer-encoding"]},
            "Encrypted round trip; framing headers stripped from the decrypted response."),
        e2e("e2e-echo-large", "echo",
            {"outcome": "ok", "status": 200, "body_hex": (b"a" * 20000).hex()},
            "20 KB round trip; exercises multi-frame request encryption end to end.",
            body="a" * 20000),
        e2e("e2e-missing-nonce-200", "drop_nonce_200",
            {"outcome": "error", "error_code": "MISSING_RESPONSE_NONCE",
             "plaintext_emitted_before_error": False, "bytes_emitted_before_error": 0},
            "2xx with no nonce MUST fail closed, not read plaintext."),
        e2e("e2e-invalid-nonce-len", "invalid_nonce_len",
            {"outcome": "error", "error_code": "INVALID_RESPONSE_NONCE"},
            "Nonce present but 16 bytes."),
        e2e("e2e-duplicate-nonce", "duplicate_nonce",
            {"outcome": "error", "error_code": "DUPLICATE_RESPONSE_NONCE"},
            "Two nonce headers MUST fail closed.",
            browser={"runnable": False, "skip_reason": "browser-coalesces-duplicate-headers"}),
        e2e("e2e-tampered-tag", "tamper_tag",
            {"outcome": "error", "error_code": "AEAD_DECRYPT_FAILED",
             "plaintext_emitted_before_error": False, "bytes_emitted_before_error": 0},
            "Flipped tag byte."),
        e2e("e2e-truncated-frame", "truncate_final_frame",
            {"outcome": "error", "error_code": "FRAMING_TRUNCATED",
             "plaintext_emitted_before_error": False, "bytes_emitted_before_error": 0},
            "Response ends mid-frame."),
        e2e("e2e-oversized-chunk", "oversized_chunk",
            {"outcome": "error", "error_code": "CHUNK_TOO_LARGE",
             "plaintext_emitted_before_error": False, "bytes_emitted_before_error": 0},
            "Length prefix exceeds the cap."),
        e2e("e2e-keyconfig-422", "key_config_mismatch_422",
            {"outcome": "error", "error_code": "KEY_CONFIG_MISMATCH"},
            "422 problem+json key-config mismatch is a typed recoverable error."),
        e2e("e2e-passthrough-502", "plaintext_error_502",
            {"outcome": "ok", "status": 502, "passthrough": True,
             "body_hex": b"upstream unavailable".hex()},
            "Non-2xx with no nonce MAY pass through as an unauthenticated body."),
        e2e("e2e-plaintext-200-failclosed", "plaintext_success_200",
            {"outcome": "error", "error_code": "MISSING_RESPONSE_NONCE",
             "plaintext_emitted_before_error": False, "bytes_emitted_before_error": 0},
            "2xx plaintext MUST fail closed."),
        e2e("e2e-empty-response", "empty_encrypted",
            {"outcome": "ok", "status": 200, "body_hex": ""},
            "Encrypted response with a nonce but zero frames decrypts to an empty body."),
        e2e("e2e-bodyless-passthrough", "bodyless_plaintext",
            {"outcome": "ok", "status": 200,
             "body_hex": b"plaintext for bodyless request".hex()},
            "Bodyless request is unencrypted; its plaintext response is returned as-is (SPEC 7.4).",
            body=None, method="GET"),
    ]

    def shape(fid, body, desc):
        return {
            "id": fid, "description": desc, "category": "shape", "operation": "request",
            "server_scenario": "shape",
            "request": {"method": "POST", "path": "/s/shape",
                        "body_hex": body.hex(), "headers": {}},
            "expect": {"outcome": "ok"},
        }

    # Observational only: the harness records the received wire shape and never
    # fails on these. The large body reveals clients that fragment the request.
    shape_list = [
        shape("shape-small-body", b"hello",
              "Small body: compares transfer-encoding and framing."),
        shape("shape-large-body", b"a" * 20000,
              "20 KB body: reveals clients that split the request into frames."),
    ]

    def capi(fid, op, expect, desc, inputs=None):
        return {
            "id": fid, "description": desc, "category": "client-api", "operation": op,
            "inputs": inputs or {},
            "browser": {"runnable": False, "skip_reason": "client-api-ops-tested-in-native-adapters"},
            "expect": expect,
        }

    # Capability-gated: each adapter runs the ops its library implements and reports
    # `skipped` for the rest (discovery: no Swift; hardening: Python/Rust only).
    client_api = [
        capi("discover-bad-content-type", "discover",
             {"outcome": "error", "error_code": "INVALID_KEY_CONFIG"},
             "Discovery rejects a key config served under the wrong content type.",
             inputs={"target": "bad_ct"}),
        capi("discover-non-200", "discover",
             {"outcome": "error", "error_code": "INVALID_KEY_CONFIG"},
             "Discovery rejects a non-200 key-config response.",
             inputs={"target": "non200"}),
        capi("harden-reserved-header", "reject_reserved_header",
             {"outcome": "error", "error_code": "INVALID_INPUT"},
             "Client rejects a caller setting a reserved protocol header."),
        capi("harden-cross-origin", "reject_cross_origin",
             {"outcome": "error", "error_code": "INVALID_INPUT"},
             "Client rejects a request to a different origin."),
        capi("harden-url-credentials", "reject_url_credentials",
             {"outcome": "error", "error_code": "INVALID_INPUT"},
             "Client rejects credentials embedded in the URL."),
    ]

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "client-api.json").write_text(json.dumps(client_api, indent=2) + "\n")
    (OUT / "crypto.json").write_text(json.dumps(crypto, indent=2) + "\n")
    (OUT / "config.json").write_text(json.dumps(cfg, indent=2) + "\n")
    (OUT / "e2e.json").write_text(json.dumps(e2e_list, indent=2) + "\n")
    (OUT / "shape.json").write_text(json.dumps(shape_list, indent=2) + "\n")
    print(f"wrote {len(crypto)} crypto + {len(cfg)} config + {len(e2e_list)} e2e "
          f"+ {len(shape_list)} shape + {len(client_api)} client-api fixtures to {OUT}")


if __name__ == "__main__":
    main()
