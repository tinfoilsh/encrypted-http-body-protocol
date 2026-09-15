#!/usr/bin/env python3
"""Generate the deterministic conformance and security fixtures.

Derived values (config bytes, concatenations, malformed variants) are computed
here so the committed fixtures cannot drift from a typo. Run from anywhere:

    python3 conformance/tools/gen_fixtures.py

It reads the three existing golden vectors under test-vectors/ and writes
all JSON files under test-vectors/conformance. The written files are the source
of truth the harness consumes; this script is the reproducible authoring aid.
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

    mf0 = frame(0, b"one")
    mf1 = frame(1, b"two")
    mf2 = frame(2, b"three")
    mf = mf0 + mf1 + mf2                                             # 3 valid frames
    mf_hex = mf.hex()
    f0 = frame(0, b"first")
    f1 = bytearray(frame(1, b"second"))
    f1[-1] ^= 0x01                                                  # tamper frame 1's tag
    partial_hex = (f0 + bytes(f1)).hex()
    f0_len = len(f0)

    # A zero-length frame (bare 0x00000000 prefix) must be ignored without
    # advancing the sequence number (SPEC 4.3).
    zero_frame_hex = (frame(0, b"before") + bytes(4) + frame(1, b"after")).hex()
    zero_frame_flood_hex = (bytes(4 * 4096) + frame(0, b"after-flood")).hex()

    # Security mutations deliberately preserve every input except the property
    # named by the fixture. This keeps an authentication failure attributable to
    # one cause rather than to malformed authoring data.
    partial_prefixes = [bytes.fromhex("00" * n).hex() for n in (1, 2, 3)]
    authenticated_then_partial = frame(0, b"authenticated") + b"\x00\x00\x00"
    short_ciphertext_1 = (1).to_bytes(4, "big") + b"\x00"
    short_ciphertext_15 = (15).to_bytes(4, "big") + bytes(15)
    duplicate_frame = mf0 + mf0  # second copy is replayed under sequence 1
    reordered_frames = mf1 + mf0  # first ciphertext was sealed for sequence 1
    wrong_nonce = bytearray.fromhex(resp["responseNonce"])
    wrong_nonce[0] ^= 0x01
    wrong_secret = bytearray.fromhex(resp["exportedSecret"])
    wrong_secret[0] ^= 0x01
    wrong_request_enc = bytearray.fromhex(resp["requestEnc"])
    wrong_request_enc[0] ^= 0x01

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
            "id": "decrypt-response-zero-frame-flood",
            "description": "4096 legal empty frames precede one authenticated frame; parser must not hang or crash.",
            "category": "crypto", "operation": "decrypt_response_streaming",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": zero_frame_flood_hex},
            "chunking": [1, 3, 4, 4096, 8192, 16384],
            "expect": {"outcome": "ok", "body_hex": b"after-flood".hex()},
        },
        *[
            {
                "id": f"decrypt-response-partial-prefix-{n}",
                "description": f"Entity body ends after {n} of 4 frame-length bytes.",
                "category": "crypto", "operation": "decrypt_response_streaming",
                "inputs": {"exportedSecret": resp["exportedSecret"],
                           "requestEnc": resp["requestEnc"],
                           "responseNonce": resp["responseNonce"],
                           "encryptedResponse": partial_prefixes[n - 1]},
                "chunking": [1],
                "expect": {"outcome": "error", "error_code": "FRAMING_TRUNCATED",
                           "plaintext_emitted_before_error": False,
                           "bytes_emitted_before_error": 0},
            }
            for n in (1, 2, 3)
        ],
        {
            "id": "decrypt-response-authenticated-then-partial-prefix",
            "description": "A valid frame is delivered before a trailing partial length prefix is detected.",
            "category": "crypto", "operation": "decrypt_response_streaming",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": authenticated_then_partial.hex()},
            "chunking": [len(authenticated_then_partial) - 3],
            "expect": {"outcome": "error", "error_code": "FRAMING_TRUNCATED",
                       "plaintext_emitted_before_error": True,
                       "bytes_emitted_before_error": len(b"authenticated")},
        },
        {
            "id": "decrypt-response-ciphertext-shorter-than-tag-1",
            "description": "A one-byte ciphertext cannot contain an AES-GCM tag.",
            "category": "crypto", "operation": "decrypt_response",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": short_ciphertext_1.hex()},
            "expect": {"outcome": "error", "error_code": "AEAD_DECRYPT_FAILED",
                       "plaintext_emitted_before_error": False,
                       "bytes_emitted_before_error": 0},
        },
        {
            "id": "decrypt-response-ciphertext-shorter-than-tag-15",
            "description": "A 15-byte ciphertext is one byte shorter than an AES-GCM tag.",
            "category": "crypto", "operation": "decrypt_response",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": short_ciphertext_15.hex()},
            "expect": {"outcome": "error", "error_code": "AEAD_DECRYPT_FAILED",
                       "plaintext_emitted_before_error": False,
                       "bytes_emitted_before_error": 0},
        },
        {
            "id": "decrypt-response-reordered-frames",
            "description": "Reordering valid frames changes their sequence nonces and must fail authentication.",
            "category": "crypto", "operation": "decrypt_response",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": reordered_frames.hex()},
            "expect": {"outcome": "error", "error_code": "AEAD_DECRYPT_FAILED",
                       "plaintext_emitted_before_error": False,
                       "bytes_emitted_before_error": 0},
        },
        {
            "id": "decrypt-response-replayed-frame",
            "description": "Replaying frame 0 as frame 1 emits only the first authenticated plaintext, then fails.",
            "category": "crypto", "operation": "decrypt_response_streaming",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": duplicate_frame.hex()},
            "chunking": [len(mf0)],
            "expect": {"outcome": "error", "error_code": "AEAD_DECRYPT_FAILED",
                       "plaintext_emitted_before_error": True,
                       "bytes_emitted_before_error": len(b"one")},
        },
        *[
            {
                "id": f"decrypt-response-wrong-{name}",
                "description": description,
                "category": "crypto", "operation": "decrypt_response",
                "inputs": {"exportedSecret": secret.hex() if name == "exported-secret" else resp["exportedSecret"],
                           "requestEnc": request_enc.hex() if name == "request-enc" else resp["requestEnc"],
                           "responseNonce": nonce.hex() if name == "nonce" else resp["responseNonce"],
                           "encryptedResponse": enc},
                "expect": {"outcome": "error", "error_code": "AEAD_DECRYPT_FAILED",
                           "plaintext_emitted_before_error": False,
                           "bytes_emitted_before_error": 0},
            }
            for name, description, secret, request_enc, nonce in [
                ("exported-secret", "A one-bit change to the exported secret breaks response binding.", wrong_secret, wrong_request_enc, wrong_nonce),
                ("request-enc", "A one-bit change to requestEnc breaks response-to-request binding.", wrong_secret, wrong_request_enc, wrong_nonce),
                ("nonce", "A valid-length but incorrect response nonce breaks authentication.", wrong_secret, wrong_request_enc, wrong_nonce),
            ]
        ],
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
        {
            "id": "token-request-enc-wrong-length",
            "description": "requestEnc decodes to 31 bytes, not 32.",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": json.dumps({"exportedSecret": token["exportedSecret"],
                                           "requestEnc": "00" * 31})},
            "expect": {"outcome": "error", "error_code": "INVALID_TOKEN"},
        },
        {
            "id": "token-odd-length-hex",
            "description": "Hex fields must contain complete byte pairs.",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": json.dumps({"exportedSecret": token["exportedSecret"] + "0",
                                           "requestEnc": token["requestEnc"]})},
            "expect": {"outcome": "error", "error_code": "INVALID_TOKEN"},
        },
        {
            "id": "token-null",
            "description": "The token must be an object, not JSON null.",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": "null"},
            "expect": {"outcome": "error", "error_code": "INVALID_TOKEN"},
        },
        {
            "id": "token-array",
            "description": "The token must be an object, not an array.",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": "[]"},
            "expect": {"outcome": "error", "error_code": "INVALID_TOKEN"},
        },
        {
            "id": "token-non-string-field",
            "description": "Token byte fields must be hex strings.",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": json.dumps({"exportedSecret": 7,
                                           "requestEnc": token["requestEnc"]})},
            "expect": {"outcome": "error", "error_code": "INVALID_TOKEN"},
        },
        {
            "id": "token-empty-object",
            "description": "An object with both required fields absent is invalid.",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": "{}"},
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
            "id": "parse-config-empty",
            "description": "An empty discovery body is not a key configuration.",
            "category": "config", "operation": "parse_config",
            "inputs": {"config": ""},
            "expect": {"outcome": "error", "error_code": "INVALID_KEY_CONFIG"},
        },
        {
            "id": "parse-config-truncated-kem-id",
            "description": "Only the key id and first KEM-id byte are present.",
            "category": "config", "operation": "parse_config",
            "inputs": {"config": "0000"},
            "expect": {"outcome": "error", "error_code": "INVALID_KEY_CONFIG"},
        },
        {
            "id": "parse-config-truncated-suites-length",
            "description": "The public key is complete but the suites-length field has one byte.",
            "category": "config", "operation": "parse_config",
            "inputs": {"config": "00" + KEM_X25519 + "07" * 32 + "00"},
            "expect": {"outcome": "error", "error_code": "INVALID_KEY_CONFIG"},
        },
        {
            "id": "parse-config-declared-suites-truncated",
            "description": "The suites length declares eight bytes but only one suite follows.",
            "category": "config", "operation": "parse_config",
            "inputs": {"config": "00" + KEM_X25519 + "07" * 32 + "0008" + KDF_HKDF_SHA256 + AEAD_AES_256_GCM},
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
        {
            "id": "parse-config-unsupported-kdf",
            "description": "KDF id is HKDF-SHA384, not HKDF-SHA256.",
            "category": "config", "operation": "parse_config",
            "inputs": {"config": config(pubkey="07" * 32, kdf="0002")},
            "expect": {"outcome": "error", "error_code": "UNSUPPORTED_SUITE"},
        },
    ]

    # Swift intentionally has no public config parse/marshal accessor. Skips are
    # explicit per fixture so an adapter cannot conceal another failure by
    # returning an arbitrary `skipped` result.
    for fx in cfg:
        fx["allowed_skips"] = {
            "swift": "swift-client-has-no-public-key-accessor-or-config-marshal"
        }

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
        e2e("e2e-invalid-nonce-hex", "invalid_nonce_hex",
            {"outcome": "error", "error_code": "INVALID_RESPONSE_NONCE"},
            "Nonce has the correct encoded length but contains non-hex characters."),
        e2e("e2e-invalid-nonce-odd-hex", "invalid_nonce_odd_hex",
            {"outcome": "error", "error_code": "INVALID_RESPONSE_NONCE"},
            "Nonce contains an odd number of hex characters."),
        e2e("e2e-invalid-nonce-too-long", "invalid_nonce_too_long",
            {"outcome": "error", "error_code": "INVALID_RESPONSE_NONCE"},
            "Nonce is valid hex but 33 bytes rather than 32."),
        e2e("e2e-duplicate-nonce", "duplicate_nonce",
            {"outcome": "error", "error_code": "DUPLICATE_RESPONSE_NONCE"},
            "Two nonce headers MUST fail closed.",
            browser={"runnable": False, "skip_reason": "browser-coalesces-duplicate-headers"}),
        e2e("e2e-tampered-tag", "tamper_tag",
            {"outcome": "error", "error_code": "AEAD_DECRYPT_FAILED",
             "plaintext_emitted_before_error": False, "bytes_emitted_before_error": 0},
            "Flipped tag byte."),
        e2e("e2e-wrong-valid-length-nonce", "wrong_nonce",
            {"outcome": "error", "error_code": "AEAD_DECRYPT_FAILED",
             "plaintext_emitted_before_error": False, "bytes_emitted_before_error": 0},
            "A valid-length nonce other than the sealing nonce must fail authentication."),
        e2e("e2e-partial-length-prefix-1", "partial_prefix_1",
            {"outcome": "error", "error_code": "FRAMING_TRUNCATED",
             "plaintext_emitted_before_error": False, "bytes_emitted_before_error": 0},
            "Response ends after one byte of a frame-length prefix."),
        e2e("e2e-partial-length-prefix-2", "partial_prefix_2",
            {"outcome": "error", "error_code": "FRAMING_TRUNCATED",
             "plaintext_emitted_before_error": False, "bytes_emitted_before_error": 0},
            "Response ends after two bytes of a frame-length prefix."),
        e2e("e2e-partial-length-prefix-3", "partial_prefix_3",
            {"outcome": "error", "error_code": "FRAMING_TRUNCATED",
             "plaintext_emitted_before_error": False, "bytes_emitted_before_error": 0},
            "Response ends after three bytes of a frame-length prefix."),
        e2e("e2e-truncated-frame", "truncate_final_frame",
            {"outcome": "error", "error_code": "FRAMING_TRUNCATED",
             "plaintext_emitted_before_error": False, "bytes_emitted_before_error": 0},
            "Response ends mid-frame."),
        e2e("e2e-ciphertext-shorter-than-tag", "ciphertext_shorter_than_tag",
            {"outcome": "error", "error_code": "AEAD_DECRYPT_FAILED",
             "plaintext_emitted_before_error": False, "bytes_emitted_before_error": 0},
            "A complete 15-byte frame is too short to contain an AES-GCM tag."),
        e2e("e2e-zero-frame-flood", "zero_frame_flood",
            {"outcome": "ok", "status": 200, "body_hex": b"hello".hex()},
            "4096 legal empty frames must not hang or crash the response parser."),
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
        e2e("e2e-encrypted-error-500", "encrypted_error_500",
            {"outcome": "ok", "status": 500, "body_hex": b"hello".hex()},
            "A non-2xx response carrying a nonce is authenticated ciphertext and must decrypt."),
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

    # Discovery is capability-gated for Swift. Request-boundary probes run on all
    # native clients; adapter-local sinks prevent hostile URLs reaching the network.
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
    for fx in client_api:
        if fx["operation"] == "discover":
            fx["allowed_skips"] = {
                "swift": "swift-client-has-no-discovery-or-request-guards"
            }

    def server_fx(fid, op, mutation, expect, desc, **inputs):
        return {
            "id": fid, "description": desc, "category": "server",
            "operation": op, "runners": ["go"],
            "inputs": {"mutation": mutation, **inputs}, "expect": expect,
        }

    # The repository currently has one server implementation (Go). These use
    # its public identity/middleware APIs in an isolated adapter process.
    server_security = [
        server_fx(
            "server-request-duplicate-encapsulated-key",
            "decrypt_request", "duplicate_encapsulated_key",
            {"outcome": "error", "error_code": "INVALID_ENCAPSULATED_KEY"},
            "Two encapsulated-key headers are ambiguous and must be rejected."),
        server_fx(
            "server-request-oversized-frame",
            "decrypt_request", "oversized_frame",
            {"outcome": "error", "error_code": "CHUNK_TOO_LARGE"},
            "A request frame above 64 MiB must be rejected before allocation."),
        server_fx(
            "server-request-partial-prefix",
            "decrypt_request", "partial_prefix",
            {"outcome": "error", "error_code": "FRAMING_TRUNCATED"},
            "A request ending midway through its length prefix is truncated."),
        server_fx(
            "server-request-zero-frame-burst",
            "decrypt_request", "zero_frame_burst",
            {"outcome": "ok", "body_hex": b"after-zero-frames".hex()},
            "Ten thousand legal empty frames must not recurse, hang, or crash.",
            zeroFrameCount=10000),
        server_fx(
            "server-middleware-trailing-tamper",
            "middleware_request", "trailing_tamper",
            {"outcome": "error", "error_code": "KEY_CONFIG_MISMATCH"},
            "The application handler must not run before the complete request body authenticates."),
    ]

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "client-api.json").write_text(json.dumps(client_api, indent=2) + "\n")
    (OUT / "crypto.json").write_text(json.dumps(crypto, indent=2) + "\n")
    (OUT / "config.json").write_text(json.dumps(cfg, indent=2) + "\n")
    (OUT / "e2e.json").write_text(json.dumps(e2e_list, indent=2) + "\n")
    (OUT / "shape.json").write_text(json.dumps(shape_list, indent=2) + "\n")
    (OUT / "server-security.json").write_text(json.dumps(server_security, indent=2) + "\n")
    print(f"wrote {len(crypto)} crypto + {len(cfg)} config + {len(e2e_list)} e2e "
          f"+ {len(shape_list)} shape + {len(client_api)} client-api + "
          f"{len(server_security)} server-security fixtures to {OUT}")


if __name__ == "__main__":
    main()
