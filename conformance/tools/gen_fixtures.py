#!/usr/bin/env python3
"""Generate the crypto conformance fixtures: the one family whose expected
values need native crypto (frames sealed with the reference key schedule).
Every other family is dafny/fixtures.dfy; dafny/gen-fixtures.sh runs both.

    PYTHONPATH=python/src conformance/.venv/bin/python conformance/tools/gen_fixtures.py

It reads the three golden vectors under test-vectors/ and writes
test-vectors/conformance/crypto.json.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test-vectors"
OUT = VECTORS / "conformance"


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text())


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
    import struct
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from ehbp import core
    key, nonce_base = core.derive_keys(bytes.fromhex(resp["exportedSecret"]),
                                       bytes.fromhex(resp["requestEnc"]),
                                       bytes.fromhex(resp["responseNonce"]))

    def frame(seq, pt):
        # Server-side sealing: the client library no longer exposes it.
        ct = AESGCM(key).encrypt(core.nonce_for(nonce_base, seq), pt, b"")
        return struct.pack(">I", len(ct)) + ct

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
            "id": "decrypt-response-cap-plus-one",
            "description": "Length prefix of exactly 64 MiB + 1 must be rejected before any read: CHUNK_TOO_LARGE, not FRAMING_TRUNCATED.",
            "category": "crypto", "operation": "decrypt_response",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": "04000001" + "00" * 16},
            "expect": {"outcome": "error", "error_code": "CHUNK_TOO_LARGE",
                       "plaintext_emitted_before_error": False,
                       "bytes_emitted_before_error": 0},
        },
        {
            "id": "decrypt-response-cap-exact",
            "description": "A length prefix of exactly 64 MiB is within the cap; the body then ends inside the frame.",
            "category": "crypto", "operation": "decrypt_response",
            "inputs": {"exportedSecret": resp["exportedSecret"],
                       "requestEnc": resp["requestEnc"],
                       "responseNonce": resp["responseNonce"],
                       "encryptedResponse": "04000000" + "00" * 16},
            "expect": {"outcome": "error", "error_code": "FRAMING_TRUNCATED",
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
        {
            "id": "token-hex-0x-prefix",
            "description": "Hex is decoded strictly (SPEC 4.1): a 0x prefix is not hex.",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": json.dumps({"exportedSecret": "0x" + token["exportedSecret"][2:],
                                           "requestEnc": token["requestEnc"]})},
            "expect": {"outcome": "error", "error_code": "INVALID_TOKEN"},
        },
        {
            "id": "token-hex-whitespace",
            "description": "Hex is decoded strictly (SPEC 4.1): embedded whitespace is not hex.",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": json.dumps({"exportedSecret": token["exportedSecret"][:10] + " " + token["exportedSecret"][11:],
                                           "requestEnc": token["requestEnc"]})},
            "expect": {"outcome": "error", "error_code": "INVALID_TOKEN"},
        },
        {
            "id": "token-hex-uppercase",
            "description": "Either letter case is accepted on input (SPEC 4.1).",
            "category": "crypto", "operation": "token_roundtrip",
            "inputs": {"json": json.dumps({"exportedSecret": token["exportedSecret"].upper(),
                                           "requestEnc": token["requestEnc"].upper()})},
            "expect": {"outcome": "ok",
                       "body_hex": token["exportedSecret"] + token["requestEnc"]},
        },
    ]

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "crypto.json").write_text(json.dumps(crypto, indent=2) + "\n")
    print(f"wrote {len(crypto)} crypto fixtures to {OUT / 'crypto.json'}")


if __name__ == "__main__":
    main()
