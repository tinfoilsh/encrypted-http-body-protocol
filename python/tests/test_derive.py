"""Unit tests for chunk framing, nonce derivation, and secret redaction."""

import pytest

from ehbp import FrameDecryptor, ResponseKeyMaterial, SessionRecoveryToken, compute_nonce
from ehbp.derive import decrypt_framed_response, derive_response_keys, encrypt_chunk, frame_chunk
from ehbp.errors import CryptoError, ProtocolError
from ehbp.protocol import AES_GCM_NONCE_LENGTH, MAX_SEQUENCE, RESPONSE_NONCE_LENGTH


def test_nonce_uses_big_endian_sequence_xor():
    base = bytes(AES_GCM_NONCE_LENGTH)
    nonce = compute_nonce(base, 0x0102_0304_0506_0708)
    assert nonce == bytes([0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8])


def test_response_key_material_repr_is_redacted():
    key_material = ResponseKeyMaterial(key=bytes([1]) * 32, nonce_base=bytes([2]) * 12)
    text = repr(key_material)
    assert "[redacted]" in text
    assert "01" not in text


def test_session_recovery_token_repr_is_redacted():
    token = SessionRecoveryToken(bytes([1]) * 32, bytes([2]) * 32)
    text = repr(token)
    assert "[redacted]" in text
    assert "0101" not in text


def _key_material() -> ResponseKeyMaterial:
    return ResponseKeyMaterial(key=bytes(range(32)), nonce_base=bytes(range(12)))


def test_framed_roundtrip_multiple_chunks():
    km = _key_material()
    framed = (
        frame_chunk(encrypt_chunk(km, 0, b"hello "))
        + frame_chunk(encrypt_chunk(km, 1, b"world"))
    )
    assert decrypt_framed_response(km, framed) == b"hello world"


def test_zero_length_frames_are_skipped_without_consuming_sequence():
    km = _key_material()
    framed = (
        b"\x00\x00\x00\x00"
        + frame_chunk(encrypt_chunk(km, 0, b"data"))
        + b"\x00\x00\x00\x00"
    )
    assert decrypt_framed_response(km, framed) == b"data"


def test_truncated_trailing_chunk_is_rejected():
    km = _key_material()
    framed = frame_chunk(encrypt_chunk(km, 0, b"data"))
    with pytest.raises(ProtocolError):
        decrypt_framed_response(km, framed[:-1])


def test_streaming_decryptor_handles_fragmented_frames():
    km = _key_material()
    framed = (
        frame_chunk(encrypt_chunk(km, 0, b"abc"))
        + frame_chunk(encrypt_chunk(km, 1, b"defgh"))
    )
    decryptor = FrameDecryptor(km)
    out = bytearray()
    for byte in framed:
        for chunk in decryptor.push(bytes([byte])):
            out += chunk
    decryptor.finish()
    assert bytes(out) == b"abcdefgh"


def test_streaming_decryptor_rejects_oversized_chunk_length():
    km = _key_material()
    decryptor = FrameDecryptor(km, max_chunk_length=16)
    # A length prefix declaring a 1 MiB chunk must be rejected before buffering
    # the (unauthenticated) chunk body, even if no body bytes have arrived yet.
    oversized_prefix = (1 << 20).to_bytes(4, "big")
    with pytest.raises(ProtocolError):
        decryptor.push(oversized_prefix)


def test_token_decryptor_delivers_before_source_eof():
    exported_secret = bytes(range(32))
    request_enc = bytes(reversed(range(32)))
    response_nonce = bytes([7]) * RESPONSE_NONCE_LENGTH
    token = SessionRecoveryToken(exported_secret, request_enc)
    km = derive_response_keys(exported_secret, request_enc, response_nonce)
    first = frame_chunk(encrypt_chunk(km, 0, b"first"))
    second = frame_chunk(encrypt_chunk(km, 1, b"second"))

    decryptor = token.create_response_decryptor(response_nonce)

    assert decryptor.push(first) == [b"first"]
    assert decryptor.push(second) == [b"second"]
    decryptor.finish()


def test_token_decryptor_handles_coalesced_and_zero_length_frames():
    exported_secret = bytes(range(32))
    request_enc = bytes(reversed(range(32)))
    response_nonce = bytes([9]) * RESPONSE_NONCE_LENGTH
    token = SessionRecoveryToken(exported_secret, request_enc)
    km = derive_response_keys(exported_secret, request_enc, response_nonce)
    framed = (
        b"\x00\x00\x00\x00"
        + frame_chunk(encrypt_chunk(km, 0, b"one"))
        + frame_chunk(encrypt_chunk(km, 1, b"two"))
        + b"\x00\x00\x00\x00"
    )

    decryptor = token.create_response_decryptor(response_nonce)

    assert decryptor.push(framed) == [b"one", b"two"]
    decryptor.finish()


def test_token_decryptor_rejects_authentication_failure_before_emitting():
    exported_secret = bytes(range(32))
    request_enc = bytes(reversed(range(32)))
    response_nonce = bytes([11]) * RESPONSE_NONCE_LENGTH
    token = SessionRecoveryToken(exported_secret, request_enc)
    km = derive_response_keys(exported_secret, request_enc, response_nonce)
    framed = bytearray(frame_chunk(encrypt_chunk(km, 0, b"secret")))
    framed[-1] ^= 1

    decryptor = token.create_response_decryptor(response_nonce)

    with pytest.raises(CryptoError):
        decryptor.push(bytes(framed))


def test_streaming_decryptor_rejects_truncated_eof():
    km = _key_material()
    framed = frame_chunk(encrypt_chunk(km, 0, b"data"))
    decryptor = FrameDecryptor(km)

    assert decryptor.push(framed[:-1]) == []
    with pytest.raises(ProtocolError):
        decryptor.finish()


def test_streaming_decryptor_rejects_sequence_overflow():
    km = _key_material()
    framed = frame_chunk(encrypt_chunk(km, MAX_SEQUENCE, b"last"))
    decryptor = FrameDecryptor(km)
    decryptor._seq = MAX_SEQUENCE

    with pytest.raises(ProtocolError, match="sequence overflow"):
        decryptor.push(framed)
