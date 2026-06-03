"""Response key derivation and chunk framing (SPEC Sections 4.3 and 4.4).

Request bodies are sealed with HPKE directly (see :mod:`ehbp.identity`).
Response bodies use AES-256-GCM under keys derived from the request's HPKE
context via raw HKDF (RFC 5869), following OHTTP (RFC 9458):

    salt = enc || response_nonce
    prk  = HKDF-Extract(salt, exported_secret)
    key  = HKDF-Expand(prk, "key", 32)
    base = HKDF-Expand(prk, "nonce", 12)

The per-chunk nonce is ``base XOR seq`` with ``seq`` big-endian in the low 8
bytes. Raw HKDF and AES-GCM come from the audited ``cryptography`` package so
the derivation matches the Go/Rust/JS clients byte-for-byte.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from .errors import CryptoError, InvalidInputError, ProtocolError
from .protocol import (
    AES256_KEY_LENGTH,
    AES_GCM_NONCE_LENGTH,
    EXPORT_LENGTH,
    LENGTH_PREFIX_SIZE,
    MAX_CHUNK_LENGTH,
    MAX_SEQUENCE,
    REQUEST_ENC_LENGTH,
    RESPONSE_KEY_LABEL,
    RESPONSE_NONCE_LABEL,
    RESPONSE_NONCE_LENGTH,
)


@dataclass
class ResponseKeyMaterial:
    """Derived AES-256-GCM key and base nonce for one response."""

    key: bytes
    nonce_base: bytes

    def __repr__(self) -> str:
        return "ResponseKeyMaterial(key='[redacted]', nonce_base='[redacted]')"


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


def derive_response_keys(
    exported_secret: bytes, request_enc: bytes, response_nonce: bytes
) -> ResponseKeyMaterial:
    if len(exported_secret) != EXPORT_LENGTH:
        raise InvalidInputError(
            f"exported secret must be {EXPORT_LENGTH} bytes, got {len(exported_secret)}"
        )
    if len(request_enc) != REQUEST_ENC_LENGTH:
        raise InvalidInputError(
            f"request enc must be {REQUEST_ENC_LENGTH} bytes, got {len(request_enc)}"
        )
    if len(response_nonce) != RESPONSE_NONCE_LENGTH:
        raise InvalidInputError(
            f"response nonce must be {RESPONSE_NONCE_LENGTH} bytes, got {len(response_nonce)}"
        )

    salt = bytes(request_enc) + bytes(response_nonce)
    prk = _hkdf_extract(salt, bytes(exported_secret))
    key = _hkdf_expand(prk, RESPONSE_KEY_LABEL, AES256_KEY_LENGTH)
    nonce_base = _hkdf_expand(prk, RESPONSE_NONCE_LABEL, AES_GCM_NONCE_LENGTH)
    return ResponseKeyMaterial(key=key, nonce_base=nonce_base)


def compute_nonce(nonce_base: bytes, seq: int) -> bytes:
    if len(nonce_base) != AES_GCM_NONCE_LENGTH:
        raise InvalidInputError(f"nonce base must be {AES_GCM_NONCE_LENGTH} bytes")
    if seq < 0 or seq > MAX_SEQUENCE:
        raise ProtocolError("response chunk sequence out of range")
    nonce = bytearray(nonce_base)
    for i in range(8):
        nonce[AES_GCM_NONCE_LENGTH - 1 - i] ^= (seq >> (i * 8)) & 0xFF
    return bytes(nonce)


def encrypt_chunk(km: ResponseKeyMaterial, seq: int, plaintext: bytes) -> bytes:
    nonce = compute_nonce(km.nonce_base, seq)
    try:
        return AESGCM(km.key).encrypt(nonce, bytes(plaintext), b"")
    except Exception as err:  # noqa: BLE001 - normalize to a stable error shape
        raise CryptoError("failed to encrypt chunk") from err


def decrypt_chunk(km: ResponseKeyMaterial, seq: int, ciphertext: bytes) -> bytes:
    nonce = compute_nonce(km.nonce_base, seq)
    try:
        return AESGCM(km.key).decrypt(nonce, bytes(ciphertext), b"")
    except Exception as err:  # noqa: BLE001 - do not leak the failing crypto stage
        raise CryptoError("failed to decrypt chunk") from err


def frame_chunk(ciphertext: bytes) -> bytes:
    length = len(ciphertext)
    if length > MAX_CHUNK_LENGTH:
        raise InvalidInputError("ciphertext chunk is too large")
    return struct.pack(">I", length) + bytes(ciphertext)


def decrypt_framed_response(km: ResponseKeyMaterial, body: bytes) -> bytes:
    out = bytearray()
    offset = 0
    seq = 0
    total = len(body)

    while offset < total:
        if total - offset < LENGTH_PREFIX_SIZE:
            raise ProtocolError("truncated chunk length")
        chunk_len = struct.unpack_from(">I", body, offset)[0]
        offset += LENGTH_PREFIX_SIZE

        if chunk_len == 0:
            continue
        if total - offset < chunk_len:
            raise ProtocolError("truncated encrypted chunk")

        out += decrypt_chunk(km, seq, body[offset : offset + chunk_len])
        if seq >= MAX_SEQUENCE:
            raise ProtocolError("response chunk sequence overflow")
        seq += 1
        offset += chunk_len

    return bytes(out)


class FrameDecryptor:
    """Incrementally decrypts a length-prefixed AEAD stream.

    Feed network bytes with :meth:`push` (returns any fully decrypted plaintext
    chunks) and call :meth:`finish` at end-of-stream to detect a truncated
    trailing chunk. Zero-length frames are skipped without consuming a sequence
    number, matching the framing rules in SPEC Section 4.3.
    """

    def __init__(
        self, km: ResponseKeyMaterial, max_chunk_length: int = MAX_CHUNK_LENGTH
    ) -> None:
        self._km = km
        self._buffer = bytearray()
        self._seq = 0
        self._max_chunk_length = max_chunk_length

    def push(self, data: bytes) -> list[bytes]:
        self._buffer += data
        chunks: list[bytes] = []

        while True:
            if len(self._buffer) < LENGTH_PREFIX_SIZE:
                break
            chunk_len = struct.unpack_from(">I", self._buffer, 0)[0]
            if chunk_len == 0:
                del self._buffer[:LENGTH_PREFIX_SIZE]
                continue
            if chunk_len > self._max_chunk_length:
                raise ProtocolError("response chunk exceeds maximum allowed size")
            if len(self._buffer) < LENGTH_PREFIX_SIZE + chunk_len:
                break

            ciphertext = bytes(
                self._buffer[LENGTH_PREFIX_SIZE : LENGTH_PREFIX_SIZE + chunk_len]
            )
            del self._buffer[: LENGTH_PREFIX_SIZE + chunk_len]
            chunks.append(decrypt_chunk(self._km, self._seq, ciphertext))
            if self._seq >= MAX_SEQUENCE:
                raise ProtocolError("response chunk sequence overflow")
            self._seq += 1

        return chunks

    def finish(self) -> None:
        if self._buffer:
            raise ProtocolError("truncated encrypted response chunk")
