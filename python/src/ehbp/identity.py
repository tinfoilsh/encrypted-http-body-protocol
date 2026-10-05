"""Server identity: RFC 9458 key-config handling and HPKE request encryption."""

from __future__ import annotations

import struct
from collections.abc import AsyncIterable, AsyncIterator, Iterable, Iterator
from dataclasses import dataclass

from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from .derive import frame_chunk
from .errors import HPKESetupFailedError, InvalidKeyConfigError, UnsupportedSuiteError
from .protocol import (
    AEAD_AES_256_GCM,
    EXPORT_LABEL,
    EXPORT_LENGTH,
    HPKE_REQUEST_INFO,
    KDF_HKDF_SHA256,
    KEM_X25519_HKDF_SHA256,
    KEY_ID,
    REQUEST_ENC_LENGTH,
)
from .session import SessionRecoveryToken

_CIPHER_SUITE_ENTRY_SIZE = 4
_MAX_KEY_ID = 0xFF


def _new_suite() -> CipherSuite:
    return CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
    )


# Plaintext bytes sealed per frame (SPEC 4.3). Small enough to bound memory on
# both ends, large enough that the per-frame tag and length are noise.
REQUEST_FRAME_SIZE = 64 * 1024


@dataclass(frozen=True)
class EncryptedRequest:
    encapsulated_key: bytes
    body: bytes
    token: SessionRecoveryToken


@dataclass(frozen=True)
class EncryptedRequestStream:
    """A request body encrypted frame by frame as the source is consumed.

    ``frames`` is an iterator (or async iterator) of ``LEN || CIPHERTEXT``
    frames; only one frame of plaintext is held at a time.
    """

    encapsulated_key: bytes
    frames: Iterator[bytes] | AsyncIterator[bytes]
    token: SessionRecoveryToken


def _seal_frames(sender, chunks: Iterable[bytes]) -> Iterator[bytes]:
    """Re-chunk an arbitrary byte source into REQUEST_FRAME_SIZE frames."""
    buf = bytearray()
    for chunk in chunks:
        mv = memoryview(chunk)
        if not buf and len(mv) >= REQUEST_FRAME_SIZE:
            # Slice large inputs directly instead of copying them into buf.
            whole = len(mv) - len(mv) % REQUEST_FRAME_SIZE
            for off in range(0, whole, REQUEST_FRAME_SIZE):
                yield frame_chunk(sender.seal(bytes(mv[off : off + REQUEST_FRAME_SIZE]), b""))
            mv = mv[whole:]
        buf += mv
        while len(buf) >= REQUEST_FRAME_SIZE:
            yield frame_chunk(sender.seal(bytes(buf[:REQUEST_FRAME_SIZE]), b""))
            del buf[:REQUEST_FRAME_SIZE]
    if buf:
        yield frame_chunk(sender.seal(bytes(buf), b""))


async def _seal_frames_async(sender, chunks: AsyncIterable[bytes]) -> AsyncIterator[bytes]:
    buf = bytearray()
    async for chunk in chunks:
        buf += chunk
        while len(buf) >= REQUEST_FRAME_SIZE:
            yield frame_chunk(sender.seal(bytes(buf[:REQUEST_FRAME_SIZE]), b""))
            del buf[:REQUEST_FRAME_SIZE]
    if buf:
        yield frame_chunk(sender.seal(bytes(buf), b""))


def _read_u16(data: bytes, offset: int, field: str) -> tuple[int, int]:
    if len(data) - offset < 2:
        raise InvalidKeyConfigError(f"missing {field}")
    return struct.unpack_from(">H", data, offset)[0], offset + 2


class ServerIdentity:
    """The server's public HPKE configuration.

    Holds only the public key; it can encrypt requests but never decrypt them.
    """

    def __init__(self, public_key: bytes, key_id: int = KEY_ID) -> None:
        if len(public_key) != REQUEST_ENC_LENGTH:
            raise InvalidKeyConfigError(
                f"public key must be {REQUEST_ENC_LENGTH} bytes, got {len(public_key)}"
            )
        self._suite = _new_suite()
        try:
            self._public_key = self._suite.kem.deserialize_public_key(bytes(public_key))
        except Exception as err:  # noqa: BLE001 - pyhpke raises library-specific errors
            raise InvalidKeyConfigError(f"invalid X25519 public key: {err}") from err
        self._public_key_bytes = bytes(public_key)
        if not 0 <= key_id <= _MAX_KEY_ID:
            raise InvalidKeyConfigError(f"key id must be between 0 and {_MAX_KEY_ID}, got {key_id}")
        self._key_id = key_id

    @classmethod
    def from_public_key_bytes(cls, public_key: bytes) -> ServerIdentity:
        return cls(bytes(public_key))

    @classmethod
    def from_public_key_hex(cls, public_key_hex: str) -> ServerIdentity:
        try:
            raw = bytes.fromhex(public_key_hex)
        except ValueError as err:
            raise InvalidKeyConfigError(f"invalid public key hex: {err}") from err
        return cls(raw)

    @classmethod
    def unmarshal_public_config(cls, data: bytes) -> ServerIdentity:
        if len(data) < 1:
            raise InvalidKeyConfigError("missing key id")
        key_id = data[0]
        offset = 1

        kem_id, offset = _read_u16(data, offset, "KEM id")
        if kem_id != KEM_X25519_HKDF_SHA256:
            raise UnsupportedSuiteError(f"unsupported KEM: 0x{kem_id:04x}")

        public_key_end = offset + REQUEST_ENC_LENGTH
        if public_key_end > len(data):
            raise InvalidKeyConfigError("truncated public key")
        public_key = data[offset:public_key_end]
        offset = public_key_end

        suites_len, offset = _read_u16(data, offset, "cipher suites length")
        if suites_len == 0:
            raise InvalidKeyConfigError("no cipher suites found in config")
        if suites_len % _CIPHER_SUITE_ENTRY_SIZE != 0:
            raise InvalidKeyConfigError("cipher suites length must be a multiple of 4")
        if offset + suites_len > len(data):
            raise InvalidKeyConfigError("truncated cipher suites")
        if suites_len != _CIPHER_SUITE_ENTRY_SIZE:
            raise UnsupportedSuiteError(
                f"expected exactly one cipher suite, got {suites_len // _CIPHER_SUITE_ENTRY_SIZE}"
            )

        kdf_id, offset = _read_u16(data, offset, "KDF id")
        aead_id, offset = _read_u16(data, offset, "AEAD id")
        if kdf_id != KDF_HKDF_SHA256 or aead_id != AEAD_AES_256_GCM:
            raise UnsupportedSuiteError(
                f"unsupported cipher suite: KDF=0x{kdf_id:04x}, AEAD=0x{aead_id:04x}"
            )

        return cls(public_key, key_id)

    def marshal_public_config(self) -> bytes:
        out = bytearray()
        out.append(self._key_id)
        out += struct.pack(">H", KEM_X25519_HKDF_SHA256)
        out += self._public_key_bytes
        out += struct.pack(">H", _CIPHER_SUITE_ENTRY_SIZE)
        out += struct.pack(">H", KDF_HKDF_SHA256)
        out += struct.pack(">H", AEAD_AES_256_GCM)
        return bytes(out)

    @property
    def key_id(self) -> int:
        return self._key_id

    def public_key_bytes(self) -> bytes:
        return self._public_key_bytes

    def public_key_hex(self) -> str:
        return self._public_key_bytes.hex()

    def _new_sender(self):
        try:
            enc, sender = self._suite.create_sender_context(
                self._public_key, info=HPKE_REQUEST_INFO
            )
            exported_secret = sender.export(EXPORT_LABEL, EXPORT_LENGTH)
        except Exception as err:  # noqa: BLE001 - normalize HPKE library failures
            raise HPKESetupFailedError(f"failed to set up request encryption: {err}") from err
        return bytes(enc), sender, SessionRecoveryToken(exported_secret, enc)

    def encrypt_request_body(self, plaintext: bytes):
        """Seal a request body to the server's public key.

        Returns ``None`` for empty bodies: bodyless requests pass through
        unencrypted and receive a plaintext response (SPEC Section 7.4).
        Bodies longer than ``REQUEST_FRAME_SIZE`` are emitted as several frames.
        """
        if len(plaintext) == 0:
            return None
        enc, sender, token = self._new_sender()
        return EncryptedRequest(
            encapsulated_key=enc,
            body=b"".join(_seal_frames(sender, (bytes(plaintext),))),
            token=token,
        )

    def encrypt_request_stream(self, chunks: Iterable[bytes]) -> EncryptedRequestStream:
        """Seal a request body lazily, one frame at a time, as ``chunks`` is consumed.

        The session recovery token is available immediately, before any chunk
        is read. A source that yields no bytes still produces an encrypted
        (empty) body; use ``encrypt_request_body(b"")`` for a bodyless request.
        """
        enc, sender, token = self._new_sender()
        return EncryptedRequestStream(enc, _seal_frames(sender, chunks), token)

    def encrypt_request_stream_async(self, chunks: AsyncIterable[bytes]) -> EncryptedRequestStream:
        enc, sender, token = self._new_sender()
        return EncryptedRequestStream(enc, _seal_frames_async(sender, chunks), token)
