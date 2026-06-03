"""Server identity: RFC 9458 key-config handling and HPKE request encryption."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from .derive import frame_chunk
from .errors import HPKEError, InvalidConfigError
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


@dataclass(frozen=True)
class EncryptedRequest:
    encapsulated_key: bytes
    body: bytes
    token: SessionRecoveryToken


def _read_u16(data: bytes, offset: int, field: str) -> tuple[int, int]:
    if len(data) - offset < 2:
        raise InvalidConfigError(f"missing {field}")
    return struct.unpack_from(">H", data, offset)[0], offset + 2


class ServerIdentity:
    """The server's public HPKE configuration.

    Holds only the public key; it can encrypt requests but never decrypt them.
    """

    def __init__(self, public_key: bytes, key_id: int = KEY_ID) -> None:
        if len(public_key) != REQUEST_ENC_LENGTH:
            raise InvalidConfigError(
                f"public key must be {REQUEST_ENC_LENGTH} bytes, got {len(public_key)}"
            )
        self._suite = _new_suite()
        try:
            self._public_key = self._suite.kem.deserialize_public_key(bytes(public_key))
        except Exception as err:  # noqa: BLE001 - pyhpke raises library-specific errors
            raise InvalidConfigError(f"invalid X25519 public key: {err}") from err
        self._public_key_bytes = bytes(public_key)
        if not 0 <= key_id <= _MAX_KEY_ID:
            raise InvalidConfigError(f"key id must be between 0 and {_MAX_KEY_ID}, got {key_id}")
        self._key_id = key_id

    @classmethod
    def from_public_key_bytes(cls, public_key: bytes) -> ServerIdentity:
        return cls(bytes(public_key))

    @classmethod
    def from_public_key_hex(cls, public_key_hex: str) -> ServerIdentity:
        try:
            raw = bytes.fromhex(public_key_hex)
        except ValueError as err:
            raise InvalidConfigError(f"invalid public key hex: {err}") from err
        return cls(raw)

    @classmethod
    def unmarshal_public_config(cls, data: bytes) -> ServerIdentity:
        if len(data) < 1:
            raise InvalidConfigError("missing key id")
        key_id = data[0]
        offset = 1

        kem_id, offset = _read_u16(data, offset, "KEM id")
        if kem_id != KEM_X25519_HKDF_SHA256:
            raise InvalidConfigError(f"unsupported KEM: 0x{kem_id:04x}")

        public_key_end = offset + REQUEST_ENC_LENGTH
        if public_key_end > len(data):
            raise InvalidConfigError("truncated public key")
        public_key = data[offset:public_key_end]
        offset = public_key_end

        suites_len, offset = _read_u16(data, offset, "cipher suites length")
        if suites_len == 0:
            raise InvalidConfigError("no cipher suites found in config")
        if suites_len % _CIPHER_SUITE_ENTRY_SIZE != 0:
            raise InvalidConfigError("cipher suites length must be a multiple of 4")
        if offset + suites_len > len(data):
            raise InvalidConfigError("truncated cipher suites")

        kdf_id, offset = _read_u16(data, offset, "KDF id")
        aead_id, offset = _read_u16(data, offset, "AEAD id")
        if kdf_id != KDF_HKDF_SHA256 or aead_id != AEAD_AES_256_GCM:
            raise InvalidConfigError(
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

    def encrypt_request_body(self, plaintext: bytes):
        """Seal a request body to the server's public key.

        Returns ``None`` for empty bodies: bodyless requests pass through
        unencrypted and receive a plaintext response (SPEC Section 7.4).
        """
        if len(plaintext) == 0:
            return None
        try:
            enc, sender = self._suite.create_sender_context(
                self._public_key, info=HPKE_REQUEST_INFO
            )
            ciphertext = sender.seal(bytes(plaintext), b"")
            exported_secret = sender.export(EXPORT_LABEL, EXPORT_LENGTH)
        except Exception as err:  # noqa: BLE001 - normalize HPKE library failures
            raise HPKEError(f"failed to encrypt request body: {err}") from err

        token = SessionRecoveryToken(exported_secret, enc)
        return EncryptedRequest(
            encapsulated_key=bytes(enc), body=frame_chunk(ciphertext), token=token
        )
