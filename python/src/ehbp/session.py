"""Session recovery tokens (SPEC Section 6).

A token carries the minimal material needed to decrypt a single response
without retaining the live HPKE context: the HPKE export secret and the request
encapsulated key. It MUST be treated as sensitive key material.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Union

from .derive import decrypt_framed_response, derive_response_keys
from .errors import InvalidInputError, ProtocolError
from .protocol import EXPORT_LENGTH, REQUEST_ENC_LENGTH, RESPONSE_NONCE_LENGTH

_EXPORTED_SECRET_KEY = "exportedSecret"
_REQUEST_ENC_KEY = "requestEnc"


class SessionRecoveryToken:
    __slots__ = ("_exported_secret", "_request_enc")

    def __init__(self, exported_secret: bytes, request_enc: bytes) -> None:
        if len(exported_secret) != EXPORT_LENGTH:
            raise InvalidInputError(
                f"exported secret must be {EXPORT_LENGTH} bytes, got {len(exported_secret)}"
            )
        if len(request_enc) != REQUEST_ENC_LENGTH:
            raise InvalidInputError(
                f"request enc must be {REQUEST_ENC_LENGTH} bytes, got {len(request_enc)}"
            )
        self._exported_secret = bytes(exported_secret)
        self._request_enc = bytes(request_enc)

    @property
    def exported_secret(self) -> bytes:
        return self._exported_secret

    @property
    def request_enc(self) -> bytes:
        return self._request_enc

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SessionRecoveryToken):
            return NotImplemented
        return (
            self._exported_secret == other._exported_secret
            and self._request_enc == other._request_enc
        )

    def __hash__(self) -> int:
        return hash((self._exported_secret, self._request_enc))

    def __repr__(self) -> str:
        return "SessionRecoveryToken(exported_secret='[redacted]', request_enc='[redacted]')"

    def to_dict(self) -> dict[str, str]:
        return {
            _EXPORTED_SECRET_KEY: self._exported_secret.hex(),
            _REQUEST_ENC_KEY: self._request_enc.hex(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SessionRecoveryToken:
        try:
            exported_secret = bytes.fromhex(data[_EXPORTED_SECRET_KEY])
            request_enc = bytes.fromhex(data[_REQUEST_ENC_KEY])
        except (KeyError, TypeError, ValueError) as err:
            raise InvalidInputError(f"invalid session recovery token: {err}") from err
        return cls(exported_secret, request_enc)

    @classmethod
    def from_json(cls, data: Union[str, bytes]) -> SessionRecoveryToken:
        try:
            decoded = json.loads(data)
        except (TypeError, ValueError) as err:
            raise InvalidInputError(f"invalid session recovery token JSON: {err}") from err
        if not isinstance(decoded, Mapping):
            raise InvalidInputError("invalid session recovery token: expected JSON object")
        return cls.from_dict(decoded)

    def decrypt_response_body(self, response_nonce: bytes, body: bytes) -> bytes:
        if len(response_nonce) != RESPONSE_NONCE_LENGTH:
            raise ProtocolError(
                f"response nonce must be {RESPONSE_NONCE_LENGTH} bytes, got {len(response_nonce)}"
            )
        key_material = derive_response_keys(
            self._exported_secret, self._request_enc, response_nonce
        )
        return decrypt_framed_response(key_material, body)
