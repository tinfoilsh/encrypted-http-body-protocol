"""Exception hierarchy for the EHBP client.

Every error carries a canonical, cross-SDK ``Code`` (SPEC Section 5.5) so a caller
switches on one key in any language. ``str(err)`` is ``"<CODE>: <detail>"``. Codes
are for the in-process caller only and are never sent on the wire (SPEC 5.4.4).
"""

from __future__ import annotations

from enum import Enum
from typing import Optional


class Code(str, Enum):
    INVALID_KEY_CONFIG = "INVALID_KEY_CONFIG"
    UNSUPPORTED_SUITE = "UNSUPPORTED_SUITE"
    INVALID_ENCAPSULATED_KEY = "INVALID_ENCAPSULATED_KEY"
    HPKE_SETUP_FAILED = "HPKE_SETUP_FAILED"
    MISSING_RESPONSE_NONCE = "MISSING_RESPONSE_NONCE"
    INVALID_RESPONSE_NONCE = "INVALID_RESPONSE_NONCE"
    DUPLICATE_RESPONSE_NONCE = "DUPLICATE_RESPONSE_NONCE"
    KEY_CONFIG_MISMATCH = "KEY_CONFIG_MISMATCH"
    FRAMING_TRUNCATED = "FRAMING_TRUNCATED"
    CHUNK_TOO_LARGE = "CHUNK_TOO_LARGE"
    AEAD_DECRYPT_FAILED = "AEAD_DECRYPT_FAILED"
    SEQUENCE_OVERFLOW = "SEQUENCE_OVERFLOW"
    INVALID_TOKEN = "INVALID_TOKEN"
    INVALID_INPUT = "INVALID_INPUT"


class EHBPError(Exception):
    """Base class for all EHBP errors.

    Subclasses set a default ``code``; raise sites whose class covers several
    codes pass ``code=`` explicitly.
    """

    code: Code = Code.INVALID_INPUT

    def __init__(self, message: str, code: Optional[Code] = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code

    def __str__(self) -> str:
        return f"{self.code.value}: {self.message}"


class InvalidConfigError(EHBPError):
    """The server key configuration could not be parsed or is unsupported."""

    code = Code.INVALID_KEY_CONFIG


class InvalidInputError(EHBPError):
    """Caller-supplied input is invalid (bad URL, reserved header, ...)."""

    code = Code.INVALID_INPUT


class ProtocolError(EHBPError):
    """The peer violated the EHBP framing or header contract; ``code`` says how."""


class KeyConfigMismatchError(EHBPError):
    """The server reported a key-configuration mismatch (HTTP 422).

    The request was rejected before application processing completed, so it is
    safe to refresh the server key configuration and retry (SPEC Section 5.4.3).
    """

    code = Code.KEY_CONFIG_MISMATCH


class HPKEError(EHBPError):
    """An HPKE setup, seal, or export operation failed."""

    code = Code.HPKE_SETUP_FAILED


class CryptoError(EHBPError):
    """An AEAD or key-derivation operation failed."""

    code = Code.AEAD_DECRYPT_FAILED


def code_of(err: BaseException) -> Optional[Code]:
    """Return the canonical code of ``err``, or ``None`` for a non-EHBP error."""
    return err.code if isinstance(err, EHBPError) else None
