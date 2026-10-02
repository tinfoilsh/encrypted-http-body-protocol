"""Exception hierarchy for the EHBP client.

One subclass per canonical, cross-SDK error class (SPEC Section 5.5), named after
its code. ``str(err)`` is ``"<CODE>: <detail>"``. Codes are for the in-process
caller only and are never sent on the wire (SPEC 5.4.4).
"""

from __future__ import annotations

from enum import Enum
from typing import ClassVar, Optional


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
    """Base class; catch this for any EHBP failure. Raise only a subclass."""

    code: ClassVar[Code]

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        code = getattr(self, "code", None)
        return f"{code.value}: {self.message}" if code else self.message


class InvalidKeyConfigError(EHBPError):
    code = Code.INVALID_KEY_CONFIG


class UnsupportedSuiteError(EHBPError):
    code = Code.UNSUPPORTED_SUITE


class InvalidEncapsulatedKeyError(EHBPError):
    code = Code.INVALID_ENCAPSULATED_KEY


class HPKESetupFailedError(EHBPError):
    code = Code.HPKE_SETUP_FAILED


class MissingResponseNonceError(EHBPError):
    code = Code.MISSING_RESPONSE_NONCE


class InvalidResponseNonceError(EHBPError):
    code = Code.INVALID_RESPONSE_NONCE


class DuplicateResponseNonceError(EHBPError):
    code = Code.DUPLICATE_RESPONSE_NONCE


class KeyConfigMismatchError(EHBPError):
    """HTTP 422 key-configuration problem: refresh the key config and retry (SPEC 5.4.3)."""

    code = Code.KEY_CONFIG_MISMATCH


class FramingTruncatedError(EHBPError):
    code = Code.FRAMING_TRUNCATED


class ChunkTooLargeError(EHBPError):
    code = Code.CHUNK_TOO_LARGE


class AEADDecryptFailedError(EHBPError):
    code = Code.AEAD_DECRYPT_FAILED


class SequenceOverflowError(EHBPError):
    code = Code.SEQUENCE_OVERFLOW


class InvalidTokenError(EHBPError):
    code = Code.INVALID_TOKEN


class InvalidInputError(EHBPError):
    code = Code.INVALID_INPUT


def code_of(err: BaseException) -> Optional[Code]:
    """Return the canonical code of ``err``, or ``None`` for a non-EHBP error."""
    return err.code if isinstance(err, EHBPError) else None
