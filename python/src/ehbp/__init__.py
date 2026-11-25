"""Python client for the encrypted HTTP body protocol (EHBP)."""

from . import errors, protocol
from . import identity as core
from .client import Client, Config, Discover, PublicKey, Response, discover, self_check
from .identity import SessionRecoveryToken
from .errors import (
    AEADDecryptFailedError,
    ChunkTooLargeError,
    Code,
    DuplicateResponseNonceError,
    EHBPError,
    FramingTruncatedError,
    HPKESetupFailedError,
    InvalidEncapsulatedKeyError,
    InvalidInputError,
    InvalidKeyConfigError,
    InvalidResponseNonceError,
    InvalidTokenError,
    KeyConfigMismatchError,
    MissingResponseNonceError,
    SequenceOverflowError,
    UnexpectedRedirectError,
    UnsupportedSuiteError,
    code_of,
)

__version__ = "0.7.0"

__all__ = [
    "Client", "Config", "Discover", "PublicKey", "Response", "SessionRecoveryToken", "discover", "self_check",
    "core", "errors", "protocol", "__version__",
    "Code", "EHBPError", "code_of",
    "AEADDecryptFailedError", "ChunkTooLargeError", "DuplicateResponseNonceError",
    "FramingTruncatedError", "HPKESetupFailedError", "InvalidEncapsulatedKeyError",
    "InvalidInputError", "InvalidKeyConfigError", "InvalidResponseNonceError",
    "InvalidTokenError", "KeyConfigMismatchError", "MissingResponseNonceError",
    "SequenceOverflowError", "UnexpectedRedirectError", "UnsupportedSuiteError",
]
