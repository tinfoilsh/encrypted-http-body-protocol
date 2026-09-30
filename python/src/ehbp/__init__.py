"""Python client for the encrypted HTTP body protocol (EHBP)."""

from . import protocol
from .client import Client, Response, StreamingResponse
from .derive import (
    FrameDecryptor,
    ResponseKeyMaterial,
    compute_nonce,
    decrypt_chunk,
    derive_response_keys,
    encrypt_chunk,
    frame_chunk,
)
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
    UnsupportedSuiteError,
    code_of,
)
from .identity import EncryptedRequest, ServerIdentity
from .session import SessionRecoveryToken
from .transport import AsyncEHBPTransport, EHBPTransport

__version__ = "0.3.3"

__all__ = [
    "Client",
    "Response",
    "StreamingResponse",
    "EHBPTransport",
    "AsyncEHBPTransport",
    "ServerIdentity",
    "EncryptedRequest",
    "SessionRecoveryToken",
    "FrameDecryptor",
    "ResponseKeyMaterial",
    "derive_response_keys",
    "compute_nonce",
    "encrypt_chunk",
    "decrypt_chunk",
    "frame_chunk",
    "Code",
    "EHBPError",
    "InvalidKeyConfigError",
    "UnsupportedSuiteError",
    "InvalidEncapsulatedKeyError",
    "HPKESetupFailedError",
    "MissingResponseNonceError",
    "InvalidResponseNonceError",
    "DuplicateResponseNonceError",
    "KeyConfigMismatchError",
    "FramingTruncatedError",
    "ChunkTooLargeError",
    "AEADDecryptFailedError",
    "SequenceOverflowError",
    "InvalidTokenError",
    "InvalidInputError",
    "code_of",
    "code_of",
    "EHBPError",
    "InvalidInputError",
    "KeyConfigMismatchError",
    "protocol",
    "__version__",
]
