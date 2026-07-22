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
    CryptoError,
    EHBPError,
    HPKEError,
    InvalidConfigError,
    InvalidInputError,
    KeyConfigMismatchError,
    ProtocolError,
)
from .identity import EncryptedRequest, ServerIdentity
from .session import SessionRecoveryToken
from .transport import AsyncEHBPTransport, EHBPTransport

__version__ = "0.2.6"

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
    "EHBPError",
    "InvalidConfigError",
    "InvalidInputError",
    "ProtocolError",
    "KeyConfigMismatchError",
    "HPKEError",
    "CryptoError",
    "protocol",
    "__version__",
]
