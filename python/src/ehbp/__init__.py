"""Python client for the encrypted HTTP body protocol (EHBP)."""

from . import protocol
from .client import Client, Response, StreamingResponse
from .derive import (
    ResponseKeyMaterial,
    compute_nonce,
    decrypt_chunk,
    derive_response_keys,
    encrypt_chunk,
    frame_chunk,
)
from .errors import (
    ChannelClosedError,
    ChannelTruncatedError,
    CryptoError,
    EHBPError,
    HandshakeError,
    HPKEError,
    InvalidConfigError,
    InvalidInputError,
    KeyConfigMismatchError,
    ProtocolError,
    WebSocketError,
)
from .identity import EncryptedRequest, ServerIdentity
from .noisews import AsyncNoiseWebSocket, NoiseWebSocket
from .session import SessionRecoveryToken
from .transport import AsyncEHBPTransport, EHBPTransport

__version__ = "0.2.5"

__all__ = [
    "Client",
    "Response",
    "StreamingResponse",
    "EHBPTransport",
    "AsyncEHBPTransport",
    "NoiseWebSocket",
    "AsyncNoiseWebSocket",
    "ServerIdentity",
    "EncryptedRequest",
    "SessionRecoveryToken",
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
    "HandshakeError",
    "WebSocketError",
    "ChannelClosedError",
    "ChannelTruncatedError",
    "protocol",
    "__version__",
]
