"""End-to-end encrypted WebSocket channels for EHBP (EHBP-WS).

The channel runs the Noise NK handshake (``Noise_NK_25519_AESGCM_SHA256``)
inside WebSocket binary messages: the client authenticates the server by its
X25519 static key (the EHBP HPKE identity key) while remaining anonymous
itself, mirroring the trust model of the HTTP mode. The WebSocket upgrade
request and control frames stay in cleartext so intermediaries can route the
connection; every application message is carried as an encrypted record
inside a binary frame.

Termination is authenticated: peers exchange an encrypted close record before
the WebSocket close handshake, so truncation by an intermediary is
distinguishable from an intentional shutdown (``ChannelTruncatedError``).
"""

from __future__ import annotations

import asyncio
from typing import Optional, Union

import websockets.asyncio.client
import websockets.exceptions
import websockets.sync.client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from noise.connection import Keypair, NoiseConnection
from websockets.typing import Subprotocol

from .errors import (
    ChannelClosedError,
    ChannelTruncatedError,
    CryptoError,
    EHBPError,
    HandshakeError,
    InvalidInputError,
    ProtocolError,
    WebSocketError,
)
from .identity import ServerIdentity
from .protocol import (
    AES256_KEY_LENGTH,
    DEFAULT_WS_MAX_MESSAGE_SIZE,
    MAX_SEQUENCE,
    NOISE_PROLOGUE,
    NOISE_PROTOCOL_NAME,
    WS_HANDSHAKE_READ_LIMIT,
    WS_HANDSHAKE_TIMEOUT,
    WS_RECORD_CLOSE,
    WS_RECORD_DATA,
    WS_RECORD_OVERHEAD,
    WS_REKEY_INTERVAL,
    WS_SUBPROTOCOL,
)

_CLOSE_POLICY_VIOLATION = 1008
_ZERO_BLOCK = b"\x00" * AES256_KEY_LENGTH


class _CipherState:
    """One direction of the record layer.

    AES-256-GCM with the Noise implicit nonce (4 zero bytes followed by an
    8-byte big-endian counter) and the deterministic rekey schedule of SPEC
    Section 8.6. The record layer runs on raw cipher states because EHBP-WS
    records may exceed the Noise transport message cap of 65535 bytes.
    """

    def __init__(self, key: bytes, rekey_interval: int) -> None:
        if rekey_interval <= 0:
            raise InvalidInputError("rekey interval must be positive")
        self._cipher = AESGCM(key)
        self._count = 0
        self._rekey_interval = rekey_interval

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")

    def encrypt(self, plaintext: bytes) -> bytes:
        self._check_counter()
        ciphertext = self._cipher.encrypt(self._nonce(self._count), bytes(plaintext), None)
        self._advance()
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        self._check_counter()
        try:
            plaintext = self._cipher.decrypt(self._nonce(self._count), bytes(ciphertext), None)
        except Exception as err:
            raise CryptoError("failed to decrypt record") from err
        self._advance()
        return plaintext

    def _check_counter(self) -> None:
        # The maximum nonce is reserved for rekeying, so an exhausted
        # counter must fail before any cryptographic use of the nonce.
        if self._count >= MAX_SEQUENCE:
            raise CryptoError("record counter exhausted")

    def _advance(self) -> None:
        self._count += 1
        if self._count % self._rekey_interval == 0:
            self._rekey()

    def _rekey(self) -> None:
        # Noise spec Section 4.2: the new key is the encryption of 32 zero
        # bytes under the maximum nonce, with the tag discarded. The nonce
        # counter deliberately keeps running.
        block = self._cipher.encrypt(self._nonce(MAX_SEQUENCE), _ZERO_BLOCK, None)
        self._cipher = AESGCM(block[:AES256_KEY_LENGTH])


class _Handshake:
    """Client side of the Noise NK handshake."""

    def __init__(self, server_public_key: bytes) -> None:
        conn = NoiseConnection.from_name(NOISE_PROTOCOL_NAME.encode("ascii"))
        conn.set_as_initiator()
        conn.set_prologue(NOISE_PROLOGUE)
        conn.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, bytes(server_public_key))
        conn.start_handshake()
        self._conn = conn

    def message1(self) -> bytes:
        return self._conn.write_message()

    def finish(self, message2: Union[bytes, bytearray]) -> tuple[bytes, bytes]:
        if len(message2) > WS_HANDSHAKE_READ_LIMIT:
            raise HandshakeError(
                f"handshake message of {len(message2)} bytes "
                f"exceeds limit {WS_HANDSHAKE_READ_LIMIT}"
            )
        try:
            # Receivers must ignore any handshake payload present.
            self._conn.read_message(bytes(message2))
        except Exception as err:
            raise HandshakeError(f"handshake failed: {err}") from err
        if not self._conn.handshake_finished:
            raise HandshakeError("handshake did not complete")
        proto = self._conn.noise_protocol
        # Raw split keys, initiator-to-responder first: the client sends
        # with the first key and receives with the second.
        return proto.cipher_state_encrypt.k, proto.cipher_state_decrypt.k


def _websocket_url(url: str) -> str:
    scheme, _, rest = url.partition("://")
    mapped = {"ws": "ws", "wss": "wss", "http": "ws", "https": "wss"}.get(scheme.lower())
    if not rest or mapped is None:
        raise InvalidInputError(f"unsupported URL scheme {scheme!r}")
    return f"{mapped}://{rest}"


def _parse_record(record: bytes, max_message_size: int) -> tuple[int, bytes]:
    if len(record) == 0:
        raise ProtocolError("empty record")
    record_type, payload = record[0], record[1:]
    if record_type == WS_RECORD_DATA:
        # The WebSocket read limit leaves margin above the payload cap, so
        # the decrypted payload size must be checked explicitly.
        if len(payload) > max_message_size:
            raise ProtocolError(
                f"received message of {len(payload)} bytes "
                f"exceeds maximum size {max_message_size}"
            )
        return record_type, payload
    if record_type == WS_RECORD_CLOSE:
        return record_type, b""
    raise ProtocolError(f"unknown record type 0x{record_type:02x}")


class _ChannelState:
    """Connection state and protocol logic shared by the sync and async
    channels; subclasses contribute only the WebSocket I/O calls."""

    def __init__(
        self,
        send_key: bytes,
        recv_key: bytes,
        max_message_size: int,
        rekey_interval: int,
    ) -> None:
        self._send = _CipherState(send_key, rekey_interval)
        self._recv = _CipherState(recv_key, rekey_interval)
        self._max_message_size = max_message_size
        self._peer_closed = False
        self._close_sent = False
        self._local_closed = False
        self._sticky: Optional[EHBPError] = None

    def _encode_data_record(self, payload: bytes) -> bytes:
        if len(payload) > self._max_message_size:
            raise InvalidInputError(
                f"message of {len(payload)} bytes "
                f"exceeds maximum size {self._max_message_size}"
            )
        if self._close_sent or self._local_closed:
            raise ChannelClosedError("encrypted channel closed")
        return self._send.encrypt(bytes([WS_RECORD_DATA]) + bytes(payload))

    def _encode_close_record(self) -> bytes:
        return self._send.encrypt(bytes([WS_RECORD_CLOSE]))

    def _decode_record(self, message: Union[str, bytes]) -> tuple[int, bytes]:
        if isinstance(message, str):
            raise ProtocolError("unexpected text message")
        record = self._recv.decrypt(message)
        return _parse_record(record, self._max_message_size)

    def _transport_ended(self, detail: str) -> EHBPError:
        if self._local_closed:
            self._sticky = ChannelClosedError("encrypted channel closed")
        else:
            self._sticky = ChannelTruncatedError(
                f"connection closed without encrypted close record: {detail}"
            )
        return self._sticky

    def _record_terminal(self, err: EHBPError) -> EHBPError:
        # Record the sticky error after a protocol violation; nothing the
        # peer sends can be trusted at this point.
        self._sticky = err
        self._local_closed = True
        return err


class NoiseWebSocket(_ChannelState):
    """A message-oriented connection whose payloads are encrypted end-to-end
    inside WebSocket binary messages (synchronous API)."""

    def __init__(
        self,
        ws: websockets.sync.client.ClientConnection,
        send_key: bytes,
        recv_key: bytes,
        max_message_size: int,
        rekey_interval: int,
    ) -> None:
        super().__init__(send_key, recv_key, max_message_size, rekey_interval)
        self._ws = ws

    @classmethod
    def connect(
        cls,
        url: str,
        server_identity: ServerIdentity,
        *,
        max_message_size: int = DEFAULT_WS_MAX_MESSAGE_SIZE,
        handshake_timeout: float = WS_HANDSHAKE_TIMEOUT,
        rekey_interval_for_testing: int = WS_REKEY_INTERVAL,
    ) -> NoiseWebSocket:
        """Opens a WebSocket connection to ``url`` (ws, wss, http, or https
        scheme) and runs the Noise handshake against the server identity's
        public key. No application data is sent before the handshake
        completes.

        ``max_message_size`` caps the payload size of a single record in
        both directions; both peers should agree on the cap. ``handshake_timeout``
        bounds the WebSocket dial and the Noise handshake, each independently,
        so a stalled or hostile peer cannot hang the caller.
        """
        # Validated before dialing so channel construction after the
        # handshake cannot fail and leak the open WebSocket.
        if rekey_interval_for_testing <= 0:
            raise InvalidInputError("rekey interval must be positive")
        try:
            ws = websockets.sync.client.connect(
                _websocket_url(url),
                subprotocols=[Subprotocol(WS_SUBPROTOCOL)],
                max_size=max_message_size + WS_RECORD_OVERHEAD,
                open_timeout=handshake_timeout,
            )
        except (OSError, websockets.exceptions.WebSocketException) as err:
            raise WebSocketError(f"dial: {err}") from err
        if ws.subprotocol != WS_SUBPROTOCOL:
            ws.close(_CLOSE_POLICY_VIOLATION, "ehbp noise subprotocol required")
            raise HandshakeError("server did not accept required subprotocol")
        try:
            handshake = _Handshake(server_identity.public_key_bytes())
            ws.send(handshake.message1())
            message2 = ws.recv(timeout=handshake_timeout)
            if isinstance(message2, str):
                raise HandshakeError("handshake message must be binary")
            send_key, recv_key = handshake.finish(message2)
        except EHBPError:
            ws.close(_CLOSE_POLICY_VIOLATION, "handshake failed")
            raise
        except TimeoutError as err:
            ws.close(_CLOSE_POLICY_VIOLATION, "handshake failed")
            raise HandshakeError(f"handshake timed out after {handshake_timeout}s") from err
        except websockets.exceptions.WebSocketException as err:
            ws.close(_CLOSE_POLICY_VIOLATION, "handshake failed")
            raise HandshakeError(f"handshake failed: {err}") from err
        return cls(ws, send_key, recv_key, max_message_size, rekey_interval_for_testing)

    def send(self, payload: bytes) -> None:
        """Encrypts ``payload`` as a single data record and sends it as one
        WebSocket binary message."""
        record = self._encode_data_record(payload)
        try:
            self._ws.send(record)
        except websockets.exceptions.WebSocketException as err:
            raise WebSocketError(str(err)) from err

    def recv(self) -> Optional[bytes]:
        """Receives one record and returns its decrypted payload.

        Returns ``None`` after the peer's encrypted close record. Raises
        ``ChannelClosedError`` if the transport ends after a local close and
        ``ChannelTruncatedError`` if the connection ends without the peer's
        close record. Errors are terminal and sticky.
        """
        if self._peer_closed:
            return None
        if self._sticky is not None:
            raise self._sticky
        try:
            message = self._ws.recv()
        except websockets.exceptions.ConnectionClosed as err:
            raise self._transport_ended(str(err)) from err
        try:
            record_type, payload = self._decode_record(message)
        except EHBPError as err:
            raise self._terminate(err) from err
        if record_type == WS_RECORD_CLOSE:
            self._peer_closed = True
            # Respond with our own close record and complete the WebSocket
            # close handshake.
            try:
                self._close_internal()
            except EHBPError:
                pass
            return None
        return payload

    def close(self) -> None:
        """Sends an encrypted close record and performs the WebSocket close
        handshake. The record lets the peer distinguish an intentional
        shutdown from truncation by an intermediary. Repeated calls are
        no-ops."""
        self._local_closed = True
        self._close_internal()

    def _close_internal(self) -> None:
        if self._close_sent:
            return
        self._close_sent = True
        self._local_closed = True
        error: Optional[EHBPError] = None
        # The close record is best-effort: the WebSocket close handshake
        # below must run even if encrypting or sending the record fails.
        try:
            record = self._encode_close_record()
        except EHBPError as err:
            error = err
        else:
            try:
                self._ws.send(record)
            except websockets.exceptions.WebSocketException as err:
                error = WebSocketError(f"send close record: {err}")
        try:
            self._ws.close()
        except websockets.exceptions.WebSocketException as err:
            if error is None:
                error = WebSocketError(f"close: {err}")
        if error is not None:
            raise error

    def _terminate(self, err: EHBPError) -> EHBPError:
        # Tear the connection down after a protocol violation.
        self._record_terminal(err)
        try:
            self._ws.close(_CLOSE_POLICY_VIOLATION, "protocol violation")
        except websockets.exceptions.WebSocketException:
            pass
        return err

    def __enter__(self) -> NoiseWebSocket:
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            self.close()
        except EHBPError:
            pass


class AsyncNoiseWebSocket(_ChannelState):
    """A message-oriented connection whose payloads are encrypted end-to-end
    inside WebSocket binary messages (asyncio API)."""

    def __init__(
        self,
        ws: websockets.asyncio.client.ClientConnection,
        send_key: bytes,
        recv_key: bytes,
        max_message_size: int,
        rekey_interval: int,
    ) -> None:
        super().__init__(send_key, recv_key, max_message_size, rekey_interval)
        self._ws = ws

    @classmethod
    async def connect(
        cls,
        url: str,
        server_identity: ServerIdentity,
        *,
        max_message_size: int = DEFAULT_WS_MAX_MESSAGE_SIZE,
        handshake_timeout: float = WS_HANDSHAKE_TIMEOUT,
        rekey_interval_for_testing: int = WS_REKEY_INTERVAL,
    ) -> AsyncNoiseWebSocket:
        """Opens a WebSocket connection to ``url`` (ws, wss, http, or https
        scheme) and runs the Noise handshake against the server identity's
        public key. No application data is sent before the handshake
        completes.

        ``max_message_size`` caps the payload size of a single record in
        both directions; both peers should agree on the cap. ``handshake_timeout``
        bounds the WebSocket dial and the Noise handshake, each independently,
        so a stalled or hostile peer cannot hang the caller.
        """
        # Validated before dialing so channel construction after the
        # handshake cannot fail and leak the open WebSocket.
        if rekey_interval_for_testing <= 0:
            raise InvalidInputError("rekey interval must be positive")
        try:
            ws = await websockets.asyncio.client.connect(
                _websocket_url(url),
                subprotocols=[Subprotocol(WS_SUBPROTOCOL)],
                max_size=max_message_size + WS_RECORD_OVERHEAD,
                open_timeout=handshake_timeout,
            )
        except (OSError, websockets.exceptions.WebSocketException) as err:
            raise WebSocketError(f"dial: {err}") from err
        if ws.subprotocol != WS_SUBPROTOCOL:
            await ws.close(_CLOSE_POLICY_VIOLATION, "ehbp noise subprotocol required")
            raise HandshakeError("server did not accept required subprotocol")
        try:
            handshake = _Handshake(server_identity.public_key_bytes())
            await ws.send(handshake.message1())
            message2 = await asyncio.wait_for(ws.recv(), timeout=handshake_timeout)
            if isinstance(message2, str):
                raise HandshakeError("handshake message must be binary")
            send_key, recv_key = handshake.finish(message2)
        except EHBPError:
            await ws.close(_CLOSE_POLICY_VIOLATION, "handshake failed")
            raise
        except asyncio.TimeoutError as err:
            await ws.close(_CLOSE_POLICY_VIOLATION, "handshake failed")
            raise HandshakeError(f"handshake timed out after {handshake_timeout}s") from err
        except websockets.exceptions.WebSocketException as err:
            await ws.close(_CLOSE_POLICY_VIOLATION, "handshake failed")
            raise HandshakeError(f"handshake failed: {err}") from err
        return cls(ws, send_key, recv_key, max_message_size, rekey_interval_for_testing)

    async def send(self, payload: bytes) -> None:
        """Encrypts ``payload`` as a single data record and sends it as one
        WebSocket binary message."""
        record = self._encode_data_record(payload)
        try:
            await self._ws.send(record)
        except websockets.exceptions.WebSocketException as err:
            raise WebSocketError(str(err)) from err

    async def recv(self) -> Optional[bytes]:
        """Receives one record and returns its decrypted payload.

        Returns ``None`` after the peer's encrypted close record. Raises
        ``ChannelClosedError`` if the transport ends after a local close and
        ``ChannelTruncatedError`` if the connection ends without the peer's
        close record. Errors are terminal and sticky.
        """
        if self._peer_closed:
            return None
        if self._sticky is not None:
            raise self._sticky
        try:
            message = await self._ws.recv()
        except websockets.exceptions.ConnectionClosed as err:
            raise self._transport_ended(str(err)) from err
        try:
            record_type, payload = self._decode_record(message)
        except EHBPError as err:
            raise await self._terminate(err) from err
        if record_type == WS_RECORD_CLOSE:
            self._peer_closed = True
            # Respond with our own close record and complete the WebSocket
            # close handshake.
            try:
                await self._close_internal()
            except EHBPError:
                pass
            return None
        return payload

    async def close(self) -> None:
        """Sends an encrypted close record and performs the WebSocket close
        handshake. The record lets the peer distinguish an intentional
        shutdown from truncation by an intermediary. Repeated calls are
        no-ops."""
        self._local_closed = True
        await self._close_internal()

    async def _close_internal(self) -> None:
        if self._close_sent:
            return
        self._close_sent = True
        self._local_closed = True
        error: Optional[EHBPError] = None
        # The close record is best-effort: the WebSocket close handshake
        # below must run even if encrypting or sending the record fails.
        try:
            record = self._encode_close_record()
        except EHBPError as err:
            error = err
        else:
            try:
                await self._ws.send(record)
            except websockets.exceptions.WebSocketException as err:
                error = WebSocketError(f"send close record: {err}")
        try:
            await self._ws.close()
        except websockets.exceptions.WebSocketException as err:
            if error is None:
                error = WebSocketError(f"close: {err}")
        if error is not None:
            raise error

    async def _terminate(self, err: EHBPError) -> EHBPError:
        # Tear the connection down after a protocol violation.
        self._record_terminal(err)
        try:
            await self._ws.close(_CLOSE_POLICY_VIOLATION, "protocol violation")
        except websockets.exceptions.WebSocketException:
            pass
        return err

    async def __aenter__(self) -> AsyncNoiseWebSocket:
        return self

    async def __aexit__(self, *exc: object) -> None:
        try:
            await self.close()
        except EHBPError:
            pass
