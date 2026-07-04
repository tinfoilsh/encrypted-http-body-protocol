"""Tests for the encrypted WebSocket channels (EHBP-WS)."""

import asyncio
import json
import queue
import threading
import time
from pathlib import Path
from typing import Callable, Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from noise.connection import Keypair, NoiseConnection
from websockets.exceptions import ConnectionClosed
from websockets.sync.server import Server, ServerConnection, serve
from websockets.typing import Subprotocol

from ehbp import (
    AsyncNoiseWebSocket,
    ChannelClosedError,
    ChannelTruncatedError,
    CryptoError,
    HandshakeError,
    InvalidInputError,
    NoiseWebSocket,
    ProtocolError,
    ServerIdentity,
)
from ehbp.noisews import _CipherState
from ehbp.protocol import (
    AES256_KEY_LENGTH,
    DEFAULT_WS_MAX_MESSAGE_SIZE,
    MAX_SEQUENCE,
    NOISE_PROLOGUE,
    NOISE_PROTOCOL_NAME,
    WS_RECORD_CLOSE,
    WS_RECORD_DATA,
    WS_RECORD_OVERHEAD,
    WS_REKEY_INTERVAL,
    WS_SUBPROTOCOL,
)

VECTORS = Path(__file__).resolve().parents[2] / "test-vectors"

Behavior = Callable[[ServerConnection, _CipherState, _CipherState, "queue.Queue[tuple]"], None]


class NoiseTestServer:
    """In-process WebSocket server running the Noise responder handshake and
    handing the encrypted record layer to a per-test behavior."""

    def __init__(
        self,
        behavior: Behavior,
        *,
        rekey_interval: int = WS_REKEY_INTERVAL,
        negotiate_subprotocol: bool = True,
    ) -> None:
        private_key = X25519PrivateKey.generate()
        self._private_bytes = private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.identity = ServerIdentity.from_public_key_bytes(public_bytes)
        self.events: queue.Queue = queue.Queue()
        self._behavior = behavior
        self._rekey_interval = rekey_interval

        subprotocols: Optional[list] = None
        if negotiate_subprotocol:
            subprotocols = [Subprotocol(WS_SUBPROTOCOL)]
        self._server: Server = serve(
            self._handler,
            "127.0.0.1",
            0,
            subprotocols=subprotocols,
            max_size=DEFAULT_WS_MAX_MESSAGE_SIZE + WS_RECORD_OVERHEAD,
        )
        port = self._server.socket.getsockname()[1]
        self.url = f"ws://127.0.0.1:{port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _handler(self, websocket: ServerConnection) -> None:
        try:
            responder = NoiseConnection.from_name(NOISE_PROTOCOL_NAME.encode("ascii"))
            responder.set_as_responder()
            responder.set_prologue(NOISE_PROLOGUE)
            responder.set_keypair_from_private_bytes(Keypair.STATIC, self._private_bytes)
            responder.start_handshake()
            message1 = websocket.recv()
            responder.read_message(bytes(message1))
            websocket.send(responder.write_message())
            proto = responder.noise_protocol
            send = _CipherState(proto.cipher_state_encrypt.k, self._rekey_interval)
            recv = _CipherState(proto.cipher_state_decrypt.k, self._rekey_interval)
        except Exception as err:
            self.events.put(("handshake_error", repr(err)))
            return
        self._behavior(websocket, send, recv, self.events)

    def __enter__(self) -> "NoiseTestServer":
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._thread.join(timeout=5)


def echo_behavior(websocket, send, recv, events) -> None:
    while True:
        try:
            message = websocket.recv()
        except ConnectionClosed:
            events.put(("truncated",))
            return
        try:
            record = recv.decrypt(message)
        except CryptoError as err:
            events.put(("decrypt_error", repr(err)))
            return
        if record[0] == WS_RECORD_CLOSE:
            # Respond with our own close record; the client may already have
            # completed the WebSocket close handshake by then.
            try:
                websocket.send(send.encrypt(bytes([WS_RECORD_CLOSE])))
                websocket.close()
            except ConnectionClosed:
                pass
            events.put(("eof",))
            return
        websocket.send(send.encrypt(record))


def test_echo_round_trip_and_clean_close():
    with NoiseTestServer(echo_behavior) as server:
        conn = NoiseWebSocket.connect(server.url, server.identity)
        for message in (b"hello", b"", b"second message"):
            conn.send(message)
            assert conn.recv() == message
        conn.close()
        assert server.events.get(timeout=5) == ("eof",)
        with pytest.raises(ChannelClosedError):
            conn.send(b"after close")


def test_async_echo_round_trip_and_clean_close():
    with NoiseTestServer(echo_behavior) as server:

        async def run() -> None:
            conn = await AsyncNoiseWebSocket.connect(server.url, server.identity)
            for message in (b"hello", b"", b"second message"):
                await conn.send(message)
                assert await conn.recv() == message
            await conn.close()
            with pytest.raises(ChannelClosedError):
                await conn.send(b"after close")

        asyncio.run(run())
        assert server.events.get(timeout=5) == ("eof",)


def test_recv_after_peer_close_returns_none():
    def close_immediately(websocket, send, recv, events) -> None:
        websocket.send(send.encrypt(bytes([WS_RECORD_CLOSE])))
        try:
            websocket.recv()
        except ConnectionClosed:
            pass
        websocket.close()

    with NoiseTestServer(close_immediately) as server:

        async def run() -> None:
            conn = await AsyncNoiseWebSocket.connect(server.url, server.identity)
            assert await conn.recv() is None
            assert await conn.recv() is None

        asyncio.run(run())


def test_wrong_server_key_fails_handshake():
    with NoiseTestServer(echo_behavior) as server:
        wrong_key = X25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        wrong_identity = ServerIdentity.from_public_key_bytes(wrong_key)
        with pytest.raises(HandshakeError):
            NoiseWebSocket.connect(server.url, wrong_identity)


def test_tampered_record_fails_closed():
    def tamper(websocket, send, recv, events) -> None:
        ciphertext = bytearray(send.encrypt(bytes([WS_RECORD_DATA]) + b"hi"))
        ciphertext[0] ^= 0xFF
        websocket.send(bytes(ciphertext))
        # Keep the socket open so the client failure comes from the AEAD,
        # not from the transport ending.
        try:
            websocket.recv()
        except ConnectionClosed:
            pass

    with NoiseTestServer(tamper) as server:
        conn = NoiseWebSocket.connect(server.url, server.identity)
        with pytest.raises(CryptoError):
            conn.recv()
        with pytest.raises(CryptoError):
            conn.recv()


def test_truncation_detected():
    def truncate(websocket, send, recv, events) -> None:
        message = websocket.recv()
        websocket.send(send.encrypt(recv.decrypt(message)))
        # Close the WebSocket without sending an encrypted close record,
        # simulating truncation by an intermediary.
        websocket.close()

    with NoiseTestServer(truncate) as server:
        conn = NoiseWebSocket.connect(server.url, server.identity)
        conn.send(b"last message")
        assert conn.recv() == b"last message"
        with pytest.raises(ChannelTruncatedError):
            conn.recv()
        with pytest.raises(ChannelTruncatedError):
            conn.recv()


def test_server_detects_client_truncation():
    with NoiseTestServer(echo_behavior) as server:
        conn = NoiseWebSocket.connect(server.url, server.identity)
        conn.send(b"hello")
        assert conn.recv() == b"hello"
        # Tear down the socket without sending an encrypted close record.
        conn._ws.close()
        assert server.events.get(timeout=5) == ("truncated",)


def test_rekey_keeps_directions_in_sync():
    with NoiseTestServer(echo_behavior, rekey_interval=3) as server:
        conn = NoiseWebSocket.connect(
            server.url, server.identity, rekey_interval_for_testing=3
        )
        payload = b"x" * 100
        for _ in range(10):
            conn.send(payload)
            assert conn.recv() == payload
        conn.close()
        assert server.events.get(timeout=5) == ("eof",)


def test_oversized_write_rejected():
    with NoiseTestServer(echo_behavior) as server:
        conn = NoiseWebSocket.connect(server.url, server.identity, max_message_size=16)
        with pytest.raises(InvalidInputError):
            conn.send(b"x" * 17)
        conn.send(b"x" * 16)
        assert conn.recv() == b"x" * 16
        conn.close()


def test_oversized_inbound_record_fails_connection():
    # The server's cap is larger than the client's, so it can produce a
    # record that fits the client's WebSocket read limit margin but exceeds
    # the client's payload cap.
    def oversized(websocket, send, recv, events) -> None:
        websocket.send(send.encrypt(bytes([WS_RECORD_DATA]) + b"x" * 32))
        try:
            websocket.recv()
        except ConnectionClosed:
            pass

    with NoiseTestServer(oversized) as server:
        conn = NoiseWebSocket.connect(server.url, server.identity, max_message_size=16)
        with pytest.raises(ProtocolError, match="exceeds maximum size"):
            conn.recv()


def test_dial_requires_negotiated_subprotocol():
    with NoiseTestServer(echo_behavior, negotiate_subprotocol=False) as server:
        with pytest.raises(HandshakeError, match="subprotocol"):
            NoiseWebSocket.connect(server.url, server.identity)


def _serve_stalled_handshake():
    """Starts a raw WebSocket server that negotiates the subprotocol and
    reads the client's handshake message but never replies, simulating a
    stalled or hostile peer."""

    def handler(websocket: ServerConnection) -> None:
        websocket.recv()
        time.sleep(5)

    server = serve(handler, "127.0.0.1", 0, subprotocols=[Subprotocol(WS_SUBPROTOCOL)])
    port = server.socket.getsockname()[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"ws://127.0.0.1:{port}"


def test_dial_handshake_timeout():
    server, thread, url = _serve_stalled_handshake()
    try:
        identity = ServerIdentity.from_public_key_bytes(
            X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        start = time.monotonic()
        with pytest.raises(HandshakeError, match="timed out"):
            NoiseWebSocket.connect(url, identity, handshake_timeout=0.2)
        assert time.monotonic() - start < 2
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_async_dial_handshake_timeout():
    server, thread, url = _serve_stalled_handshake()
    try:
        identity = ServerIdentity.from_public_key_bytes(
            X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

        async def run() -> None:
            start = time.monotonic()
            with pytest.raises(HandshakeError, match="timed out"):
                await AsyncNoiseWebSocket.connect(url, identity, handshake_timeout=0.2)
            assert time.monotonic() - start < 2

        asyncio.run(run())
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_cipher_state_rejects_the_reserved_maximum_nonce_before_use():
    key = b"\x11" * AES256_KEY_LENGTH
    sender = _CipherState(key, WS_REKEY_INTERVAL)
    sender._count = MAX_SEQUENCE - 1
    # The last usable nonce still works.
    ciphertext = sender.encrypt(b"last record")
    assert sender._count == MAX_SEQUENCE
    # The maximum nonce is reserved for rekeying and must be rejected before
    # it reaches the AEAD cipher, not just on the following call.
    with pytest.raises(CryptoError):
        sender.encrypt(b"one too many")

    receiver = _CipherState(key, WS_REKEY_INTERVAL)
    receiver._count = MAX_SEQUENCE - 1
    assert receiver.decrypt(ciphertext) == b"last record"
    with pytest.raises(CryptoError):
        receiver.decrypt(ciphertext)


def test_cipher_state_rejects_a_non_positive_rekey_interval():
    key = b"\x11" * AES256_KEY_LENGTH
    for interval in (0, -1):
        with pytest.raises(InvalidInputError):
            _CipherState(key, interval)


def test_connect_rejects_a_non_positive_rekey_interval_before_dialing():
    identity = ServerIdentity.from_public_key_bytes(
        X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    # The unroutable URL proves the option is validated before any dial:
    # reaching the network would raise WebSocketError instead.
    url = "ws://127.0.0.1:1"
    with pytest.raises(InvalidInputError):
        NoiseWebSocket.connect(url, identity, rekey_interval_for_testing=0)

    async def run() -> None:
        with pytest.raises(InvalidInputError):
            await AsyncNoiseWebSocket.connect(url, identity, rekey_interval_for_testing=0)

    asyncio.run(run())


def test_close_completes_websocket_shutdown_when_close_record_fails():
    with NoiseTestServer(echo_behavior) as server:
        conn = NoiseWebSocket.connect(server.url, server.identity)
        # Exhaust the send counter so encrypting the close record fails.
        conn._send._count = MAX_SEQUENCE
        with pytest.raises(CryptoError):
            conn.close()
        # The WebSocket close handshake must still run; the server observes
        # the connection ending without an encrypted close record.
        assert server.events.get(timeout=5) == ("truncated",)


def test_noisews_interop_vector():
    vector = json.loads((VECTORS / "noisews.json").read_text())
    assert vector["protocolName"] == NOISE_PROTOCOL_NAME
    assert vector["prologue"].encode("ascii") == NOISE_PROLOGUE

    initiator = NoiseConnection.from_name(vector["protocolName"].encode("ascii"))
    initiator.set_as_initiator()
    initiator.set_prologue(NOISE_PROLOGUE)
    initiator.set_keypair_from_public_bytes(
        Keypair.REMOTE_STATIC, bytes.fromhex(vector["serverStaticPublic"])
    )
    initiator.set_keypair_from_private_bytes(
        Keypair.EPHEMERAL, bytes.fromhex(vector["clientEphemeralPrivate"])
    )
    initiator.start_handshake()

    responder = NoiseConnection.from_name(vector["protocolName"].encode("ascii"))
    responder.set_as_responder()
    responder.set_prologue(NOISE_PROLOGUE)
    responder.set_keypair_from_private_bytes(
        Keypair.STATIC, bytes.fromhex(vector["serverStaticPrivate"])
    )
    responder.set_keypair_from_private_bytes(
        Keypair.EPHEMERAL, bytes.fromhex(vector["serverEphemeralPrivate"])
    )
    responder.start_handshake()

    message1 = initiator.write_message()
    assert message1.hex() == vector["message1"]
    responder.read_message(message1)
    message2 = responder.write_message()
    assert message2.hex() == vector["message2"]
    initiator.read_message(message2)
    assert initiator.handshake_finished and responder.handshake_finished
    assert initiator.get_handshake_hash().hex() == vector["handshakeHash"]
    assert responder.get_handshake_hash().hex() == vector["handshakeHash"]

    interval = vector["rekeyInterval"]
    client_send = _CipherState(initiator.noise_protocol.cipher_state_encrypt.k, interval)
    client_recv = _CipherState(initiator.noise_protocol.cipher_state_decrypt.k, interval)
    server_send = _CipherState(responder.noise_protocol.cipher_state_encrypt.k, interval)
    server_recv = _CipherState(responder.noise_protocol.cipher_state_decrypt.k, interval)

    for i, entry in enumerate(vector["records"]):
        record_type = {"data": WS_RECORD_DATA, "close": WS_RECORD_CLOSE}[entry["type"]]
        record = bytes([record_type]) + bytes.fromhex(entry["payload"])
        send, recv = {
            "c2s": (client_send, server_recv),
            "s2c": (server_send, client_recv),
        }[entry["dir"]]
        ciphertext = send.encrypt(record)
        assert ciphertext.hex() == entry["ciphertext"], f"record {i} ciphertext mismatch"
        assert recv.decrypt(ciphertext) == record, f"record {i} round trip mismatch"

    # Not part of the vector, but keep the default schedule aligned with the
    # reference implementation.
    assert WS_REKEY_INTERVAL == 1 << 16
