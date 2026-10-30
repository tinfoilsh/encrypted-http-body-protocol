"""Per-request timeouts against a real local server.

``httpx.MockTransport`` cannot model idle time on the wire, so these tests use
a socket server that pauses mid-response. Encrypted requests get a nonce-less
503, which the client passes through, so no server-side HPKE is needed.
"""

import socket
import threading
import time
from collections.abc import Iterator

import httpx
import pytest

from ehbp import Client, ServerIdentity
from ehbp.protocol import ENCAPSULATED_KEY_HEADER

GAP_SECONDS = 1.0
PUBLIC_KEY_HEX = "09" + "00" * 31


def _read_request(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, body = data.split(b"\r\n\r\n", 1)
    lowered = head.lower()
    if b"transfer-encoding: chunked" in lowered:
        while not body.endswith(b"0\r\n\r\n"):
            body += conn.recv(65536)
    elif b"content-length:" in lowered:
        length = int(lowered.split(b"content-length:", 1)[1].split(b"\r\n", 1)[0])
        while len(body) < length:
            body += conn.recv(65536)
    return head


def _serve(listener: socket.socket, gap_before_headers: bool) -> None:
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return

        def handle(conn: socket.socket) -> None:
            with conn:
                head = _read_request(conn)
                encrypted = ENCAPSULATED_KEY_HEADER.lower().encode() in head.lower()
                status = b"503 Service Unavailable" if encrypted else b"200 OK"
                try:
                    if gap_before_headers:
                        time.sleep(GAP_SECONDS)
                    conn.sendall(
                        b"HTTP/1.1 " + status + b"\r\nContent-Type: text/plain\r\n"
                        b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n"
                    )
                    if not gap_before_headers:
                        time.sleep(GAP_SECONDS)
                    conn.sendall(b"1\r\nb\r\n0\r\n\r\n")
                except OSError:
                    pass

        threading.Thread(target=handle, args=(conn,), daemon=True).start()


@pytest.fixture(params=["before_headers", "mid_body"])
def slow_base_url(request) -> Iterator[str]:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    thread = threading.Thread(
        target=_serve, args=(listener, request.param == "before_headers"), daemon=True
    )
    thread.start()
    yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    listener.close()


def _client(base_url: str, client_timeout: float) -> Client:
    return Client(
        base_url,
        ServerIdentity.from_public_key_hex(PUBLIC_KEY_HEX),
        http_client=httpx.Client(timeout=client_timeout),
    )


def _request(client: Client, body, **kwargs) -> bytes:
    return client.request("POST", "/", body=body, **kwargs).content


def _stream(client: Client, body, **kwargs) -> bytes:
    with client.stream("POST", "/", body=body, **kwargs) as response:
        return b"".join(response)


SEND = pytest.mark.parametrize("send", [_request, _stream], ids=["request", "stream"])
BODY = pytest.mark.parametrize("body", [None, b"hi"], ids=["bodyless", "encrypted"])


@SEND
@BODY
def test_shorter_request_timeout_overrides_client(slow_base_url, send, body):
    with _client(slow_base_url, client_timeout=2) as client:
        with pytest.raises(httpx.ReadTimeout):
            send(client, body, timeout=0.5)


@SEND
@BODY
def test_longer_request_timeout_overrides_client(slow_base_url, send, body):
    with _client(slow_base_url, client_timeout=0.5) as client:
        assert send(client, body, timeout=2) == b"ab"


@SEND
@BODY
def test_default_keeps_client_timeout(slow_base_url, send, body):
    with _client(slow_base_url, client_timeout=0.5) as client:
        with pytest.raises(httpx.ReadTimeout):
            send(client, body)


def test_convenience_methods_forward_timeout(slow_base_url):
    with _client(slow_base_url, client_timeout=0.5) as client:
        assert client.get("/", timeout=2).content == b"ab"
        assert client.delete("/", timeout=2).content == b"ab"
        assert client.post("/", body=b"hi", timeout=2).content == b"ab"
        assert client.put("/", body=b"hi", timeout=2).content == b"ab"
