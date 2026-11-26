"""The http_client's timeout against a real local server.

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

from ehbp import Client, PublicKey
from ehbp.protocol import ENCAPSULATED_KEY_HEADER

GAP_SECONDS = 1.0
PUBLIC_KEY = bytes([9]) + bytes(31)


def _read_request(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, body = data.split(b"\r\n\r\n", 1)
    if b"transfer-encoding: chunked" in head.lower():
        while not body.endswith(b"0\r\n\r\n"):
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
    threading.Thread(
        target=_serve, args=(listener, request.param == "before_headers"), daemon=True
    ).start()
    yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    listener.close()


def _client(base_url: str, timeout: float) -> Client:
    return Client(base_url, PublicKey(PUBLIC_KEY), http_client=httpx.Client(timeout=timeout))


@pytest.mark.parametrize("body", [None, b"hi"], ids=["bodyless", "encrypted"])
def test_client_read_timeout_bounds_each_gap(slow_base_url, body):
    with _client(slow_base_url, timeout=0.5) as client:
        with pytest.raises(httpx.ReadTimeout):
            client.request("POST", "/", body=body).read()
    with _client(slow_base_url, timeout=2) as client:
        assert client.request("POST", "/", body=body).read() == b"ab"
