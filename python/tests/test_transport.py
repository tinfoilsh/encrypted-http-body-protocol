"""Tests for the httpx EHBP transports against the in-process mock server."""

import asyncio

import httpx
import pytest

from conftest import MockServer
from ehbp import AsyncEHBPTransport, EHBPTransport
from ehbp.errors import ChunkTooLargeError, KeyConfigMismatchError, MissingResponseNonceError
from ehbp.identity import REQUEST_FRAME_SIZE
from ehbp.protocol import ENCAPSULATED_KEY_HEADER

URL = "https://server.example/v1/echo"


def _sync_client(server: MockServer, **kwargs) -> httpx.Client:
    transport = EHBPTransport.from_public_key_hex(
        server.public_key_bytes.hex(),
        inner=httpx.MockTransport(server.handler),
        **kwargs,
    )
    return httpx.Client(transport=transport)


def _async_client(server: MockServer, **kwargs) -> httpx.AsyncClient:
    transport = AsyncEHBPTransport.from_public_key_hex(
        server.public_key_bytes.hex(),
        inner=httpx.MockTransport(server.handler),
        **kwargs,
    )
    return httpx.AsyncClient(transport=transport)


def test_encrypted_round_trip(server: MockServer):
    with _sync_client(server) as client:
        response = client.post(URL, content=b"hello world")
    assert response.status_code == 200
    assert response.content == b"echo:hello world"


def test_multi_chunk_response_round_trip(make_server):
    server = make_server(chunk_size=3)
    with _sync_client(server) as client:
        response = client.post(URL, content=b"abcdefghij")
    assert response.content == b"echo:abcdefghij"


def test_streaming_response_decrypts_lazily(make_server):
    server = make_server(chunk_size=4)
    collected = bytearray()
    with _sync_client(server) as client, client.stream(
        "POST", URL, content=b"streamed payload"
    ) as response:
        assert response.status_code == 200
        for chunk in response.iter_bytes():
            collected += chunk
    assert bytes(collected) == b"echo:streamed payload"


def test_encrypted_request_uses_chunked_body_without_content_length(server: MockServer):
    with _sync_client(server) as client:
        client.post(URL, content=b"payload")
    headers = server.last_request.headers
    assert ENCAPSULATED_KEY_HEADER in headers
    assert "content-length" not in headers
    assert headers.get("transfer-encoding") == "chunked"


def test_bodyless_request_passes_through(server: MockServer):
    with _sync_client(server) as client:
        response = client.get("https://server.example/health")
    assert response.content == b"plaintext ok"
    assert ENCAPSULATED_KEY_HEADER not in server.last_request.headers


def test_key_config_mismatch_raises_dedicated_error(make_server):
    server = make_server(mode="key_config_mismatch")
    with _sync_client(server) as client, pytest.raises(KeyConfigMismatchError):
        client.post(URL, content=b"payload")


def test_missing_response_nonce_fails_closed(make_server):
    server = make_server(mode="strip_nonce")
    with _sync_client(server) as client, pytest.raises(MissingResponseNonceError):
        client.post(URL, content=b"payload")


@pytest.mark.parametrize("status_code", [300, 400, 503])
def test_unencrypted_non_success_response_passes_through(make_server, status_code):
    server = make_server(mode="unencrypted_response", status_code=status_code)
    with _sync_client(server) as client:
        response = client.post(URL, content=b"payload")
    assert response.status_code == status_code
    assert response.headers["content-type"] == "text/plain"
    assert response.headers["x-upstream"] == "proxy"
    assert response.content == b"upstream unavailable"


def test_streaming_unencrypted_non_success_response_passes_through(make_server):
    server = make_server(mode="unencrypted_response", status_code=429)
    with _sync_client(server) as client, client.stream(
        "POST", URL, content=b"payload"
    ) as response:
        assert response.status_code == 429
        assert response.headers["content-type"] == "text/plain"
        assert b"".join(response.iter_bytes()) == b"upstream unavailable"


def test_encrypted_non_success_response_is_decrypted(make_server):
    server = make_server(status_code=503)
    with _sync_client(server) as client:
        response = client.post(URL, content=b"payload")
    assert response.status_code == 503
    assert response.content == b"echo:payload"


def test_oversized_response_chunk_is_rejected(server: MockServer):
    with _sync_client(server, max_response_bytes=4) as client, pytest.raises(ChunkTooLargeError):
        client.post(URL, content=b"this response will exceed the tiny cap")


def test_missing_nonce_response_body_is_capped(make_server):
    server = make_server(mode="strip_nonce")
    client = _sync_client(server, max_response_bytes=4)
    with client, pytest.raises(ChunkTooLargeError) as excinfo:
        client.post(URL, content=b"payload")
    assert "exceeds maximum allowed size" in str(excinfo.value)


def test_encrypted_request_preserves_extensions(server: MockServer):
    with _sync_client(server) as client:
        client.post(URL, content=b"payload")
    assert "timeout" in server.last_request.extensions


def test_async_encrypted_round_trip(server: MockServer):
    async def run() -> httpx.Response:
        async with _async_client(server) as client:
            return await client.post(URL, content=b"hello world")

    response = asyncio.run(run())
    assert response.status_code == 200
    assert response.content == b"echo:hello world"


def test_async_streaming_response_decrypts_lazily(make_server):
    server = make_server(chunk_size=4)

    async def run() -> bytes:
        collected = bytearray()
        async with _async_client(server) as client, client.stream(
            "POST", URL, content=b"streamed payload"
        ) as response:
            assert response.status_code == 200
            async for chunk in response.aiter_bytes():
                collected += chunk
        return bytes(collected)

    assert asyncio.run(run()) == b"echo:streamed payload"


def test_async_bodyless_request_passes_through(server: MockServer):
    async def run() -> httpx.Response:
        async with _async_client(server) as client:
            return await client.get("https://server.example/health")

    response = asyncio.run(run())
    assert response.content == b"plaintext ok"
    assert ENCAPSULATED_KEY_HEADER not in server.last_request.headers


def test_async_unencrypted_non_success_response_passes_through(make_server):
    server = make_server(mode="unencrypted_response", status_code=503)

    async def run() -> httpx.Response:
        async with _async_client(server) as client:
            return await client.post(URL, content=b"payload")

    response = asyncio.run(run())
    assert response.status_code == 503
    assert response.headers["content-type"] == "text/plain"
    assert response.headers["x-upstream"] == "proxy"
    assert response.content == b"upstream unavailable"


def test_async_streaming_unencrypted_non_success_response_passes_through(make_server):
    server = make_server(mode="unencrypted_response", status_code=429)

    async def run() -> bytes:
        async with _async_client(server) as client, client.stream(
            "POST", URL, content=b"payload"
        ) as response:
            assert response.status_code == 429
            assert response.headers["content-type"] == "text/plain"
            return b"".join([chunk async for chunk in response.aiter_bytes()])

    assert asyncio.run(run()) == b"upstream unavailable"


def test_async_key_config_mismatch_raises_dedicated_error(make_server):
    server = make_server(mode="key_config_mismatch")

    async def run() -> None:
        async with _async_client(server) as client:
            await client.post(URL, content=b"payload")

    with pytest.raises(KeyConfigMismatchError):
        asyncio.run(run())


def test_async_missing_nonce_response_body_is_capped(make_server):
    server = make_server(mode="strip_nonce")

    async def run() -> None:
        async with _async_client(server, max_response_bytes=4) as client:
            await client.post(URL, content=b"payload")

    with pytest.raises(ChunkTooLargeError) as excinfo:
        asyncio.run(run())
    assert "exceeds maximum allowed size" in str(excinfo.value)


def test_async_encrypted_request_preserves_extensions(server: MockServer):
    async def run() -> None:
        async with _async_client(server) as client:
            await client.post(URL, content=b"payload")

    asyncio.run(run())
    assert "timeout" in server.last_request.extensions


class _StreamingInner(httpx.BaseTransport):
    """Forwards to the mock server but records how many source chunks had been
    pulled when each encrypted chunk reached the wire, so a transport that
    buffers the whole upload first is caught."""

    def __init__(self, server: MockServer, pulled: list) -> None:
        self._server = server
        self._pulled = pulled
        self.pulled_at_wire: list = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.wire_headers = request.headers
        body = bytearray()
        for chunk in request.stream:
            self.pulled_at_wire.append(len(self._pulled))
            body += chunk
        headers = httpx.Headers(request.headers)
        del headers["transfer-encoding"]
        return self._server.handler(
            httpx.Request(request.method, request.url, headers=headers, content=bytes(body))
        )


def test_streamed_request_body_is_encrypted_frame_by_frame(server: MockServer):
    pulled = []
    # Frame-sized parts: each pull completes a frame, so the first frame can
    # leave before the next part is pulled.
    parts = [bytes([i]) * REQUEST_FRAME_SIZE for i in (1, 2, 3)]

    def source():
        for part in parts:
            pulled.append(part)
            yield part

    inner = _StreamingInner(server, pulled)
    transport = EHBPTransport.from_public_key_hex(server.public_key_bytes.hex(), inner=inner)
    with httpx.Client(transport=transport) as client:
        response = client.post(URL, content=source())
    assert response.content == b"echo:" + b"".join(parts)
    # Streamed content goes out chunked; the transport never buffers it.
    assert "content-length" not in inner.wire_headers
    # The first encrypted chunk reached the wire before the source was exhausted.
    assert inner.pulled_at_wire, "no encrypted chunks were streamed"
    assert inner.pulled_at_wire[0] < len(pulled)


def test_headerless_stream_request_is_encrypted_not_passed_through(server: MockServer):
    class RawStream(httpx.SyncByteStream):
        def __iter__(self):
            yield b"secret"

    with _sync_client(server) as client:
        # A low-level Request(stream=...) carries neither Content-Length nor
        # Transfer-Encoding; the body must still be encrypted.
        request = httpx.Request("POST", URL, stream=RawStream())
        response = client.send(request)
    assert response.content == b"echo:secret"
    assert ENCAPSULATED_KEY_HEADER in server.last_request.headers


def test_content_length_zero_header_does_not_bypass_encryption(server: MockServer):
    class RawStream(httpx.SyncByteStream):
        def __iter__(self):
            yield b"SECRET-PLAINTEXT"

    with _sync_client(server) as client:
        # A caller-supplied Content-Length: 0 must not make a non-empty stream
        # bodyless: the stream decides, and the body goes out encrypted.
        request = httpx.Request("POST", URL, stream=RawStream(), headers={"content-length": "0"})
        response = client.send(request)
    assert response.content == b"echo:SECRET-PLAINTEXT"
    assert ENCAPSULATED_KEY_HEADER in server.last_request.headers
    assert b"SECRET-PLAINTEXT" not in server.last_request.read()


def test_async_content_length_zero_header_does_not_bypass_encryption(server: MockServer):
    class RawStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"SECRET-PLAINTEXT"

    async def run() -> httpx.Response:
        async with _async_client(server) as client:
            headers = {"content-length": "0"}
            return await client.send(httpx.Request("POST", URL, stream=RawStream(), headers=headers))

    response = asyncio.run(run())
    assert response.content == b"echo:SECRET-PLAINTEXT"
    assert ENCAPSULATED_KEY_HEADER in server.last_request.headers
    assert b"SECRET-PLAINTEXT" not in server.last_request.read()


def test_empty_stream_request_passes_through_bodyless(server: MockServer):
    class EmptyStream(httpx.SyncByteStream):
        def __iter__(self):
            yield b""

    with _sync_client(server) as client:
        response = client.send(httpx.Request("POST", URL, stream=EmptyStream()))
    assert response.content == b"plaintext ok"
    assert ENCAPSULATED_KEY_HEADER not in server.last_request.headers


def test_async_empty_stream_request_passes_through_bodyless(server: MockServer):
    async def source():
        yield b""

    async def run() -> httpx.Response:
        async with _async_client(server) as client:
            return await client.post(URL, content=source())

    response = asyncio.run(run())
    assert response.content == b"plaintext ok"
    assert ENCAPSULATED_KEY_HEADER not in server.last_request.headers


def test_async_streamed_request_body_round_trip(server: MockServer):
    async def source():
        yield b"async "
        yield b"stream"

    async def run() -> bytes:
        async with _async_client(server) as client:
            response = await client.post(URL, content=source())
            return response.content

    assert asyncio.run(run()) == b"echo:async stream"
