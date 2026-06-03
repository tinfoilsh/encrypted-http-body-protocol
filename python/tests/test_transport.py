"""Tests for the httpx EHBP transports against the in-process mock server."""

import asyncio

import httpx
import pytest

from conftest import MockServer
from ehbp import AsyncEHBPTransport, EHBPTransport
from ehbp.errors import KeyConfigMismatchError, ProtocolError
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
    with _sync_client(server) as client, pytest.raises(ProtocolError):
        client.post(URL, content=b"payload")


def test_oversized_response_chunk_is_rejected(server: MockServer):
    with _sync_client(server, max_response_bytes=4) as client, pytest.raises(ProtocolError):
        client.post(URL, content=b"this response will exceed the tiny cap")


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


def test_async_key_config_mismatch_raises_dedicated_error(make_server):
    server = make_server(mode="key_config_mismatch")

    async def run() -> None:
        async with _async_client(server) as client:
            await client.post(URL, content=b"payload")

    with pytest.raises(KeyConfigMismatchError):
        asyncio.run(run())
