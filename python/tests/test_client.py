"""Client behavior tests against the in-process EHBP mock server."""

import httpx
import pytest

from conftest import DEFAULT_BASE_URL, MockServer
from ehbp import Client, ServerIdentity
from ehbp.errors import (
    InvalidConfigError,
    InvalidInputError,
    KeyConfigMismatchError,
    ProtocolError,
)
from ehbp.protocol import ENCAPSULATED_KEY_HEADER, RESPONSE_NONCE_HEADER


def test_encrypted_round_trip(server: MockServer):
    client = server.make_client()
    response = client.post("/v1/echo", body=b"hello world")
    assert response.status_code == 200
    assert response.content == b"echo:hello world"


def test_round_trip_with_multi_chunk_response(make_server):
    server = make_server(chunk_size=3)
    client = server.make_client()
    response = client.post("/v1/echo", body=b"abcdefghij")
    assert response.content == b"echo:abcdefghij"


def test_streaming_round_trip(make_server):
    server = make_server(chunk_size=4)
    client = server.make_client()
    collected = bytearray()
    with client.stream("POST", "/v1/echo", body=b"streamed payload") as response:
        assert response.status_code == 200
        for chunk in response:
            collected += chunk
    assert bytes(collected) == b"echo:streamed payload"


def test_bodyless_request_passes_through_as_plaintext(server: MockServer):
    client = server.make_client()
    response = client.get("/health")
    assert response.content == b"plaintext ok"
    assert client.get_session_recovery_token() is None


def test_successful_request_retains_session_recovery_token(server: MockServer):
    client = server.make_client()
    client.post("/v1/echo", body=b"payload")
    token = client.get_session_recovery_token()
    assert token is not None
    assert token.request_enc == bytes.fromhex(
        server.last_request.headers[ENCAPSULATED_KEY_HEADER]
    )


def test_encrypted_body_uses_chunked_transfer_without_content_length(server: MockServer):
    client = server.make_client()
    client.post("/v1/echo", body=b"payload")
    headers = server.last_request.headers
    assert "content-length" not in headers
    assert headers.get("transfer-encoding") == "chunked"


def test_request_to_foreign_origin_is_rejected(server: MockServer):
    client = server.make_client()
    with pytest.raises(InvalidInputError):
        client.get("https://evil.example/steal")


def test_protocol_relative_url_to_foreign_host_is_rejected(server: MockServer):
    client = server.make_client()
    with pytest.raises(InvalidInputError):
        client.get("//evil.example/steal")


def test_reserved_header_is_rejected(server: MockServer):
    client = server.make_client()
    with pytest.raises(InvalidInputError):
        client.post("/v1/echo", body=b"payload", headers={RESPONSE_NONCE_HEADER: "00"})


def test_base_url_with_credentials_is_rejected(server: MockServer):
    with pytest.raises(InvalidInputError):
        Client(
            "https://user:pass@server.example/",
            ServerIdentity.from_public_key_bytes(server.public_key_bytes),
            http_client=server.http_client(),
        )


def test_missing_response_nonce_fails_closed(make_server):
    server = make_server(mode="strip_nonce")
    client = server.make_client()
    with pytest.raises(ProtocolError):
        client.post("/v1/echo", body=b"payload")
    assert client.get_session_recovery_token() is None


def test_key_config_mismatch_raises_dedicated_error(make_server):
    server = make_server(mode="key_config_mismatch")
    client = server.make_client()
    with pytest.raises(KeyConfigMismatchError):
        client.post("/v1/echo", body=b"payload")
    assert client.get_session_recovery_token() is None


def test_response_size_cap_is_enforced(server: MockServer):
    client = server.make_client(max_response_bytes=4)
    with pytest.raises(ProtocolError):
        client.post("/v1/echo", body=b"this response will exceed the tiny cap")


def test_discover_fetches_config_over_mock_transport(server: MockServer):
    client = Client.discover(DEFAULT_BASE_URL, http_client=server.http_client())
    assert client.server_identity.public_key_bytes() == server.public_key_bytes
    response = client.post("/v1/echo", body=b"discovered")
    assert response.content == b"echo:discovered"


def test_discover_accepts_http_transport_by_default(server: MockServer):
    client = Client.discover("http://server.example", http_client=server.http_client())
    assert client.server_identity.public_key_bytes() == server.public_key_bytes


def test_discover_allows_insecure_when_opted_in(server: MockServer):
    client = Client.discover(
        "http://server.example", http_client=server.http_client(), allow_insecure=True
    )
    assert client.server_identity.public_key_bytes() == server.public_key_bytes


def test_server_identity_rejects_out_of_range_key_id(server: MockServer):
    with pytest.raises(InvalidConfigError):
        ServerIdentity(server.public_key_bytes, key_id=256)


def test_custom_client_cannot_reenable_redirects(server: MockServer):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/redirect":
            return httpx.Response(302, headers={"location": "https://server.example/target"})
        return httpx.Response(200, content=b"followed")

    permissive = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    client = Client(
        DEFAULT_BASE_URL,
        ServerIdentity.from_public_key_bytes(server.public_key_bytes),
        http_client=permissive,
    )
    response = client.get("/redirect")
    assert response.status_code == 302
