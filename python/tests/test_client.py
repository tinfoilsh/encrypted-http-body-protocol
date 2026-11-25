"""The httpx surface of the client against the in-process mock server: the
public API, streaming, the token lifecycle through it and concurrency. The
protocol itself is covered by the conformance fixtures."""

import io
import threading

import httpx
import pytest

from conftest import DEFAULT_BASE_URL, MockServer
from ehbp import Client, Config, Discover, core, discover
from ehbp.errors import FramingTruncatedError, InvalidInputError
from ehbp.protocol import RESPONSE_NONCE_HEADER


def test_encrypted_round_trip(server: MockServer):
    response = server.make_client().request("POST", "/v1/echo", body=b"hello world")
    assert response.status_code == 200
    assert response.read() == b"echo:hello world"


def test_streaming_round_trip_decrypts_frame_by_frame(make_server):
    server = make_server(chunk_size=4)
    client = server.make_client()
    response = client.request("POST", "/v1/echo", body=b"streamed payload")
    assert b"".join(response) == b"echo:streamed payload"
    assert client.session_recovery_token() is None


def test_file_body_is_stream_encrypted(server: MockServer):
    response = server.make_client().request("POST", "/v1/echo", body=io.BytesIO(b"from a file"))
    assert response.read() == b"echo:from a file"


def test_encrypted_body_uses_chunked_transfer_without_content_length(server: MockServer):
    server.make_client().request("POST", "/v1/echo", body=b"payload").read()
    headers = server.last_request.headers
    assert "content-length" not in headers
    assert headers.get("transfer-encoding") == "chunked"


def test_token_is_readable_until_the_response_is_consumed(make_server):
    server = make_server(chunk_size=4)
    client = server.make_client()
    response = client.request("POST", "/v1/echo", body=b"payload")
    token = client.session_recovery_token()
    assert token is not None
    assert token.request_enc.hex() == server.last_request.headers["ehbp-encapsulated-key"]
    assert core.parse_token(token.json) == token
    with pytest.raises(InvalidInputError):
        core.nonce_for(b"\0" * 12, -1)
    assert response.read() == b"echo:payload"
    assert client.session_recovery_token() is None


def test_closing_a_partly_read_response_consumes_the_token(make_server):
    server = make_server(chunk_size=4)
    client = server.make_client()
    response = client.request("POST", "/v1/echo", body=b"payload")
    next(iter(response))
    assert client.session_recovery_token() is not None
    response.close()
    assert client.session_recovery_token() is None


def test_closing_an_unread_response_consumes_the_token(server: MockServer):
    client = server.make_client()
    response = client.request("POST", "/v1/echo", body=b"payload")
    assert client.session_recovery_token() is not None
    response.close()
    assert client.session_recovery_token() is None


def test_older_response_completion_does_not_clear_newer_token(make_server):
    server = make_server(chunk_size=4)
    client = server.make_client()
    older = client.request("POST", "/v1/echo", body=b"older")
    newer = client.request("POST", "/v1/echo", body=b"newer")
    newer_token = client.session_recovery_token()
    assert newer_token is not None
    assert older.read() == b"echo:older"
    assert client.session_recovery_token() == newer_token
    assert newer.read() == b"echo:newer"
    assert client.session_recovery_token() is None


@pytest.mark.parametrize("older_outcome", ["success", "error"])
def test_older_request_cannot_publish_or_clear_newer_recovery_token(make_server, older_outcome):
    server = make_server(chunk_size=4)
    older_encryption_started = threading.Event()
    release_older_encryption = threading.Event()
    older_request_started = threading.Event()
    release_older_request = threading.Event()
    newer_request_started = threading.Event()
    release_newer_request = threading.Event()

    def older_body():
        # Read after the older request's generation began and before its token exists.
        older_encryption_started.set()
        assert release_older_encryption.wait(5)
        yield b"older"

    def handler(request):
        if request.url.path == "/older":
            older_request_started.set()
            assert release_older_request.wait(5)
            if older_outcome == "error":
                raise RuntimeError("older request failed")
        else:
            newer_request_started.set()
            assert release_newer_request.wait(5)
        return server.handler(request)

    client = server.make_client(server.http_client(handler))
    errors = []

    def run(path, body):
        try:
            client.request("POST", path, body=body).read()
        except BaseException as error:
            errors.append(error)

    older_thread = threading.Thread(target=run, args=("/older", older_body()), daemon=True)
    newer_thread = threading.Thread(target=run, args=("/newer", b"newer"), daemon=True)
    try:
        older_thread.start()
        assert older_encryption_started.wait(5)
        newer_thread.start()
        assert newer_request_started.wait(5)
        newer_token = client.session_recovery_token()
        assert newer_token is not None

        release_older_encryption.set()
        assert older_request_started.wait(5)
        assert client.session_recovery_token() == newer_token

        release_older_request.set()
        older_thread.join(5)
        assert not older_thread.is_alive()
        assert client.session_recovery_token() == newer_token
    finally:
        release_older_encryption.set()
        release_older_request.set()
        release_newer_request.set()
        older_thread.join(5)
        newer_thread.join(5)

    assert not newer_thread.is_alive()
    expected = ["older request failed"] if older_outcome == "error" else []
    assert [str(e) for e in errors] == expected
    assert client.session_recovery_token() is None


def test_transport_failure_mid_frame_is_framing_truncated(server: MockServer):
    class Broken(httpx.SyncByteStream):
        def __iter__(self):
            yield b"\x00\x00\x00\x10\xaa"
            raise httpx.ReadError("connection reset")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={RESPONSE_NONCE_HEADER: "00" * 32}, stream=Broken())

    client = server.make_client(server.http_client(handler))
    with pytest.raises(FramingTruncatedError):
        client.request("POST", "/v1/echo", body=b"payload").read()
    assert client.session_recovery_token() is None


def test_discover_and_config_keys(server: MockServer):
    key = discover(DEFAULT_BASE_URL, http_client=server.http_client())
    assert key == server.public_key_bytes
    client = Client(DEFAULT_BASE_URL, Discover, http_client=server.http_client())
    assert client.request("POST", "/v1/echo", body=b"discovered").read() == b"echo:discovered"
    config = Config(server.config_bytes())
    client = Client(DEFAULT_BASE_URL, config, http_client=server.http_client())
    assert client.request("POST", "/v1/echo", body=b"configured").read() == b"echo:configured"


def test_custom_client_cannot_reenable_redirects(server: MockServer):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/redirect":
            return httpx.Response(302, headers={"location": "https://server.example/target"})
        return httpx.Response(200, content=b"followed")

    permissive = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    client = server.make_client(permissive)
    assert client.request("GET", "/redirect").status_code == 302


def test_bytes_body_is_sealed_lazily(server: MockServer, monkeypatch):
    from ehbp import _residue

    seals, seen_at_wire = [], []
    original = _residue.aead_seal
    def counting_seal(key, nonce, plaintext):
        seals.append(len(plaintext))
        return original(key, nonce, plaintext)

    monkeypatch.setattr(_residue, "aead_seal", counting_seal)

    class Inner(httpx.BaseTransport):
        def handle_request(self, request):
            body = bytearray()
            for chunk in request.stream:
                seen_at_wire.append(len(seals))
                body += chunk
            headers = httpx.Headers(request.headers)
            del headers["transfer-encoding"]
            return server.handler(
                httpx.Request(request.method, request.url, headers=headers, content=bytes(body))
            )

    client = server.make_client(httpx.Client(transport=Inner()))
    payload = bytes(range(256)) * 800  # 200 KiB -> 4 frames
    assert client.request("POST", "/v1/echo", body=payload).read() == b"echo:" + payload
    assert len(seals) == 4
    # Only one frame had been sealed when the first one went out: no up-front copy.
    assert seen_at_wire[0] == 1
