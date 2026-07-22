"""Synchronous EHBP client transport built on httpx.

The client encrypts request bodies to the server's HPKE public key and decrypts
the bound response body. It passes through nonce-less non-success responses,
fails closed on nonce-less successes or invalid nonces, and enforces several
defensive constraints (single configured origin, no credentials in URLs,
reserved protocol headers cannot be overridden, redirects disabled, response
size capped).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Optional, Union

import httpx

from ._http import (
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_TIMEOUT,
)
from ._http import (
    raise_for_key_config_mismatch as _raise_for_key_config_mismatch,
)
from ._http import (
    response_nonce_for_status as _response_nonce_for_status,
)
from ._http import (
    single_chunk_body as _single_chunk_body,
)
from .errors import InvalidInputError, ProtocolError
from .identity import ServerIdentity
from .protocol import (
    ENCAPSULATED_KEY_HEADER,
    KEYS_MEDIA_TYPE,
    KEYS_PATH,
    RESPONSE_NONCE_HEADER,
)
from .session import SessionRecoveryToken

_RESERVED_REQUEST_HEADERS = frozenset(
    {
        "content-length",
        "transfer-encoding",
        "host",
        ENCAPSULATED_KEY_HEADER.lower(),
        RESPONSE_NONCE_HEADER.lower(),
    }
)

Body = Union[bytes, bytearray, str, None]
HeadersInput = Optional[Mapping[str, str]]


@dataclass
class Response:
    status_code: int
    headers: httpx.Headers
    content: bytes

    def text(self, encoding: str = "utf-8") -> str:
        return self.content.decode(encoding)

    def json(self) -> Any:
        return json.loads(self.content)


@dataclass
class StreamingResponse:
    status_code: int
    headers: httpx.Headers
    _chunks: Iterator[bytes]

    def __iter__(self) -> Iterator[bytes]:
        return self._chunks

    def iter_bytes(self) -> Iterator[bytes]:
        return self._chunks


class Client:
    def __init__(
        self,
        base_url: Union[str, httpx.URL],
        identity: ServerIdentity,
        *,
        http_client: Optional[httpx.Client] = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self._base_url = _normalize_base_url(base_url)
        self._identity = identity
        self._http = http_client or _default_http_client()
        self._max_response_bytes = max_response_bytes
        self._token_lock = threading.Lock()
        self._last_token: Optional[SessionRecoveryToken] = None

    @classmethod
    def discover(
        cls,
        base_url: str,
        *,
        http_client: Optional[httpx.Client] = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> Client:
        """Fetch the server key configuration and build a client."""
        base = _normalize_base_url(base_url)
        http = http_client or _default_http_client()
        response = http.get(base.join(KEYS_PATH), follow_redirects=False)
        if response.status_code // 100 != 2:
            raise ProtocolError(
                f"server returned status {response.status_code} while fetching key configuration"
            )
        content_type = response.headers.get("content-type", "")
        if content_type != KEYS_MEDIA_TYPE:
            raise ProtocolError(f"server returned invalid key content type: {content_type}")
        identity = ServerIdentity.unmarshal_public_config(response.content)
        return cls(
            base,
            identity,
            http_client=http,
            max_response_bytes=max_response_bytes,
        )

    @classmethod
    def with_config(
        cls,
        base_url: str,
        hpke_config: bytes,
        *,
        http_client: Optional[httpx.Client] = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> Client:
        identity = ServerIdentity.unmarshal_public_config(hpke_config)
        return cls(
            base_url,
            identity,
            http_client=http_client,
            max_response_bytes=max_response_bytes,
        )

    @classmethod
    def with_public_key_hex(
        cls,
        base_url: str,
        public_key_hex: str,
        *,
        http_client: Optional[httpx.Client] = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> Client:
        identity = ServerIdentity.from_public_key_hex(public_key_hex)
        return cls(
            base_url,
            identity,
            http_client=http_client,
            max_response_bytes=max_response_bytes,
        )

    @property
    def server_identity(self) -> ServerIdentity:
        return self._identity

    def get_session_recovery_token(self) -> Optional[SessionRecoveryToken]:
        with self._token_lock:
            return self._last_token

    def take_session_recovery_token(self) -> Optional[SessionRecoveryToken]:
        with self._token_lock:
            token = self._last_token
            self._last_token = None
            return token

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        body: Body = None,
        json_body: Any = None,
        headers: HeadersInput = None,
    ) -> Response:
        url = self._resolve_url(path_or_url)
        request_headers, plaintext = self._prepare_body(headers, body, json_body)
        self._set_token(None)
        encrypted = self._identity.encrypt_request_body(plaintext)

        if encrypted is None:
            with self._http.stream(
                method, url, headers=request_headers, content=None, follow_redirects=False
            ) as resp:
                raw = self._read_body_capped(resp)
                return Response(resp.status_code, resp.headers, raw)

        request_headers[ENCAPSULATED_KEY_HEADER] = encrypted.encapsulated_key.hex()
        token = encrypted.token
        self._set_token(token)
        try:
            with self._http.stream(
                method,
                url,
                headers=request_headers,
                content=_single_chunk_body(encrypted.body),
                follow_redirects=False,
            ) as resp:
                status = resp.status_code
                response_headers = resp.headers
                raw = self._read_body_capped(resp)
            _raise_for_key_config_mismatch(status, response_headers, raw)
            response_nonce = _response_nonce_for_status(status, response_headers)
            if response_nonce is None:
                self._clear_token_if_current(token)
                return Response(status, response_headers, raw)
            decrypted = token.decrypt_response_body(response_nonce, raw)
        except BaseException:
            self._clear_token_if_current(token)
            raise
        return Response(status, response_headers, decrypted)

    def get(self, path_or_url: str, *, headers: HeadersInput = None) -> Response:
        return self.request("GET", path_or_url, headers=headers)

    def delete(self, path_or_url: str, *, headers: HeadersInput = None) -> Response:
        return self.request("DELETE", path_or_url, headers=headers)

    def post(
        self,
        path_or_url: str,
        *,
        body: Body = None,
        json_body: Any = None,
        headers: HeadersInput = None,
    ) -> Response:
        return self.request("POST", path_or_url, body=body, json_body=json_body, headers=headers)

    def put(
        self,
        path_or_url: str,
        *,
        body: Body = None,
        json_body: Any = None,
        headers: HeadersInput = None,
    ) -> Response:
        return self.request("PUT", path_or_url, body=body, json_body=json_body, headers=headers)

    @contextmanager
    def stream(
        self,
        method: str,
        path_or_url: str,
        *,
        body: Body = None,
        json_body: Any = None,
        headers: HeadersInput = None,
    ) -> Iterator[StreamingResponse]:
        url = self._resolve_url(path_or_url)
        request_headers, plaintext = self._prepare_body(headers, body, json_body)
        self._set_token(None)
        encrypted = self._identity.encrypt_request_body(plaintext)

        if encrypted is None:
            with self._http.stream(
                method, url, headers=request_headers, content=None, follow_redirects=False
            ) as resp:
                yield StreamingResponse(resp.status_code, resp.headers, resp.iter_bytes())
            return

        request_headers[ENCAPSULATED_KEY_HEADER] = encrypted.encapsulated_key.hex()
        token = encrypted.token
        self._set_token(token)
        try:
            with self._http.stream(
                method,
                url,
                headers=request_headers,
                content=_single_chunk_body(encrypted.body),
                follow_redirects=False,
            ) as resp:
                status = resp.status_code
                response_headers = resp.headers
                if RESPONSE_NONCE_HEADER not in response_headers:
                    raw = self._read_body_capped(resp)
                    self._clear_token_if_current(token)
                    _raise_for_key_config_mismatch(status, response_headers, raw)
                    response_nonce = _response_nonce_for_status(status, response_headers)
                    if response_nonce is None:
                        yield StreamingResponse(status, response_headers, iter((raw,)))
                        return
                else:
                    response_nonce = _response_nonce_for_status(status, response_headers)
                assert response_nonce is not None
                yield StreamingResponse(
                    status,
                    response_headers,
                    self._decrypt_stream(resp, token, response_nonce),
                )
        except BaseException:
            self._clear_token_if_current(token)
            raise

    def _decrypt_stream(
        self, resp: httpx.Response, token: SessionRecoveryToken, response_nonce: bytes
    ) -> Iterator[bytes]:
        decryptor = token.create_response_decryptor(
            response_nonce, max_chunk_length=self._max_response_bytes
        )
        try:
            for chunk in resp.iter_bytes():
                yield from decryptor.push(chunk)
            decryptor.finish()
        except BaseException:
            self._clear_token_if_current(token)
            raise

    def _prepare_body(
        self, headers: HeadersInput, body: Body, json_body: Any
    ) -> tuple[httpx.Headers, bytes]:
        request_headers = self._prepare_headers(headers)
        if json_body is not None:
            if body is not None:
                raise InvalidInputError("provide either body or json_body, not both")
            request_headers["content-type"] = "application/json"
            return request_headers, json.dumps(json_body).encode("utf-8")
        return request_headers, _as_bytes(body)

    def _prepare_headers(self, headers: HeadersInput) -> httpx.Headers:
        prepared = httpx.Headers(headers or {})
        for name in prepared:
            if name.lower() in _RESERVED_REQUEST_HEADERS:
                raise InvalidInputError(
                    f"reserved request header cannot be set by callers: {name}"
                )
        return prepared

    def _read_body_capped(self, resp: httpx.Response) -> bytes:
        chunks = []
        total = 0
        for chunk in resp.iter_bytes():
            total += len(chunk)
            if total > self._max_response_bytes:
                raise ProtocolError("response body exceeds maximum allowed size")
            chunks.append(chunk)
        return b"".join(chunks)

    def _resolve_url(self, path_or_url: str) -> httpx.URL:
        url = self._base_url.join(path_or_url)
        if not _same_origin(self._base_url, url):
            raise InvalidInputError(
                f"request URL must use the configured origin: "
                f"{self._base_url.scheme}://{self._base_url.netloc.decode('ascii')}"
            )
        if url.username or url.password:
            raise InvalidInputError("request URL must not include credentials")
        return url

    def _set_token(self, token: Optional[SessionRecoveryToken]) -> None:
        with self._token_lock:
            self._last_token = token

    def _clear_token_if_current(self, token: SessionRecoveryToken) -> None:
        with self._token_lock:
            if self._last_token == token:
                self._last_token = None


def _default_http_client() -> httpx.Client:
    return httpx.Client(follow_redirects=False, timeout=DEFAULT_TIMEOUT)


def _as_bytes(body: Body) -> bytes:
    if body is None:
        return b""
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    raise InvalidInputError("body must be bytes, str, or None")


def _normalize_base_url(raw: Union[str, httpx.URL]) -> httpx.URL:
    url = httpx.URL(raw)
    if not url.host:
        raise InvalidInputError("base URL must include an HTTP origin")
    if url.username or url.password:
        raise InvalidInputError("base URL must not include credentials")
    if url.scheme not in ("http", "https"):
        raise InvalidInputError("base URL scheme must be http or https")
    path = url.path or "/"
    if not path.endswith("/"):
        path = path + "/"
    return httpx.URL(scheme=url.scheme, host=url.host, port=url.port, path=path)


def _origin(url: httpx.URL) -> tuple[str, Optional[str], int]:
    port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
    return (url.scheme, url.host, port)


def _same_origin(left: httpx.URL, right: httpx.URL) -> bool:
    return _origin(left) == _origin(right)
