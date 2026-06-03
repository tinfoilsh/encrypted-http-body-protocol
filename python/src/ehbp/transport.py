"""Drop-in httpx transports that encrypt request bodies and decrypt responses.

These let any httpx-based client (for example the OpenAI SDK) speak EHBP by
wrapping an existing inner transport::

    identity = ServerIdentity.from_public_key_hex(attested_hpke_key_hex)
    transport = EHBPTransport(identity, inner=tls_pinned_transport)
    client = httpx.Client(transport=transport)

Request bodies are sealed to the server's HPKE public key; bodyless requests
pass through unchanged. Responses are decrypted lazily so server-sent event
streams work without buffering.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Optional, cast

import httpx

from ._http import (
    DEFAULT_MAX_RESPONSE_BYTES,
    raise_for_key_config_mismatch,
    response_nonce,
    single_chunk_body,
)
from .derive import FrameDecryptor, derive_response_keys
from .errors import ProtocolError
from .identity import ServerIdentity
from .protocol import ENCAPSULATED_KEY_HEADER, RESPONSE_NONCE_HEADER
from .session import SessionRecoveryToken

_FRAMING_HEADERS = ("content-length", "transfer-encoding")


async def _single_chunk_body_async(body: bytes) -> AsyncIterator[bytes]:
    yield body


def _read_capped(stream: httpx.SyncByteStream, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in stream:
        total += len(chunk)
        if total > max_bytes:
            raise ProtocolError("response body exceeds maximum allowed size")
        chunks.append(chunk)
    return b"".join(chunks)


async def _aread_capped(stream: httpx.AsyncByteStream, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in stream:
        total += len(chunk)
        if total > max_bytes:
            raise ProtocolError("response body exceeds maximum allowed size")
        chunks.append(chunk)
    return b"".join(chunks)


def _encrypted_headers(request: httpx.Request, encapsulated_key: bytes) -> httpx.Headers:
    headers = httpx.Headers(request.headers)
    for name in _FRAMING_HEADERS:
        if name in headers:
            del headers[name]
    headers[ENCAPSULATED_KEY_HEADER] = encapsulated_key.hex()
    return headers


def _decrypted_headers(response: httpx.Response) -> httpx.Headers:
    headers = httpx.Headers(response.headers)
    # The decrypted body length differs from the encrypted Content-Length, so
    # drop it and let the end of the stream delimit the body.
    if "content-length" in headers:
        del headers["content-length"]
    return headers


def _make_decryptor(
    token: SessionRecoveryToken, nonce: bytes, max_bytes: int
) -> FrameDecryptor:
    key_material = derive_response_keys(token.exported_secret, token.request_enc, nonce)
    return FrameDecryptor(key_material, max_bytes)


class _DecryptingByteStream(httpx.SyncByteStream):
    def __init__(self, response: httpx.Response, decryptor: FrameDecryptor) -> None:
        self._response = response
        self._decryptor = decryptor

    def __iter__(self) -> Iterator[bytes]:
        try:
            for chunk in cast(httpx.SyncByteStream, self._response.stream):
                yield from self._decryptor.push(chunk)
            self._decryptor.finish()
        finally:
            self._response.close()

    def close(self) -> None:
        self._response.close()


class _AsyncDecryptingByteStream(httpx.AsyncByteStream):
    def __init__(self, response: httpx.Response, decryptor: FrameDecryptor) -> None:
        self._response = response
        self._decryptor = decryptor

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in cast(httpx.AsyncByteStream, self._response.stream):
                for plaintext in self._decryptor.push(chunk):
                    yield plaintext
            self._decryptor.finish()
        finally:
            await self._response.aclose()

    async def aclose(self) -> None:
        await self._response.aclose()


class EHBPTransport(httpx.BaseTransport):
    """A synchronous httpx transport that speaks EHBP over an inner transport."""

    def __init__(
        self,
        identity: ServerIdentity,
        *,
        inner: Optional[httpx.BaseTransport] = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self._identity = identity
        self._inner = inner if inner is not None else httpx.HTTPTransport()
        self._max_response_bytes = max_response_bytes

    @classmethod
    def from_public_key_hex(
        cls,
        public_key_hex: str,
        *,
        inner: Optional[httpx.BaseTransport] = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> EHBPTransport:
        return cls(
            ServerIdentity.from_public_key_hex(public_key_hex),
            inner=inner,
            max_response_bytes=max_response_bytes,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        plaintext = request.read()
        encrypted = self._identity.encrypt_request_body(plaintext)
        if encrypted is None:
            return self._inner.handle_request(request)

        enc_request = httpx.Request(
            method=request.method,
            url=request.url,
            headers=_encrypted_headers(request, encrypted.encapsulated_key),
            content=single_chunk_body(encrypted.body),
            extensions=request.extensions,
        )
        response = self._inner.handle_request(enc_request)
        return self._decrypt_response(response, encrypted.token)

    def _decrypt_response(
        self, response: httpx.Response, token: SessionRecoveryToken
    ) -> httpx.Response:
        if RESPONSE_NONCE_HEADER not in response.headers:
            try:
                body = _read_capped(
                    cast(httpx.SyncByteStream, response.stream), self._max_response_bytes
                )
            finally:
                response.close()
            raise_for_key_config_mismatch(response.status_code, response.headers, body)
            raise ProtocolError(f"missing {RESPONSE_NONCE_HEADER} header")

        nonce = response_nonce(response.headers)
        decryptor = _make_decryptor(token, nonce, self._max_response_bytes)
        return httpx.Response(
            status_code=response.status_code,
            headers=_decrypted_headers(response),
            stream=_DecryptingByteStream(response, decryptor),
            extensions=response.extensions,
        )

    def close(self) -> None:
        self._inner.close()


class AsyncEHBPTransport(httpx.AsyncBaseTransport):
    """An asynchronous httpx transport that speaks EHBP over an inner transport."""

    def __init__(
        self,
        identity: ServerIdentity,
        *,
        inner: Optional[httpx.AsyncBaseTransport] = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self._identity = identity
        self._inner = inner if inner is not None else httpx.AsyncHTTPTransport()
        self._max_response_bytes = max_response_bytes

    @classmethod
    def from_public_key_hex(
        cls,
        public_key_hex: str,
        *,
        inner: Optional[httpx.AsyncBaseTransport] = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> AsyncEHBPTransport:
        return cls(
            ServerIdentity.from_public_key_hex(public_key_hex),
            inner=inner,
            max_response_bytes=max_response_bytes,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        plaintext = await request.aread()
        encrypted = self._identity.encrypt_request_body(plaintext)
        if encrypted is None:
            return await self._inner.handle_async_request(request)

        enc_request = httpx.Request(
            method=request.method,
            url=request.url,
            headers=_encrypted_headers(request, encrypted.encapsulated_key),
            content=_single_chunk_body_async(encrypted.body),
            extensions=request.extensions,
        )
        response = await self._inner.handle_async_request(enc_request)
        return await self._decrypt_response(response, encrypted.token)

    async def _decrypt_response(
        self, response: httpx.Response, token: SessionRecoveryToken
    ) -> httpx.Response:
        if RESPONSE_NONCE_HEADER not in response.headers:
            try:
                body = await _aread_capped(
                    cast(httpx.AsyncByteStream, response.stream), self._max_response_bytes
                )
            finally:
                await response.aclose()
            raise_for_key_config_mismatch(response.status_code, response.headers, body)
            raise ProtocolError(f"missing {RESPONSE_NONCE_HEADER} header")

        nonce = response_nonce(response.headers)
        decryptor = _make_decryptor(token, nonce, self._max_response_bytes)
        return httpx.Response(
            status_code=response.status_code,
            headers=_decrypted_headers(response),
            stream=_AsyncDecryptingByteStream(response, decryptor),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()
