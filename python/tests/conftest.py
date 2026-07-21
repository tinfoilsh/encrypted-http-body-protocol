"""Shared test fixtures, including an in-process EHBP mock server.

The mock server implements the server half of the protocol (HPKE recipient and
response encryption) so the client can be exercised end-to-end over
``httpx.MockTransport`` without real sockets or TLS.
"""

import json
import os
import struct
from typing import Optional

import httpx
import pytest
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from ehbp import Client, ServerIdentity
from ehbp.derive import derive_response_keys, encrypt_chunk, frame_chunk
from ehbp.protocol import (
    AEAD_AES_256_GCM,
    ENCAPSULATED_KEY_HEADER,
    EXPORT_LABEL,
    EXPORT_LENGTH,
    HPKE_REQUEST_INFO,
    KDF_HKDF_SHA256,
    KEM_X25519_HKDF_SHA256,
    KEY_CONFIG_PROBLEM_TYPE,
    KEY_ID,
    KEYS_MEDIA_TYPE,
    KEYS_PATH,
    LENGTH_PREFIX_SIZE,
    PROBLEM_JSON_MEDIA_TYPE,
    RESPONSE_NONCE_HEADER,
    RESPONSE_NONCE_LENGTH,
)

DEFAULT_BASE_URL = "https://server.example/"


def _new_suite() -> CipherSuite:
    return CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
    )


class MockServer:
    def __init__(
        self, *, mode: str = "ok", chunk_size: Optional[int] = None, status_code: int = 200
    ) -> None:
        self.suite = _new_suite()
        self.keypair = self.suite.kem.derive_key_pair(b"ehbp-python-test-server-ikm-0001")
        self.public_key_bytes = self.keypair.public_key.to_public_bytes()
        self.mode = mode
        self.chunk_size = chunk_size
        self.status_code = status_code
        self.last_request: Optional[httpx.Request] = None

    def config_bytes(self) -> bytes:
        config = bytearray([KEY_ID])
        config += KEM_X25519_HKDF_SHA256.to_bytes(2, "big")
        config += self.public_key_bytes
        config += (4).to_bytes(2, "big")
        config += KDF_HKDF_SHA256.to_bytes(2, "big")
        config += AEAD_AES_256_GCM.to_bytes(2, "big")
        return bytes(config)

    def _open_request(self, enc: bytes, body: bytes) -> "tuple[bytes, bytes]":
        recipient = self.suite.create_recipient_context(
            enc, self.keypair.private_key, info=HPKE_REQUEST_INFO
        )
        plaintext = bytearray()
        offset = 0
        while offset < len(body):
            (chunk_len,) = struct.unpack_from(">I", body, offset)
            offset += LENGTH_PREFIX_SIZE
            if chunk_len == 0:
                continue
            plaintext += recipient.open(bytes(body[offset : offset + chunk_len]), b"")
            offset += chunk_len
        exported = recipient.export(EXPORT_LABEL, EXPORT_LENGTH)
        return bytes(plaintext), exported

    def _encrypt_response(
        self, exported: bytes, enc: bytes, plaintext: bytes
    ) -> "tuple[bytes, bytes]":
        response_nonce = os.urandom(RESPONSE_NONCE_LENGTH)
        key_material = derive_response_keys(exported, enc, response_nonce)
        size = self.chunk_size or max(len(plaintext), 1)
        framed = bytearray()
        seq = 0
        for start in range(0, len(plaintext), size):
            framed += frame_chunk(encrypt_chunk(key_material, seq, plaintext[start : start + size]))
            seq += 1
        return response_nonce, bytes(framed)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.last_request = request
        if request.url.path == KEYS_PATH:
            return httpx.Response(
                200, headers={"content-type": KEYS_MEDIA_TYPE}, content=self.config_bytes()
            )

        enc_hex = request.headers.get(ENCAPSULATED_KEY_HEADER)
        body = request.read()
        if not enc_hex:
            return httpx.Response(200, content=b"plaintext ok")

        enc = bytes.fromhex(enc_hex)
        request_plaintext, exported = self._open_request(enc, body)

        if self.mode == "unencrypted_response":
            return httpx.Response(
                self.status_code,
                headers={"content-type": "text/plain", "x-upstream": "proxy"},
                content=b"upstream unavailable",
            )

        if self.mode == "key_config_mismatch":
            problem = {"type": KEY_CONFIG_PROBLEM_TYPE, "title": "stale key configuration"}
            return httpx.Response(
                422,
                headers={"content-type": PROBLEM_JSON_MEDIA_TYPE},
                content=json.dumps(problem).encode("utf-8"),
            )

        response_plaintext = b"echo:" + request_plaintext
        response_nonce, framed = self._encrypt_response(exported, enc, response_plaintext)
        headers = {}
        if self.mode != "strip_nonce":
            headers[RESPONSE_NONCE_HEADER] = response_nonce.hex()
        return httpx.Response(self.status_code, headers=headers, content=framed)

    def http_client(self) -> httpx.Client:
        return httpx.Client(
            transport=httpx.MockTransport(self.handler), follow_redirects=False
        )

    def make_client(self, base_url: str = DEFAULT_BASE_URL, **kwargs) -> Client:
        return Client(
            base_url,
            ServerIdentity.from_public_key_bytes(self.public_key_bytes),
            http_client=self.http_client(),
            **kwargs,
        )


@pytest.fixture
def make_server():
    def _factory(
        *, mode: str = "ok", chunk_size: Optional[int] = None, status_code: int = 200
    ) -> MockServer:
        return MockServer(mode=mode, chunk_size=chunk_size, status_code=status_code)

    return _factory


@pytest.fixture
def server(make_server) -> MockServer:
    return make_server()
