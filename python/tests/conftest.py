"""Shared test fixtures, including an in-process EHBP mock server.

The mock server implements the server half of the protocol (HPKE recipient and
response encryption) so the client can be exercised end-to-end over
``httpx.MockTransport`` without real sockets or TLS. Protocol edge cases live
in the conformance fixtures; these tests cover the httpx surface only.
"""

import os
import struct
from typing import Optional

import httpx
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from ehbp import Client, PublicKey, core
from ehbp.protocol import (
    AEAD_AES_256_GCM,
    ENCAPSULATED_KEY_HEADER,
    EXPORT_LABEL,
    EXPORT_LENGTH,
    HPKE_REQUEST_INFO,
    KDF_HKDF_SHA256,
    KEM_X25519_HKDF_SHA256,
    KEY_ID,
    KEYS_MEDIA_TYPE,
    KEYS_PATH,
    LENGTH_PREFIX_SIZE,
    RESPONSE_NONCE_HEADER,
    RESPONSE_NONCE_LENGTH,
)

DEFAULT_BASE_URL = "https://server.example/"


class MockServer:
    def __init__(self, *, chunk_size: Optional[int] = None) -> None:
        self.suite = CipherSuite.new(
            KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
        )
        self.keypair = self.suite.kem.derive_key_pair(b"ehbp-python-test-server-ikm-0001")
        self.public_key_bytes = self.keypair.public_key.to_public_bytes()
        self.chunk_size = chunk_size
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
        return bytes(plaintext), recipient.export(EXPORT_LABEL, EXPORT_LENGTH)

    def _encrypt_response(
        self, exported: bytes, enc: bytes, plaintext: bytes
    ) -> "tuple[bytes, bytes]":
        response_nonce = os.urandom(RESPONSE_NONCE_LENGTH)
        key, nonce_base = core.derive_keys(exported, enc, response_nonce)
        size = self.chunk_size or max(len(plaintext), 1)
        framed = bytearray()
        for seq, start in enumerate(range(0, len(plaintext), size)):
            chunk = plaintext[start : start + size]
            sealed = AESGCM(key).encrypt(core.nonce_for(nonce_base, seq), chunk, b"")
            framed += struct.pack(">I", len(sealed)) + sealed
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
        response_nonce, framed = self._encrypt_response(exported, enc, b"echo:" + request_plaintext)
        headers = {RESPONSE_NONCE_HEADER: response_nonce.hex()}
        return httpx.Response(200, headers=headers, content=framed)

    def http_client(self, handler=None) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(handler or self.handler))

    def make_client(self, http_client: Optional[httpx.Client] = None) -> Client:
        http_client = http_client or self.http_client()
        return Client(DEFAULT_BASE_URL, PublicKey(self.public_key_bytes), http_client=http_client)


@pytest.fixture
def make_server():
    return lambda **kwargs: MockServer(**kwargs)


@pytest.fixture
def server() -> MockServer:
    return MockServer()
