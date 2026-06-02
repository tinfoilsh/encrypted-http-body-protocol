"""Interop tests against the shared cross-language test vectors."""

import json
from pathlib import Path

import pytest

from ehbp import (
    ServerIdentity,
    SessionRecoveryToken,
    derive_response_keys,
)
from ehbp.errors import InvalidInputError
from ehbp.protocol import (
    AEAD_AES_256_GCM,
    KDF_HKDF_SHA256,
    KEM_X25519_HKDF_SHA256,
    KEY_ID,
)

VECTORS = Path(__file__).resolve().parents[2] / "test-vectors"


def _load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text())


def test_derive_matches_shared_vector():
    vector = _load("derive.json")
    key_material = derive_response_keys(
        bytes.fromhex(vector["exportedSecret"]),
        bytes.fromhex(vector["requestEnc"]),
        bytes.fromhex(vector["responseNonce"]),
    )
    assert key_material.key.hex() == vector["derivedKey"]
    assert key_material.nonce_base.hex() == vector["derivedNonceBase"]


def test_decrypt_response_matches_shared_vector():
    vector = _load("response-decryption.json")
    token = SessionRecoveryToken(
        bytes.fromhex(vector["exportedSecret"]),
        bytes.fromhex(vector["requestEnc"]),
    )
    plaintext = token.decrypt_response_body(
        bytes.fromhex(vector["responseNonce"]),
        bytes.fromhex(vector["encryptedResponse"]),
    )
    assert plaintext.hex() == vector["plaintext"]


def test_session_recovery_token_json_shape():
    vector = _load("session-recovery-token.json")
    token = SessionRecoveryToken.from_dict(vector)
    assert json.loads(token.to_json()) == vector


def test_session_recovery_token_rejects_malformed_json():
    with pytest.raises(InvalidInputError):
        SessionRecoveryToken.from_json("{")


def _build_config(public_key: bytes) -> bytes:
    config = bytearray()
    config.append(KEY_ID)
    config += KEM_X25519_HKDF_SHA256.to_bytes(2, "big")
    config += public_key
    config += (4).to_bytes(2, "big")
    config += KDF_HKDF_SHA256.to_bytes(2, "big")
    config += AEAD_AES_256_GCM.to_bytes(2, "big")
    return bytes(config)


def test_parse_and_marshal_public_config():
    public_key = bytes([7]) * 32
    config = _build_config(public_key)
    identity = ServerIdentity.unmarshal_public_config(config)
    assert identity.public_key_bytes() == public_key
    assert identity.marshal_public_config() == config


def test_parses_first_config_and_ignores_additional():
    first = bytes([7]) * 32
    second = bytes([8]) * 32
    config = _build_config(first) + _build_config(second)
    identity = ServerIdentity.unmarshal_public_config(config)
    assert identity.public_key_bytes() == first
