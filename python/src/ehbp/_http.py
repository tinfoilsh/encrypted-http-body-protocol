"""Shared wire-level helpers for the high-level client and the httpx transports.

These implement concerns that are identical whether a request is driven through
the convenience :class:`~ehbp.client.Client` or an httpx transport: building a
chunked single-frame request body, recognising the key-configuration-mismatch
problem response, and parsing the response nonce header.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import httpx

from .errors import KeyConfigMismatchError, ProtocolError
from .protocol import (
    KEY_CONFIG_PROBLEM_TYPE,
    PROBLEM_JSON_MEDIA_TYPE,
    RESPONSE_NONCE_HEADER,
    RESPONSE_NONCE_LENGTH,
)

DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024

KEY_CONFIG_MISMATCH_STATUS = 422


def single_chunk_body(body: bytes) -> Iterator[bytes]:
    # Yielding from an iterator makes httpx use chunked transfer-encoding and
    # omit Content-Length, as required for encrypted bodies (SPEC Section 4.1).
    yield body


def media_type(headers: httpx.Headers) -> str:
    raw = headers.get("content-type", "")
    return raw.split(";", 1)[0].strip().lower()


def raise_for_key_config_mismatch(status: int, headers: httpx.Headers, body: bytes) -> None:
    if status != KEY_CONFIG_MISMATCH_STATUS:
        return
    if media_type(headers) != PROBLEM_JSON_MEDIA_TYPE:
        return
    try:
        problem = json.loads(body)
    except (ValueError, TypeError):
        return
    if isinstance(problem, dict) and problem.get("type") == KEY_CONFIG_PROBLEM_TYPE:
        title = problem.get("title")
        if not isinstance(title, str):
            title = "key configuration mismatch"
        raise KeyConfigMismatchError(title)


def response_nonce(headers: httpx.Headers) -> bytes:
    values = headers.get_list(RESPONSE_NONCE_HEADER)
    if not values:
        raise ProtocolError(f"missing {RESPONSE_NONCE_HEADER} header")
    if len(values) > 1:
        raise ProtocolError(f"multiple {RESPONSE_NONCE_HEADER} headers")
    try:
        nonce = bytes.fromhex(values[0].strip())
    except ValueError as err:
        raise ProtocolError(f"invalid response nonce header: {err}") from err
    if len(nonce) != RESPONSE_NONCE_LENGTH:
        raise ProtocolError(
            f"invalid response nonce length: expected {RESPONSE_NONCE_LENGTH}, got {len(nonce)}"
        )
    return nonce
