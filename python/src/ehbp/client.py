"""Synchronous EHBP client: the API shim over the event-driven Dafny core.

Every protocol decision is made by the core (dafny/ehbp_events.dfy); this
module only hands it the caller's values and drives it through the pump in
:mod:`ehbp._residue` (handler.md section 7).
"""

from __future__ import annotations

import io
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from itertools import chain
from typing import IO, Optional, Union

import httpx

from . import _residue as r
from . import identity
from ._gen import EHBP
from ._gen import EHBPEvents as ev
from .errors import InvalidInputError

DEFAULT_TIMEOUT = 30.0

# bytes-like is buffered; an iterable of bytes or a binary file is
# stream-encrypted frame by frame without ever being held in memory.
Body = Union[bytes, bytearray, Iterable[bytes], IO[bytes], None]

# constructor: a Client over one server origin and the key a KeySource yields.


class Discover:
    """Fetch the server's key configuration from /.well-known/hpke-keys."""


@dataclass(frozen=True)
class Config:
    """An RFC 9458 key configuration."""

    data: bytes


@dataclass(frozen=True)
class PublicKey:
    """The server's 32-byte X25519 public key."""

    data: bytes


Keys = Union[type[Discover], Discover, Config, PublicKey]


class Client:
    def __init__(
        self, server: str, keys: Keys, *, http_client: Optional[httpx.Client] = None
    ) -> None:
        self._base_url, self._origin = _parse_base(server)
        self._http = http_client or httpx.Client(follow_redirects=False, timeout=DEFAULT_TIMEOUT)
        if isinstance(keys, Config):
            self._public_key = identity.parse_config(keys.data)
        elif isinstance(keys, PublicKey):
            self._public_key = identity.check_public_key(keys.data)
        elif keys is Discover or isinstance(keys, Discover):
            self._public_key = discover(server, http_client=self._http)
        else:
            raise InvalidInputError("keys must be Discover, Config(bytes) or PublicKey(bytes)")
        self._session = r.Session()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


    # token: the exchange in flight.

    def session_recovery_token(self) -> Optional[identity.SessionRecoveryToken]:
        """The token of the exchange in flight, or None (SPEC 6)."""
        token = self._session.token()
        if token is None:
            return None
        return identity.SessionRecoveryToken(r.bytes_(token.exportedSecret), r.bytes_(token.requestEnc))


    # request: the one entry point; the core validates, seals, classifies and decrypts.

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        body: Body = None,
    ) -> Response:
        """Send a request; the response body decrypts as it is iterated or read.

        The ``http_client``'s read timeout is an idle timeout: it bounds each
        gap between response chunks, not the whole response.
        """
        u = self._base_url.join(path)
        chunks = _as_chunks(body)
        start = ev.Event_Start(
            r.str_(method), r.str_(str(u)), r.str_(u.scheme), r.str_(u.host),
            u.port or 0, u.port is not None, bool(u.username or u.password),
            r.header_seq(list((headers or {}).items())), chunks is not None,
        )
        initial = ev.default__.Initial(self._origin, r.seq(self._public_key))
        x = r.Exchange(initial, self._session, self._http, chunks)
        r.feed(x, start)
        if x.failure is not None:
            raise x.failure
        body_iter = chain([x.prefix], x.chunks) if x.passthrough else identity.decrypted_body(x)
        return Response(x, body_iter)


class Response:
    """The response; its body is decrypted (or passed through) as it is read.
    Reading to the end, a failure or ``close`` ends the exchange (SPEC 6.3)."""

    def __init__(self, x: r.Exchange, body: Iterator[bytes]) -> None:
        self.status_code, self.headers = x.status, httpx.Headers(x.headers)
        self._x: Optional[r.Exchange] = x
        self._body = self._closing(body)

    def _closing(self, body: Iterator[bytes]) -> Iterator[bytes]:
        try:
            yield from body
        finally:
            self.close()

    def __iter__(self) -> Iterator[bytes]:
        return self._body

    def read(self) -> bytes:
        return b"".join(self)

    def close(self) -> None:
        if self._x is not None:
            x, self._x = self._x, None
            r.feed(x, ev.Event_CallerClose())


def _as_chunks(body: Body) -> Optional[Iterator[bytes]]:
    """The caller's body as the residue's source: bytes buffered, a file or iterable pulled frame by frame."""
    if body is None:
        return None
    if isinstance(body, (bytes, bytearray)):
        body = io.BytesIO(body)
    read = getattr(body, "read", None)
    if callable(read):
        return iter(lambda: read(EHBP.default__.RequestFrameBytes), b"")
    if isinstance(body, Iterable):
        return iter(body)
    raise InvalidInputError("body must be bytes, an iterable of bytes, a binary file, or None")


def _parse_base(raw: str) -> tuple[httpx.URL, EHBP.Origin]:
    """Hands the parsed parts of ``raw`` to the core, which validates them."""
    u = httpx.URL(raw)
    port = EHBP.Option_Some(u.port) if u.port is not None else EHBP.Option_None()
    origin = r.unwrap(EHBP.default__.MakeOrigin(r.str_(u.scheme), r.str_(u.host), port, bool(u.username or u.password)))
    path = u.path if u.path.endswith("/") else u.path + "/"
    return httpx.URL(scheme=u.scheme, host=u.host, port=u.port, path=path), origin


# discover: the same discovery the constructor runs; the 32-byte public key.


def discover(server: str, *, http_client: Optional[httpx.Client] = None) -> bytes:
    """Fetch the server key configuration (SPEC 3.1); the 32-byte key to build a Client with."""
    _, origin = _parse_base(server)
    http = http_client or httpx.Client(follow_redirects=False, timeout=DEFAULT_TIMEOUT)
    x = r.Exchange(ev.default__.Initial(origin, r.seq(b"")), r.Session(), http, None)
    r.feed(x, ev.Event_DiscoverStart())
    if x.failure is not None:
        raise x.failure
    return x.public_key


# selfCheck: the core's primitive vectors through this residue.


def self_check() -> list[str]:
    """Runs the core's primitive vectors through this residue; the failures."""
    return r.self_check()
