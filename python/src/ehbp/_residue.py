"""The Python residue of the event-driven core (dafny/ehbp_events.dfy): one
binding per action the core can emit, the loop of conformance/spec/handler.md
section 5 over the core's Perform, and the conversions at the runtime boundary. Nothing here decides anything
about the protocol; the layout follows conformance/spec/handler.md section 4
and mirrors internal/eventresidue/residue.go declaration for declaration."""

from __future__ import annotations

import os
import threading
from collections import deque
from collections.abc import Iterable, Iterator
from typing import Any, Optional, Union

import httpx
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import errors
from ._gen import EHBP, _dafny
from ._gen import EHBPEvents as ev

# crypto: one native call each, bytes in, bytes out. A failure is an empty
# result (or ok False for aead_open), which the core rejects by length.
# The cryptography package: X25519 (raises on a low-order point), HMAC, AESGCM; os.urandom.


def x25519(scalar: bytes, point: bytes) -> bytes:
    try:
        priv = X25519PrivateKey.from_private_bytes(scalar)
        return priv.exchange(X25519PublicKey.from_public_bytes(point))
    except Exception:  # noqa: BLE001 - a failure is an empty result
        return b""


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    try:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        return h.finalize()
    except Exception:  # noqa: BLE001 - a failure is an empty result
        return b""


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    try:
        return AESGCM(key).encrypt(nonce, plaintext, b"")
    except Exception:  # noqa: BLE001 - a failure is an empty result
        return b""


def aead_open(key: bytes, nonce: bytes, ciphertext: bytes) -> tuple[bool, bytes]:
    try:
        return True, AESGCM(key).decrypt(nonce, ciphertext, b"")
    except Exception:  # noqa: BLE001 - a failure is an empty result
        return False, b""


def random_bytes(length: int) -> bytes:
    try:
        return os.urandom(length)
    except Exception:  # noqa: BLE001 - a failure is an empty result
        return b""


# http: the only block holding native state. One Exchange per request or
# discovery; the bindings are its methods.


class Exchange:
    def __init__(self, state: ev.State, session: Session, http: httpx.Client,
                 body: Optional[Iterator[bytes]]) -> None:
        self.state, self.session, self.http = state, session, http
        self.body = bounded(body) if body is not None else None  # the caller's request body, None when absent
        self.lane: Optional[Iterator[bytes]] = None  # the upload: run over the actions after Send
        self.pipe: deque = deque()  # fed by write, pulled by httpx via run
        self.response: Optional[httpx.Response] = None
        self.chunks: Optional[Iterator[bytes]] = None  # the native response body
        self.send_err = self.resp_err = self.body_err = None  # native causes behind Transport
        # The outcome, written by the terminal actions and read by the shim.
        self.failure: Optional[BaseException] = None
        self.passthrough = self.done = self.finished = False
        self.status, self.headers, self.prefix, self.public_key = 0, [], b"", b""
        self.plain = bytearray()  # EmitPlaintext since the last Read

    # http: the four performers over httpx (send, write, read, close), written by hand.
    def send(self, verb: str, url: str, headers: list, has_body: bool) -> tuple[bool, int, list]:
        """One transaction, never following a redirect; with a body httpx pulls
        the upload lane while it waits for the head."""
        try:
            request = self.http.build_request(verb, url, headers=headers,
                                              content=self.lane if has_body else None)
            self.response = self.http.send(request, stream=True, follow_redirects=False)
        except Exception as err:  # noqa: BLE001 - the shim re-raises the cause
            self.send_err = err
            return False, 0, []
        self.chunks = self.response.iter_bytes()
        return True, self.response.status_code, self.response.headers.multi_items()

    def write(self, data: bytes, end: ev.BodyEnd) -> None:
        """Feeds one encrypted chunk; Done ends the upload, Aborted fails it with the code."""
        if data:
            self.pipe.append(data)
        if end.is_Done:
            self.pipe.append(None)
        elif end.is_Aborted:
            self.pipe.append(error(end.code, "request body failed", self.body_err))

    def read(self, stream: ev.Stream) -> tuple[bytes, bool, bool]:
        """Reads once from the caller's body or the native response: chunk, eof, ok."""
        if stream.is_RequestBody:
            chunk, eof, self.body_err = read_chunk(self.body)
            return chunk, eof, self.body_err is None
        chunk, eof, self.resp_err = read_chunk(self.chunks)
        return chunk, eof, self.resp_err is None

    def close(self, stream: ev.Stream) -> None:
        """Releases the native response; the caller's iterator is dropped with the exchange."""
        if stream.is_ResponseBody and self.response is not None:
            self.response.close()

    # performer: the core's Performer (Perform in ehbp_events.dfy); each method
    # converts at the runtime boundary and calls one binding.
    def BeginSession(self) -> int:
        return self.session.begin_session()

    def PublishToken(self, generation: int, exported_secret: _dafny.Seq, request_enc: _dafny.Seq) -> None:
        self.session.publish_token(generation, bytes_(exported_secret), bytes_(request_enc))

    def ClearToken(self, generation: int) -> None:
        self.session.clear_token(generation)

    def RandomBytes(self, length: int) -> _dafny.Seq:
        return seq(random_bytes(length))

    def X25519(self, scalar: _dafny.Seq, point: _dafny.Seq) -> _dafny.Seq:
        return seq(x25519(bytes_(scalar), bytes_(point)))

    def HmacSha256(self, key: _dafny.Seq, data: _dafny.Seq) -> _dafny.Seq:
        return seq(hmac_sha256(bytes_(key), bytes_(data)))

    def AeadSeal(self, key: _dafny.Seq, nonce: _dafny.Seq, plaintext: _dafny.Seq) -> _dafny.Seq:
        return seq(aead_seal(bytes_(key), bytes_(nonce), bytes_(plaintext)))

    def AeadOpen(self, key: _dafny.Seq, nonce: _dafny.Seq, ciphertext: _dafny.Seq) -> tuple[bool, _dafny.Seq]:
        ok, plaintext = aead_open(bytes_(key), bytes_(nonce), bytes_(ciphertext))
        return ok, seq(plaintext)

    def Send(self, verb: _dafny.Seq, url: _dafny.Seq, headers: _dafny.Seq, has_body: bool) -> tuple[bool, int, _dafny.Seq, bool]:
        ok, status, head = self.send(string(verb), string(url), header_pairs(headers), has_body)
        return ok, status, header_seq(head), False

    def Write(self, data: _dafny.Seq, end: ev.BodyEnd) -> bool:
        self.write(bytes_(data), end)
        return True

    def Read(self, stream: ev.Stream) -> tuple[bool, _dafny.Seq, bool]:
        data, eof, ok = self.read(stream)
        return ok, seq(data), eof

    def Close(self, stream: ev.Stream) -> None:
        self.close(stream)

    def EmitPlaintext(self, data: _dafny.Seq) -> None:
        self.plain += bytes_(data)


def bounded(chunks: Iterator[bytes], limit: int = 64 * 1024) -> Iterator[bytes]:
    """Re-slices the caller's chunks to at most `limit` bytes: the runtime holds a
    chunk as a list of ints, so a 1 MiB chunk would cost ~40 MiB per copy."""
    for chunk in chunks:
        chunk = bytes(chunk)
        for offset in range(0, len(chunk), limit):
            yield chunk[offset:offset + limit]


def read_chunk(chunks: Iterator[bytes]) -> tuple[bytes, bool, Optional[BaseException]]:
    try:
        return bytes(next(chunks)), False, None
    except StopIteration:
        return b"", True, None
    except Exception as err:  # noqa: BLE001
        return b"", False, err


# session: a mutex around one SessionStore value; every rule is SessionApply.


class Session:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.store = ev.default__.NewSession

    def apply(self, action: ev.SessionAction) -> ev.SessionStore:
        with self.lock:
            self.store = ev.default__.SessionApply(self.store, action)
            return self.store

    def begin_session(self) -> int:
        return self.apply(ev.SessionAction_Begin()).generation

    def publish_token(self, generation: int, exported_secret: bytes, request_enc: bytes) -> None:
        token = EHBP.Token_Token(seq(exported_secret), seq(request_enc))
        self.apply(ev.SessionAction_Publish(generation, token))

    def clear_token(self, generation: int) -> None:
        self.apply(ev.SessionAction_Clear(generation))

    def token(self) -> Optional[EHBP.Token]:
        """The stored token, or None."""
        with self.lock:
            return self.store.token.value if self.store.token.is_Some else None


# pump: handler.md section 5. Perform (ehbp_events.dfy) dispatches one action
# to the Performer methods of Exchange; run is the loop.


def run(x: Exchange, acts: list) -> Iterator[bytes]:
    """Feeds events to Step until a terminal action. run is a generator, so the
    actions after a Send with a body, the upload, become the request body that
    httpx pulls while this lane waits inside send for the response head."""
    events: list = []
    while True:
        for i, a in enumerate(acts):
            if a.is_Passthrough:
                x.passthrough, x.prefix = True, bytes_(a.prefix)
                x.status, x.headers = a.status, header_pairs(a.headers)
                return
            if a.is_Done:
                x.done, x.status, x.headers = True, a.status, header_pairs(a.headers)
                return
            if a.is_Finished:
                x.finished = True
                return
            if a.is_Discovered:
                x.public_key = bytes_(a.publicKey)
                return
            if a.is_Fail:
                x.failure = error(a.code, string(a.message), cause(x))
                return
            if a.is_Send and a.hasBody:
                x.lane = run(x, acts[i + 1:])
            r = ev.default__.Perform(x, a)
            while x.pipe:
                item = x.pipe.popleft()
                if item is None:
                    return
                if isinstance(item, BaseException):
                    raise item
                yield item
            if r.is_Stop:
                return
            if r.is_Got:
                events.append(r.e)
            if a.is_Send and a.hasBody:
                break  # the lane owns the rest
        if not events:
            return
        acts = step(x, events.pop())


def step(x: Exchange, e: ev.Event) -> list:
    x.state, acts = ev.default__.Step(x.state, e)
    return list(acts.Elements)


def cause(x: Exchange) -> Optional[BaseException]:
    """The native error behind a Transport failure, if any."""
    return x.send_err or x.resp_err or x.body_err


def feed(x: Exchange, e: ev.Event) -> None:
    """Runs the pump on one caller event: Start, DiscoverStart, CallerRead or CallerClose."""
    for _ in run(x, step(x, e)):
        pass


# conversions: the runtime boundary only.


def seq(items: Union[bytes, Iterable[Any]]) -> _dafny.Seq:
    return _dafny.Seq(items, isStr=None)


def bytes_(s: _dafny.Seq) -> bytes:
    return bytes(s.Elements)


def str_(s: str) -> _dafny.Seq:
    return _dafny.Seq(map(_dafny.CodePoint, s), isStr=None)


def string(s: _dafny.Seq) -> str:
    return "".join(s.Elements)


def header_seq(pairs: Iterable[tuple[str, str]]) -> _dafny.Seq:
    return seq([(str_(k), str_(v)) for k, v in pairs])


def header_pairs(s: _dafny.Seq) -> list[tuple[str, str]]:
    return [(string(k), string(v)) for k, v in s.Elements]


# mapping: from the core's CodeString; no table of strings.


def code(c: EHBP.Code) -> Optional[errors.Code]:
    """The canonical code of a core code; Transport has none."""
    name = string(EHBP.default__.CodeString(c))
    return errors.Code(name) if name else None


_BY_CODE = {cls.code: cls for cls in errors.EHBPError.__subclasses__()}


def error(c: EHBP.Code, message: str, cause: Optional[BaseException] = None) -> BaseException:
    """A coded failure becomes the protocol error; Transport the native cause."""
    cls = _BY_CODE.get(code(c))
    if cls is None:
        return cause or errors.EHBPError(message)
    err = cls(message)
    err.__cause__ = cause
    return err


def unwrap(result: EHBP.Result) -> Any:
    if result.is_Err:
        raise error(result.code, string(result.message))
    return result.value


# Self-check: the core's primitive vectors through this residue.


def self_check() -> list[str]:
    x = Exchange.__new__(Exchange)  # no native state: only crypto actions
    results = seq([ev.default__.Perform(x, a).e for a in ev.default__.SelfCheckActions.Elements])
    return [string(f) for f in ev.default__.SelfCheckJudge(results).Elements]
