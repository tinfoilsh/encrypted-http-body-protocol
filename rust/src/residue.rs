//! The Rust residue of the event-driven core (dafny/ehbp_events.dfy): one
//! binding per action the core can emit, the pump of
//! conformance/spec/handler.md section 5, and the conversions at the runtime boundary.
//! Nothing here decides anything about the protocol; the layout follows
//! conformance/spec/handler.md section 4 and mirrors Go's
//! internal/eventresidue. `Step` is pure, so an exchange is an ordinary async
//! task: every binding is awaited inside `perform`, nothing blocks a thread.
// The residue checker finds bindings by `fn name`, so the async ones are
// written as `fn` returning a future.
#![allow(clippy::manual_async_fn)]

use std::{
    future::{poll_fn, Future},
    pin::Pin,
    sync::{Arc, Mutex},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use bytes::Bytes;
use ehbp_core::{
    EHBPEvents as ev,
    EHBP::{self as core, string_of, DafnyChar, DafnyInt, DafnyType, Sequence},
};
use futures_core::Stream;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, TryRngCore};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use sha2::Sha256;
use tokio::{sync::mpsc, task::AbortHandle};

use crate::{Code, Error, Result};

pub(crate) type Headers = Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>;
pub(crate) type BodyStream = Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>;

// crypto: one native call each, bytes in, bytes out. A failure is an empty
// result (or ok false for aead_open), which the core rejects by length.
// x25519-dalek (an all-zero output is a low-order point), hmac with sha2, aes-gcm, rand's OsRng.

#[rustfmt::skip]
fn gcm(key: &[u8], nonce: &[u8]) -> Option<Aes256Gcm> {
    (nonce.len() == 12).then(|| Aes256Gcm::new_from_slice(key).ok()).flatten()
}

#[rustfmt::skip]
pub(crate) fn x25519(scalar: &[u8], point: &[u8]) -> Vec<u8> {
    let (scalar, point) = (<[u8; 32]>::try_from(scalar).ok(), <[u8; 32]>::try_from(point).ok());
    scalar.zip(point).map(|(s, p)| x25519_dalek::x25519(s, p)).filter(|s| *s != [0; 32]).map(|s| s.to_vec()).unwrap_or_default()
}

#[rustfmt::skip]
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    <Hmac<Sha256> as Mac>::new_from_slice(key).ok().map(|mut mac| { mac.update(data); mac.finalize().into_bytes().to_vec() }).unwrap_or_default()
}

#[rustfmt::skip]
pub(crate) fn aead_seal(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    gcm(key, nonce).and_then(|g| g.encrypt(Nonce::from_slice(nonce), plaintext).ok()).unwrap_or_default()
}

#[rustfmt::skip]
pub(crate) fn aead_open(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> (bool, Vec<u8>) {
    match gcm(key, nonce).and_then(|g| g.decrypt(Nonce::from_slice(nonce), ciphertext).ok()) { Some(v) => (true, v), None => (false, Vec::new()) }
}

#[rustfmt::skip]
pub(crate) fn random_bytes(length: usize) -> Vec<u8> {
    let mut out = vec![0; length];
    OsRng.try_fill_bytes(&mut out).ok().map(|()| out).unwrap_or_default()
}

// http: the only block holding native state. One Exchange per request or
// discovery; the bindings are its methods. This impl and the pump are
// hand-formatted so each binding stays the few lines the residue matrix
// compares across languages.

pub(crate) struct Exchange {
    state: Mutex<Arc<ev::State>>,
    session: Arc<Session>,
    client: reqwest::Client,
    body: tokio::sync::Mutex<Option<BodyStream>>, // the caller's request body, None when absent
    tx: Mutex<Option<mpsc::Sender<Result<Bytes>>>>, // the encrypted upload, fed by write
    rx: Mutex<Option<mpsc::Receiver<Result<Bytes>>>>,
    pub response: tokio::sync::Mutex<Option<reqwest::Response>>, // the native response
    pub out: Mutex<Outcome>,
}

/// The outcome, written by the terminal actions and read by the shim.
#[derive(Default)]
pub(crate) struct Outcome {
    pub failure: Option<Error>,
    pub passthrough: bool,
    pub done: bool,
    pub finished: bool,
    pub status: u16,
    pub headers: HeaderMap,
    pub prefix: Vec<u8>,
    pub public_key: Vec<u8>,
    pub plain: Vec<u8>,        // EmitPlaintext since the last Read
    cause: Option<Error>,      // the native error behind a Transport failure
    generation: Option<u64>,   // what begin_session handed out, for cancellation
    lane: Option<AbortHandle>, // the upload lane
}

#[rustfmt::skip]
impl Exchange {
    /// Binds a core state to the native pieces: `client` performs one HTTP
    /// transaction; `body` is the caller's body or None.
    pub fn new(state: Arc<ev::State>, session: Arc<Session>, client: reqwest::Client, body: Option<BodyStream>) -> Arc<Self> {
        let (tx, rx) = body.as_ref().map(|_| mpsc::channel(1)).unzip();
        Arc::new(Exchange {
            state: Mutex::new(state), session, client, body: tokio::sync::Mutex::new(body),
            tx: Mutex::new(tx), rx: Mutex::new(rx), response: Default::default(), out: Default::default(),
        })
    }

    // http: the four performers over reqwest (send, write, read, close), written by hand.
    /// Performs the transaction and reports its head; with a body the upload
    /// lane feeds the channel meanwhile. `redirected` is whether the final
    /// URL differs from the one sent: a caller-supplied client may follow.
    fn send(&self, verb: String, url: String, headers: HeaderMap, has_body: bool) -> impl Future<Output = Option<(u16, HeaderMap, bool)>> + '_ {
        async move {
            let method = reqwest::Method::from_bytes(verb.as_bytes()).ok()?;
            let mut request = self.client.request(method, url.as_str()).headers(headers);
            if has_body {
                let mut rx = self.rx.lock().unwrap().take()?;
                let upload = async_stream::stream! { while let Some(item) = rx.recv().await { yield item; } };
                request = request.body(reqwest::Body::wrap_stream(upload));
            }
            match request.send().await {
                Ok(response) => {
                    let head = (response.status().as_u16(), response.headers().clone(), response.url().as_str() != url);
                    *self.response.lock().await = Some(response);
                    Some(head)
                }
                Err(err) => { self.out.lock().unwrap().cause = Some(err.into()); None }
            }
        }
    }

    /// Feeds one encrypted chunk and, by `end`, ends the upload: Done closes
    /// the channel, Aborted fails it with the code; false once the transport
    /// is gone. The abort cause is taken before the await so no lock guard
    /// lives across it.
    fn write(&self, data: Vec<u8>, end: &ev::BodyEnd) -> impl Future<Output = bool> + '_ {
        let more = matches!(end, ev::BodyEnd::More {});
        let tx = if more { self.tx.lock().unwrap().clone() } else { self.tx.lock().unwrap().take() };
        let reason = match end {
            ev::BodyEnd::Aborted { code } => { let cause = self.out.lock().unwrap().cause.take(); Some(error(code, "request body failed", cause)) }
            _ => None,
        };
        async move {
            let Some(tx) = tx else { return false };
            if !data.is_empty() && tx.send(Ok(Bytes::from(data))).await.is_err() { return false }
            if let Some(reason) = reason { let _ = tx.send(Err(reason)).await; }
            if !more { drop(tx); self.body.lock().await.take(); }
            true
        }
    }

    /// Reads once from the caller's body or the native response: the chunk and eof; None on a failure, kept as the cause.
    fn read(&self, stream: &ev::Stream) -> impl Future<Output = Option<(Bytes, bool)>> + '_ {
        let request = matches!(stream, ev::Stream::RequestBody {});
        async move {
            let next = if request {
                let mut guard = self.body.lock().await;
                let body = guard.as_mut()?;
                poll_fn(|cx| body.as_mut().poll_next(cx)).await
            } else {
                self.response.lock().await.as_mut()?.chunk().await.map_err(Error::from).transpose()
            };
            match next {
                Some(Ok(data)) => Some((data, false)),
                None => Some((Bytes::new(), true)),
                Some(Err(err)) => { self.out.lock().unwrap().cause = Some(err); None }
            }
        }
    }

    /// Releases the native stream.
    fn close(&self, stream: &ev::Stream) -> impl Future<Output = ()> + '_ {
        let request = matches!(stream, ev::Stream::RequestBody {});
        async move { if request { self.body.lock().await.take(); } else { self.response.lock().await.take(); } }
    }

    /// Cancellation: the upload lane stops and the token this exchange
    /// published, if still current, is cleared.
    pub fn cancel(&self) {
        let mut out = self.out.lock().unwrap();
        if let Some(lane) = out.lane.take() { lane.abort(); }
        if let Some(generation) = out.generation.take() { self.session.clear_token(generation); }
    }
}

// session: a mutex around one SessionStore value; every rule is SessionApply.

#[rustfmt::skip]
pub(crate) struct Session {
    store: Mutex<Arc<ev::SessionStore>>,
}

#[rustfmt::skip]
impl Default for Session {
    fn default() -> Self {
        Session { store: Mutex::new(ev::_default::NewSession()) }
    }
}

#[rustfmt::skip]
impl Session {
    fn apply(&self, a: ev::SessionAction) -> Arc<ev::SessionStore> {
        let mut store = self.store.lock().unwrap();
        *store = ev::_default::SessionApply(&store, &Arc::new(a));
        store.clone()
    }

    pub fn begin_session(&self) -> u64 {
        *self.apply(ev::SessionAction::Begin {}).generation()
    }

    pub fn publish_token(&self, generation: u64, exported_secret: &[u8], request_enc: &[u8]) {
        let token = core_token(exported_secret, request_enc);
        self.apply(ev::SessionAction::Publish { generation, token });
    }

    pub fn clear_token(&self, generation: u64) {
        self.apply(ev::SessionAction::Clear { generation });
    }

    /// The stored token, or none; never computes anything.
    pub fn token(&self) -> Option<Arc<core::Token>> {
        match self.store.lock().unwrap().token().as_ref() {
            core::Option::Some { value } => Some(value.clone()),
            core::Option::None {} => None,
        }
    }
}

// pump: handler.md section 5, written by hand: perform awaits inside.

pub(crate) enum Control {
    None,                  // no result event
    Event(Arc<ev::Event>), // feed the event back
    Stop,                  // the upload sink is gone; this lane ends
}

#[rustfmt::skip]
impl Exchange {
    /// Maps one action to one binding call and returns the result event.
    fn perform<'a>(&'a self, a: &'a ev::Action) -> impl Future<Output = Control> + 'a {
        use ev::{Action as A, Event as E};
        let ev = |e: E| Control::Event(Arc::new(e));
        async move {
            match a {
                A::BeginSession { .. } => {
                    let generation = self.session.begin_session();
                    self.out.lock().unwrap().generation = Some(generation);
                    ev(E::SessionBegun { generation })
                }
                A::PublishToken { .. } => { self.session.publish_token(*a.generation(), &bytes(a.exportedSecret()), &bytes(a.requestEnc())); Control::None }
                A::ClearToken { .. } => { self.session.clear_token(*a.generation()); Control::None }
                A::RandomBytes { .. } => ev(E::RandomResult { data: seq(&random_bytes((*a.length()).into())) }),
                A::X25519 { .. } => ev(E::X25519Result { point: seq(&x25519(&bytes(a.scalar()), &bytes(a.point()))) }),
                A::HmacSha256 { .. } => ev(E::HmacResult { mac: seq(&hmac_sha256(&bytes(a.key()), &bytes(a.data()))) }),
                A::AeadSeal { .. } => ev(E::AeadSealResult { ciphertext: seq(&aead_seal(&bytes(a.key()), &bytes(a.nonce()), &bytes(a.plaintext()))) }),
                A::AeadOpen { .. } => {
                    let (ok, plaintext) = aead_open(&bytes(a.key()), &bytes(a.nonce()), &bytes(a.ciphertext()));
                    ev(E::AeadOpenResult { ok, plaintext: seq(&plaintext) })
                }
                A::Send { .. } => match self.send(string(a.verb()), string(a.url()), header_pairs(a.headers()), *a.hasBody()).await {
                    Some((status, headers, redirected)) => ev(E::ResponseHead { status: DafnyInt::from(status), headers: header_seq(&headers), redirected }),
                    None => ev(E::StreamFailed { stream: Arc::new(ev::Stream::ResponseBody {}) }),
                },
                A::Write { .. } => if self.write(bytes(a.data()), a.end()).await { Control::None } else { Control::Stop },
                A::Read { .. } => match self.read(a.stream()).await {
                    Some((data, eof)) => ev(E::Chunk { stream: a.stream().clone(), data: seq(&data), eof }),
                    None => ev(E::StreamFailed { stream: a.stream().clone() }),
                },
                A::Close { .. } => { self.close(a.stream()).await; Control::None }
                _ => Control::None,
            }
        }
    }

    /// Feeds events to Step until a terminal action. A Send with a body hands
    /// the rest of its action list, the upload, to a second lane (a tokio task)
    /// so the transaction can await the response head; this lane stops there.
    fn run(self: Arc<Self>, mut acts: Vec<Arc<ev::Action>>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        use ev::Action as A;
        Box::pin(async move {
            let mut events = Vec::new();
            loop {
                for i in 0..acts.len() {
                    let a = &acts[i];
                    let settled = {
                        let mut out = self.out.lock().unwrap();
                        match a.as_ref() {
                            A::EmitPlaintext { .. } => { out.plain.extend_from_slice(&bytes(a.data())); continue }
                            A::Passthrough { .. } => { (out.passthrough, out.status) = (true, u16::from(*a.status())); (out.headers, out.prefix) = (header_pairs(a.headers()), bytes(a.prefix())); true }
                            A::Done { .. } => { (out.done, out.status, out.headers) = (true, u16::from(*a.status()), header_pairs(a.headers())); true }
                            A::Finished { .. } => { out.finished = true; true }
                            A::Discovered { .. } => { out.public_key = bytes(a.publicKey()); true }
                            A::Fail { .. } => { let cause = out.cause.take(); out.failure = Some(error(a.code(), &string(a.message()), cause)); true }
                            A::Send { hasBody: true, .. } => {
                                let lane = tokio::spawn(self.clone().run(acts[i + 1..].to_vec()));
                                out.lane = Some(lane.abort_handle());
                                false
                            }
                            _ => false,
                        }
                    };
                    if settled { return }
                    match self.perform(a).await {
                        Control::Stop => return,
                        Control::Event(e) => events.push(e),
                        Control::None => {}
                    }
                    if matches!(a.as_ref(), A::Send { hasBody: true, .. }) { break }
                }
                let Some(e) = events.pop() else { return };
                acts = self.step(e);
            }
        })
    }

    fn step(&self, e: Arc<ev::Event>) -> Vec<Arc<ev::Action>> {
        let mut state = self.state.lock().unwrap();
        let (next, acts) = ev::_default::Step(&state, &e);
        *state = next;
        acts.iter().collect()
    }

    /// Runs the pump on one caller event: Start, DiscoverStart, CallerRead or CallerClose.
    pub fn feed(self: &Arc<Self>, e: ev::Event) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let acts = self.step(Arc::new(e));
        self.clone().run(acts)
    }
}

/// Held by the caller's future or stream for one exchange; dropping it is cancellation.
pub(crate) struct Guard(pub(crate) Arc<Exchange>);
#[rustfmt::skip]
impl Drop for Guard { fn drop(&mut self) { self.0.cancel(); } }

/// The pass-through body: the bytes the core read ahead, then the rest of the native response.
#[rustfmt::skip]
pub(crate) fn passthrough(prefix: Vec<u8>, response: Option<reqwest::Response>, guard: Guard) -> BodyStream {
    Box::pin(async_stream::stream! {
        let _guard = guard;
        if !prefix.is_empty() { yield Ok(Bytes::from(prefix)); }
        if let Some(mut response) = response {
            while let Some(chunk) = response.chunk().await.transpose() {
                let failed = chunk.is_err();
                yield chunk.map_err(Error::from);
                if failed { break; }
            }
        }
    })
}

/// The decrypted body after Done: each pull drives the core with CallerRead until it emits plaintext, finishes or fails.
#[rustfmt::skip]
pub(crate) fn plaintext(guard: Guard) -> BodyStream {
    Box::pin(async_stream::stream! {
        loop {
            guard.0.feed(ev::Event::CallerRead {}).await;
            let (plain, failure, finished) = {
                let mut out = guard.0.out.lock().unwrap();
                (std::mem::take(&mut out.plain), out.failure.take(), out.finished)
            };
            if !plain.is_empty() { yield Ok(Bytes::from(plain)); }
            if let Some(err) = failure { yield Err(err); break; }
            if finished { break; }
        }
    })
}

// conversions: the runtime boundary only.

#[rustfmt::skip]
pub(crate) fn seq(b: &[u8]) -> Sequence<u8> {
    Sequence::from_array_owned(b.to_vec())
}

#[rustfmt::skip]
pub(crate) fn bytes(s: &Sequence<u8>) -> Vec<u8> {
    s.to_array().to_vec()
}

#[rustfmt::skip]
pub(crate) fn str(s: &str) -> Sequence<DafnyChar> {
    string_of(s)
}

#[rustfmt::skip]
pub(crate) fn string(s: &Sequence<DafnyChar>) -> String {
    s.iter().map(|c| c.0).collect()
}

/// The core's header list, one entry per value.
#[rustfmt::skip]
pub(crate) fn header_seq(headers: &HeaderMap) -> Headers {
    headers.iter().map(|(name, value)| (str(name.as_str()), str(&String::from_utf8_lossy(value.as_bytes())))).collect()
}

/// The core's header list back as native name/value pairs; a name or value
/// the native stack cannot hold is dropped.
#[rustfmt::skip]
pub(crate) fn header_pairs(headers: &Headers) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers.iter() {
        let (name, value) = (string(&name), string(&value));
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(&value)) {
            map.append(name, value);
        }
    }
    map
}

pub(crate) fn core_token(exported_secret: &[u8], request_enc: &[u8]) -> Arc<core::Token> {
    Arc::new(core::Token::Token {
        exportedSecret: seq(exported_secret),
        requestEnc: seq(request_enc),
    })
}

// mapping: from the core's CodeString; no table of strings.

/// The canonical code of a core code; Transport has none.
#[rustfmt::skip]
pub(crate) fn code(c: &Arc<core::Code>) -> Option<Code> {
    let name = string(&core::_default::CodeString(c));
    Code::ALL.into_iter().find(|k| k.as_str() == name)
}

/// A core failure as a Rust error: a coded protocol error, or the native
/// cause of a Transport failure.
#[rustfmt::skip]
pub(crate) fn error(c: &Arc<core::Code>, message: &str, cause: Option<Error>) -> Error {
    match (code(c), cause) {
        (Some(code), Some(cause)) => Error::Coded(code, format!("{message}: {cause}")),
        (Some(code), None) => Error::Coded(code, message.to_owned()),
        (None, Some(cause)) => cause,
        (None, None) => Error::Protocol(message.to_owned()),
    }
}

/// Unwraps a core result.
pub(crate) fn result<T: DafnyType>(r: &Arc<core::Result<T>>) -> Result<T> {
    match r.as_ref() {
        core::Result::Ok { value } => Ok(value.clone()),
        core::Result::Err { code, message } => Err(error(code, &string(message), None)),
    }
}

// Self-check: the core's primitive vectors through this residue.

pub(crate) async fn self_check() -> Vec<String> {
    let Ok(client) = reqwest::Client::builder().build() else {
        return vec!["self-check: no HTTP client".into()];
    };
    let origin = Arc::new(core::Origin::Origin {
        scheme: str("https"),
        host: str("localhost"),
        port: DafnyInt::from(443u16),
    });
    let state = ev::_default::Initial(&origin, &seq(&[]));
    let x = Exchange::new(state, Arc::default(), client, None);
    let mut results = Vec::new();
    for a in ev::_default::SelfCheckActions().iter() {
        if let Control::Event(e) = x.perform(&a).await {
            results.push(e);
        }
    }
    let failures = ev::_default::SelfCheckJudge(&results.into_iter().collect());
    failures.iter().map(|line| string(&line)).collect()
}
