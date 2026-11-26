//! The API shim over the event-driven EHBP core (dafny/ehbp_events.dfy).
//! Every protocol decision is made by the core; this file parses URLs,
//! collects headers, wraps bodies as streams, runs the pump in `residue.rs`
//! and turns the core's terminal actions back into reqwest-shaped responses
//! (conformance/spec/handler.md section 7).

use std::{
    future::poll_fn,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use ehbp_core::{
    EHBPEvents as ev,
    EHBP::{self as core, DafnyInt},
};
use futures_core::Stream;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    StatusCode, Url,
};

use crate::{
    core::SessionRecoveryToken,
    residue::{self, header_seq, seq, str, BodyStream, Exchange, Guard, Session},
    Code, Error, Result,
};

// constructor: a Client over one server origin and the key a KeySource yields.

/// Where the server's HPKE public key comes from (SPEC 3).
pub enum KeySource {
    /// Fetch `/.well-known/hpke-keys` from the server.
    Discover,
    /// A key configuration (RFC 9458 bytes).
    Config(Vec<u8>),
    /// The X25519 public key itself.
    PublicKey([u8; 32]),
}

#[derive(Clone)]
pub struct Client {
    base_url: Url,
    origin: Arc<core::Origin>,
    public_key: Vec<u8>,
    http_client: reqwest::Client,
    session: Arc<Session>,
}

impl Client {
    /// `server` is an http(s) origin; `http_client` carries the native
    /// transport options (timeouts, pinning) and defaults to one that never
    /// follows redirects.
    pub async fn new(
        server: impl AsRef<str>,
        keys: KeySource,
        http_client: Option<reqwest::Client>,
    ) -> Result<Self> {
        let http_client = match http_client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        };
        let base_url = parse_base_url(server.as_ref())?;
        let origin = residue::result(&origin_of(&base_url))?;
        let public_key = match keys {
            KeySource::Discover => discover_from(&origin, &http_client).await?,
            KeySource::Config(config) => crate::core::parse_config(&config)?,
            KeySource::PublicKey(key) => crate::core::check_public_key(&key)?,
        };
        Ok(Self {
            base_url,
            origin,
            public_key,
            http_client,
            session: Arc::default(),
        })
    }

    // discover: the same discovery the constructor runs; the 32-byte public key.

    /// The discovery the constructor runs (SPEC 3.1), for callers that cache
    /// keys: the server's public key, for `KeySource::PublicKey`.
    pub async fn discover(
        server: impl AsRef<str>,
        http_client: Option<reqwest::Client>,
    ) -> Result<[u8; 32]> {
        let client = Self::new(server, KeySource::Discover, http_client).await?;
        Ok(client.public_key.try_into().expect("core key length"))
    }

    // token: the exchange in flight.

    /// The token of the exchange in flight, or none (SPEC 6): none before any
    /// request, after a bodyless one, and once an exchange has ended.
    pub fn session_recovery_token(&self) -> Option<SessionRecoveryToken> {
        self.session
            .token()
            .map(|t| SessionRecoveryToken::from_core(&t))
    }

    // request: the one entry point; the core validates, seals, classifies and decrypts.

    /// One exchange: `path` resolves against the server; the core validates
    /// the request and its headers, seals the body when present, classifies
    /// the response and decrypts its body as the caller reads.
    pub async fn request(
        &self,
        method: impl AsRef<str>,
        path: impl AsRef<str>,
        headers: &[(&str, &str)],
        body: Option<Body>,
    ) -> Result<Response> {
        let u = self.base_url.join(path.as_ref())?;
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            let invalid = |err: &dyn std::fmt::Display| Error::Coded(Code::InvalidInput, format!("invalid header: {err}"));
            map.append(HeaderName::from_bytes(name.as_bytes()).map_err(|e| invalid(&e))?, HeaderValue::from_str(value).map_err(|e| invalid(&e))?);
        }
        let start = ev::Event::Start {
            verb: str(method.as_ref()),
            url: str(u.as_str()),
            scheme: str(u.scheme()),
            host: str(u.host_str().unwrap_or_default()),
            port: DafnyInt::from(u.port().unwrap_or(0)),
            hasPort: u.port().is_some(),
            hasUserinfo: !u.username().is_empty() || u.password().is_some(),
            headers: header_seq(&map),
            hasBody: body.is_some(),
        };
        let x = Exchange::new(
            ev::_default::Initial(&self.origin, &seq(&self.public_key)),
            self.session.clone(),
            self.http_client.clone(),
            body.map(|b| b.0),
        );
        let guard = Guard(x.clone());
        x.feed(start).await;
        // The native response leaves the exchange only on a passthrough.
        let response = x
            .response
            .lock()
            .await
            .take_if(|_| x.out.lock().unwrap().passthrough);
        let mut out = x.out.lock().unwrap();
        if let Some(err) = out.failure.take() {
            return Err(err);
        }
        let status =
            StatusCode::from_u16(out.status).map_err(|err| Error::Protocol(err.to_string()))?;
        let headers = std::mem::take(&mut out.headers);
        let body = if out.passthrough {
            residue::passthrough(std::mem::take(&mut out.prefix), response, guard)
        } else if out.done {
            residue::plaintext(guard)
        } else {
            return Err(Error::Protocol("exchange ended without an outcome".into()));
        };
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

/// Runs discovery (`DiscoverStart`) against `origin`.
async fn discover_from(
    origin: &Arc<core::Origin>,
    http_client: &reqwest::Client,
) -> Result<Vec<u8>> {
    let x = Exchange::new(
        ev::_default::Initial(origin, &seq(&[])),
        Arc::default(),
        http_client.clone(),
        None,
    );
    x.feed(ev::Event::DiscoverStart {}).await;
    let mut out = x.out.lock().unwrap();
    if let Some(err) = out.failure.take() {
        return Err(err);
    }
    Ok(std::mem::take(&mut out.public_key))
}

/// A request body: bytes (copied in once), or a stream the core seals
/// chunk by chunk into bounded frames without buffering it.
pub struct Body(BodyStream);

impl Body {
    /// A streamed body; a chunk's error fails the request.
    pub fn stream<S, E>(body: S) -> Self
    where
        S: Stream<Item = std::result::Result<Bytes, E>> + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        let mut body = Box::pin(body);
        Body(Box::pin(async_stream::stream! {
            while let Some(chunk) = poll_fn(|cx| body.as_mut().poll_next(cx)).await {
                yield chunk.map_err(|err| Error::Protocol(format!("request body stream failed: {err}")));
            }
        }))
    }
}

impl<T: AsRef<[u8]>> From<T> for Body {
    fn from(body: T) -> Self {
        let chunk = Bytes::copy_from_slice(body.as_ref());
        Body(Box::pin(async_stream::stream! { yield Ok(chunk) }))
    }
}

/// The response; its body is the decrypted stream, or the pass-through, read
/// as a `Stream` of chunks or whole with [`Self::bytes`].
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: BodyStream,
}

impl Response {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub async fn bytes(mut self) -> Result<Bytes> {
        let mut body = Vec::new();
        while let Some(chunk) = poll_fn(|cx| self.body.as_mut().poll_next(cx)).await {
            body.extend_from_slice(&chunk?);
        }
        Ok(Bytes::from(body))
    }
}

impl Stream for Response {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.body.as_mut().poll_next(cx)
    }
}

/// Validates the origin (MakeOrigin) and makes relative paths resolve under it.
fn parse_base_url(base_url: &str) -> Result<Url> {
    let mut url = Url::parse(base_url)?;
    residue::result(&origin_of(&url))?;
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

/// Hands the parsed parts of `u` to the core, which validates them.
fn origin_of(u: &Url) -> Arc<core::Result<Arc<core::Origin>>> {
    let port = Arc::new(match u.port() {
        Some(port) => core::Option::Some {
            value: DafnyInt::from(port),
        },
        None => core::Option::None {},
    });
    core::_default::MakeOrigin(
        &str(u.scheme()),
        &str(u.host_str().unwrap_or_default()),
        &port,
        !u.username().is_empty() || u.password().is_some(),
    )
}

// selfCheck: `tinfoil_ehbp::self_check` in lib.rs runs residue::self_check at the crate root.

// The protocol rules (framing, nonces, classification, discovery, request
// validation) are the core's and are pinned by the conformance fixtures; the
// tests here cover what is reqwest- or tokio-specific: the request body as a
// stream, cancellation by dropping the future, caller-supplied clients that
// follow redirects, and the token lifecycle through the API.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::HPKE_REQUEST_INFO;
    use futures_util::{stream, StreamExt};
    use hpke::{
        aead::AesGcm256,
        kdf::HkdfSha256,
        kem::{Kem as _, X25519HkdfSha256},
        setup_receiver, Deserializable as _, OpModeR, Serializable as _,
    };
    use rand::{rngs::StdRng, SeedableRng as _};
    use reqwest::header::CONTENT_TYPE;
    use std::{sync::Mutex, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    type TestPrivateKey = <X25519HkdfSha256 as hpke::kem::Kem>::PrivateKey;

    /// A client over reqwest's default client, which follows redirects.
    async fn client_at(addr: impl std::fmt::Display, public_key: [u8; 32]) -> Client {
        Client::new(
            format!("http://{addr}/"),
            KeySource::PublicKey(public_key),
            Some(reqwest::Client::new()),
        )
        .await
        .unwrap()
    }

    fn keypair() -> ([u8; 32], TestPrivateKey) {
        let (private_key, public_key) = X25519HkdfSha256::gen_keypair(&mut StdRng::from_os_rng());
        (public_key.to_bytes().into(), private_key)
    }

    /// Serves `raw` verbatim once the encrypted request body has arrived, then
    /// closes the connection.
    async fn client_with_raw_response(raw: Vec<u8>) -> Client {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0u8; 1024];
            while !bytes.windows(5).any(|window| window == b"0\r\n\r\n") {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..n]);
            }
            socket.write_all(&raw).await.unwrap();
        });
        client_at(addr, [7u8; 32]).await
    }

    #[tokio::test]
    async fn send_failure_clears_session_recovery_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = client_at(addr, [7u8; 32]).await;

        let result = client
            .request("POST", "/secure", &[], Some("secret".into()))
            .await;

        assert!(matches!(result, Err(Error::Http(_))));
        assert!(client.session_recovery_token().is_none());
    }

    #[tokio::test]
    async fn transport_refuses_an_answer_reached_through_a_followed_redirect() {
        // The first connection is redirected; the second, the bodyless
        // follow-up, is answered in plaintext.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for reply in [
                "HTTP/1.1 303 See Other\r\nLocation: /followed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nforged",
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut seen = Vec::new();
                let mut buf = [0u8; 1024];
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buf[..n]);
                }
                socket.write_all(reply.as_bytes()).await.unwrap();
            }
        });

        let client = client_at(addr, [7u8; 32]).await;
        let err = client
            .request("POST", "/secure", &[], Some("secret".into()))
            .await
            .err()
            .unwrap();
        assert!(matches!(err, Error::Coded(Code::UnexpectedRedirect, _)));
        assert!(client.session_recovery_token().is_none());
    }

    /// The 50 000-deep problem body of the conformance suite on a 2 MiB
    /// thread, as a tokio worker has: the core's JSON parser must not recurse.
    #[test]
    fn deep_problem_body_passes_through_on_a_worker_sized_stack() {
        std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let body = [b"{\"type\":".to_vec(), vec![b'['; 50_000]].concat();
                        let header = format!(
                            "HTTP/1.1 422 Unprocessable Content\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len(),
                        );
                        let client = client_with_raw_response([header.as_bytes(), &body[..]].concat()).await;
                        let response = client.request("POST", "/secure", &[], Some("secret".into())).await.unwrap();
                        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
                        let mut got = Vec::new();
                        for chunk in response.collect::<Vec<_>>().await {
                            got.extend_from_slice(&chunk.unwrap());
                        }
                        assert_eq!(got, body);
                    })
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[tokio::test]
    async fn unencrypted_http_errors_pass_through_as_a_stream() {
        let body = b"upstream unavailable";
        let header = format!(
            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nX-Upstream: proxy\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len(),
        );
        let client = client_with_raw_response([header.as_bytes(), body].concat()).await;

        let response = client
            .request("POST", "/secure", &[], Some("secret".into()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/plain");
        assert_eq!(response.headers()["x-upstream"], "proxy");
        assert!(client.session_recovery_token().is_none());
        let chunks: Vec<_> = response.collect().await;
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ref().unwrap(), &body[..]);
    }

    #[tokio::test]
    async fn request_stream_errors_fail_the_request_and_clear_the_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            while socket.read(&mut buffer).await.unwrap_or_default() != 0 {}
        });

        let client = client_at(addr, [7u8; 32]).await;
        let body = stream::iter([
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"first")),
            Err(std::io::Error::other("request stream failed")),
        ]);
        let sent = client
            .request("POST", "/secure", &[], Some(Body::stream(body).into()))
            .await;
        assert!(sent.is_err());
        assert!(client.session_recovery_token().is_none());
    }

    #[tokio::test]
    async fn cancelling_a_request_clears_session_recovery_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request_received = Arc::new(tokio::sync::Notify::new());
        let request_received_by_server = Arc::clone(&request_received);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            let _ = socket.read(&mut buffer).await.unwrap();
            request_received_by_server.notify_one();
            std::future::pending::<()>().await;
        });

        let client = client_at(addr, [7u8; 32]).await;
        let client_for_request = client.clone();
        let request_task = tokio::spawn(async move {
            client_for_request
                .request("POST", "/secure", &[], Some("secret".into()))
                .await
        });

        request_received.notified().await;
        assert!(client.session_recovery_token().is_some());
        request_task.abort();
        let _ = request_task.await;

        assert!(client.session_recovery_token().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn discovery_rejects_followed_redirects_from_caller_clients() {
        // 302 at the keys path, valid config at /elsewhere; a redirect-following
        // client reaches the config, which the core still refuses.
        let config = crate::core::marshal_config(&[7u8; 32]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let config = config.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        let n = socket.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        let reply = if buf[..n].starts_with(b"GET /elsewhere ") {
                            [
                                format!("HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n", crate::KEYS_MEDIA_TYPE, config.len()).into_bytes(),
                                config.clone(),
                            ]
                            .concat()
                        } else {
                            b"HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n".to_vec()
                        };
                        socket.write_all(&reply).await.unwrap();
                    }
                });
            }
        });

        let following = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .unwrap();
        let err = Client::discover(format!("http://{addr}/"), Some(following))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(&err, Error::Coded(Code::InvalidKeyConfig, _)),
            "{err}"
        );
    }

    /// Sends `source` as a streamed body to a raw TCP listener and returns the
    /// captured request bytes plus the server private key.
    async fn capture_body_stream<S>(source: S) -> (Vec<u8>, TestPrivateKey)
    where
        S: Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send + 'static,
    {
        let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured_for_task = Arc::clone(&captured);
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..n]);
                if bytes.ends_with(b"0\r\n\r\n") {
                    break;
                }
                // A bodyless request has no chunked body: stop at the header end.
                if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&bytes[..pos]).to_ascii_lowercase();
                    if !head.contains("transfer-encoding: chunked")
                        && !head.contains("content-length:")
                    {
                        break;
                    }
                }
            }
            *captured_for_task.lock().unwrap() = bytes;
            socket
                .write_all(b"HTTP/1.1 422 Unprocessable Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let (public_key, private_key) = keypair();
        let client = client_at(addr, public_key).await;
        let _ = client
            .request("POST", "/secure", &[], Some(Body::stream(source).into()))
            .await;
        let raw = captured.lock().unwrap().clone();
        (raw, private_key)
    }

    /// Decodes the captured request: dechunks the body and opens each frame
    /// with the server's HPKE receiver context.
    fn captured_frames(raw: &[u8], private_key: &TestPrivateKey) -> (String, Vec<Vec<u8>>) {
        let text = String::from_utf8_lossy(raw).to_ascii_lowercase();
        let enc_hex = text
            .lines()
            .find_map(|l| l.strip_prefix("ehbp-encapsulated-key: "))
            .unwrap()
            .trim()
            .to_string();
        let encapped_key = <X25519HkdfSha256 as hpke::kem::Kem>::EncappedKey::from_bytes(
            &hex::decode(enc_hex).unwrap(),
        )
        .unwrap();
        let mut receiver = setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            private_key,
            &encapped_key,
            HPKE_REQUEST_INFO,
        )
        .unwrap();

        let body_start = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let mut body = &raw[body_start..];
        let mut framed = Vec::new();
        loop {
            let line_end = body.windows(2).position(|w| w == b"\r\n").unwrap();
            let size =
                usize::from_str_radix(std::str::from_utf8(&body[..line_end]).unwrap().trim(), 16)
                    .unwrap();
            body = &body[line_end + 2..];
            if size == 0 {
                break;
            }
            framed.extend_from_slice(&body[..size]);
            body = &body[size + 2..];
        }

        let mut offset = 0usize;
        let mut frames = Vec::new();
        while offset < framed.len() {
            let len = u32::from_be_bytes(framed[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            frames.push(receiver.open(&framed[offset..offset + len], &[]).unwrap());
            offset += len;
        }
        (text, frames)
    }

    #[tokio::test]
    async fn body_stream_is_encrypted_lazily_into_bounded_frames() {
        // Three source items, one of 1 MiB: the core re-frames it into 64 KiB
        // frames and pulls the source as it goes.
        let pulls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pulls_for_stream = Arc::clone(&pulls);
        let chunks = vec![
            Bytes::from_static(b"first"),
            Bytes::from(vec![0x5Au8; 1024 * 1024]),
            Bytes::from_static(b"last"),
        ];
        let expected: Vec<u8> = chunks.concat();
        let source =
            stream::iter(chunks.into_iter().map(Ok::<Bytes, std::io::Error>)).inspect(move |_| {
                pulls_for_stream.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });

        let (raw, private_key) = capture_body_stream(source).await;
        let (text, frames) = captured_frames(&raw, &private_key);
        assert!(text.contains("transfer-encoding: chunked"));
        assert!(!text.contains("content-length:"));
        assert_eq!(frames.len(), 18, "5 B, 16 x 64 KiB, 4 B");
        assert!(frames.iter().all(|f| f.len() <= 65536));
        assert_eq!(frames.concat(), expected);
        assert_eq!(pulls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn empty_body_stream_is_a_bodyless_request() {
        let source = stream::iter(Vec::<std::result::Result<Bytes, std::io::Error>>::new());
        let (raw, _) = capture_body_stream(source).await;
        let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
        assert!(text.starts_with("post /secure"));
        assert!(!text.contains("ehbp-encapsulated-key:"), "{text}");
        assert!(!text.contains("transfer-encoding: chunked"), "{text}");
    }

    #[tokio::test]
    async fn session_recovery_token_is_readable_while_request_is_in_flight() {
        // A server that reads the request, then holds its reply: the token
        // must already be published while we wait (SPEC 6).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0u8; 4096];
            while !bytes.ends_with(b"0\r\n\r\n") {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..n]);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            socket
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let client = client_at(addr, keypair().0).await;
        let observer = client.clone();
        let (resp, in_flight) = tokio::join!(
            client
                .request("POST", "/secure", &[], Some(b"hi".to_vec().into())),
            async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                observer.session_recovery_token()
            }
        );
        assert!(
            in_flight.is_some(),
            "token must be published before the response arrives"
        );
        let resp = resp.unwrap();
        assert_eq!(resp.status().as_u16(), 502);
        // A nonce-less pass-through consumes the token.
        assert!(client.session_recovery_token().is_none());
    }

    // The generated printers of the secret-bearing datatypes are redacted by
    // dafny/patch-runtime.py (SECRET_TYPES): rendering a token, a context or a
    // value holding one must not expose key material.
    #[test]
    fn generated_printers_redact_secrets() {
        use crate::residue::{core_token, seq};
        let secret = [0xABu8; 32];
        let token = core_token(&secret, &secret);
        let ctx = ev::Ctx::Ctx { key: seq(&secret), baseNonce: seq(&[0; 12]), exporterSecret: seq(&secret), seqNo: 0 };
        let store = ev::SessionStore::SessionStore { generation: 1, token: Arc::new(core::Option::Some { value: token.clone() }) };
        let action = ev::Action::PublishToken { generation: 1, exportedSecret: seq(&secret), requestEnc: seq(&secret) };
        for rendered in [format!("{:?}", token), format!("{:?}", ctx), format!("{:?}", store), format!("{:?}", action)] {
            assert!(rendered.contains("(<redacted>)") && !rendered.contains("171"), "{rendered}");
        }
    }
}
