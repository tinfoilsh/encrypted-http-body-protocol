use bytes::{Bytes, BytesMut};
use futures_core::Stream;
#[cfg(not(target_arch = "wasm32"))]
use http_body_util::BodyExt;
#[cfg(not(target_arch = "wasm32"))]
use reqwest::ResponseBuilderExt;
use reqwest::{
    header::{
        HeaderMap, HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE, HOST, TRANSFER_ENCODING,
    },
    Method, StatusCode, Url,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use crate::{
    derive::{derive_response_keys, ResponseDecryptor},
    identity::ServerIdentity,
    protocol::{
        ENCAPSULATED_KEY_HEADER, KEYS_MEDIA_TYPE, KEYS_PATH, KEY_CONFIG_PROBLEM_TYPE,
        PROBLEM_JSON_MEDIA_TYPE, RESPONSE_NONCE_HEADER, RESPONSE_NONCE_LENGTH,
    },
    session::SessionRecoveryToken,
    Error, Result,
};

const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROBLEM_DETAILS_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct Client {
    base_url: Url,
    identity: ServerIdentity,
    http_client: reqwest::Client,
    session: Arc<Mutex<SessionState>>,
}

#[derive(Default)]
struct SessionState {
    generation: u64,
    token: Option<SessionRecoveryToken>,
}

impl Client {
    pub async fn new(base_url: impl AsRef<str>) -> Result<Self> {
        Self::new_with_http_client(base_url, default_http_client()?).await
    }

    pub async fn new_with_http_client(
        base_url: impl AsRef<str>,
        http_client: reqwest::Client,
    ) -> Result<Self> {
        let base_url = parse_base_url(base_url.as_ref())?;
        let keys_url = base_url.join(KEYS_PATH)?;
        let response = http_client.get(keys_url).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Protocol(format!(
                "server returned status {status} while fetching key configuration"
            )));
        }
        let content_type = media_type(response.headers());
        if content_type != KEYS_MEDIA_TYPE {
            return Err(Error::Protocol(format!(
                "server returned invalid key content type: {content_type}"
            )));
        }

        let config = read_response_body_capped(response, DEFAULT_MAX_RESPONSE_BYTES).await?;
        let identity = ServerIdentity::unmarshal_public_config(&config)?;
        Self::with_identity_and_http_client(base_url, identity, http_client)
    }

    pub fn with_config(base_url: impl AsRef<str>, hpke_config: &[u8]) -> Result<Self> {
        Self::with_config_and_http_client(base_url, hpke_config, default_http_client()?)
    }

    pub fn with_config_and_http_client(
        base_url: impl AsRef<str>,
        hpke_config: &[u8],
        http_client: reqwest::Client,
    ) -> Result<Self> {
        let identity = ServerIdentity::unmarshal_public_config(hpke_config)?;
        Self::with_identity_and_http_client(
            parse_base_url(base_url.as_ref())?,
            identity,
            http_client,
        )
    }

    pub fn with_public_key_hex(base_url: impl AsRef<str>, public_key_hex: &str) -> Result<Self> {
        Self::with_public_key_hex_and_http_client(base_url, public_key_hex, default_http_client()?)
    }

    pub fn with_public_key_hex_and_http_client(
        base_url: impl AsRef<str>,
        public_key_hex: &str,
        http_client: reqwest::Client,
    ) -> Result<Self> {
        let identity = ServerIdentity::from_public_key_hex(public_key_hex)?;
        Self::with_identity_and_http_client(
            parse_base_url(base_url.as_ref())?,
            identity,
            http_client,
        )
    }

    pub fn with_identity_and_http_client(
        base_url: Url,
        identity: ServerIdentity,
        http_client: reqwest::Client,
    ) -> Result<Self> {
        let base_url = normalize_base_url(base_url)?;
        Ok(Self {
            base_url,
            identity,
            http_client,
            session: Arc::new(Mutex::new(SessionState::default())),
        })
    }

    pub fn server_identity(&self) -> &ServerIdentity {
        &self.identity
    }

    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    pub fn get_session_recovery_token(&self) -> Option<SessionRecoveryToken> {
        self.session.lock().ok()?.token.clone()
    }

    pub fn take_session_recovery_token(&self) -> Option<SessionRecoveryToken> {
        self.session.lock().ok()?.token.take()
    }

    fn begin_request(&self) -> u64 {
        let mut state = self.session.lock().expect("session mutex poisoned");
        state.generation = state.generation.wrapping_add(1);
        state.token = None;
        state.generation
    }

    fn publish_session_recovery_token(&self, generation: u64, token: SessionRecoveryToken) {
        if let Ok(mut state) = self.session.lock() {
            if state.generation == generation {
                state.token = Some(token);
            }
        }
    }

    fn clear_session_recovery_token_if_current(&self, generation: u64) {
        clear_session_recovery_token_if_current(&self.session, generation);
    }

    pub fn request(&self, method: Method, path_or_url: impl AsRef<str>) -> Result<RequestBuilder> {
        Ok(RequestBuilder {
            client: self.clone(),
            method,
            url: self.resolve_url(path_or_url.as_ref())?,
            headers: HeaderMap::new(),
            body: None,
        })
    }

    pub fn get(&self, path_or_url: impl AsRef<str>) -> Result<RequestBuilder> {
        self.request(Method::GET, path_or_url)
    }

    pub fn post(&self, path_or_url: impl AsRef<str>) -> Result<RequestBuilder> {
        self.request(Method::POST, path_or_url)
    }

    pub fn put(&self, path_or_url: impl AsRef<str>) -> Result<RequestBuilder> {
        self.request(Method::PUT, path_or_url)
    }

    pub fn delete(&self, path_or_url: impl AsRef<str>) -> Result<RequestBuilder> {
        self.request(Method::DELETE, path_or_url)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn execute(&self, request: reqwest::Request) -> Result<reqwest::Response> {
        let PreparedRawRequest {
            request,
            token,
            generation,
        } = self.prepare_raw_request(request).await?;
        let mut guard = token
            .as_ref()
            .map(|_| SessionGuard::new(generation, Arc::clone(&self.session)));
        let response = match self.http_client.execute(request).await {
            Ok(response) => response,
            Err(err) => return Err(err.into()),
        };
        let response = self.open_raw_response(response, token, generation).await?;
        if let Some(guard) = guard.as_mut() {
            guard.disarm();
        }
        Ok(response)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn prepare_raw_request(
        &self,
        mut request: reqwest::Request,
    ) -> Result<PreparedRawRequest> {
        let generation = self.begin_request();
        self.validate_raw_request(&request)?;

        let Some(body) = request.body_mut().take() else {
            return Ok(PreparedRawRequest {
                request,
                token: None,
                generation,
            });
        };

        let mut plaintext = Box::pin(body.into_data_stream());
        let first_chunk = loop {
            match std::future::poll_fn(|cx| plaintext.as_mut().poll_next(cx)).await {
                Some(Ok(chunk)) if chunk.is_empty() => continue,
                Some(chunk) => break chunk?,
                None => {
                    return Ok(PreparedRawRequest {
                        request,
                        token: None,
                        generation,
                    });
                }
            }
        };
        let mut encryptor = self.identity.request_encryptor()?;
        let encapsulated_key = hex::encode(&encryptor.encapsulated_key);
        let token = encryptor.token.clone();
        let encrypted: Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>> =
            Box::pin(async_stream::try_stream! {
                yield Bytes::from(encryptor.encrypt_chunk(&first_chunk)?);
                while let Some(chunk) =
                    std::future::poll_fn(|cx| plaintext.as_mut().poll_next(cx)).await
                {
                    let chunk = chunk?;
                    if !chunk.is_empty() {
                        yield Bytes::from(encryptor.encrypt_chunk(&chunk)?);
                    }
                }
            });

        request.headers_mut().insert(
            header_name(ENCAPSULATED_KEY_HEADER)?,
            HeaderValue::from_str(&encapsulated_key)?,
        );
        request.headers_mut().remove(CONTENT_LENGTH);
        request.headers_mut().remove(TRANSFER_ENCODING);
        *request.body_mut() = Some(reqwest::Body::wrap_stream(encrypted));
        self.publish_session_recovery_token(generation, token.clone());

        Ok(PreparedRawRequest {
            request,
            token: Some(token),
            generation,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn open_raw_response(
        &self,
        mut response: reqwest::Response,
        token: Option<SessionRecoveryToken>,
        generation: u64,
    ) -> Result<reqwest::Response> {
        let Some(token) = token else {
            return Ok(response);
        };

        let version = response.version();
        let url = response.url().clone();
        let extensions = std::mem::take(response.extensions_mut());
        let opened = self
            .open_encrypted_response(response, token, generation)
            .await?;
        let mut builder = http::Response::builder()
            .status(opened.status)
            .version(version);
        if let Some(target) = builder.headers_mut() {
            *target = opened.headers;
        }
        if let Some(target) = builder.extensions_mut() {
            *target = extensions;
        }
        let rebuilt = builder
            .url(url)
            .body(reqwest::Body::wrap_stream(opened.body))
            .map_err(|err| Error::Protocol(format!("failed to rebuild response: {err}")))?;
        Ok(reqwest::Response::from(rebuilt))
    }

    async fn open_encrypted_response(
        &self,
        response: reqwest::Response,
        token: SessionRecoveryToken,
        generation: u64,
    ) -> Result<OpenedEncryptedResponse> {
        let mut guard = SessionGuard::new(generation, Arc::clone(&self.session));
        let status = response.status();
        let mut headers = response.headers().clone();

        if !headers.contains_key(RESPONSE_NONCE_HEADER) {
            if status.is_success() {
                return Err(Error::Protocol(format!(
                    "missing {RESPONSE_NONCE_HEADER} header"
                )));
            }

            let body = if is_problem_json_status(status, &headers) {
                inspect_problem_response(response, status, &headers).await?
            } else {
                Box::pin(response.bytes_stream().map_reqwest_error())
            };
            return Ok(OpenedEncryptedResponse {
                status,
                headers,
                body,
            });
        }

        let response_nonce = response_nonce(&headers)?;
        let key_material =
            derive_response_keys(&token.exported_secret, &token.request_enc, &response_nonce)?;
        strip_encrypted_framing_headers(&mut headers);
        let body = Box::pin(SessionClearingStream {
            inner: Box::pin(decrypt_response_stream(
                response.bytes_stream(),
                key_material,
            )),
            generation,
            session: Arc::clone(&self.session),
            cleared: false,
        });
        guard.disarm();

        Ok(OpenedEncryptedResponse {
            status,
            headers,
            body,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn validate_raw_request(&self, request: &reqwest::Request) -> Result<()> {
        self.validate_request_url(request.url())?;
        for name in request.headers().keys() {
            if is_reserved_raw_request_header(name) {
                return Err(Error::InvalidInput(format!(
                    "reserved request header cannot be set by callers: {name}"
                )));
            }
        }
        Ok(())
    }

    async fn send_parts(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Bytes>,
    ) -> Result<Response> {
        let PreparedRequest {
            request,
            token,
            generation,
        } = self.prepare_request_builder(method, url, headers, body)?;
        let mut guard = token
            .as_ref()
            .map(|_| SessionGuard::new(generation, Arc::clone(&self.session)));
        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = read_response_body_capped(response, DEFAULT_MAX_RESPONSE_BYTES).await?;

        let Some(token) = token else {
            return Ok(Response {
                status,
                headers,
                body,
            });
        };

        if !headers.contains_key(RESPONSE_NONCE_HEADER) {
            check_key_config_mismatch(status, &headers, &body)?;
            if !status.is_success() {
                return Ok(Response {
                    status,
                    headers,
                    body,
                });
            }
        }

        let response_nonce = response_nonce(&headers)?;
        let decrypted = token.decrypt_response_body(&response_nonce, &body)?;
        self.clear_session_recovery_token_if_current(generation);
        if let Some(guard) = guard.as_mut() {
            guard.disarm();
        }

        let mut headers = headers;
        strip_encrypted_framing_headers(&mut headers);
        Ok(Response {
            status,
            headers,
            body: Bytes::from(decrypted),
        })
    }

    async fn send_stream_parts(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Bytes>,
    ) -> Result<StreamingResponse> {
        let PreparedRequest {
            request,
            token,
            generation,
        } = self.prepare_request_builder(method, url, headers, body)?;
        let mut guard = token
            .as_ref()
            .map(|_| SessionGuard::new(generation, Arc::clone(&self.session)));
        let response = request.send().await?;

        let Some(token) = token else {
            return Ok(StreamingResponse {
                status: response.status(),
                headers: response.headers().clone(),
                body: Box::pin(response.bytes_stream().map_reqwest_error()),
            });
        };

        let opened = self
            .open_encrypted_response(response, token, generation)
            .await?;
        if let Some(guard) = guard.as_mut() {
            guard.disarm();
        }
        Ok(StreamingResponse {
            status: opened.status,
            headers: opened.headers,
            body: opened.body,
        })
    }

    fn prepare_request_builder(
        &self,
        method: Method,
        url: Url,
        mut headers: HeaderMap,
        body: Option<Bytes>,
    ) -> Result<PreparedRequest> {
        let plaintext_body = body.unwrap_or_default();
        let generation = self.begin_request();
        let encrypted = self.identity.encrypt_request_body(&plaintext_body)?;

        let mut request = self.http_client.request(method, url);
        let token = if let Some(encrypted) = encrypted {
            headers.insert(
                header_name(ENCAPSULATED_KEY_HEADER)?,
                HeaderValue::from_str(&hex::encode(&encrypted.encapsulated_key))?,
            );
            let token = encrypted.token;
            self.publish_session_recovery_token(generation, token.clone());
            request = request
                .headers(headers)
                .body(encrypted_reqwest_body(encrypted.body));
            Some(token)
        } else {
            request = request.headers(headers);
            None
        };

        Ok(PreparedRequest {
            request,
            token,
            generation,
        })
    }

    fn resolve_url(&self, path_or_url: &str) -> Result<Url> {
        let url = self.base_url.join(path_or_url)?;
        self.validate_request_url(&url)?;
        Ok(url)
    }

    fn validate_request_url(&self, url: &Url) -> Result<()> {
        if !same_origin(&self.base_url, url) {
            return Err(Error::InvalidInput(format!(
                "request URL must use the configured origin: {}",
                self.base_url.origin().ascii_serialization()
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::InvalidInput(
                "request URL must not include credentials".into(),
            ));
        }
        Ok(())
    }
}

pub struct RequestBuilder {
    client: Client,
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Option<Bytes>,
}

struct PreparedRequest {
    request: reqwest::RequestBuilder,
    token: Option<SessionRecoveryToken>,
    generation: u64,
}

#[cfg(not(target_arch = "wasm32"))]
struct PreparedRawRequest {
    request: reqwest::Request,
    token: Option<SessionRecoveryToken>,
    generation: u64,
}

struct OpenedEncryptedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>,
}

impl RequestBuilder {
    pub fn header<K, V>(mut self, name: K, value: V) -> Result<Self>
    where
        K: TryInto<HeaderName>,
        K::Error: std::fmt::Display,
        V: TryInto<HeaderValue>,
        V::Error: std::fmt::Display,
    {
        let name = name
            .try_into()
            .map_err(|err| Error::InvalidInput(format!("invalid header name: {err}")))?;
        if is_reserved_request_header(&name) {
            return Err(Error::InvalidInput(format!(
                "reserved request header cannot be set by callers: {name}"
            )));
        }
        let value = value
            .try_into()
            .map_err(|err| Error::InvalidInput(format!("invalid header value: {err}")))?;
        self.headers.insert(name, value);
        Ok(self)
    }

    pub fn bearer_auth(self, token: &str) -> Result<Self> {
        let value = HeaderValue::from_str(&format!("Bearer {token}"))?;
        self.header(HeaderName::from_static("authorization"), value)
    }

    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn json<T: Serialize + ?Sized>(mut self, value: &T) -> Result<Self> {
        let body = serde_json::to_vec(value)?;
        self.headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        self.body = Some(Bytes::from(body));
        Ok(self)
    }

    pub async fn send(self) -> Result<Response> {
        self.client
            .send_parts(self.method, self.url, self.headers, self.body)
            .await
    }

    pub async fn send_stream(self) -> Result<StreamingResponse> {
        self.client
            .send_stream_parts(self.method, self.url, self.headers, self.body)
            .await
    }
}

pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

pub struct StreamingResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>,
}

impl StreamingResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn into_stream(self) -> Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>> {
        self.body
    }
}

impl Response {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn bytes(&self) -> Bytes {
        self.body.clone()
    }

    pub fn text(self) -> Result<String> {
        String::from_utf8(self.body.to_vec()).map_err(Error::from)
    }

    pub fn json<T: DeserializeOwned>(self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(Error::from)
    }
}

fn parse_base_url(base_url: &str) -> Result<Url> {
    normalize_base_url(Url::parse(base_url)?)
}

fn default_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(Error::from)
}

fn normalize_base_url(mut url: Url) -> Result<Url> {
    if url.cannot_be_a_base() || url.host_str().is_none() {
        return Err(Error::InvalidInput(
            "base URL must include an HTTP origin".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::InvalidInput(
            "base URL must not include credentials".into(),
        ));
    }
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(Error::InvalidInput(
            "base URL scheme must be http or https".into(),
        ));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn header_name(name: &str) -> Result<HeaderName> {
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|err| Error::InvalidInput(format!("invalid protocol header name: {err}")))
}

fn is_reserved_request_header(name: &HeaderName) -> bool {
    name == CONTENT_LENGTH
        || name == TRANSFER_ENCODING
        || name == HOST
        || name.as_str().eq_ignore_ascii_case(ENCAPSULATED_KEY_HEADER)
        || name.as_str().eq_ignore_ascii_case(RESPONSE_NONCE_HEADER)
}

#[cfg(not(target_arch = "wasm32"))]
fn is_reserved_raw_request_header(name: &HeaderName) -> bool {
    name == HOST
        || name.as_str().eq_ignore_ascii_case(ENCAPSULATED_KEY_HEADER)
        || name.as_str().eq_ignore_ascii_case(RESPONSE_NONCE_HEADER)
}

fn encrypted_reqwest_body(body: Vec<u8>) -> reqwest::Body {
    reqwest::Body::wrap_stream(async_stream::stream! {
        yield Ok::<Bytes, std::io::Error>(Bytes::from(body));
    })
}

fn clear_session_recovery_token_if_current(session: &Arc<Mutex<SessionState>>, generation: u64) {
    if let Ok(mut state) = session.lock() {
        if state.generation == generation {
            state.token = None;
        }
    }
}

/// Removes framing headers that describe the encrypted body. The decrypted
/// body has a different length, so consumers that forward the response
/// headers verbatim (for example a proxy) would otherwise announce a body
/// length that no longer matches what is written, truncating the reply.
fn strip_encrypted_framing_headers(headers: &mut HeaderMap) {
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
}

fn response_nonce(headers: &HeaderMap) -> Result<Vec<u8>> {
    let mut values = headers.get_all(RESPONSE_NONCE_HEADER).iter();
    let nonce = values
        .next()
        .ok_or_else(|| Error::Protocol(format!("missing {RESPONSE_NONCE_HEADER} header")))?;
    if values.next().is_some() {
        return Err(Error::Protocol(format!(
            "multiple {RESPONSE_NONCE_HEADER} headers"
        )));
    }
    let nonce = nonce
        .to_str()
        .map_err(|err| Error::Protocol(format!("invalid response nonce header: {err}")))?;
    let nonce = hex::decode(nonce)?;
    if nonce.len() != RESPONSE_NONCE_LENGTH {
        return Err(Error::Protocol(format!(
            "invalid response nonce length: expected {RESPONSE_NONCE_LENGTH}, got {}",
            nonce.len()
        )));
    }
    Ok(nonce)
}

fn check_key_config_mismatch(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> Result<()> {
    if !is_problem_json_status(status, headers) {
        return Ok(());
    }

    if status.as_u16() != 422 {
        return Ok(());
    }

    let media_type = media_type(headers);
    if media_type != PROBLEM_JSON_MEDIA_TYPE {
        return Ok(());
    }
    if body.len() > MAX_PROBLEM_DETAILS_BYTES {
        return Ok(());
    }

    let Ok(problem) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Ok(());
    };
    if problem.get("type").and_then(|value| value.as_str()) == Some(KEY_CONFIG_PROBLEM_TYPE) {
        let title = problem
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("key configuration mismatch");
        return Err(Error::KeyConfigMismatch(title.to_owned()));
    }

    Ok(())
}

async fn inspect_problem_response(
    response: reqwest::Response,
    status: StatusCode,
    headers: &HeaderMap,
) -> Result<Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>> {
    let mut stream = Box::pin(response.bytes_stream());
    let mut prefix = BytesMut::with_capacity(MAX_PROBLEM_DETAILS_BYTES + 1);

    while prefix.len() <= MAX_PROBLEM_DETAILS_BYTES {
        let Some(chunk) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await else {
            let body = prefix.freeze();
            check_key_config_mismatch(status, headers, &body)?;
            return Ok(Box::pin(async_stream::stream! {
                yield Ok(body);
            }));
        };
        let chunk = chunk?;
        let remaining = MAX_PROBLEM_DETAILS_BYTES + 1 - prefix.len();
        if chunk.len() <= remaining {
            prefix.extend_from_slice(&chunk);
        } else {
            prefix.extend_from_slice(&chunk[..remaining]);
            let tail = chunk.slice(remaining..);
            let prefix = prefix.freeze();
            return Ok(Box::pin(async_stream::try_stream! {
                yield prefix;
                if !tail.is_empty() {
                    yield tail;
                }
                while let Some(chunk) =
                    std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
                {
                    yield chunk?;
                }
            }));
        }

        if prefix.len() > MAX_PROBLEM_DETAILS_BYTES {
            let prefix = prefix.freeze();
            return Ok(Box::pin(async_stream::try_stream! {
                yield prefix;
                while let Some(chunk) =
                    std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
                {
                    yield chunk?;
                }
            }));
        }
    }

    unreachable!()
}

fn is_problem_json_status(status: StatusCode, headers: &HeaderMap) -> bool {
    status.as_u16() == 422 && media_type(headers) == PROBLEM_JSON_MEDIA_TYPE
}

fn media_type(headers: &HeaderMap) -> String {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

async fn read_response_body_capped(
    response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<Bytes> {
    collect_response_stream_capped(response.bytes_stream(), max_response_bytes).await
}

async fn collect_response_stream_capped<S>(stream: S, max_response_bytes: usize) -> Result<Bytes>
where
    S: Stream<Item = reqwest::Result<Bytes>>,
{
    let mut stream = Box::pin(stream);
    let mut body = BytesMut::new();

    while let Some(chunk) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
        let chunk = chunk?;
        let new_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| Error::Protocol("response body size overflow".into()))?;
        if new_len > max_response_bytes {
            return Err(Error::Protocol(
                "response body exceeds maximum allowed size".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body.freeze())
}

struct SessionClearingStream {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>,
    generation: u64,
    session: Arc<Mutex<SessionState>>,
    cleared: bool,
}

struct SessionGuard {
    generation: u64,
    session: Arc<Mutex<SessionState>>,
    active: bool,
}

impl SessionGuard {
    fn new(generation: u64, session: Arc<Mutex<SessionState>>) -> Self {
        Self {
            generation,
            session,
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if self.active {
            clear_session_recovery_token_if_current(&self.session, self.generation);
        }
    }
}

impl SessionClearingStream {
    fn clear_if_current(&mut self) {
        if !self.cleared {
            clear_session_recovery_token_if_current(&self.session, self.generation);
            self.cleared = true;
        }
    }
}

impl Stream for SessionClearingStream {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(None) => {
                self.clear_if_current();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                self.clear_if_current();
                Poll::Ready(Some(Err(err)))
            }
            other => other,
        }
    }
}

impl Drop for SessionClearingStream {
    fn drop(&mut self) {
        self.clear_if_current();
    }
}

fn decrypt_response_stream(
    mut stream: impl Stream<Item = reqwest::Result<Bytes>> + Send + Unpin + 'static,
    key_material: crate::derive::ResponseKeyMaterial,
) -> impl Stream<Item = Result<Bytes>> + Send {
    async_stream::try_stream! {
        let mut decryptor = ResponseDecryptor::from_key_material(key_material);

        while let Some(chunk) = poll_next(&mut stream).await {
            let chunk = chunk?;
            decryptor.feed(&chunk);
            while let Some(plaintext) = decryptor.next_frame()? {
                yield Bytes::from(plaintext);
            }
        }

        decryptor.finish()?;
    }
}

async fn poll_next<S>(stream: &mut S) -> Option<S::Item>
where
    S: Stream + Unpin,
{
    std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

trait MapReqwestError: Stream<Item = reqwest::Result<Bytes>> + Sized + Send + 'static {
    fn map_reqwest_error(self) -> Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>;
}

impl<T> MapReqwestError for T
where
    T: Stream<Item = reqwest::Result<Bytes>> + Send + 'static,
{
    fn map_reqwest_error(self) -> Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>> {
        Box::pin(async_stream::try_stream! {
            let mut stream = Box::pin(self);
            while let Some(chunk) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
                yield chunk?;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{stream, StreamExt};
    use serde::Deserialize;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ResponseVector {
        exported_secret: String,
        request_enc: String,
        response_nonce: String,
        plaintext: String,
        encrypted_response: String,
    }

    struct DropTrackedResponseStream {
        first: Option<Bytes>,
        dropped: Arc<AtomicBool>,
    }

    impl Stream for DropTrackedResponseStream {
        type Item = reqwest::Result<Bytes>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.first.take() {
                Some(chunk) => Poll::Ready(Some(Ok(chunk))),
                None => Poll::Pending,
            }
        }
    }

    impl Drop for DropTrackedResponseStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn streaming_decryption_handles_fragmented_frames() {
        let vector: ResponseVector =
            serde_json::from_str(include_str!("../../test-vectors/response-decryption.json"))
                .unwrap();
        let key_material = derive_response_keys(
            &hex::decode(vector.exported_secret).unwrap(),
            &hex::decode(vector.request_enc).unwrap(),
            &hex::decode(vector.response_nonce).unwrap(),
        )
        .unwrap();

        let mut framed = vec![0, 0, 0, 0];
        framed.extend_from_slice(&hex::decode(vector.encrypted_response).unwrap());
        let chunks: Vec<_> = framed
            .chunks(3)
            .map(|chunk| Ok::<Bytes, reqwest::Error>(Bytes::copy_from_slice(chunk)))
            .collect();
        let mut stream = Box::pin(decrypt_response_stream(stream::iter(chunks), key_material));

        let mut plaintext = Vec::new();
        while let Some(chunk) = stream.next().await {
            plaintext.extend_from_slice(&chunk.unwrap());
        }

        assert_eq!(hex::encode(plaintext), vector.plaintext);
    }

    #[tokio::test]
    async fn streaming_decryption_delivers_before_eof_and_cancels_source() {
        let vector: ResponseVector =
            serde_json::from_str(include_str!("../../test-vectors/response-decryption.json"))
                .unwrap();
        let key_material = derive_response_keys(
            &hex::decode(vector.exported_secret).unwrap(),
            &hex::decode(vector.request_enc).unwrap(),
            &hex::decode(vector.response_nonce).unwrap(),
        )
        .unwrap();
        let source_dropped = Arc::new(AtomicBool::new(false));
        let source = DropTrackedResponseStream {
            first: Some(Bytes::from(hex::decode(vector.encrypted_response).unwrap())),
            dropped: Arc::clone(&source_dropped),
        };
        let mut decrypted = Box::pin(decrypt_response_stream(source, key_material));

        let plaintext = decrypted
            .next()
            .await
            .expect("first frame should be delivered without source EOF")
            .unwrap();
        assert_eq!(hex::encode(plaintext), vector.plaintext);
        assert!(!source_dropped.load(Ordering::SeqCst));

        drop(decrypted);
        assert!(source_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn streaming_decryption_yields_before_processing_later_frames() {
        use aes_gcm::{
            aead::{Aead as _, KeyInit as _, Payload},
            Aes256Gcm, Nonce,
        };

        let vector: ResponseVector =
            serde_json::from_str(include_str!("../../test-vectors/response-decryption.json"))
                .unwrap();
        let key_material = derive_response_keys(
            &hex::decode(vector.exported_secret).unwrap(),
            &hex::decode(vector.request_enc).unwrap(),
            &hex::decode(vector.response_nonce).unwrap(),
        )
        .unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key_material.key).unwrap();
        let nonce = crate::derive::compute_nonce(&key_material.nonce_base, 1);
        let mut second = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: b"second",
                    aad: &[],
                },
            )
            .unwrap();
        *second.last_mut().unwrap() ^= 1;

        let mut coalesced = hex::decode(vector.encrypted_response).unwrap();
        coalesced.extend_from_slice(&crate::derive::frame_chunk(&second).unwrap());
        let source = stream::iter([Ok::<Bytes, reqwest::Error>(Bytes::from(coalesced))]);
        let mut decrypted = Box::pin(decrypt_response_stream(source, key_material));

        let first = decrypted.next().await.unwrap().unwrap();
        assert_eq!(hex::encode(first), vector.plaintext);
        assert!(matches!(
            decrypted.next().await.unwrap(),
            Err(Error::Crypto(_))
        ));
    }

    #[tokio::test]
    async fn capped_body_read_rejects_oversized_response() {
        let chunks = stream::iter([Ok::<Bytes, reqwest::Error>(Bytes::from_static(b"12345"))]);
        let err = collect_response_stream_capped(chunks, 4)
            .await
            .err()
            .unwrap();

        assert!(matches!(
            err,
            Error::Protocol(message) if message.contains("exceeds maximum allowed size")
        ));
    }

    #[tokio::test]
    async fn oversized_problem_diagnostics_remain_streaming_passthrough() {
        let body = Bytes::from(format!(
            r#"{{"type":"{KEY_CONFIG_PROBLEM_TYPE}","title":"{}"}}"#,
            "x".repeat(MAX_PROBLEM_DETAILS_BYTES)
        ));
        let response = reqwest::Response::from(
            http::Response::builder()
                .status(StatusCode::UNPROCESSABLE_ENTITY)
                .header(CONTENT_TYPE, PROBLEM_JSON_MEDIA_TYPE)
                .body(reqwest::Body::from(body.clone()))
                .unwrap(),
        );
        let status = response.status();
        let headers = response.headers().clone();

        let streamed = inspect_problem_response(response, status, &headers)
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()
            .unwrap()
            .concat();

        assert_eq!(streamed, body);
    }

    #[tokio::test]
    async fn streaming_rejects_oversized_chunk_length() {
        let key_material = crate::derive::ResponseKeyMaterial {
            key: [0u8; crate::protocol::AES256_KEY_LENGTH],
            nonce_base: [0u8; crate::protocol::AES_GCM_NONCE_LENGTH],
        };
        // A length prefix declaring a ~4 GiB chunk must be rejected before buffering.
        let framed = Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        let chunks = stream::iter([Ok::<Bytes, reqwest::Error>(framed)]);
        let mut stream = Box::pin(decrypt_response_stream(chunks, key_material));

        let err = stream
            .next()
            .await
            .expect("stream should yield an item")
            .unwrap_err();

        assert!(matches!(
            err,
            Error::Protocol(message) if message.contains("exceeds maximum allowed size")
        ));
    }

    #[tokio::test]
    async fn send_failure_clears_session_recovery_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let identity = ServerIdentity::from_public_key_bytes(&[7u8; 32]).unwrap();
        let client = Client::with_identity_and_http_client(
            Url::parse(&format!("http://{addr}/")).unwrap(),
            identity,
            reqwest::Client::new(),
        )
        .unwrap();

        let result = client.post("/secure").unwrap().body("secret").send().await;

        assert!(result.is_err());
        assert!(client.get_session_recovery_token().is_none());
    }

    async fn client_with_unencrypted_response(status: StatusCode) -> Client {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..n]);
                if bytes.windows(5).any(|window| window == b"0\r\n\r\n") {
                    break;
                }
            }

            let body = b"upstream unavailable";
            let header = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nX-Upstream: proxy\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status.as_u16(),
                status.canonical_reason().unwrap(),
                body.len(),
            );
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(body).await.unwrap();
        });

        let identity = ServerIdentity::from_public_key_bytes(&[7u8; 32]).unwrap();
        Client::with_identity_and_http_client(
            Url::parse(&format!("http://{addr}/")).unwrap(),
            identity,
            reqwest::Client::new(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn buffered_transport_passes_through_unencrypted_http_errors() {
        let client = client_with_unencrypted_response(StatusCode::BAD_GATEWAY).await;

        let response = client
            .post("/secure")
            .unwrap()
            .body("secret")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/plain");
        assert_eq!(response.headers()["x-upstream"], "proxy");
        assert_eq!(response.text().unwrap(), "upstream unavailable");
        assert!(client.get_session_recovery_token().is_none());
    }

    #[tokio::test]
    async fn streaming_transport_passes_through_unencrypted_http_errors() {
        let client = client_with_unencrypted_response(StatusCode::TOO_MANY_REQUESTS).await;

        let response = client
            .post("/secure")
            .unwrap()
            .body("secret")
            .send_stream()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/plain");
        assert_eq!(response.headers()["x-upstream"], "proxy");
        assert!(client.get_session_recovery_token().is_none());
        let body = response
            .into_stream()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()
            .unwrap()
            .concat();
        assert_eq!(body, b"upstream unavailable");
        assert!(client.get_session_recovery_token().is_none());
    }

    #[tokio::test]
    async fn buffered_transport_rejects_unencrypted_successes() {
        let client = client_with_unencrypted_response(StatusCode::OK).await;

        let err = client
            .post("/secure")
            .unwrap()
            .body("secret")
            .send()
            .await
            .err()
            .unwrap();

        assert!(matches!(
            err,
            Error::Protocol(message) if message.contains(RESPONSE_NONCE_HEADER)
        ));
        assert!(client.get_session_recovery_token().is_none());
    }

    #[tokio::test]
    async fn streaming_transport_rejects_unencrypted_successes() {
        let client = client_with_unencrypted_response(StatusCode::OK).await;

        let err = client
            .post("/secure")
            .unwrap()
            .body("secret")
            .send_stream()
            .await
            .err()
            .unwrap();

        assert!(matches!(
            err,
            Error::Protocol(message) if message.contains(RESPONSE_NONCE_HEADER)
        ));
        assert!(client.get_session_recovery_token().is_none());
    }

    fn dummy_client() -> Client {
        let identity = ServerIdentity::from_public_key_bytes(&[7u8; 32]).unwrap();
        Client::with_identity_and_http_client(
            Url::parse("https://example.com/").unwrap(),
            identity,
            reqwest::Client::new(),
        )
        .unwrap()
    }

    type TestPrivateKey = <hpke::kem::X25519HkdfSha256 as hpke::kem::Kem>::PrivateKey;

    fn raw_client_with_private_key() -> (Client, TestPrivateKey) {
        use hpke::{
            kem::{Kem as _, X25519HkdfSha256},
            Serializable as _,
        };
        use rand::{rngs::StdRng, SeedableRng as _};

        let mut csprng = StdRng::from_os_rng();
        let (private_key, public_key) = X25519HkdfSha256::gen_keypair(&mut csprng);
        let identity = ServerIdentity::from_public_key_bytes(&public_key.to_bytes()).unwrap();
        let client = Client::with_identity_and_http_client(
            Url::parse("https://example.com/").unwrap(),
            identity,
            reqwest::Client::new(),
        )
        .unwrap();
        (client, private_key)
    }

    fn decrypt_request_frames(
        private_key: &TestPrivateKey,
        request_enc: &[u8],
        framed: &[u8],
    ) -> Vec<Vec<u8>> {
        use hpke::{
            aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver,
            Deserializable as _, OpModeR,
        };

        let encapped_key =
            <X25519HkdfSha256 as hpke::kem::Kem>::EncappedKey::from_bytes(request_enc).unwrap();
        let mut receiver = setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            private_key,
            &encapped_key,
            crate::protocol::HPKE_REQUEST_INFO,
        )
        .unwrap();
        let mut offset = 0usize;
        let mut plaintext = Vec::new();

        while offset < framed.len() {
            let chunk_len = u32::from_be_bytes(
                framed[offset..offset + 4]
                    .try_into()
                    .expect("frame must include a length"),
            ) as usize;
            offset += 4;
            let chunk = &framed[offset..offset + chunk_len];
            offset += chunk_len;
            plaintext.push(receiver.open(chunk, &[]).unwrap());
        }

        plaintext
    }

    #[tokio::test]
    async fn raw_transport_encrypts_streaming_request_chunks() {
        let (client, private_key) = raw_client_with_private_key();
        let plaintext = stream::iter([
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"first")),
            Ok(Bytes::new()),
            Ok(Bytes::from_static(b"second")),
        ]);
        let request = reqwest::Client::new()
            .post("https://example.com/v1/audio")
            .body(reqwest::Body::wrap_stream(plaintext))
            .build()
            .unwrap();

        let mut prepared = client.prepare_raw_request(request).await.unwrap();
        let token = prepared.token.unwrap();
        let request_enc = hex::decode(
            prepared.request.headers()[ENCAPSULATED_KEY_HEADER]
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let body = prepared
            .request
            .body_mut()
            .take()
            .unwrap()
            .collect()
            .await
            .unwrap()
            .to_bytes();

        assert_eq!(request_enc, token.request_enc);
        assert!(prepared.request.headers().get(CONTENT_LENGTH).is_none());
        assert_eq!(
            decrypt_request_frames(&private_key, &request_enc, &body),
            [b"first".to_vec(), b"second".to_vec()]
        );
    }

    #[tokio::test]
    async fn raw_transport_encrypts_streaming_multipart_requests() {
        let (client, private_key) = raw_client_with_private_key();
        let file = stream::iter([
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"audio-")),
            Ok(Bytes::from_static(b"payload")),
        ]);
        let form = reqwest::multipart::Form::new()
            .text("model", "gpt-oss-120b")
            .part(
                "file",
                reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(file))
                    .file_name("sample.wav"),
            );
        let request = reqwest::Client::new()
            .post("https://example.com/v1/audio/transcriptions")
            .multipart(form)
            .build()
            .unwrap();

        let mut prepared = client.prepare_raw_request(request).await.unwrap();
        let request_enc = hex::decode(
            prepared.request.headers()[ENCAPSULATED_KEY_HEADER]
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let body = prepared
            .request
            .body_mut()
            .take()
            .unwrap()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let chunks = decrypt_request_frames(&private_key, &request_enc, &body);
        let plaintext = chunks.concat();
        let plaintext = String::from_utf8(plaintext).unwrap();

        assert!(chunks.len() > 1);
        assert!(plaintext.contains("name=\"model\""));
        assert!(plaintext.contains("gpt-oss-120b"));
        assert!(plaintext.contains("filename=\"sample.wav\""));
        assert!(plaintext.contains("audio-payload"));
        assert!(prepared.request.headers().get(CONTENT_LENGTH).is_none());
        assert!(prepared.request.headers().get(CONTENT_TYPE).is_some());
    }

    #[tokio::test]
    async fn raw_transport_preserves_decrypted_response_metadata() {
        use aes_gcm::{
            aead::{Aead as _, KeyInit as _, Payload},
            Aes256Gcm, Nonce,
        };

        #[derive(Clone, Debug, PartialEq)]
        struct Marker(u8);

        let (client, _) = raw_client_with_private_key();
        let request = reqwest::Client::new()
            .post("https://example.com/v1/chat")
            .body("secret")
            .build()
            .unwrap();
        let prepared = client.prepare_raw_request(request).await.unwrap();
        let generation = prepared.generation;
        let token = prepared.token.unwrap();
        let response_nonce = [9u8; RESPONSE_NONCE_LENGTH];
        let key_material =
            derive_response_keys(&token.exported_secret, &token.request_enc, &response_nonce)
                .unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key_material.key).unwrap();
        let nonce = crate::derive::compute_nonce(&key_material.nonce_base, 0);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: b"decrypted reply",
                    aad: &[],
                },
            )
            .unwrap();
        let body = crate::derive::frame_chunk(&ciphertext).unwrap();
        let url = Url::parse("https://example.com/v1/chat").unwrap();
        let response = http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .url(url.clone())
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, body.len())
            .header(RESPONSE_NONCE_HEADER, hex::encode(response_nonce))
            .body(reqwest::Body::from(body))
            .unwrap();
        let mut response = reqwest::Response::from(response);
        response.extensions_mut().insert(Marker(7));

        let response = client
            .open_raw_response(response, Some(token), generation)
            .await
            .unwrap();

        assert_eq!(response.url(), &url);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.extensions().get::<Marker>(), Some(&Marker(7)));
        assert_eq!(response.headers()[CONTENT_TYPE], "text/plain");
        assert!(response.headers().get(CONTENT_LENGTH).is_none());
        assert!(client.get_session_recovery_token().is_some());
        assert_eq!(response.bytes().await.unwrap(), "decrypted reply");
        assert!(client.get_session_recovery_token().is_none());
    }

    #[tokio::test]
    async fn raw_transport_returns_typed_key_config_mismatch() {
        let (client, _) = raw_client_with_private_key();
        let request = reqwest::Client::new()
            .post("https://example.com/v1/chat")
            .body("secret")
            .build()
            .unwrap();
        let prepared = client.prepare_raw_request(request).await.unwrap();
        let response = http::Response::builder()
            .status(StatusCode::UNPROCESSABLE_ENTITY)
            .header(CONTENT_TYPE, "Application/Problem+Json; charset=utf-8")
            .body(reqwest::Body::from(format!(
                r#"{{"type":"{KEY_CONFIG_PROBLEM_TYPE}","title":"rotate key"}}"#
            )))
            .unwrap();
        let response = reqwest::Response::from(response);

        let err = client
            .open_raw_response(response, prepared.token, prepared.generation)
            .await
            .unwrap_err();

        assert!(matches!(err, Error::KeyConfigMismatch(title) if title == "rotate key"));
        assert!(client.get_session_recovery_token().is_none());
    }

    #[tokio::test]
    async fn raw_transport_passes_through_unencrypted_http_errors() {
        let (client, _) = raw_client_with_private_key();
        let request = reqwest::Client::new()
            .post("https://example.com/v1/chat")
            .body("secret")
            .build()
            .unwrap();
        let prepared = client.prepare_raw_request(request).await.unwrap();
        let url = Url::parse("https://example.com/v1/chat").unwrap();
        let response = http::Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .url(url.clone())
            .header(CONTENT_TYPE, "text/plain")
            .header("x-upstream", "proxy")
            .body(reqwest::Body::from("upstream unavailable"))
            .unwrap();

        let response = client
            .open_raw_response(
                reqwest::Response::from(response),
                prepared.token,
                prepared.generation,
            )
            .await
            .unwrap();

        assert_eq!(response.url(), &url);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/plain");
        assert_eq!(response.headers()["x-upstream"], "proxy");
        assert_eq!(
            response.bytes().await.unwrap(),
            Bytes::from_static(b"upstream unavailable")
        );
        assert!(client.get_session_recovery_token().is_none());
    }

    #[tokio::test]
    async fn older_raw_response_error_preserves_newer_recovery_token() {
        let (client, _) = raw_client_with_private_key();
        let build_request = || {
            reqwest::Client::new()
                .post("https://example.com/v1/chat")
                .body("secret")
                .build()
                .unwrap()
        };
        let first = client.prepare_raw_request(build_request()).await.unwrap();
        let first_generation = first.generation;
        let first_token = first.token.unwrap();
        let second = client.prepare_raw_request(build_request()).await.unwrap();
        let second_token = second.token.unwrap();
        let response = reqwest::Response::from(
            http::Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(reqwest::Body::from("missing nonce"))
                .unwrap(),
        );

        let response = client
            .open_raw_response(response, Some(first_token), first_generation)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            client.get_session_recovery_token().as_ref(),
            Some(&second_token)
        );
    }

    #[tokio::test]
    async fn raw_transport_rejects_unsafe_request_identity() {
        let (client, _) = raw_client_with_private_key();
        let cross_origin = reqwest::Client::new()
            .post("https://evil.example/v1/chat")
            .body("secret")
            .build()
            .unwrap();
        assert!(client.prepare_raw_request(cross_origin).await.is_err());

        let credential_url = reqwest::Request::new(
            Method::POST,
            Url::parse("https://user@example.com/v1/chat").unwrap(),
        );
        assert!(client.prepare_raw_request(credential_url).await.is_err());

        let reserved_header = reqwest::Client::new()
            .post("https://example.com/v1/chat")
            .header(ENCAPSULATED_KEY_HEADER, "00")
            .body("secret")
            .build()
            .unwrap();
        assert!(client.prepare_raw_request(reserved_header).await.is_err());
    }

    #[tokio::test]
    async fn raw_transport_leaves_bodyless_requests_unencrypted() {
        let (client, _) = raw_client_with_private_key();
        let request = reqwest::Client::new()
            .get("https://example.com/v1/models")
            .build()
            .unwrap();

        let prepared = client.prepare_raw_request(request).await.unwrap();

        assert!(prepared.token.is_none());
        assert!(prepared.request.body().is_none());
        assert!(prepared
            .request
            .headers()
            .get(ENCAPSULATED_KEY_HEADER)
            .is_none());
    }

    #[tokio::test]
    async fn raw_transport_propagates_request_stream_errors() {
        #[derive(Debug)]
        struct StreamError;

        impl std::fmt::Display for StreamError {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("request stream failed")
            }
        }

        impl std::error::Error for StreamError {}

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            while socket.read(&mut buffer).await.unwrap_or_default() != 0 {}
        });

        let identity = ServerIdentity::from_public_key_bytes(&[7u8; 32]).unwrap();
        let client = Client::with_identity_and_http_client(
            Url::parse(&format!("http://{addr}/")).unwrap(),
            identity,
            reqwest::Client::new(),
        )
        .unwrap();
        let body = stream::iter([
            Ok::<Bytes, StreamError>(Bytes::from_static(b"first")),
            Err(StreamError),
        ]);
        let request = reqwest::Client::new()
            .post(format!("http://{addr}/secure"))
            .body(reqwest::Body::wrap_stream(body))
            .build()
            .unwrap();

        assert!(client.execute(request).await.is_err());
        assert!(client.get_session_recovery_token().is_none());
    }

    #[tokio::test]
    async fn cancelling_raw_transport_clears_session_recovery_token() {
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

        let identity = ServerIdentity::from_public_key_bytes(&[7u8; 32]).unwrap();
        let client = Client::with_identity_and_http_client(
            Url::parse(&format!("http://{addr}/")).unwrap(),
            identity,
            reqwest::Client::new(),
        )
        .unwrap();
        let request = reqwest::Client::new()
            .post(format!("http://{addr}/secure"))
            .body("secret")
            .build()
            .unwrap();
        let client_for_request = client.clone();
        let request_task = tokio::spawn(async move { client_for_request.execute(request).await });

        request_received.notified().await;
        assert!(client.get_session_recovery_token().is_some());
        request_task.abort();
        let _ = request_task.await;

        assert!(client.get_session_recovery_token().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn raw_transport_uses_fresh_contexts_for_rebuilt_requests() {
        let (client, _) = raw_client_with_private_key();
        let build_request = || {
            reqwest::Client::new()
                .post("https://example.com/v1/chat")
                .body("same plaintext")
                .build()
                .unwrap()
        };

        let first = client.prepare_raw_request(build_request()).await.unwrap();
        let second = client.prepare_raw_request(build_request()).await.unwrap();

        assert_ne!(
            first.request.headers()[ENCAPSULATED_KEY_HEADER],
            second.request.headers()[ENCAPSULATED_KEY_HEADER]
        );
    }

    async fn serve_key_config(content_type: &'static str) -> String {
        let identity = ServerIdentity::from_public_key_bytes(&[7u8; 32]).unwrap();
        let config = identity.marshal_public_config();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await.unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
                config.len()
            );
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(&config).await.unwrap();
        });

        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn key_config_content_type_allows_parameters_and_case() {
        for content_type in [
            KEYS_MEDIA_TYPE,
            "Application/OHTTP-Keys",
            "application/ohttp-keys; charset=utf-8",
        ] {
            let base_url = serve_key_config(content_type).await;
            let client = Client::new_with_http_client(base_url, reqwest::Client::new())
                .await
                .unwrap();

            assert_eq!(client.server_identity().public_key_bytes(), vec![7u8; 32]);
        }
    }

    #[tokio::test]
    async fn key_config_content_type_rejects_other_media_types() {
        let base_url = serve_key_config("application/json").await;
        let err = Client::new_with_http_client(base_url, reqwest::Client::new())
            .await
            .err()
            .unwrap();

        assert!(matches!(
            err,
            Error::Protocol(message) if message.contains("invalid key content type")
        ));
    }

    #[test]
    fn request_urls_must_stay_on_configured_origin() {
        let client = dummy_client();

        assert!(client.get("/v1/models").is_ok());
        assert!(client.get("https://example.com/v1/models").is_ok());
        assert!(client.get("https://evil.example/v1/models").is_err());
        assert!(client.get("//evil.example/v1/models").is_err());
        assert!(client
            .get("https://userinfo@example.com/v1/models")
            .is_err());
        assert!(parse_base_url("https://userinfo@example.com").is_err());
    }

    #[test]
    fn callers_cannot_set_reserved_protocol_headers() {
        let client = dummy_client();

        assert!(client
            .post("/v1/chat")
            .unwrap()
            .header(ENCAPSULATED_KEY_HEADER, "00")
            .is_err());
        assert!(client
            .post("/v1/chat")
            .unwrap()
            .header(RESPONSE_NONCE_HEADER, "00")
            .is_err());
        assert!(client
            .post("/v1/chat")
            .unwrap()
            .header(CONTENT_LENGTH, "1")
            .is_err());
        assert!(client
            .post("/v1/chat")
            .unwrap()
            .header(TRANSFER_ENCODING, "chunked")
            .is_err());
        assert!(client
            .post("/v1/chat")
            .unwrap()
            .header(HOST, "evil")
            .is_err());
    }

    #[test]
    fn duplicate_response_nonce_headers_fail_closed() {
        let mut headers = HeaderMap::new();
        headers.append(RESPONSE_NONCE_HEADER, HeaderValue::from_static("00"));
        headers.append(RESPONSE_NONCE_HEADER, HeaderValue::from_static("00"));

        assert!(response_nonce(&headers).is_err());
    }

    #[test]
    fn token_cleanup_does_not_clear_newer_request_token() {
        let second = SessionRecoveryToken::new(vec![3; 32], vec![4; 32]).unwrap();
        let session = Arc::new(Mutex::new(SessionState {
            generation: 2,
            token: Some(second.clone()),
        }));

        clear_session_recovery_token_if_current(&session, 1);
        assert_eq!(session.lock().unwrap().token.as_ref(), Some(&second));

        clear_session_recovery_token_if_current(&session, 2);
        assert!(session.lock().unwrap().token.is_none());
    }

    #[tokio::test]
    async fn stalled_older_raw_request_cannot_overwrite_or_clear_newer_token() {
        let (client, _) = raw_client_with_private_key();
        let first_polled = Arc::new(tokio::sync::Notify::new());
        let release_first = Arc::new(tokio::sync::Notify::new());
        let first_polled_by_stream = Arc::clone(&first_polled);
        let release_first_stream = Arc::clone(&release_first);
        let body = async_stream::stream! {
            yield Ok::<Bytes, std::io::Error>(Bytes::new());
            first_polled_by_stream.notify_one();
            release_first_stream.notified().await;
            yield Ok(Bytes::from_static(b"older"));
        };
        let first_request = reqwest::Client::new()
            .post("https://example.com/v1/chat")
            .body(reqwest::Body::wrap_stream(body))
            .build()
            .unwrap();
        let first_client = client.clone();
        let first_task =
            tokio::spawn(async move { first_client.prepare_raw_request(first_request).await });

        first_polled.notified().await;
        let second_request = reqwest::Client::new()
            .post("https://example.com/v1/chat")
            .body("newer")
            .build()
            .unwrap();
        let second = client.prepare_raw_request(second_request).await.unwrap();
        let second_token = second.token.unwrap();

        release_first.notify_one();
        let first = first_task.await.unwrap().unwrap();
        assert_eq!(
            client.get_session_recovery_token().as_ref(),
            Some(&second_token)
        );

        drop(SessionGuard::new(
            first.generation,
            Arc::clone(&client.session),
        ));
        assert_eq!(
            client.get_session_recovery_token().as_ref(),
            Some(&second_token)
        );
    }

    #[tokio::test]
    async fn raw_execute_encrypts_requests_without_content_length() {
        let captured = Arc::new(Mutex::new(String::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured_for_task = Arc::clone(&captured);

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..n]);
                if bytes.windows(5).any(|window| window == b"0\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&bytes).to_string();
            *captured_for_task.lock().unwrap() = request;
            socket
                .write_all(b"HTTP/1.1 422 Unprocessable Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let identity = ServerIdentity::from_public_key_bytes(&[7u8; 32]).unwrap();
        let client = Client::with_identity_and_http_client(
            Url::parse(&format!("http://{addr}/")).unwrap(),
            identity,
            reqwest::Client::new(),
        )
        .unwrap();

        let request = reqwest::Client::new()
            .post(format!("http://{addr}/secure"))
            .body("secret")
            .build()
            .unwrap();
        let _ = client.execute(request).await;

        let request = captured.lock().unwrap().to_ascii_lowercase();
        assert!(request.contains("transfer-encoding: chunked"));
        assert!(!request.contains("content-length:"));
        assert!(request.contains("ehbp-encapsulated-key:"));
    }

    // Emulates a server whose encrypted reply reaches the client with an
    // explicit Content-Length, as buffering middleboxes produce when they
    // re-frame the server's chunked response. The decrypted responses must
    // not retain framing headers that describe the ciphertext, or consumers
    // forwarding the headers verbatim (proxies) would truncate the reply.
    #[tokio::test]
    async fn decrypted_responses_drop_encrypted_framing_headers() {
        use aes_gcm::{
            aead::{Aead as _, KeyInit as _, Payload},
            Aes256Gcm, Nonce,
        };
        use hpke::{
            aead::AesGcm256,
            kdf::HkdfSha256,
            kem::{Kem as _, X25519HkdfSha256},
            setup_receiver, Deserializable as _, OpModeR, Serializable as _,
        };
        use rand::{rngs::StdRng, SeedableRng as _};

        use crate::derive::{compute_nonce, frame_chunk};
        use crate::protocol::{EXPORT_LABEL, EXPORT_LENGTH, HPKE_REQUEST_INFO};

        const REPLY: &[u8] = b"full reply from the enclave";

        let mut csprng = StdRng::from_os_rng();
        let (private_key, public_key) = X25519HkdfSha256::gen_keypair(&mut csprng);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buf[..n]);
                    if bytes.windows(5).any(|window| window == b"0\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&bytes).to_string();
                let enc_hex = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.trim()
                            .eq_ignore_ascii_case("ehbp-encapsulated-key")
                            .then(|| value.trim().to_string())
                    })
                    .expect("request must carry the encapsulated key header");
                let request_enc = hex::decode(&enc_hex).unwrap();

                let encapped_key =
                    <X25519HkdfSha256 as hpke::kem::Kem>::EncappedKey::from_bytes(&request_enc)
                        .unwrap();
                let receiver = setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
                    &OpModeR::Base,
                    &private_key,
                    &encapped_key,
                    HPKE_REQUEST_INFO,
                )
                .unwrap();
                let mut exported_secret = vec![0u8; EXPORT_LENGTH];
                receiver.export(EXPORT_LABEL, &mut exported_secret).unwrap();

                let response_nonce = [3u8; RESPONSE_NONCE_LENGTH];
                let key_material =
                    derive_response_keys(&exported_secret, &request_enc, &response_nonce).unwrap();
                let cipher = Aes256Gcm::new_from_slice(&key_material.key).unwrap();
                let nonce = compute_nonce(&key_material.nonce_base, 0);
                let ciphertext = cipher
                    .encrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: REPLY,
                            aad: &[],
                        },
                    )
                    .unwrap();
                let body = frame_chunk(&ciphertext).unwrap();

                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{RESPONSE_NONCE_HEADER}: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    hex::encode(response_nonce),
                    body.len(),
                );
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
        });

        let identity = ServerIdentity::from_public_key_bytes(&public_key.to_bytes()).unwrap();
        let client = Client::with_identity_and_http_client(
            Url::parse(&format!("http://{addr}/")).unwrap(),
            identity,
            reqwest::Client::new(),
        )
        .unwrap();

        let response = client
            .post("/secure")
            .unwrap()
            .body("secret")
            .send()
            .await
            .unwrap();

        assert_eq!(response.body.as_ref(), REPLY);
        assert!(response.headers.get(CONTENT_LENGTH).is_none());
        assert!(response.headers.get(TRANSFER_ENCODING).is_none());
        assert!(response.headers.get(RESPONSE_NONCE_HEADER).is_some());
        assert_eq!(response.headers.get(CONTENT_TYPE).unwrap(), "text/plain");

        let streaming = client
            .post("/stream")
            .unwrap()
            .body("secret")
            .send_stream()
            .await
            .unwrap();

        assert!(streaming.headers.get(CONTENT_LENGTH).is_none());
        assert!(streaming.headers.get(TRANSFER_ENCODING).is_none());

        let mut body = streaming.body;
        let mut collected = Vec::new();
        while let Some(chunk) = body.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(collected, REPLY);
    }
}
