use bytes::{Buf, Bytes, BytesMut};
use futures_core::Stream;
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
    derive::{decrypt_chunk, derive_response_keys},
    identity::ServerIdentity,
    protocol::{
        ENCAPSULATED_KEY_HEADER, KEYS_MEDIA_TYPE, KEYS_PATH, KEY_CONFIG_PROBLEM_TYPE,
        PROBLEM_JSON_MEDIA_TYPE, RESPONSE_NONCE_HEADER, RESPONSE_NONCE_LENGTH,
    },
    session::SessionRecoveryToken,
    Error, Result,
};

const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct Client {
    base_url: Url,
    identity: ServerIdentity,
    http_client: reqwest::Client,
    last_session_recovery_token: Arc<Mutex<Option<SessionRecoveryToken>>>,
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
            last_session_recovery_token: Arc::new(Mutex::new(None)),
        })
    }

    pub fn server_identity(&self) -> &ServerIdentity {
        &self.identity
    }

    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    pub fn get_session_recovery_token(&self) -> Option<SessionRecoveryToken> {
        self.last_session_recovery_token.lock().ok()?.clone()
    }

    pub fn take_session_recovery_token(&self) -> Option<SessionRecoveryToken> {
        self.last_session_recovery_token.lock().ok()?.take()
    }

    fn replace_session_recovery_token(&self, token: Option<SessionRecoveryToken>) {
        if let Ok(mut guard) = self.last_session_recovery_token.lock() {
            *guard = token;
        }
    }

    fn clear_session_recovery_token_if_current(&self, token: &SessionRecoveryToken) {
        clear_session_recovery_token_if_current(&self.last_session_recovery_token, token);
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

    async fn send_parts(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Bytes>,
    ) -> Result<Response> {
        let PreparedRequest { request, token } =
            self.prepare_request_builder(method, url, headers, body)?;
        let response = match request.send().await {
            Ok(response) => response,
            Err(err) => {
                if token.is_some() {
                    self.replace_session_recovery_token(None);
                }
                return Err(err.into());
            }
        };
        let status = response.status();
        let headers = response.headers().clone();
        let body = match read_response_body_capped(response, DEFAULT_MAX_RESPONSE_BYTES).await {
            Ok(body) => body,
            Err(err) => {
                if token.is_some() {
                    self.replace_session_recovery_token(None);
                }
                return Err(err);
            }
        };

        let Some(token) = token else {
            return Ok(Response {
                status,
                headers,
                body,
            });
        };

        if let Err(err) = check_key_config_mismatch(status, &headers, &body) {
            self.replace_session_recovery_token(None);
            return Err(err);
        }

        let response_nonce = match response_nonce(&headers) {
            Ok(nonce) => nonce,
            Err(err) => {
                self.replace_session_recovery_token(None);
                return Err(err);
            }
        };
        let decrypted = match token.decrypt_response_body(&response_nonce, &body) {
            Ok(decrypted) => decrypted,
            Err(err) => {
                self.replace_session_recovery_token(None);
                return Err(err);
            }
        };
        self.clear_session_recovery_token_if_current(&token);

        let mut headers = headers;
        headers.remove(CONTENT_LENGTH);

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
        let PreparedRequest { request, token } =
            self.prepare_request_builder(method, url, headers, body)?;
        let response = match request.send().await {
            Ok(response) => response,
            Err(err) => {
                if token.is_some() {
                    self.replace_session_recovery_token(None);
                }
                return Err(err.into());
            }
        };
        let status = response.status();
        let headers = response.headers().clone();

        let Some(token) = token else {
            return Ok(StreamingResponse {
                status,
                headers,
                body: Box::pin(response.bytes_stream().map_reqwest_error()),
            });
        };

        if !headers.contains_key(RESPONSE_NONCE_HEADER) {
            let body = match read_response_body_capped(response, DEFAULT_MAX_RESPONSE_BYTES).await {
                Ok(body) => body,
                Err(err) => {
                    self.replace_session_recovery_token(None);
                    return Err(err);
                }
            };
            if let Err(err) = check_key_config_mismatch(status, &headers, &body) {
                self.replace_session_recovery_token(None);
                return Err(err);
            }
            self.replace_session_recovery_token(None);
            return Err(Error::Protocol(format!(
                "missing {RESPONSE_NONCE_HEADER} header"
            )));
        }

        let response_nonce = match response_nonce(&headers) {
            Ok(nonce) => nonce,
            Err(err) => {
                self.replace_session_recovery_token(None);
                return Err(err);
            }
        };
        let key_material =
            match derive_response_keys(&token.exported_secret, &token.request_enc, &response_nonce)
            {
                Ok(key_material) => key_material,
                Err(err) => {
                    self.replace_session_recovery_token(None);
                    return Err(err);
                }
            };

        let mut headers = headers;
        headers.remove(CONTENT_LENGTH);

        Ok(StreamingResponse {
            status,
            headers,
            body: Box::pin(SessionClearingStream {
                inner: Box::pin(decrypt_response_stream(
                    response.bytes_stream(),
                    key_material,
                )),
                token,
                session: Arc::clone(&self.last_session_recovery_token),
                cleared: false,
            }),
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
        self.replace_session_recovery_token(None);
        let encrypted = self.identity.encrypt_request_body(&plaintext_body)?;

        let mut request = self.http_client.request(method, url);
        let token = if let Some(encrypted) = encrypted {
            headers.insert(
                header_name(ENCAPSULATED_KEY_HEADER)?,
                HeaderValue::from_str(&hex::encode(&encrypted.encapsulated_key))?,
            );
            let token = encrypted.token;
            self.replace_session_recovery_token(Some(token.clone()));
            request = request
                .headers(headers)
                .body(encrypted_reqwest_body(encrypted.body));
            Some(token)
        } else {
            request = request.headers(headers);
            None
        };

        Ok(PreparedRequest { request, token })
    }

    fn resolve_url(&self, path_or_url: &str) -> Result<Url> {
        let url = self.base_url.join(path_or_url)?;
        if !same_origin(&self.base_url, &url) {
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
        Ok(url)
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

fn encrypted_reqwest_body(body: Vec<u8>) -> reqwest::Body {
    reqwest::Body::wrap_stream(async_stream::stream! {
        yield Ok::<Bytes, std::io::Error>(Bytes::from(body));
    })
}

fn clear_session_recovery_token_if_current(
    session: &Arc<Mutex<Option<SessionRecoveryToken>>>,
    token: &SessionRecoveryToken,
) {
    if let Ok(mut guard) = session.lock() {
        if guard.as_ref() == Some(token) {
            *guard = None;
        }
    }
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
    token: SessionRecoveryToken,
    session: Arc<Mutex<Option<SessionRecoveryToken>>>,
    cleared: bool,
}

impl SessionClearingStream {
    fn clear_if_current(&mut self) {
        if !self.cleared {
            clear_session_recovery_token_if_current(&self.session, &self.token);
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
        let mut buffer = BytesMut::new();
        let mut seq = 0u64;

        while let Some(chunk) = poll_next(&mut stream).await {
            let chunk = chunk?;
            buffer.extend_from_slice(&chunk);

            loop {
                if buffer.len() < 4 {
                    break;
                }

                let chunk_len = u32::from_be_bytes([
                    buffer[0],
                    buffer[1],
                    buffer[2],
                    buffer[3],
                ]) as usize;

                if chunk_len == 0 {
                    buffer.advance(4);
                    continue;
                }

                if chunk_len > DEFAULT_MAX_RESPONSE_BYTES {
                    Err(Error::Protocol(
                        "response chunk exceeds maximum allowed size".into(),
                    ))?;
                }

                if buffer.len() < 4 + chunk_len {
                    break;
                }

                buffer.advance(4);
                let ciphertext = buffer.split_to(chunk_len).freeze();
                let plaintext = decrypt_chunk(&key_material, seq, &ciphertext)?;
                seq = seq
                    .checked_add(1)
                    .ok_or_else(|| Error::Protocol("response chunk sequence overflow".into()))?;
                yield Bytes::from(plaintext);
            }
        }

        if !buffer.is_empty() {
            Err(Error::Protocol("truncated encrypted response chunk".into()))?;
        }
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
    use std::sync::{Arc, Mutex};
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

    fn dummy_client() -> Client {
        let identity = ServerIdentity::from_public_key_bytes(&[7u8; 32]).unwrap();
        Client::with_identity_and_http_client(
            Url::parse("https://example.com/").unwrap(),
            identity,
            reqwest::Client::new(),
        )
        .unwrap()
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
        let first = SessionRecoveryToken::new(vec![1; 32], vec![2; 32]).unwrap();
        let second = SessionRecoveryToken::new(vec![3; 32], vec![4; 32]).unwrap();
        let session = Arc::new(Mutex::new(Some(second.clone())));

        clear_session_recovery_token_if_current(&session, &first);
        assert_eq!(session.lock().unwrap().as_ref(), Some(&second));

        clear_session_recovery_token_if_current(&session, &second);
        assert!(session.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn encrypted_requests_omit_content_length() {
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

        let _ = client.post("/secure").unwrap().body("secret").send().await;

        let request = captured.lock().unwrap().to_ascii_lowercase();
        assert!(request.contains("transfer-encoding: chunked"));
        assert!(!request.contains("content-length:"));
        assert!(request.contains("ehbp-encapsulated-key:"));
    }
}
