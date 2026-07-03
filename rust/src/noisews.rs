//! End-to-end encrypted WebSocket channels for EHBP (EHBP-WS).
//!
//! The channel runs the Noise NK handshake (`Noise_NK_25519_AESGCM_SHA256`)
//! inside WebSocket binary messages: the client authenticates the server by
//! its X25519 static key (the EHBP HPKE identity key) while remaining
//! anonymous itself, mirroring the trust model of the HTTP mode. The
//! WebSocket upgrade request and control frames stay in cleartext so
//! intermediaries can route the connection; every application message is
//! carried as an encrypted record inside a binary frame.
//!
//! Termination is authenticated: peers exchange an encrypted close record
//! before the WebSocket close handshake, so truncation by an intermediary is
//! distinguishable from an intentional shutdown (see
//! [`Error::ChannelTruncated`]).

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{
        client::IntoClientRequest,
        error::ProtocolError,
        http::HeaderValue,
        protocol::{frame::coding::CloseCode, CloseFrame, WebSocketConfig},
        Error as WsError, Message,
    },
    MaybeTlsStream, WebSocketStream,
};
use url::Url;
use zeroize::Zeroize;

use crate::{
    protocol::{
        AES256_KEY_LENGTH, AES_GCM_NONCE_LENGTH, DEFAULT_WS_MAX_MESSAGE_SIZE, NOISE_PROLOGUE,
        NOISE_PROTOCOL_NAME, WS_HANDSHAKE_READ_LIMIT, WS_RECORD_CLOSE, WS_RECORD_DATA,
        WS_RECORD_OVERHEAD, WS_REKEY_INTERVAL, WS_SUBPROTOCOL,
    },
    Error, Result, ServerIdentity,
};

const SUBPROTOCOL_HEADER: &str = "Sec-WebSocket-Protocol";

/// One direction of the record layer: an AES-256-GCM cipher with the Noise
/// implicit nonce (4 zero bytes followed by a big-endian counter) and the
/// deterministic rekey schedule of SPEC Section 8.6.
struct CipherState {
    key: [u8; AES256_KEY_LENGTH],
    cipher: Aes256Gcm,
    count: u64,
    rekey_interval: u64,
}

impl CipherState {
    fn new(key: [u8; AES256_KEY_LENGTH], rekey_interval: u64) -> Self {
        let cipher = Aes256Gcm::new(&key.into());
        Self {
            key,
            cipher,
            count: 0,
            rekey_interval,
        }
    }

    fn nonce(n: u64) -> [u8; AES_GCM_NONCE_LENGTH] {
        let mut nonce = [0u8; AES_GCM_NONCE_LENGTH];
        nonce[4..].copy_from_slice(&n.to_be_bytes());
        nonce
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::nonce(self.count);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| Error::Crypto("failed to encrypt record".into()))?;
        self.advance()?;
        Ok(ciphertext)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::nonce(self.count);
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| Error::Crypto("failed to decrypt record".into()))?;
        self.advance()?;
        Ok(plaintext)
    }

    fn advance(&mut self) -> Result<()> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("record counter exhausted".into()))?;
        if self.count % self.rekey_interval == 0 {
            self.rekey()?;
        }
        Ok(())
    }

    /// Rekey per Noise spec Section 4.2: the new key is the encryption of 32
    /// zero bytes under the maximum nonce, with the tag discarded. The nonce
    /// counter deliberately keeps running.
    fn rekey(&mut self) -> Result<()> {
        let nonce = Self::nonce(u64::MAX);
        let mut block = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &[0u8; AES256_KEY_LENGTH],
                    aad: &[],
                },
            )
            .map_err(|_| Error::Crypto("failed to rekey".into()))?;
        self.key.zeroize();
        self.key.copy_from_slice(&block[..AES256_KEY_LENGTH]);
        block.zeroize();
        self.cipher = Aes256Gcm::new(&self.key.into());
        Ok(())
    }
}

impl Drop for CipherState {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Options for [`NoiseWebSocket::connect_with`].
#[derive(Clone, Debug)]
pub struct NoiseWebSocketOptions {
    max_message_size: usize,
    rekey_interval: u64,
}

impl Default for NoiseWebSocketOptions {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_WS_MAX_MESSAGE_SIZE,
            rekey_interval: WS_REKEY_INTERVAL,
        }
    }
}

impl NoiseWebSocketOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Caps the payload size of a single record in both directions. Both
    /// peers should agree on the cap; a received record larger than the
    /// local cap fails the connection.
    pub fn max_message_size(mut self, n: usize) -> Self {
        if n > 0 {
            self.max_message_size = n;
        }
        self
    }

    /// Overrides the rekey schedule so tests can exercise it cheaply. Peers
    /// that disagree on the schedule fail authentication, so production
    /// connections must keep the default.
    #[doc(hidden)]
    pub fn rekey_interval_for_testing(mut self, n: u64) -> Self {
        if n > 0 {
            self.rekey_interval = n;
        }
        self
    }
}

/// Terminal state of the receive side, reproduced by every subsequent call.
enum Sticky {
    Closed,
    Truncated(String),
    Protocol(String),
    Crypto(String),
}

impl Sticky {
    fn to_error(&self) -> Error {
        match self {
            Sticky::Closed => Error::ChannelClosed,
            Sticky::Truncated(detail) => Error::ChannelTruncated(detail.clone()),
            Sticky::Protocol(detail) => Error::Protocol(detail.clone()),
            Sticky::Crypto(detail) => Error::Crypto(detail.clone()),
        }
    }
}

type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// A message-oriented connection whose payloads are encrypted end-to-end
/// inside WebSocket binary messages.
pub struct NoiseWebSocket {
    ws: WsStream,
    send: CipherState,
    recv: CipherState,
    max_message_size: usize,
    peer_closed: bool,
    close_sent: bool,
    local_closed: bool,
    sticky: Option<Sticky>,
}

impl std::fmt::Debug for NoiseWebSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseWebSocket")
            .field("max_message_size", &self.max_message_size)
            .field("peer_closed", &self.peer_closed)
            .field("close_sent", &self.close_sent)
            .field("local_closed", &self.local_closed)
            .finish_non_exhaustive()
    }
}

impl NoiseWebSocket {
    /// Opens a WebSocket connection to `url` (ws, wss, http, or https
    /// scheme) and runs the Noise initiator handshake against the server
    /// identity's public key. No application data is sent before the
    /// handshake completes.
    pub async fn connect(url: &str, server_identity: &ServerIdentity) -> Result<Self> {
        Self::connect_with(url, server_identity, NoiseWebSocketOptions::default()).await
    }

    /// Like [`NoiseWebSocket::connect`] with explicit options.
    pub async fn connect_with(
        url: &str,
        server_identity: &ServerIdentity,
        options: NoiseWebSocketOptions,
    ) -> Result<Self> {
        let server_pub = server_identity.public_key_bytes();
        let mut parsed = Url::parse(url)?;
        let mapped = match parsed.scheme() {
            "ws" | "wss" => None,
            "http" => Some("ws"),
            "https" => Some("wss"),
            other => {
                return Err(Error::InvalidInput(format!(
                    "unsupported URL scheme {other:?}"
                )))
            }
        };
        if let Some(scheme) = mapped {
            parsed
                .set_scheme(scheme)
                .map_err(|_| Error::InvalidInput("failed to map URL scheme".into()))?;
        }

        let mut request = parsed
            .as_str()
            .into_client_request()
            .map_err(|err| Error::WebSocket(err.to_string()))?;
        request
            .headers_mut()
            .insert(SUBPROTOCOL_HEADER, HeaderValue::from_static(WS_SUBPROTOCOL));

        let config = WebSocketConfig::default()
            .max_message_size(Some(options.max_message_size + WS_RECORD_OVERHEAD))
            .max_frame_size(Some(options.max_message_size + WS_RECORD_OVERHEAD));

        let (mut ws, response) = connect_async_with_config(request, Some(config), false)
            .await
            .map_err(|err| match err {
                WsError::Protocol(ProtocolError::SecWebSocketSubProtocolError(_)) => {
                    Error::Handshake("server did not accept required subprotocol".into())
                }
                other => Error::WebSocket(format!("dial: {other}")),
            })?;

        let negotiated = response
            .headers()
            .get(SUBPROTOCOL_HEADER)
            .and_then(|value| value.to_str().ok());
        if negotiated != Some(WS_SUBPROTOCOL) {
            let _ = ws
                .close(Some(CloseFrame {
                    code: CloseCode::Policy,
                    reason: "ehbp noise subprotocol required".into(),
                }))
                .await;
            return Err(Error::Handshake(
                "server did not accept required subprotocol".into(),
            ));
        }

        match Self::client_handshake(&mut ws, &server_pub).await {
            Ok((send_key, recv_key)) => Ok(Self {
                ws,
                send: CipherState::new(send_key, options.rekey_interval),
                recv: CipherState::new(recv_key, options.rekey_interval),
                max_message_size: options.max_message_size,
                peer_closed: false,
                close_sent: false,
                local_closed: false,
                sticky: None,
            }),
            Err(err) => {
                let _ = ws
                    .close(Some(CloseFrame {
                        code: CloseCode::Policy,
                        reason: "handshake failed".into(),
                    }))
                    .await;
                Err(err)
            }
        }
    }

    async fn client_handshake(
        ws: &mut WsStream,
        server_pub: &[u8],
    ) -> Result<([u8; AES256_KEY_LENGTH], [u8; AES256_KEY_LENGTH])> {
        let params = NOISE_PROTOCOL_NAME
            .parse()
            .map_err(|err| Error::Handshake(format!("protocol name: {err}")))?;
        let mut handshake = snow::Builder::new(params)
            .prologue(NOISE_PROLOGUE)
            .map_err(|err| Error::Handshake(format!("prologue: {err}")))?
            .remote_public_key(server_pub)
            .map_err(|err| Error::Handshake(format!("server public key: {err}")))?
            .build_initiator()
            .map_err(|err| Error::Handshake(err.to_string()))?;

        let mut message1 = [0u8; 128];
        let len = handshake
            .write_message(&[], &mut message1)
            .map_err(|err| Error::Handshake(err.to_string()))?;
        ws.send(Message::Binary(message1[..len].to_vec().into()))
            .await
            .map_err(|err| Error::Handshake(format!("write handshake message: {err}")))?;

        let message2 = loop {
            match ws.next().await {
                None => {
                    return Err(Error::Handshake(
                        "connection closed during handshake".into(),
                    ))
                }
                Some(Err(err)) => {
                    return Err(Error::Handshake(format!("read handshake message: {err}")))
                }
                Some(Ok(Message::Binary(data))) => break data,
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                Some(Ok(_)) => {
                    return Err(Error::Handshake("handshake message must be binary".into()))
                }
            }
        };
        if message2.len() > WS_HANDSHAKE_READ_LIMIT {
            return Err(Error::Handshake(format!(
                "handshake message of {} bytes exceeds limit {WS_HANDSHAKE_READ_LIMIT}",
                message2.len()
            )));
        }
        // Receivers must ignore any handshake payload present.
        let mut payload = vec![0u8; message2.len()];
        handshake
            .read_message(&message2, &mut payload)
            .map_err(|err| Error::Handshake(err.to_string()))?;
        if !handshake.is_handshake_finished() {
            return Err(Error::Handshake("handshake did not complete".into()));
        }

        // Split returns the initiator-to-responder key first; the client
        // sends with it and receives with the other.
        Ok(handshake.dangerously_get_raw_split())
    }

    /// Encrypts `payload` as a single data record and sends it as one
    /// WebSocket binary message.
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() > self.max_message_size {
            return Err(Error::InvalidInput(format!(
                "message of {} bytes exceeds maximum size {}",
                payload.len(),
                self.max_message_size
            )));
        }
        if self.close_sent || self.local_closed {
            return Err(Error::ChannelClosed);
        }
        let mut record = Vec::with_capacity(1 + payload.len());
        record.push(WS_RECORD_DATA);
        record.extend_from_slice(payload);
        self.write_record(&record).await
    }

    async fn write_record(&mut self, record: &[u8]) -> Result<()> {
        let ciphertext = self.send.encrypt(record)?;
        self.ws
            .send(Message::Binary(ciphertext.into()))
            .await
            .map_err(|err| Error::WebSocket(err.to_string()))
    }

    /// Receives one record and returns its decrypted payload. Returns
    /// `Ok(None)` after the peer's encrypted close record,
    /// [`Error::ChannelClosed`] after a local close, and
    /// [`Error::ChannelTruncated`] if the connection ends without the peer's
    /// close record. Errors are terminal and sticky.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        if self.peer_closed {
            return Ok(None);
        }
        if let Some(sticky) = &self.sticky {
            return Err(sticky.to_error());
        }
        loop {
            let message = match self.ws.next().await {
                None => return Err(self.transport_ended("connection closed".into())),
                Some(Err(err)) => return Err(self.transport_ended(err.to_string())),
                Some(Ok(message)) => message,
            };
            match message {
                Message::Binary(ciphertext) => {
                    let record = match self.recv.decrypt(&ciphertext) {
                        Ok(record) => record,
                        Err(_) => {
                            return Err(self
                                .terminate(Sticky::Crypto("failed to decrypt record".into()))
                                .await)
                        }
                    };
                    if record.is_empty() {
                        return Err(self
                            .terminate(Sticky::Protocol("empty record".into()))
                            .await);
                    }
                    match record[0] {
                        WS_RECORD_DATA => {
                            // The WebSocket read limit leaves margin above
                            // the payload cap, so the decrypted payload size
                            // must be checked explicitly.
                            if record.len() - 1 > self.max_message_size {
                                return Err(self
                                    .terminate(Sticky::Protocol(format!(
                                        "received message of {} bytes exceeds maximum size {}",
                                        record.len() - 1,
                                        self.max_message_size
                                    )))
                                    .await);
                            }
                            return Ok(Some(record[1..].to_vec()));
                        }
                        WS_RECORD_CLOSE => {
                            self.peer_closed = true;
                            // Respond with our own close record and complete
                            // the WebSocket close handshake.
                            let _ = self.close_internal().await;
                            return Ok(None);
                        }
                        other => {
                            return Err(self
                                .terminate(Sticky::Protocol(format!(
                                    "unknown record type 0x{other:02x}"
                                )))
                                .await)
                        }
                    }
                }
                Message::Text(_) => {
                    return Err(self
                        .terminate(Sticky::Protocol("unexpected text message".into()))
                        .await)
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                // A close frame without a close record is unauthenticated;
                // keep polling so the stream end is reported as truncation.
                Message::Close(_) => continue,
            }
        }
    }

    /// Sends an encrypted close record and performs the WebSocket close
    /// handshake. The record lets the peer distinguish an intentional
    /// shutdown from truncation by an intermediary. Repeated calls return
    /// `Ok(())`.
    pub async fn close(&mut self) -> Result<()> {
        self.local_closed = true;
        self.close_internal().await
    }

    async fn close_internal(&mut self) -> Result<()> {
        if self.close_sent {
            return Ok(());
        }
        self.close_sent = true;
        self.local_closed = true;
        let write_result = self.write_record(&[WS_RECORD_CLOSE]).await;
        let close_result = self.ws.close(None).await;
        write_result?;
        match close_result {
            Ok(()) | Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => Ok(()),
            Err(err) => Err(Error::WebSocket(err.to_string())),
        }
    }

    fn transport_ended(&mut self, detail: String) -> Error {
        let sticky = if self.local_closed {
            Sticky::Closed
        } else {
            Sticky::Truncated(detail)
        };
        let err = sticky.to_error();
        self.sticky = Some(sticky);
        err
    }

    /// Records the sticky error and tears the connection down immediately
    /// after a protocol violation. Waiting for a close handshake would let a
    /// misbehaving peer pin resources, so no close frame exchange is
    /// attempted.
    async fn terminate(&mut self, sticky: Sticky) -> Error {
        let err = sticky.to_error();
        self.sticky = Some(sticky);
        self.local_closed = true;
        let _ = self.ws.get_mut().shutdown().await;
        err
    }
}
