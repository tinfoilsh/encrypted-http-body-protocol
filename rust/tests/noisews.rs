#![cfg(feature = "ws")]

use std::future::Future;
use std::time::{Duration, Instant};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::{
    accept_async, accept_hdr_async,
    tungstenite::{
        handshake::server::{ErrorResponse, Request, Response},
        http::HeaderValue,
        protocol::{frame::coding::CloseCode, CloseFrame},
        Message,
    },
    WebSocketStream,
};

use tinfoil_ehbp::{
    Error, NoiseWebSocket, NoiseWebSocketOptions, ServerIdentity, DEFAULT_WS_MAX_MESSAGE_SIZE,
    NOISE_PROLOGUE, NOISE_PROTOCOL_NAME, WS_RECORD_CLOSE, WS_RECORD_DATA, WS_REKEY_INTERVAL,
    WS_SUBPROTOCOL,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Independent record-layer cipher used by the test responder and the vector
/// checks: Noise implicit nonces and the deterministic rekey schedule.
struct TestCipher {
    key: [u8; 32],
    cipher: Aes256Gcm,
    count: u64,
    rekey_interval: u64,
}

impl TestCipher {
    fn new(key: [u8; 32], rekey_interval: u64) -> Self {
        Self {
            key,
            cipher: Aes256Gcm::new(&key.into()),
            count: 0,
            rekey_interval,
        }
    }

    fn nonce(n: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&n.to_be_bytes());
        nonce
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
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
            .expect("encrypt");
        self.advance();
        ciphertext
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
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
            .map_err(|_| "decrypt failed".to_string())?;
        self.advance();
        Ok(plaintext)
    }

    fn advance(&mut self) {
        self.count += 1;
        if self.count % self.rekey_interval == 0 {
            let nonce = Self::nonce(u64::MAX);
            let block = self
                .cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &[0u8; 32],
                        aad: &[],
                    },
                )
                .expect("rekey");
            self.key.copy_from_slice(&block[..32]);
            self.cipher = Aes256Gcm::new(&self.key.into());
        }
    }
}

#[derive(Debug, PartialEq)]
enum ServerEvent {
    Eof,
    Truncated,
    Failed(String),
}

struct ServerConn {
    ws: WebSocketStream<TcpStream>,
    send: TestCipher,
    recv: TestCipher,
    close_sent: bool,
}

enum ServerRead {
    Data(Vec<u8>),
    Eof,
    Truncated,
    Failed(String),
}

impl ServerConn {
    async fn read(&mut self) -> ServerRead {
        loop {
            match self.ws.next().await {
                None => return ServerRead::Truncated,
                Some(Err(_)) => return ServerRead::Truncated,
                Some(Ok(Message::Binary(ciphertext))) => {
                    let record = match self.recv.decrypt(&ciphertext) {
                        Ok(record) => record,
                        Err(err) => return ServerRead::Failed(err),
                    };
                    match record.split_first() {
                        Some((&WS_RECORD_DATA, payload)) => {
                            return ServerRead::Data(payload.to_vec())
                        }
                        Some((&WS_RECORD_CLOSE, _)) => return ServerRead::Eof,
                        Some((other, _)) => {
                            return ServerRead::Failed(format!("unknown record type {other}"))
                        }
                        None => return ServerRead::Failed("empty record".into()),
                    }
                }
                Some(Ok(Message::Close(_))) => continue,
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                Some(Ok(Message::Text(_))) => {
                    return ServerRead::Failed("unexpected text message".into())
                }
            }
        }
    }

    async fn write(&mut self, payload: &[u8]) -> Result<(), String> {
        let mut record = Vec::with_capacity(1 + payload.len());
        record.push(WS_RECORD_DATA);
        record.extend_from_slice(payload);
        let ciphertext = self.send.encrypt(&record);
        self.ws
            .send(Message::Binary(ciphertext.into()))
            .await
            .map_err(|err| err.to_string())
    }

    async fn close(&mut self) {
        if self.close_sent {
            return;
        }
        self.close_sent = true;
        let ciphertext = self.send.encrypt(&[WS_RECORD_CLOSE]);
        let _ = self.ws.send(Message::Binary(ciphertext.into())).await;
        let _ = self.ws.close(None).await;
    }
}

struct TestServer {
    url: String,
    identity: ServerIdentity,
}

/// WebSocket upgrade callback that selects the EHBP subprotocol when the
/// client offers it, like a real server.
#[allow(clippy::result_large_err)] // signature fixed by tungstenite's Callback trait
fn negotiate_subprotocol(
    request: &Request,
    mut response: Response,
) -> Result<Response, ErrorResponse> {
    let offered = request
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if offered
        .split(',')
        .map(str::trim)
        .any(|p| p == WS_SUBPROTOCOL)
    {
        response.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static(WS_SUBPROTOCOL),
        );
    }
    Ok(response)
}

async fn spawn_server<F, Fut>(rekey_interval: u64, handler: F) -> TestServer
where
    F: FnOnce(ServerConn) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let params = NOISE_PROTOCOL_NAME.parse().unwrap();
    let keypair = snow::Builder::new(params).generate_keypair().unwrap();
    let identity = ServerIdentity::from_public_key_bytes(&keypair.public).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_hdr_async(stream, negotiate_subprotocol)
            .await
            .unwrap();

        let params = NOISE_PROTOCOL_NAME.parse().unwrap();
        let mut handshake = snow::Builder::new(params)
            .prologue(NOISE_PROLOGUE)
            .unwrap()
            .local_private_key(&keypair.private)
            .unwrap()
            .build_responder()
            .unwrap();

        let message1 = match ws.next().await {
            Some(Ok(Message::Binary(data))) => data,
            _ => return,
        };
        let mut payload = vec![0u8; message1.len()];
        if handshake.read_message(&message1, &mut payload).is_err() {
            let _ = ws
                .close(Some(CloseFrame {
                    code: CloseCode::Policy,
                    reason: "noise handshake failed".into(),
                }))
                .await;
            return;
        }
        let mut message2 = [0u8; 128];
        let len = handshake.write_message(&[], &mut message2).unwrap();
        if ws
            .send(Message::Binary(message2[..len].to_vec().into()))
            .await
            .is_err()
        {
            return;
        }
        let (k1, k2) = handshake.dangerously_get_raw_split();
        let conn = ServerConn {
            ws,
            send: TestCipher::new(k2, rekey_interval),
            recv: TestCipher::new(k1, rekey_interval),
            close_sent: false,
        };
        handler(conn).await;
    });

    TestServer { url, identity }
}

async fn echo_conn(mut conn: ServerConn, events: mpsc::UnboundedSender<ServerEvent>) {
    loop {
        match conn.read().await {
            ServerRead::Data(payload) => {
                if let Err(err) = conn.write(&payload).await {
                    let _ = events.send(ServerEvent::Failed(err));
                    return;
                }
            }
            ServerRead::Eof => {
                conn.close().await;
                let _ = events.send(ServerEvent::Eof);
                return;
            }
            ServerRead::Truncated => {
                let _ = events.send(ServerEvent::Truncated);
                return;
            }
            ServerRead::Failed(err) => {
                let _ = events.send(ServerEvent::Failed(err));
                return;
            }
        }
    }
}

async fn spawn_echo_server(
    rekey_interval: u64,
) -> (TestServer, mpsc::UnboundedReceiver<ServerEvent>) {
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let server = spawn_server(rekey_interval, move |conn| echo_conn(conn, events_tx)).await;
    (server, events_rx)
}

#[tokio::test]
async fn echo_round_trip_and_clean_close() {
    let (server, mut events) = spawn_echo_server(WS_REKEY_INTERVAL).await;
    let mut conn = timeout(
        TEST_TIMEOUT,
        NoiseWebSocket::connect(&server.url, &server.identity),
    )
    .await
    .unwrap()
    .unwrap();

    for message in [&b"hello"[..], &b""[..], &b"second message"[..]] {
        conn.send(message).await.unwrap();
        let got = timeout(TEST_TIMEOUT, conn.recv()).await.unwrap().unwrap();
        assert_eq!(got.as_deref(), Some(message));
    }

    conn.close().await.unwrap();
    let event = timeout(TEST_TIMEOUT, events.recv()).await.unwrap().unwrap();
    assert_eq!(event, ServerEvent::Eof);

    match conn.send(b"after close").await {
        Err(Error::ChannelClosed) => {}
        other => panic!("write after close should return ChannelClosed, got {other:?}"),
    }
}

#[tokio::test]
async fn recv_after_local_close_is_channel_closed() {
    let (server, _events) = spawn_echo_server(WS_REKEY_INTERVAL).await;
    let mut conn = NoiseWebSocket::connect(&server.url, &server.identity)
        .await
        .unwrap();
    conn.close().await.unwrap();

    for _ in 0..2 {
        match timeout(TEST_TIMEOUT, conn.recv()).await.unwrap() {
            Err(Error::ChannelClosed) => {}
            other => panic!("recv after close should return ChannelClosed, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn recv_after_peer_close_returns_none() {
    let (events_tx, _events_rx) = mpsc::unbounded_channel();
    let server = spawn_server(WS_REKEY_INTERVAL, move |mut conn| async move {
        conn.close().await;
        let _ = events_tx.send(ServerEvent::Eof);
    })
    .await;

    let mut conn = NoiseWebSocket::connect(&server.url, &server.identity)
        .await
        .unwrap();
    assert_eq!(
        timeout(TEST_TIMEOUT, conn.recv()).await.unwrap().unwrap(),
        None
    );
    assert_eq!(
        timeout(TEST_TIMEOUT, conn.recv()).await.unwrap().unwrap(),
        None
    );
}

#[tokio::test]
async fn wrong_server_key_fails_handshake() {
    let (server, _events) = spawn_echo_server(WS_REKEY_INTERVAL).await;
    let params = NOISE_PROTOCOL_NAME.parse().unwrap();
    let wrong = snow::Builder::new(params).generate_keypair().unwrap();
    let wrong_identity = ServerIdentity::from_public_key_bytes(&wrong.public).unwrap();

    let result = timeout(
        TEST_TIMEOUT,
        NoiseWebSocket::connect(&server.url, &wrong_identity),
    )
    .await
    .unwrap();
    match result {
        Err(Error::Handshake(_)) => {}
        other => panic!("dial with wrong server key should fail the handshake, got {other:?}"),
    }
}

#[tokio::test]
async fn tampered_record_fails_closed() {
    let server = spawn_server(WS_REKEY_INTERVAL, |mut conn| async move {
        let mut ciphertext = conn.send.encrypt(&[WS_RECORD_DATA, b'h', b'i']);
        ciphertext[0] ^= 0xff;
        let _ = conn.ws.send(Message::Binary(ciphertext.into())).await;
        // Keep the socket open so the client failure comes from the AEAD,
        // not from the transport ending.
        let _ = conn.read().await;
    })
    .await;

    let mut conn = NoiseWebSocket::connect(&server.url, &server.identity)
        .await
        .unwrap();

    match timeout(TEST_TIMEOUT, conn.recv()).await.unwrap() {
        Err(Error::Crypto(_)) => {}
        other => panic!("tampered record should fail decryption, got {other:?}"),
    }
    match timeout(TEST_TIMEOUT, conn.recv()).await.unwrap() {
        Err(Error::Crypto(_)) => {}
        other => panic!("read errors should be sticky, got {other:?}"),
    }
}

#[tokio::test]
async fn truncation_detected() {
    let server = spawn_server(WS_REKEY_INTERVAL, |mut conn| async move {
        match conn.read().await {
            ServerRead::Data(payload) => {
                let _ = conn.write(&payload).await;
            }
            _ => return,
        }
        // Close the WebSocket without sending an encrypted close record,
        // simulating truncation by an intermediary.
        let _ = conn.ws.close(None).await;
    })
    .await;

    let mut conn = NoiseWebSocket::connect(&server.url, &server.identity)
        .await
        .unwrap();
    conn.send(b"last message").await.unwrap();
    timeout(TEST_TIMEOUT, conn.recv()).await.unwrap().unwrap();

    match timeout(TEST_TIMEOUT, conn.recv()).await.unwrap() {
        Err(Error::ChannelTruncated(_)) => {}
        other => panic!("client should see truncation, got {other:?}"),
    }
    match timeout(TEST_TIMEOUT, conn.recv()).await.unwrap() {
        Err(Error::ChannelTruncated(_)) => {}
        other => panic!("truncation errors should be sticky, got {other:?}"),
    }
    match timeout(TEST_TIMEOUT, conn.send(b"after failure"))
        .await
        .unwrap()
    {
        Err(Error::ChannelTruncated(_)) => {}
        other => panic!("sends after a terminal error should surface it, got {other:?}"),
    }
}

#[tokio::test]
async fn server_detects_client_truncation() {
    let (server, mut events) = spawn_echo_server(WS_REKEY_INTERVAL).await;
    {
        let mut conn = NoiseWebSocket::connect(&server.url, &server.identity)
            .await
            .unwrap();
        conn.send(b"hello").await.unwrap();
        timeout(TEST_TIMEOUT, conn.recv()).await.unwrap().unwrap();
        // Dropping the connection tears down the socket without sending an
        // encrypted close record.
    }
    let event = timeout(TEST_TIMEOUT, events.recv()).await.unwrap().unwrap();
    assert_eq!(event, ServerEvent::Truncated);
}

#[tokio::test]
async fn rekey_keeps_directions_in_sync() {
    let (server, _events) = spawn_echo_server(3).await;
    let options = NoiseWebSocketOptions::new().rekey_interval_for_testing(3);
    let mut conn = NoiseWebSocket::connect_with(&server.url, &server.identity, options)
        .await
        .unwrap();

    let payload = vec![b'x'; 100];
    for i in 0..10 {
        conn.send(&payload).await.unwrap();
        let got = timeout(TEST_TIMEOUT, conn.recv()).await.unwrap().unwrap();
        assert_eq!(
            got.as_deref(),
            Some(payload.as_slice()),
            "echo mismatch on message {i}"
        );
    }
    conn.close().await.unwrap();
}

#[tokio::test]
async fn oversized_write_rejected() {
    let (server, _events) = spawn_echo_server(WS_REKEY_INTERVAL).await;
    let options = NoiseWebSocketOptions::new().max_message_size(16);
    let mut conn = NoiseWebSocket::connect_with(&server.url, &server.identity, options)
        .await
        .unwrap();

    match conn.send(&[b'x'; 17]).await {
        Err(Error::InvalidInput(_)) => {}
        other => panic!("oversized write should fail, got {other:?}"),
    }
    conn.send(&[b'x'; 16]).await.unwrap();
}

#[tokio::test]
async fn oversized_inbound_record_fails_connection() {
    // The server's cap is larger than the client's, so it can produce a
    // record that fits the client's WebSocket read limit margin but exceeds
    // the client's payload cap.
    let server = spawn_server(WS_REKEY_INTERVAL, |mut conn| async move {
        let _ = conn.write(&[b'x'; 32]).await;
        let _ = conn.read().await;
    })
    .await;

    let options = NoiseWebSocketOptions::new().max_message_size(16);
    let mut conn = NoiseWebSocket::connect_with(&server.url, &server.identity, options)
        .await
        .unwrap();

    match timeout(TEST_TIMEOUT, conn.recv()).await.unwrap() {
        Err(Error::Protocol(detail)) => {
            assert!(
                detail.contains("exceeds maximum size"),
                "unexpected detail: {detail}"
            )
        }
        other => panic!("oversized inbound record should fail the connection, got {other:?}"),
    }
}

#[tokio::test]
async fn dial_requires_negotiated_subprotocol() {
    let params = NOISE_PROTOCOL_NAME.parse().unwrap();
    let keypair = snow::Builder::new(params).generate_keypair().unwrap();
    let identity = ServerIdentity::from_public_key_bytes(&keypair.public).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());

    // A plain WebSocket server that never selects the EHBP subprotocol.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        let _ = ws.next().await;
    });

    match timeout(TEST_TIMEOUT, NoiseWebSocket::connect(&url, &identity))
        .await
        .unwrap()
    {
        Err(Error::Handshake(detail)) => {
            assert!(
                detail.contains("subprotocol"),
                "unexpected detail: {detail}"
            )
        }
        other => panic!("dial should fail on missing subprotocol, got {other:?}"),
    }
}

#[tokio::test]
async fn dial_handshake_times_out() {
    let params = NOISE_PROTOCOL_NAME.parse().unwrap();
    let keypair = snow::Builder::new(params).generate_keypair().unwrap();
    let identity = ServerIdentity::from_public_key_bytes(&keypair.public).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());

    // Negotiates the subprotocol like a real server, then reads the
    // client's handshake message but never replies, simulating a stalled
    // or hostile peer.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_hdr_async(stream, negotiate_subprotocol)
            .await
            .unwrap();
        let _ = ws.next().await;
        std::future::pending::<()>().await;
    });

    let options = NoiseWebSocketOptions::new().handshake_timeout(Duration::from_millis(200));
    let start = Instant::now();
    match timeout(
        TEST_TIMEOUT,
        NoiseWebSocket::connect_with(&url, &identity, options),
    )
    .await
    .unwrap()
    {
        Err(Error::Handshake(detail)) => {
            assert!(detail.contains("timed out"), "unexpected detail: {detail}");
        }
        other => panic!("dial should time out waiting for the handshake reply, got {other:?}"),
    }
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "dial took too long to time out: {:?}",
        start.elapsed()
    );
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WsVectorRecord {
    dir: String,
    #[serde(rename = "type")]
    record_type: String,
    payload: String,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WsVector {
    protocol_name: String,
    prologue: String,
    server_static_private: String,
    server_static_public: String,
    client_ephemeral_private: String,
    server_ephemeral_private: String,
    message1: String,
    message2: String,
    handshake_hash: String,
    rekey_interval: u64,
    records: Vec<WsVectorRecord>,
}

#[test]
fn noisews_interop_vector() {
    let vector: WsVector =
        serde_json::from_str(include_str!("../../test-vectors/noisews.json")).unwrap();
    assert_eq!(vector.protocol_name, NOISE_PROTOCOL_NAME);
    assert_eq!(vector.prologue.as_bytes(), NOISE_PROLOGUE);

    let server_static_private = hex::decode(&vector.server_static_private).unwrap();
    let server_static_public = hex::decode(&vector.server_static_public).unwrap();
    let client_ephemeral = hex::decode(&vector.client_ephemeral_private).unwrap();
    let server_ephemeral = hex::decode(&vector.server_ephemeral_private).unwrap();

    let mut initiator = snow::Builder::new(vector.protocol_name.parse().unwrap())
        .prologue(vector.prologue.as_bytes())
        .unwrap()
        .remote_public_key(&server_static_public)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&client_ephemeral)
        .build_initiator()
        .unwrap();
    let mut responder = snow::Builder::new(vector.protocol_name.parse().unwrap())
        .prologue(vector.prologue.as_bytes())
        .unwrap()
        .local_private_key(&server_static_private)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&server_ephemeral)
        .build_responder()
        .unwrap();

    let mut message1 = [0u8; 128];
    let len = initiator.write_message(&[], &mut message1).unwrap();
    assert_eq!(hex::encode(&message1[..len]), vector.message1);

    let mut payload = [0u8; 128];
    responder
        .read_message(&message1[..len], &mut payload)
        .unwrap();

    let mut message2 = [0u8; 128];
    let len = responder.write_message(&[], &mut message2).unwrap();
    assert_eq!(hex::encode(&message2[..len]), vector.message2);

    initiator
        .read_message(&message2[..len], &mut payload)
        .unwrap();
    assert_eq!(
        hex::encode(initiator.get_handshake_hash()),
        vector.handshake_hash
    );
    assert_eq!(
        hex::encode(responder.get_handshake_hash()),
        vector.handshake_hash
    );

    let (ck1, ck2) = initiator.dangerously_get_raw_split();
    let (sk1, sk2) = responder.dangerously_get_raw_split();
    assert_eq!(ck1, sk1);
    assert_eq!(ck2, sk2);

    let mut client_send = TestCipher::new(ck1, vector.rekey_interval);
    let mut client_recv = TestCipher::new(ck2, vector.rekey_interval);
    let mut server_send = TestCipher::new(sk2, vector.rekey_interval);
    let mut server_recv = TestCipher::new(sk1, vector.rekey_interval);

    for (i, entry) in vector.records.iter().enumerate() {
        let payload = hex::decode(&entry.payload).unwrap();
        let record_type = match entry.record_type.as_str() {
            "data" => WS_RECORD_DATA,
            "close" => WS_RECORD_CLOSE,
            other => panic!("record {i}: unknown type {other}"),
        };
        let mut record = Vec::with_capacity(1 + payload.len());
        record.push(record_type);
        record.extend_from_slice(&payload);

        let (send, recv) = match entry.dir.as_str() {
            "c2s" => (&mut client_send, &mut server_recv),
            "s2c" => (&mut server_send, &mut client_recv),
            other => panic!("record {i}: unknown dir {other}"),
        };
        let ciphertext = send.encrypt(&record);
        assert_eq!(
            hex::encode(&ciphertext),
            entry.ciphertext,
            "record {i} ciphertext mismatch"
        );
        let plaintext = recv.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, record, "record {i} round trip mismatch");
    }

    // Not part of the vector, but keep the default schedule aligned with the
    // reference implementation.
    assert_eq!(WS_REKEY_INTERVAL, 1 << 16);
    assert_eq!(DEFAULT_WS_MAX_MESSAGE_SIZE, 1 << 20);
}
