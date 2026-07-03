use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid key configuration: {0}")]
    InvalidConfig(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("key configuration mismatch: {0}")]
    KeyConfigMismatch(String),

    #[error("HPKE error: {0}")]
    Hpke(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("header value error: {0}")]
    HeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("noise handshake failed: {0}")]
    Handshake(String),

    #[error("websocket error: {0}")]
    WebSocket(String),

    #[error("encrypted channel closed")]
    ChannelClosed,

    #[error("connection closed without encrypted close record: {0}")]
    ChannelTruncated(String),
}

pub type Result<T> = std::result::Result<T, Error>;
