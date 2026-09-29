use thiserror::Error;

/// Canonical, cross-SDK error class (SPEC Section 5.5). The string form is
/// identical in every SDK, so a caller's handling ports between languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    InvalidKeyConfig,
    UnsupportedSuite,
    InvalidEncapsulatedKey,
    HpkeSetupFailed,
    MissingResponseNonce,
    InvalidResponseNonce,
    DuplicateResponseNonce,
    KeyConfigMismatch,
    FramingTruncated,
    ChunkTooLarge,
    AeadDecryptFailed,
    SequenceOverflow,
    InvalidToken,
    InvalidInput,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::InvalidKeyConfig => "INVALID_KEY_CONFIG",
            Code::UnsupportedSuite => "UNSUPPORTED_SUITE",
            Code::InvalidEncapsulatedKey => "INVALID_ENCAPSULATED_KEY",
            Code::HpkeSetupFailed => "HPKE_SETUP_FAILED",
            Code::MissingResponseNonce => "MISSING_RESPONSE_NONCE",
            Code::InvalidResponseNonce => "INVALID_RESPONSE_NONCE",
            Code::DuplicateResponseNonce => "DUPLICATE_RESPONSE_NONCE",
            Code::KeyConfigMismatch => "KEY_CONFIG_MISMATCH",
            Code::FramingTruncated => "FRAMING_TRUNCATED",
            Code::ChunkTooLarge => "CHUNK_TOO_LARGE",
            Code::AeadDecryptFailed => "AEAD_DECRYPT_FAILED",
            Code::SequenceOverflow => "SEQUENCE_OVERFLOW",
            Code::InvalidToken => "INVALID_TOKEN",
            Code::InvalidInput => "INVALID_INPUT",
        }
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Every classified variant renders as `<CODE>: <detail>`. Codes are for the
/// in-process caller only and never sent on the wire (SPEC 5.4.4).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("INVALID_KEY_CONFIG: {0}")]
    InvalidConfig(String),

    #[error("UNSUPPORTED_SUITE: {0}")]
    UnsupportedSuite(String),

    #[error("INVALID_INPUT: {0}")]
    InvalidInput(String),

    #[error("INVALID_TOKEN: {0}")]
    InvalidToken(String),

    #[error("MISSING_RESPONSE_NONCE: {0}")]
    MissingResponseNonce(String),

    #[error("INVALID_RESPONSE_NONCE: {0}")]
    InvalidResponseNonce(String),

    #[error("DUPLICATE_RESPONSE_NONCE: {0}")]
    DuplicateResponseNonce(String),

    #[error("FRAMING_TRUNCATED: {0}")]
    FramingTruncated(String),

    #[error("CHUNK_TOO_LARGE: {0}")]
    ChunkTooLarge(String),

    #[error("SEQUENCE_OVERFLOW: {0}")]
    SequenceOverflow(String),

    #[error("KEY_CONFIG_MISMATCH: {0}")]
    KeyConfigMismatch(String),

    #[error("HPKE_SETUP_FAILED: {0}")]
    Hpke(String),

    #[error("AEAD_DECRYPT_FAILED: {0}")]
    Crypto(String),

    /// Unclassified protocol or internal failure; carries no canonical code.
    #[error("protocol error: {0}")]
    Protocol(String),

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
}

impl Error {
    /// The canonical code, or `None` for transport and internal errors.
    pub fn code(&self) -> Option<Code> {
        Some(match self {
            Error::InvalidConfig(_) => Code::InvalidKeyConfig,
            Error::UnsupportedSuite(_) => Code::UnsupportedSuite,
            Error::InvalidInput(_) => Code::InvalidInput,
            Error::InvalidToken(_) => Code::InvalidToken,
            Error::MissingResponseNonce(_) => Code::MissingResponseNonce,
            Error::InvalidResponseNonce(_) => Code::InvalidResponseNonce,
            Error::DuplicateResponseNonce(_) => Code::DuplicateResponseNonce,
            Error::FramingTruncated(_) => Code::FramingTruncated,
            Error::ChunkTooLarge(_) => Code::ChunkTooLarge,
            Error::SequenceOverflow(_) => Code::SequenceOverflow,
            Error::KeyConfigMismatch(_) => Code::KeyConfigMismatch,
            Error::Hpke(_) => Code::HpkeSetupFailed,
            Error::Crypto(_) => Code::AeadDecryptFailed,
            _ => return None,
        })
    }
}

pub type Result<T> = std::result::Result<T, Error>;
