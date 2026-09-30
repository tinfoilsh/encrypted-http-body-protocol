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

/// Classified failures are `Error::Coded(code, detail)` and render as
/// `<CODE>: <detail>`; match on the code as with `std::io::ErrorKind`. Codes are
/// for the in-process caller only and never sent on the wire (SPEC 5.4.4).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("{0}: {1}")]
    Coded(Code, String),

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
        match self {
            Error::Coded(code, _) => Some(*code),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
