//! Rust client for the encrypted HTTP body protocol.

mod client;
mod derive;
mod error;
mod identity;
#[cfg(feature = "ws")]
mod noisews;
mod protocol;
mod session;

pub use client::{Client, RequestBuilder, Response, StreamingResponse};
pub use derive::{compute_nonce, derive_response_keys, ResponseKeyMaterial};
pub use error::{Error, Result};
pub use identity::ServerIdentity;
#[cfg(feature = "ws")]
pub use noisews::{NoiseWebSocket, NoiseWebSocketOptions};
pub use protocol::*;
pub use session::SessionRecoveryToken;
