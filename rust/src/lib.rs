//! Rust client for the encrypted HTTP body protocol: an API shim over the
//! shared event-driven Dafny core (dafny/ehbp_events.dfy) through the
//! bindings and pump in `residue.rs`.

mod client;
mod error;
mod identity;
mod protocol;
mod residue;

pub use client::{Body, Client, KeySource, Response};
pub use error::{Code, Error, Result};
pub use protocol::*;

/// Helpers over the pure core, for the conformance adapter and tests only
/// (conformance/spec/handler.md section 7); not part of the client API.
pub mod core {
    pub use crate::identity::*;
}

/// Runs the core's shared known-answer vectors (dafny/ehbp_events.dfy
/// `SelfCheckActions`) through this crate's crypto bindings, judged by the
/// core's `SelfCheckJudge`; the failed checks, empty on pass.
pub async fn self_check() -> Vec<String> {
    residue::self_check().await
}
