//! EHBP conformance adapter (Rust). See conformance/adapters/README.md.
//!
//! Reads one fixture on stdin, runs it through the public tinfoil-ehbp API,
//! prints one normalized result. All native-error translation lives in map_error.

use std::io::Read;

use futures_util::StreamExt;
use serde::Serialize;
use serde_json::{Map, Value};
use tinfoil_ehbp::{
    core::{derive_response_keys, marshal_config, nonce_for, parse_config, parse_token, SessionRecoveryToken},
    Body, Client, Code, Error, KeySource,
};

const HEADER_SUBSET: [&str; 4] = ["ehbp-response-nonce", "content-length", "transfer-encoding", "content-type"];

#[derive(Serialize, Default)]
struct Out {
    fixture_id: String,
    outcome: String,
    error_code: Option<String>,
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_headers: Option<Map<String, Value>>,
    body_hex: Option<String>,
    passthrough: bool,
    plaintext_emitted_before_error: bool,
    bytes_emitted_before_error: usize,
    native_error: Option<String>,
    runner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    peak_rss_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_before_close: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_after_close: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_before_response: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_after_exchange: Option<bool>,
}

#[tokio::main]
async fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let fx: Value = serde_json::from_str(&input).unwrap();
    let mut out = Out {
        fixture_id: fx["id"].as_str().unwrap_or("").to_string(),
        outcome: "ok".into(),
        runner: "rust".into(),
        ..Default::default()
    };
    if let Err(err) = run(&fx, &mut out).await {
        out.outcome = "error".into();
        out.error_code = Some(map_error(&err));
        out.body_hex = None;
        out.native_error = Some(format!("{err}"));
    }
    println!("{}", serde_json::to_string(&out).unwrap());
}

/// The canonical code the library attached (Error::code()); anything uncoded is a caller/adapter input error.
fn map_error(err: &Error) -> String {
    err.code()
        .map(|c| c.as_str().to_string())
        .unwrap_or_else(|| "INVALID_INPUT".to_string())
}

async fn run(fx: &Value, out: &mut Out) -> Result<(), Error> {
    match fx["operation"].as_str().unwrap_or("") {
        "derive_keys" => {
            let km = derive_response_keys(&hex_in(fx, "exportedSecret")?, &hex_in(fx, "requestEnc")?, &hex_in(fx, "responseNonce")?)?;
            out.body_hex = Some(hex::encode([km.key.as_slice(), km.nonce_base.as_slice()].concat()));
        }
        "decrypt_response" => {
            decrypt(fx, out, false)?;
        }
        "decrypt_response_streaming" => {
            decrypt(fx, out, true)?;
        }
        "compute_nonce" => {
            let seq = u64::from_str_radix(str_in(fx, "seqHex"), 16).map_err(|e| Error::Coded(Code::InvalidInput, e.to_string()))?;
            out.body_hex = Some(hex::encode(nonce_for(&hex_in(fx, "nonceBase")?, seq)?));
        }
        "token_roundtrip" => {
            let t = parse_token(str_in(fx, "json"))?;
            out.body_hex = Some(hex::encode([t.exported_secret.as_slice(), t.request_enc.as_slice()].concat()));
        }
        "parse_config" => {
            out.body_hex = Some(hex::encode(parse_config(&hex_in(fx, "config")?)?));
        }
        "marshal_config" => {
            out.body_hex = Some(hex::encode(marshal_config(&hex_in(fx, "publicKey")?)?)); // keyId is opaque: always 0
        }
        "request" => {
            exchange(fx, out, "bytes", false, false, false, false).await?;
        }
        "discover" => {
            Client::discover(discover_target(fx), None).await?; // fails on a bad key configuration
        }
        "reject_reserved_header" => {
            hardening(fx, "header").await?;
        }
        "reject_cross_origin" => {
            hardening(fx, "cross").await?;
        }
        "residue_selfcheck" => {
            let lines = tinfoil_ehbp::self_check().await; // the core's shared vectors through this language's bindings
            out.body_hex = Some(hex::encode(lines.join("\n")));
            if !lines.is_empty() {
                out.native_error = Some(lines.join("; "));
            }
        }
        "reject_url_credentials" => {
            hardening(fx, "credentials").await?;
        }
        "large_body" => {
            exchange(fx, out, "pattern", false, false, false, true).await?;
        }
        "request_stream" => {
            exchange(fx, out, "stream", false, false, false, false).await?;
        }
        "close_response_early" => {
            exchange(fx, out, "bytes", false, true, false, false).await?;
        }
        "token_before_response" => {
            exchange(fx, out, "bytes", true, false, false, false).await?;
        }
        "token_after_exchange" => {
            exchange(fx, out, "bytes", false, false, true, false).await?;
        }
        other => return Err(Error::Coded(Code::InvalidInput, format!("unknown operation {other}"))),
    }
    Ok(())
}

/// A client over the oracle, discovering its key through the library.
async fn oracle() -> Result<(String, Client), Error> {
    let base = std::env::var("ORACLE_URL").unwrap_or_default();
    Ok((base.clone(), Client::new(base, KeySource::Discover, None).await?))
}

/// The token-only response path over the framed body, fed whole or split at
/// the fixture's byte offsets; reports the plaintext delivered.
fn decrypt(fx: &Value, out: &mut Out, streaming: bool) -> Result<(), Error> {
    let token = SessionRecoveryToken::new(hex_in(fx, "exportedSecret")?, hex_in(fx, "requestEnc")?)?;
    let mut dec = token.response_decryptor(&hex_in(fx, "responseNonce")?)?;
    let framed = hex_in(fx, "encryptedResponse")?;
    let segments = if streaming { split_at(&framed, fx.get("chunking")) } else { vec![framed] };
    let mut acc: Vec<u8> = Vec::new();
    let result = (|| {
        for seg in segments {
            for c in dec.push(&seg)? {
                acc.extend_from_slice(&c);
            }
        }
        dec.finish()
    })();
    if let Err(e) = result {
        record_partial(out, &acc);
        return Err(e);
    }
    out.body_hex = Some(hex::encode(acc));
    Ok(())
}

/// Sends the fixture request to the oracle and reads the reply. body is how
/// the fixture body is supplied (bytes, stream: unknown length, pattern: the
/// lazy large body); hold reads the token while the oracle holds its reply;
/// early reads one byte and closes; after reads the token once the exchange
/// ended, also on error; rss reports peak RSS.
async fn exchange(fx: &Value, out: &mut Out, body: &str, hold: bool, early: bool, after: bool, rss: bool) -> Result<(), Error> {
    let (_, client) = oracle().await?;
    let result: Result<(), Error> = async {
        let req = &fx["request"];
        let headers: Vec<(&str, &str)> = req["headers"].as_object().map(|h| h.iter().map(|(k, v)| (k.as_str(), v.as_str().unwrap_or(""))).collect()).unwrap_or_default();
        let payload = if body == "pattern" {
            Some(Body::stream(pattern(int_in(fx, "size_bytes"), int_in(fx, "block_seed") as usize)))
        } else if let Some(b) = req["body_hex"].as_str() {
            let b = hex::decode(b).map_err(|e| Error::Coded(Code::InvalidInput, e.to_string()))?;
            Some(if body == "stream" {
                let chunk = bytes::Bytes::from(b);
                Body::stream(futures_util::stream::once(async move { Ok::<_, std::io::Error>(chunk) }))
            } else {
                Body::from(b)
            })
        } else {
            None
        };
        let send = client.request(req["method"].as_str().unwrap_or("GET"), req["path"].as_str().unwrap_or("/"), &headers, payload);
        let (resp, token_early) = tokio::join!(send, async {
            if !hold {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await; // the oracle holds 5 s
            Some(client.session_recovery_token().is_some())
        });
        out.token_before_response = token_early;
        let mut resp = resp?;
        let status = resp.status();
        out.status = Some(status.as_u16());
        let headers = subset_headers(|n| resp.headers().get(n).and_then(|v| v.to_str().ok()));
        let no_nonce = !headers.contains_key(&"Ehbp-Response-Nonce".to_ascii_lowercase());
        out.response_headers = Some(headers);
        if early {
            let first = resp.next().await.transpose()?.unwrap_or_default();
            out.body_hex = Some(hex::encode(&first[..first.len().min(1)]));
            out.token_before_close = Some(client.session_recovery_token().is_some());
            drop(resp);
            out.token_after_close = Some(client.session_recovery_token().is_some());
        } else {
            let mut acc: Vec<u8> = Vec::new();
            while let Some(chunk) = resp.next().await {
                match chunk {
                    Ok(c) => acc.extend_from_slice(&c),
                    Err(e) => {
                        record_partial(out, &acc);
                        return Err(e);
                    }
                }
            }
            out.body_hex = Some(hex::encode(acc));
            // No nonce on a non-2xx is a sanctioned unauthenticated pass-through.
            out.passthrough = no_nonce && !status.is_success();
        }
        if rss {
            out.peak_rss_bytes = Some(peak_rss_bytes());
        }
        Ok(())
    }
    .await;
    if after {
        out.token_after_exchange = Some(client.session_recovery_token().is_some());
    }
    result
}

/// Sends a request the library must refuse before it reaches the wire; a
/// reply from the oracle is the divergent result.
async fn hardening(fx: &Value, target: &str) -> Result<(), Error> {
    let (base, client) = oracle().await?;
    let url = match target {
        "cross" => "http://other.invalid/probe".to_string(),
        "credentials" => base.replacen("://", "://user:pass@", 1) + "/probe",
        _ => base + "/probe",
    };
    let mut headers = Vec::new();
    if target == "header" {
        let name = str_in(fx, "header");
        let value = if name.eq_ignore_ascii_case("host") { "attacker.invalid" } else { "0000000000000000000000000000000000000000000000000000000000000000" };
        headers.push((name, value));
    }
    client.request("POST", url, &headers, Some("x".into())).await?.bytes().await?;
    Ok(())
}

/// The oracle listener the harness exposes as ORACLE_<TARGET>_URL (the main oracle for anything else).
fn discover_target(fx: &Value) -> String {
    let target = str_in(fx, "target").to_ascii_uppercase();
    if target != "ORACLE_URL" {
        if let Ok(url) = std::env::var(format!("ORACLE_{target}_URL")) {
            return url;
        }
    }
    std::env::var("ORACLE_URL").unwrap_or_default()
}

// --- helpers ---

/// Fail-closed bookkeeping: whatever plaintext was delivered before the error.
fn record_partial(out: &mut Out, acc: &[u8]) {
    out.bytes_emitted_before_error = acc.len();
    out.plaintext_emitted_before_error = !acc.is_empty();
}

fn split_at(data: &[u8], offsets: Option<&Value>) -> Vec<Vec<u8>> {
    let offsets: Vec<usize> = offsets
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as usize)).collect())
        .unwrap_or_default();
    let mut segs = Vec::new();
    let mut prev = 0;
    for o in offsets {
        if o > prev && o < data.len() {
            segs.push(data[prev..o].to_vec());
            prev = o;
        }
    }
    segs.push(data[prev..].to_vec());
    segs
}

/// size bytes of a 1 MiB block with block[i] = (i + seed) & 0xff, repeated, never materialised.
fn pattern(size: u64, seed: usize) -> impl futures_util::Stream<Item = std::result::Result<bytes::Bytes, std::io::Error>> {
    let block: bytes::Bytes = (0..1usize << 20).map(|i| (i + seed) as u8).collect::<Vec<u8>>().into();
    futures_util::stream::unfold((block, size), |(block, remaining)| async move {
        if remaining == 0 {
            return None;
        }
        let n = remaining.min(block.len() as u64) as usize;
        Some((Ok(block.slice(..n)), (block, remaining - n as u64)))
    })
}

fn peak_rss_bytes() -> u64 {
    // SAFETY: getrusage only writes into the zeroed struct we hand it.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let max = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") { max } else { max << 10 }
}

fn subset_headers<'a>(get: impl Fn(&str) -> Option<&'a str>) -> Map<String, Value> {
    HEADER_SUBSET
        .iter()
        .filter_map(|name| get(name).map(|v| (name.to_string(), Value::String(v.to_string()))))
        .collect()
}

// Fixture inputs are repository-controlled; a missing field is a broken fixture, so fail loudly (ADAPTER_CRASH).
fn hex_in(fx: &Value, key: &str) -> Result<Vec<u8>, Error> {
    hex::decode(str_in(fx, key)).map_err(|e| Error::Coded(Code::InvalidInput, format!("fixture field {key}: {e}")))
}

fn str_in<'a>(fx: &'a Value, key: &str) -> &'a str {
    fx["inputs"][key].as_str().unwrap_or_else(|| {
        eprintln!("fixture: input {key} missing or not a string");
        std::process::exit(2)
    })
}

fn int_in(fx: &Value, key: &str) -> u64 {
    fx["inputs"][key].as_u64().unwrap_or(0)
}
