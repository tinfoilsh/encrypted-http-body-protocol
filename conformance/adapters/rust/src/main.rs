//! EHBP conformance adapter (Rust). See conformance/adapters/README.md.
//!
//! Reads one fixture on stdin, runs it through the public tinfoil-ehbp API,
//! prints one normalized result. All native-error translation lives in map_error.

use std::io::Read;

use serde::Serialize;
use serde_json::{Map, Value};
use tinfoil_ehbp::{
    compute_nonce, derive_response_keys, Client, Code, Error, ServerIdentity, SessionRecoveryToken,
    RESPONSE_NONCE_HEADER,
};

const HEADER_SUBSET: [&str; 4] = [
    "ehbp-response-nonce",
    "content-length",
    "transfer-encoding",
    "content-type",
];

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
    token_before_response: Option<bool>,
}

#[tokio::main]
async fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let fx: Value = serde_json::from_str(&input).unwrap();

    let op = fx["operation"].as_str().unwrap_or("").to_string();
    let mut out = Out {
        fixture_id: fx["id"].as_str().unwrap_or("").to_string(),
        outcome: "ok".into(),
        runner: "rust".into(),
        ..Default::default()
    };

    if let Err(err) = run(&fx, &op, &mut out).await {
        out.outcome = "error".into();
        out.error_code = Some(map_error(&op, &err));
        out.body_hex = None;
        out.native_error = Some(format!("{err}"));
    }
    println!("{}", serde_json::to_string(&out).unwrap());
}

async fn run(fx: &Value, op: &str, out: &mut Out) -> Result<(), Error> {
    let ins = &fx["inputs"];
    match op {
        "derive_keys" => {
            let km = derive_response_keys(
                &h(ins, "exportedSecret")?,
                &h(ins, "requestEnc")?,
                &h(ins, "responseNonce")?,
            )?;
            out.body_hex = Some(hex::encode(
                [km.key.as_slice(), km.nonce_base.as_slice()].concat(),
            ));
        }
        "compute_nonce" => {
            let base: [u8; 12] = h(ins, "nonceBase")?.try_into().map_err(|_| {
                Error::Coded(Code::InvalidInput, "nonce base must be 12 bytes".into())
            })?;
            let seq = u64::from_str_radix(ins["seqHex"].as_str().unwrap_or(""), 16)
                .map_err(|e| Error::Coded(Code::InvalidInput, e.to_string()))?;
            out.body_hex = Some(hex::encode(compute_nonce(&base, seq)));
        }
        "decrypt_response" | "decrypt_response_streaming" => decrypt(fx, out)?,
        "token_roundtrip" => {
            let t = SessionRecoveryToken::from_json(ins["json"].as_str().unwrap_or(""))?;
            out.body_hex = Some(hex::encode(
                [t.exported_secret.as_slice(), t.request_enc.as_slice()].concat(),
            ));
        }
        "parse_config" => {
            let id = ServerIdentity::unmarshal_public_config(&h(ins, "config")?)?;
            out.body_hex = Some(hex::encode(id.public_key_bytes()));
        }
        "marshal_config" => {
            let id = ServerIdentity::from_public_key_bytes(&h(ins, "publicKey")?)?;
            out.body_hex = Some(hex::encode(id.marshal_public_config()));
        }
        "request" => request(fx, out).await?,
        "large_body" => large_body(fx, out).await?,
        "token_before_response" => token_before_response(fx, out).await?,
        "discover" => {
            Client::new(&discover_target(fx)).await?;
        }
        "reject_reserved_header" | "reject_cross_origin" | "reject_url_credentials" => {
            harden(op).await?;
        }
        other => {
            return Err(Error::Coded(
                Code::InvalidInput,
                format!("unknown operation {other}"),
            ))
        }
    }
    Ok(())
}

fn discover_target(fx: &Value) -> String {
    let var = match fx["inputs"]["target"].as_str().unwrap_or("") {
        "bad_ct" => "ORACLE_BAD_CT_URL",
        "non200" => "ORACLE_NON200_URL",
        _ => "ORACLE_URL",
    };
    std::env::var(var).unwrap_or_default()
}

async fn harden(op: &str) -> Result<(), Error> {
    let base = std::env::var("ORACLE_URL").unwrap_or_default();
    let client = Client::new(&base).await?;
    match op {
        "reject_reserved_header" => {
            client
                .post("/s/echo")?
                .header("ehbp-encapsulated-key", "x")?;
        }
        "reject_cross_origin" => {
            client.get("http://other.example/x")?;
        }
        _ => {
            client.get(&base.replace("http://", "http://user:pass@"))?;
        }
    }
    Ok(())
}

fn decrypt(fx: &Value, out: &mut Out) -> Result<(), Error> {
    let ins = &fx["inputs"];
    let token = SessionRecoveryToken::new(h(ins, "exportedSecret")?, h(ins, "requestEnc")?)?;
    let mut dec = token.response_decryptor(&h(ins, "responseNonce")?)?;
    let framed = h(ins, "encryptedResponse")?;
    let segments = if fx["operation"].as_str() == Some("decrypt_response_streaming") {
        split_at(&framed, fx.get("chunking"))
    } else {
        vec![framed.clone()]
    };

    let mut acc: Vec<u8> = Vec::new();
    // Fail-closed bookkeeping: whatever plaintext was delivered before the error.
    let record_partial = |out: &mut Out, acc: &[u8]| {
        out.bytes_emitted_before_error = acc.len();
        out.plaintext_emitted_before_error = !acc.is_empty();
    };
    for seg in segments {
        match dec.push(&seg) {
            Ok(chunks) => {
                for c in chunks {
                    acc.extend_from_slice(&c);
                }
            }
            Err(e) => {
                record_partial(out, &acc);
                return Err(e);
            }
        }
    }
    if let Err(e) = dec.finish() {
        record_partial(out, &acc);
        return Err(e);
    }
    out.body_hex = Some(hex::encode(acc));
    Ok(())
}

async fn request(fx: &Value, out: &mut Out) -> Result<(), Error> {
    let base = std::env::var("ORACLE_URL").unwrap_or_default();
    let client = Client::new(&base).await?;
    let req = &fx["request"];
    let path = req["path"].as_str().unwrap_or("/");

    // Reject rather than silently downgrade an unexpected method to POST.
    let mut builder = match req["method"].as_str().unwrap_or("POST") {
        "GET" => client.get(path)?,
        "PUT" => client.put(path)?,
        "DELETE" => client.delete(path)?,
        "POST" => client.post(path)?,
        other => {
            return Err(Error::Coded(
                Code::InvalidInput,
                format!("unsupported fixture method {other}"),
            ))
        }
    };
    if let Some(headers) = req["headers"].as_object() {
        for (k, v) in headers {
            builder = builder.header(k.as_str(), v.as_str().unwrap_or(""))?;
        }
    }
    if req["body_hex"].is_string() {
        builder = builder.body(h(req, "body_hex")?);
    }

    let resp = builder.send().await?;
    out.status = Some(resp.status().as_u16());

    let mut headers = Map::new();
    for name in HEADER_SUBSET {
        if let Some(v) = resp.headers().get(name).and_then(|v| v.to_str().ok()) {
            headers.insert(name.to_string(), Value::String(v.to_string()));
        }
    }
    let no_nonce = !headers.contains_key(&RESPONSE_NONCE_HEADER.to_ascii_lowercase());
    out.response_headers = Some(headers);
    let status = resp.status();
    out.body_hex = Some(hex::encode(resp.bytes()));
    out.passthrough = no_nonce && !status.is_success();
    Ok(())
}

/// large_body streams a multi-GiB patterned body (1 MiB block, block[i] =
/// (i + seed) & 0xff, repeated) to the oracle's digest route without ever
/// materialising it, and reports peak RSS so buffering would be visible.
async fn large_body(fx: &Value, out: &mut Out) -> Result<(), Error> {
    let size = fx["inputs"]["size_bytes"].as_u64().unwrap_or(0);
    let seed = fx["inputs"]["block_seed"].as_u64().unwrap_or(0) as usize;
    let block: bytes::Bytes = (0..1usize << 20)
        .map(|i| (i + seed) as u8)
        .collect::<Vec<u8>>()
        .into();
    let source = futures_util::stream::unfold((block, size), |(block, remaining)| async move {
        if remaining == 0 {
            return None;
        }
        let n = remaining.min(block.len() as u64) as usize;
        Some((
            Ok::<_, std::io::Error>(block.slice(..n)),
            (block, remaining - n as u64),
        ))
    });

    let base = std::env::var("ORACLE_URL").unwrap_or_default();
    let client = Client::new(&base).await?;
    let path = fx["request"]["path"].as_str().unwrap_or("/s/digest");
    let resp = client.post(path)?.body_stream(source).send().await?;
    out.status = Some(resp.status().as_u16());
    out.body_hex = Some(hex::encode(resp.bytes()));
    out.peak_rss_bytes = Some(peak_rss_bytes());
    Ok(())
}

/// Reads the session recovery token while the oracle still holds its reply (SPEC 6).
async fn token_before_response(fx: &Value, out: &mut Out) -> Result<(), Error> {
    let base = std::env::var("ORACLE_URL").unwrap_or_default();
    let client = Client::new(&base).await?;
    let req = &fx["request"];
    let body = h(req, "body_hex")?;
    let pending = client
        .post(req["path"].as_str().unwrap_or("/"))?
        .body(body)
        .send();
    let observer = client.clone();
    let (resp, early) = tokio::join!(pending, async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await; // oracle holds 5 s
        observer.get_session_recovery_token().is_some()
    });
    out.token_before_response = Some(early);
    let resp = resp?;
    out.status = Some(resp.status().as_u16());
    out.body_hex = Some(hex::encode(resp.bytes()));
    Ok(())
}

fn peak_rss_bytes() -> u64 {
    // SAFETY: getrusage only writes into the zeroed struct we hand it.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let max = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        max
    } else {
        max << 10
    }
}

/// map_error reads the canonical code the library attached (Error::code()).
/// Anything uncoded is a caller/adapter input error.
fn map_error(_op: &str, err: &Error) -> String {
    err.code()
        .map(|c| c.as_str().to_string())
        .unwrap_or_else(|| "INVALID_INPUT".to_string())
}

fn h(ins: &Value, key: &str) -> Result<Vec<u8>, Error> {
    hex::decode(ins[key].as_str().unwrap_or(""))
        .map_err(|e| Error::Coded(Code::InvalidInput, format!("fixture field {key}: {e}")))
}

fn split_at(data: &[u8], offsets: Option<&Value>) -> Vec<Vec<u8>> {
    let offsets: Vec<usize> = offsets
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_u64().map(|n| n as usize))
                .collect()
        })
        .unwrap_or_default();
    if offsets.is_empty() {
        return vec![data.to_vec()];
    }
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
