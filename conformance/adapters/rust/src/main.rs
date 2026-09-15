//! EHBP conformance adapter (Rust). See conformance/adapters/README.md.
//!
//! Reads one fixture on stdin, runs it through the public tinfoil-ehbp API,
//! prints one normalized result. All native-error translation lives in map_error.

use std::io::Read;

use serde::Serialize;
use serde_json::{Map, Value};
use tinfoil_ehbp::{
    compute_nonce, derive_response_keys, Client, Error, ServerIdentity, SessionRecoveryToken,
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
            let km = derive_response_keys(&h(ins, "exportedSecret"), &h(ins, "requestEnc"), &h(ins, "responseNonce"))?;
            out.body_hex = Some(hex::encode([km.key.as_slice(), km.nonce_base.as_slice()].concat()));
        }
        "compute_nonce" => {
            let base: [u8; 12] = h(ins, "nonceBase")
                .try_into()
                .map_err(|_| Error::InvalidInput("nonce base must be 12 bytes".into()))?;
            let seq = u64::from_str_radix(ins["seqHex"].as_str().unwrap_or(""), 16)
                .map_err(|e| Error::InvalidInput(e.to_string()))?;
            out.body_hex = Some(hex::encode(compute_nonce(&base, seq)));
        }
        "decrypt_response" | "decrypt_response_streaming" => decrypt(fx, out)?,
        "token_roundtrip" => {
            let t: SessionRecoveryToken = serde_json::from_str(ins["json"].as_str().unwrap_or(""))
                .map_err(Error::from)?;
            out.body_hex = Some(hex::encode([t.exported_secret.as_slice(), t.request_enc.as_slice()].concat()));
        }
        "parse_config" => {
            let id = ServerIdentity::unmarshal_public_config(&h(ins, "config"))?;
            out.body_hex = Some(hex::encode(id.public_key_bytes()));
        }
        "marshal_config" => {
            let id = ServerIdentity::from_public_key_bytes(&h(ins, "publicKey"))?;
            out.body_hex = Some(hex::encode(id.marshal_public_config()));
        }
        "request" => request(fx, out).await?,
        "discover" => {
            Client::new(&discover_target(fx)).await?;
        }
        "reject_reserved_header" | "reject_cross_origin" | "reject_url_credentials" => {
            harden(op).await?;
        }
        other => return Err(Error::InvalidInput(format!("unknown operation {other}"))),
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
            client.post("/s/echo")?.header("ehbp-encapsulated-key", "x")?;
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
    let token = SessionRecoveryToken::new(h(ins, "exportedSecret"), h(ins, "requestEnc"))?;
    let mut dec = token.response_decryptor(&h(ins, "responseNonce"))?;
    let framed = h(ins, "encryptedResponse");
    let segments = if fx["operation"].as_str() == Some("decrypt_response_streaming") {
        split_at(&framed, fx.get("chunking"))
    } else {
        vec![framed.clone()]
    };

    let mut acc: Vec<u8> = Vec::new();
    for seg in segments {
        match dec.push(&seg) {
            Ok(chunks) => {
                for c in chunks {
                    acc.extend_from_slice(&c);
                }
            }
            Err(e) => {
                out.bytes_emitted_before_error = acc.len();
                out.plaintext_emitted_before_error = !acc.is_empty();
                return Err(e);
            }
        }
    }
    if let Err(e) = dec.finish() {
        out.bytes_emitted_before_error = acc.len();
        out.plaintext_emitted_before_error = !acc.is_empty();
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

    let mut builder = match req["method"].as_str().unwrap_or("POST") {
        "GET" => client.get(path)?,
        "PUT" => client.put(path)?,
        "DELETE" => client.delete(path)?,
        _ => client.post(path)?,
    };
    if let Some(headers) = req["headers"].as_object() {
        for (k, v) in headers {
            builder = builder.header(k.as_str(), v.as_str().unwrap_or(""))?;
        }
    }
    if let Some(body_hex) = req["body_hex"].as_str() {
        builder = builder.body(hex::decode(body_hex).unwrap_or_default());
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

/// map_error is the sole native-error -> canonical-code translation.
fn map_error(op: &str, err: &Error) -> String {
    let msg = format!("{err}").to_lowercase();
    match err {
        Error::KeyConfigMismatch(_) => "KEY_CONFIG_MISMATCH",
        Error::Crypto(_) => "AEAD_DECRYPT_FAILED",
        Error::Hpke(_) => "HPKE_SETUP_FAILED",
        Error::InvalidConfig(_) => {
            if msg.contains("unsupported") {
                "UNSUPPORTED_SUITE"
            } else {
                "INVALID_KEY_CONFIG"
            }
        }
        Error::Json(_) if op == "token_roundtrip" => "INVALID_TOKEN",
        Error::InvalidInput(_) if op == "token_roundtrip" => "INVALID_TOKEN",
        Error::InvalidInput(_) => "INVALID_INPUT",
        // In the request path the only hex decode is the response nonce, so a
        // bare hex error there is a malformed nonce.
        Error::Hex(_) if op == "request" => "INVALID_RESPONSE_NONCE",
        Error::Protocol(_) => {
            if msg.contains("content type") || msg.contains("returned status") {
                "INVALID_KEY_CONFIG"
            } else if msg.contains("missing") && msg.contains("nonce") {
                "MISSING_RESPONSE_NONCE"
            } else if msg.contains("multiple") {
                "DUPLICATE_RESPONSE_NONCE"
            } else if msg.contains("nonce") {
                "INVALID_RESPONSE_NONCE"
            } else if msg.contains("truncated") {
                "FRAMING_TRUNCATED"
            } else if msg.contains("exceeds maximum") {
                "CHUNK_TOO_LARGE"
            } else if msg.contains("overflow") {
                "SEQUENCE_OVERFLOW"
            } else {
                "INVALID_INPUT"
            }
        }
        _ => "INVALID_INPUT",
    }
    .to_string()
}

fn h(ins: &Value, key: &str) -> Vec<u8> {
    hex::decode(ins[key].as_str().unwrap_or("")).unwrap_or_default()
}

fn split_at(data: &[u8], offsets: Option<&Value>) -> Vec<Vec<u8>> {
    let offsets: Vec<usize> = offsets
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as usize)).collect())
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
