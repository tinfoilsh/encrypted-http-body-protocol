// EHBP conformance adapter (JavaScript / Node). See conformance/adapters/README.md.
//
// Reads one fixture on stdin, runs it through the public ehbp API, prints one
// normalized result. All native-error translation lives in mapError.

import {
  Identity,
  createTransport,
  deriveResponseKeys,
  computeNonce,
  decryptResponseWithToken,
  deserializeSessionRecoveryToken,
  hexToBytes,
  bytesToHex,
  KeyConfigMismatchError,
  ProtocolError,
  DecryptionError,
} from '../../../js/dist/esm/index.js';

const HEADER_SUBSET = ['ehbp-response-nonce', 'content-length', 'transfer-encoding', 'content-type'];
const RESPONSE_NONCE_HEADER = 'Ehbp-Response-Nonce';

async function main() {
  const fx = JSON.parse(await readStdin());
  const res = {
    fixture_id: fx.id, outcome: 'ok', error_code: null, status: null, body_hex: null,
    passthrough: false, plaintext_emitted_before_error: false,
    bytes_emitted_before_error: 0, native_error: null, runner: 'js',
  };
  try {
    await run(fx, res);
  } catch (err) {
    res.outcome = 'error';
    res.error_code = mapError(fx.operation, err);
    res.body_hex = null;
    res.native_error = `${err?.name || 'Error'}: ${err?.message || err}`;
  }
  process.stdout.write(JSON.stringify(res));
}

async function run(fx, res) {
  const ins = fx.inputs || {};
  switch (fx.operation) {
    case 'derive_keys': {
      const km = await deriveResponseKeys(hb(ins.exportedSecret), hb(ins.requestEnc), hb(ins.responseNonce));
      res.body_hex = bytesToHex(km.keyBytes) + bytesToHex(km.nonceBase);
      return;
    }
    case 'compute_nonce': {
      const seq = Number.parseInt(ins.seqHex, 16);
      res.body_hex = bytesToHex(computeNonce(hb(ins.nonceBase), seq));
      return;
    }
    case 'decrypt_response':
    case 'decrypt_response_streaming':
      return decrypt(fx, res);
    case 'token_roundtrip': {
      const t = deserializeSessionRecoveryToken(ins.json);
      res.body_hex = bytesToHex(t.exportedSecret) + bytesToHex(t.requestEnc);
      return;
    }
    case 'parse_config': {
      const id = await Identity.unmarshalPublicConfig(hb(ins.config));
      res.body_hex = await id.getPublicKeyHex();
      return;
    }
    case 'marshal_config': {
      const id = await Identity.fromPublicKeyHex(ins.publicKey);
      res.body_hex = bytesToHex(await id.marshalConfig());
      return;
    }
    case 'request':
      return doRequest(fx, res);
    case 'discover':
      await createTransport(discoverTarget(ins));  // throws on bad content type / status
      return;
    case 'reject_reserved_header':
    case 'reject_cross_origin':
    case 'reject_url_credentials':
      res.outcome = 'skipped';
      res.skip_reason = 'js-transport-has-no-request-guards';
      return;
    default:
      throw new Error(`unknown operation ${fx.operation}`);
  }
}

function discoverTarget(ins) {
  if (ins.target === 'bad_ct') return process.env.ORACLE_BAD_CT_URL;
  if (ins.target === 'non200') return process.env.ORACLE_NON200_URL;
  return process.env.ORACLE_URL;
}

async function decrypt(fx, res) {
  const ins = fx.inputs;
  const token = { exportedSecret: hb(ins.exportedSecret), requestEnc: hb(ins.requestEnc) };
  const framed = hb(ins.encryptedResponse);
  const segments = fx.operation.endsWith('streaming') ? splitAt(framed, fx.chunking) : [framed];

  const source = new ReadableStream({
    start(controller) {
      for (const s of segments) controller.enqueue(s);
      controller.close();
    },
  });
  const response = new Response(source, { headers: { [RESPONSE_NONCE_HEADER]: bytesToHex(hb(ins.responseNonce)) } });
  const decrypted = await decryptResponseWithToken(response, token);
  res.body_hex = await drain(decrypted.body, res);
}

async function doRequest(fx, res) {
  const base = process.env.ORACLE_URL.replace(/\/$/, '');
  const transport = await createTransport(base);
  const req = fx.request;
  const init = { method: req.method, headers: req.headers || {} };
  if (req.body_hex) init.body = hb(req.body_hex);
  const response = await transport.request(base + req.path, init);

  res.status = response.status;
  res.response_headers = subsetHeaders(response.headers);
  const noNonce = !(res.response_headers || {})[RESPONSE_NONCE_HEADER.toLowerCase()];
  res.body_hex = await drain(response.body, res);
  res.passthrough = noNonce && !(response.status >= 200 && response.status < 300);
}

// mapError is the sole native-error -> canonical-code translation.
function mapError(op, err) {
  if (err instanceof KeyConfigMismatchError) return 'KEY_CONFIG_MISMATCH';
  if (err instanceof DecryptionError) return 'AEAD_DECRYPT_FAILED';
  const msg = (err?.message || String(err)).toLowerCase();
  if (err instanceof ProtocolError) {
    if (msg.includes('missing') && msg.includes('nonce')) return 'MISSING_RESPONSE_NONCE';
    if (msg.includes('nonce')) return 'INVALID_RESPONSE_NONCE';
    if (msg.includes('truncated')) return 'FRAMING_TRUNCATED';
    if (msg.includes('exceeds maximum')) return 'CHUNK_TOO_LARGE';
    if (msg.includes('no cipher suites')) return 'INVALID_KEY_CONFIG';
    if (msg.includes('cipher suite')) return 'UNSUPPORTED_SUITE';
    return 'INVALID_KEY_CONFIG';
  }
  if (op === 'discover') return 'INVALID_KEY_CONFIG';
  if (op === 'token_roundtrip') return 'INVALID_TOKEN';
  if (op === 'compute_nonce' && msg.includes('sequence')) return 'INVALID_INPUT';
  if (op === 'derive_keys' && msg.includes('must be')) return 'INVALID_INPUT';
  return 'INVALID_INPUT';
}

// --- helpers ---

async function drain(body, res) {
  if (!body) return '';
  const reader = body.getReader();
  const chunks = [];
  let n = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      n += value.length;
    }
  } catch (err) {
    res.bytes_emitted_before_error = n;
    res.plaintext_emitted_before_error = n > 0;
    throw err;
  }
  const out = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return bytesToHex(out);
}

function splitAt(data, offsets) {
  if (!offsets || offsets.length === 0) return [data];
  const segs = [];
  let prev = 0;
  for (const o of offsets) {
    if (o > prev && o < data.length) { segs.push(data.slice(prev, o)); prev = o; }
  }
  segs.push(data.slice(prev));
  return segs;
}

function subsetHeaders(headers) {
  const out = {};
  for (const name of HEADER_SUBSET) {
    const v = headers.get(name);
    if (v != null) out[name] = v;
  }
  return out;
}

function hb(hex) { return hexToBytes(hex); }

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

main().catch((err) => { console.error(err); process.exit(2); });
