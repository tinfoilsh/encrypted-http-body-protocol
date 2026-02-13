import { describe, it, before } from 'node:test';
import assert from 'node:assert';
import { Identity, Transport, createTransport, KeyConfigMismatchError } from '../index.js';
import { PROTOCOL } from '../protocol.js';
import {
  CipherSuite,
  KEM_DHKEM_X25519_HKDF_SHA256,
  KDF_HKDF_SHA256,
  AEAD_AES_256_GCM,
} from 'hpke';
import {
  bytesToHex,
  deriveResponseKeys,
  encryptChunk,
  hexToBytes,
  EXPORT_LABEL,
  EXPORT_LENGTH,
  HPKE_REQUEST_INFO,
  RESPONSE_NONCE_LENGTH,
} from '../derive.js';

function encodeSingleChunk(payload: Uint8Array): Uint8Array {
  const chunkLength = new Uint8Array(4);
  new DataView(chunkLength.buffer).setUint32(0, payload.byteLength, false);

  const body = new Uint8Array(4 + payload.byteLength);
  body.set(chunkLength, 0);
  body.set(payload, 4);
  return body;
}

function toArrayBuffer(bytes: Uint8Array<ArrayBufferLike>): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function buildEncryptedResponse(request: Request, serverIdentity: Identity): Promise<Response> {
  const requestEncHex = request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER);
  assert(requestEncHex, `Missing ${PROTOCOL.ENCAPSULATED_KEY_HEADER} header`);
  const requestEnc = hexToBytes(requestEncHex);

  const encryptedRequestBody = new Uint8Array(await request.arrayBuffer());
  assert(encryptedRequestBody.byteLength >= 4, 'Encrypted request body must include chunk length');

  const chunkLength = new DataView(
    encryptedRequestBody.buffer,
    encryptedRequestBody.byteOffset,
    encryptedRequestBody.byteLength
  ).getUint32(0, false);
  assert.strictEqual(
    encryptedRequestBody.byteLength,
    4 + chunkLength,
    'Expected exactly one encrypted request chunk'
  );
  const ciphertext = encryptedRequestBody.slice(4);

  const suite = new CipherSuite(
    KEM_DHKEM_X25519_HKDF_SHA256,
    KDF_HKDF_SHA256,
    AEAD_AES_256_GCM
  );
  const infoBytes = new TextEncoder().encode(HPKE_REQUEST_INFO);
  const recipientContext = await suite.SetupRecipient(serverIdentity.getPrivateKey(), requestEnc, {
    info: infoBytes,
  });

  const decryptedRequest = await recipientContext.Open(ciphertext);
  const decryptedText = new TextDecoder().decode(decryptedRequest);
  const responseText = `processed:${decryptedText}`;

  const responseNonce = new Uint8Array(RESPONSE_NONCE_LENGTH);
  crypto.getRandomValues(responseNonce);

  const exportLabelBytes = new TextEncoder().encode(EXPORT_LABEL);
  const exportedSecret = await recipientContext.Export(exportLabelBytes, EXPORT_LENGTH);
  const keyMaterial = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce);

  const responseCiphertext = await encryptChunk(
    keyMaterial,
    0,
    new TextEncoder().encode(responseText)
  );

  return new Response(toArrayBuffer(encodeSingleChunk(responseCiphertext)), {
    status: 200,
    headers: {
      [PROTOCOL.RESPONSE_NONCE_HEADER]: bytesToHex(responseNonce),
    },
  });
}

describe('Transport', () => {
  let serverIdentity: Identity;

  before(async () => {
    serverIdentity = await Identity.generate();
  });

  it('should create transport with server public key', () => {
    const transport = new Transport(
      serverIdentity,
      'localhost:8080'
    );

    assert(transport instanceof Transport, 'Should create transport instance');
  });

  it('should encrypt and decrypt request', async () => {
    const originalBody = new TextEncoder().encode('Hello, World!');
    const request = new Request('http://localhost:8080/test', {
      method: 'POST',
      body: originalBody
    });

    const { request: encryptedRequest, context } = await serverIdentity.encryptRequestWithContext(request);

    assert(encryptedRequest.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER), 'Encapsulated key header should be set');

    // Check that context was returned for response decryption
    assert(context, 'Context should be returned');
    assert(context.senderContext, 'Context should have sender context');
    assert(context.requestEnc, 'Context should have request enc');

    // Check that body is encrypted (different from original)
    const encryptedBody = await encryptedRequest.arrayBuffer();
    assert(encryptedBody.byteLength > 0, 'Encrypted body should not be empty');
    assert(encryptedBody.byteLength !== originalBody.length, 'Encrypted body should have different length');
  });

  it('should handle request without body', async () => {
    const request = new Request('http://localhost:8080/test', {
      method: 'GET'
    });

    const { request: resultRequest, context } = await serverIdentity.encryptRequestWithContext(request);

    // Bodyless requests pass through unmodified - no EHBP headers set
    // See SPEC.md Section 5.1
    assert.strictEqual(
      resultRequest.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER),
      null,
      'Encapsulated key header should NOT be set for bodyless requests'
    );

    // Context is null for bodyless requests (no HPKE context to derive response keys from)
    assert.strictEqual(context, null, 'Context should be null for bodyless requests');
  });

  it('should connect to actual server and POST to /secure endpoint', async (t) => {
    const serverURL = 'http://localhost:8080';

    try {
      const keysResponse = await fetch(`${serverURL}${PROTOCOL.KEYS_PATH}`);
      if (!keysResponse.ok) {
        t.skip('Server not running at localhost:8080');
        return;
      }
    } catch {
      t.skip('Server not running at localhost:8080');
      return;
    }

    const transport = await createTransport(serverURL);

    const testName = 'Integration Test User';

    const serverPubKeyHex = await transport.getServerPublicKeyHex();
    assert.strictEqual(serverPubKeyHex.length, 64, 'Server public key should be 64 hex chars (32 bytes)');

    // Make actual POST request to /secure endpoint
    const response = await transport.post(`${serverURL}/secure`, testName, {
      headers: { 'Content-Type': 'text/plain' }
    });

    // Verify response
    assert(response.ok, `Response should be ok, got status: ${response.status}`);

    const responseText = await response.text();
    assert.strictEqual(responseText, `Hello, ${testName}`, 'Server should respond with Hello, {name}');

    console.log(`✓ Integration test passed: ${responseText}`);
  });

  it('should throw KeyConfigMismatchError on 422 key mismatch response', async () => {
    const serverURL = 'https://server.test';
    const serverIdentity = await Identity.generate();
    const config = await serverIdentity.marshalConfig();

    const originalFetch = globalThis.fetch;

    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const request = input instanceof Request ? input : new Request(input);
      const requestURL = new URL(request.url);

      if (requestURL.pathname === PROTOCOL.KEYS_PATH) {
        return new Response(config, {
          status: 200,
          headers: { 'content-type': PROTOCOL.KEYS_MEDIA_TYPE },
        });
      }

      // Server returns 422 key-config mismatch
      return new Response(
        JSON.stringify({
          type: PROTOCOL.KEY_CONFIG_PROBLEM_TYPE,
          title: 'key configuration mismatch',
        }),
        {
          status: 422,
          headers: {
            'content-type': `${PROTOCOL.PROBLEM_JSON_MEDIA_TYPE}; charset=utf-8`,
          },
        }
      );
    }) as typeof fetch;

    try {
      const transport = await createTransport(serverURL);
      await assert.rejects(
        () => transport.post(`${serverURL}/secure`, 'hello'),
        (err: unknown) => {
          assert(err instanceof KeyConfigMismatchError, `Expected KeyConfigMismatchError, got ${(err as Error).constructor.name}`);
          assert.strictEqual(err.title, 'key configuration mismatch');
          return true;
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should not throw KeyConfigMismatchError for 422 without problem+json', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');

    const originalFetch = globalThis.fetch;

    globalThis.fetch = (async (): Promise<Response> => {
      // 422 without problem+json content type — not a key mismatch
      return new Response('Unprocessable', {
        status: 422,
        headers: { 'content-type': 'text/plain' },
      });
    }) as typeof fetch;

    try {
      // Should not throw KeyConfigMismatchError — but will throw ProtocolError
      // because the response has no Ehbp-Response-Nonce header
      await assert.rejects(
        () => transport.post('https://server.test/secure', 'hello'),
        (err: unknown) => {
          assert(!(err instanceof KeyConfigMismatchError), 'Should not be KeyConfigMismatchError');
          return true;
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should encrypt, send, and decrypt a full round-trip', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');

    const originalFetch = globalThis.fetch;

    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const request = input instanceof Request ? input : new Request(input);
      return buildEncryptedResponse(request, serverIdentity);
    }) as typeof fetch;

    try {
      const response = await transport.post('https://server.test/secure', 'hello');
      const responseText = await response.text();
      assert.strictEqual(responseText, 'processed:hello');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
