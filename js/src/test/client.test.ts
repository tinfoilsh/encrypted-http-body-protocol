import { describe, it, before } from 'node:test';
import assert from 'node:assert';
import {
  Identity,
  Transport,
  createTransport,
  KeyConfigMismatchError,
  ProtocolError,
} from '../index.js';
import { PROTOCOL } from '../protocol.js';
import { CipherSuite } from 'hpke';
import { KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM } from '@panva/hpke-noble';
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

async function buildEncryptedResponse(
  request: Request,
  serverIdentity: Identity,
  status = 200
): Promise<Response> {
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
    status,
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
        return new Response(toArrayBuffer(config), {
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

  it('should pass through nonce-less 4xx and 5xx responses', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');

    const originalFetch = globalThis.fetch;
    let responseStatus = 400;
    let rawResponse!: Response;

    globalThis.fetch = (async (): Promise<Response> => {
      rawResponse = new Response(`upstream error ${responseStatus}`, {
        status: responseStatus,
        headers: { 'content-type': 'text/plain' },
      });
      return rawResponse;
    }) as typeof fetch;

    try {
      for (const status of [400, 503]) {
        responseStatus = status;
        const response = await transport.post('https://server.test/secure', 'hello');

        assert.strictEqual(response, rawResponse);
        assert.strictEqual(response.status, status);
        assert.strictEqual(response.headers.get('content-type'), 'text/plain');
        assert.strictEqual(await response.text(), `upstream error ${status}`);
        assert.throws(
          () => transport.getSessionRecoveryToken(),
          /No session recovery token available/
        );
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should bound key mismatch problem parsing without consuming pass-through', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');
    const oversizedProblem = JSON.stringify({
      type: PROTOCOL.KEY_CONFIG_PROBLEM_TYPE,
      title: 'x'.repeat(64 * 1024),
    });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (): Promise<Response> => {
      return new Response(oversizedProblem, {
        status: 422,
        headers: { 'content-type': PROTOCOL.PROBLEM_JSON_MEDIA_TYPE },
      });
    }) as typeof fetch;

    try {
      const response = await transport.post('https://server.test/secure', 'hello');
      assert.strictEqual(response.status, 422);
      assert.strictEqual(await response.text(), oversizedProblem);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should reject a nonce-less 2xx response', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');

    const originalFetch = globalThis.fetch;

    globalThis.fetch = (async (): Promise<Response> => {
      return new Response('plaintext success', { status: 200 });
    }) as typeof fetch;

    try {
      await assert.rejects(
        () => transport.post('https://server.test/secure', 'hello'),
        (err: unknown) => {
          assert(err instanceof ProtocolError);
          assert.match(err.message, new RegExp(`Missing ${PROTOCOL.RESPONSE_NONCE_HEADER} header`));
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
      assert(transport.getSessionRecoveryToken());
      const responseText = await response.text();
      assert.strictEqual(responseText, 'processed:hello');
      assert.throws(
        () => transport.getSessionRecoveryToken(),
        /No session recovery token available/
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should retain the recovery token when the consumer cancels before EOF', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const request = input instanceof Request ? input : new Request(input);
      const encrypted = await buildEncryptedResponse(request, serverIdentity);
      const body = new Uint8Array(await encrypted.arrayBuffer());
      return new Response(new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(body.slice(0, body.length - 1));
        },
      }), {
        status: encrypted.status,
        headers: encrypted.headers,
      });
    }) as typeof fetch;

    try {
      const response = await transport.post('https://server.test/secure', 'hello');
      const token = transport.getSessionRecoveryToken();

      await response.body!.cancel('consumer stopped');

      assert.deepStrictEqual(transport.getSessionRecoveryToken(), token);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should not let older stream completion clear the latest recovery token', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');

    const originalFetch = globalThis.fetch;
    let requestCount = 0;
    let finishFirstResponse!: () => void;
    let secondRequestEnc = '';
    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const request = input instanceof Request ? input : new Request(input);
      const encrypted = await buildEncryptedResponse(request, serverIdentity);
      requestCount++;
      if (requestCount === 2) {
        secondRequestEnc = request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER) ?? '';
        return encrypted;
      }

      const body = new Uint8Array(await encrypted.arrayBuffer());
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(body);
          finishFirstResponse = () => controller.close();
        },
      });
      return new Response(stream, {
        status: encrypted.status,
        headers: encrypted.headers,
      });
    }) as typeof fetch;

    try {
      const first = await transport.post('https://server.test/secure', 'first');
      const second = await transport.post('https://server.test/secure', 'second');
      assert.strictEqual(
        bytesToHex(transport.getSessionRecoveryToken().requestEnc),
        secondRequestEnc
      );

      const firstText = first.text();
      finishFirstResponse();
      assert.strictEqual(await firstText, 'processed:first');
      assert.strictEqual(
        bytesToHex(transport.getSessionRecoveryToken().requestEnc),
        secondRequestEnc
      );

      await second.body!.cancel('test complete');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should preserve fetch options on the encrypted request', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');

    const originalFetch = globalThis.fetch;
    let capturedRequest!: Request;

    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      capturedRequest = input as Request;
      return buildEncryptedResponse(capturedRequest.clone(), serverIdentity);
    }) as typeof fetch;

    try {
      const controller = new AbortController();
      const response = await transport.post('https://server.test/secure', 'hello', {
        cache: 'no-store',
        credentials: 'include',
        integrity: 'sha256-test',
        mode: 'cors',
        redirect: 'manual',
        referrer: 'https://client.test/page',
        referrerPolicy: 'origin',
        signal: controller.signal,
      });
      assert.strictEqual(await response.text(), 'processed:hello');

      assert.strictEqual(capturedRequest.cache, 'no-store');
      assert.strictEqual(capturedRequest.credentials, 'include');
      assert.strictEqual(capturedRequest.integrity, 'sha256-test');
      assert.strictEqual(capturedRequest.mode, 'cors');
      assert.strictEqual(capturedRequest.redirect, 'manual');
      assert.strictEqual(capturedRequest.referrer, 'https://client.test/page');
      assert.strictEqual(capturedRequest.referrerPolicy, 'origin');

      // The outgoing request's signal must follow the caller's signal
      assert.strictEqual(capturedRequest.signal.aborted, false);
      controller.abort();
      assert.strictEqual(capturedRequest.signal.aborted, true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should preserve fetch options when input is a Request instance', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');

    const originalFetch = globalThis.fetch;
    let capturedRequest!: Request;

    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      capturedRequest = input as Request;
      return buildEncryptedResponse(capturedRequest.clone(), serverIdentity);
    }) as typeof fetch;

    try {
      const request = new Request('https://server.test/secure', {
        method: 'POST',
        body: 'hello',
        credentials: 'include',
        duplex: 'half',
      } as RequestInit);
      const response = await transport.request(request);
      assert.strictEqual(await response.text(), 'processed:hello');
      assert.strictEqual(capturedRequest.credentials, 'include');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should let init options override a Request input, like fetch()', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');

    const originalFetch = globalThis.fetch;
    let capturedRequest!: Request;

    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      capturedRequest = input as Request;
      return buildEncryptedResponse(capturedRequest.clone(), serverIdentity);
    }) as typeof fetch;

    try {
      const request = new Request('https://server.test/secure', {
        method: 'POST',
        body: 'hello',
        cache: 'reload',
        credentials: 'include',
        integrity: 'sha256-request',
        mode: 'cors',
        redirect: 'manual',
        referrer: 'https://client.test/request',
        referrerPolicy: 'strict-origin',
        duplex: 'half',
      } as RequestInit);
      const expectedRequest = new Request(request.clone(), { credentials: 'omit' });
      const response = await transport.request(request, { credentials: 'omit' });
      assert.strictEqual(await response.text(), 'processed:hello');

      // init overrides the Request; unset init members fall back to it
      assert.strictEqual(capturedRequest.cache, expectedRequest.cache);
      assert.strictEqual(capturedRequest.credentials, expectedRequest.credentials);
      assert.strictEqual(capturedRequest.integrity, expectedRequest.integrity);
      assert.strictEqual(capturedRequest.mode, expectedRequest.mode);
      assert.strictEqual(capturedRequest.redirect, expectedRequest.redirect);
      assert.strictEqual(capturedRequest.referrer, expectedRequest.referrer);
      assert.strictEqual(capturedRequest.referrerPolicy, expectedRequest.referrerPolicy);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should let init override Request method, headers, and body, like fetch()', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');

    const originalFetch = globalThis.fetch;
    let capturedRequest!: Request;

    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      capturedRequest = input as Request;
      return buildEncryptedResponse(capturedRequest.clone(), serverIdentity);
    }) as typeof fetch;

    try {
      const request = new Request('https://server.test/secure', {
        method: 'POST',
        headers: { 'x-source': 'request', 'x-replaced': 'request' },
        body: 'request body',
        duplex: 'half',
      } as RequestInit);
      const response = await transport.request(request, {
        method: 'PUT',
        headers: { 'x-init': 'init', 'x-replaced': 'init' },
        body: 'init body',
      });

      assert.strictEqual(await response.text(), 'processed:init body');
      assert.strictEqual(capturedRequest.method, 'PUT');
      assert.strictEqual(capturedRequest.headers.get('x-init'), 'init');
      assert.strictEqual(capturedRequest.headers.get('x-replaced'), 'init');
      assert.strictEqual(capturedRequest.headers.get('x-source'), null);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should preserve fetch options on bodyless passthrough requests', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');

    const originalFetch = globalThis.fetch;
    let capturedRequest!: Request;

    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      capturedRequest = input as Request;
      return new Response('plain', { status: 200 });
    }) as typeof fetch;

    try {
      const response = await transport.get('https://server.test/status', {
        credentials: 'include',
      });
      assert.strictEqual(await response.text(), 'plain');
      assert.strictEqual(capturedRequest.credentials, 'include');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should pass init to the key fetch in createTransport', async () => {
    const serverIdentity = await Identity.generate();
    const config = await serverIdentity.marshalConfig();

    const originalFetch = globalThis.fetch;
    let capturedInit: RequestInit | undefined;

    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit
    ): Promise<Response> => {
      capturedInit = init;
      return new Response(toArrayBuffer(config), {
        status: 200,
        headers: { 'content-type': PROTOCOL.KEYS_MEDIA_TYPE },
      });
    }) as typeof fetch;

    try {
      await createTransport('https://server.test', { credentials: 'include' });
      assert.strictEqual(capturedInit?.credentials, 'include');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should decrypt a response with a nonce regardless of HTTP status', async () => {
    const serverIdentity = await Identity.generate();
    const transport = new Transport(serverIdentity, 'server.test');

    const originalFetch = globalThis.fetch;

    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const request = input instanceof Request ? input : new Request(input);
      return buildEncryptedResponse(request, serverIdentity, 503);
    }) as typeof fetch;

    try {
      const response = await transport.post('https://server.test/secure', 'hello');
      assert.strictEqual(response.status, 503);
      assert.strictEqual(await response.text(), 'processed:hello');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
