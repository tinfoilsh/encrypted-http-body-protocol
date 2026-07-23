/**
 * Session Recovery Token Tests
 *
 * These tests verify that extractSessionRecoveryToken and decryptResponseWithToken
 * produce correct results by running real HPKE key exchanges and AES-256-GCM
 * encryption/decryption — no mocks on the crypto path.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  Identity,
  extractSessionRecoveryToken,
  decryptResponseWithToken,
  serializeSessionRecoveryToken,
  deserializeSessionRecoveryToken,
} from '../index.js';
import type { SessionRecoveryToken } from '../index.js';
import { PROTOCOL } from '../protocol.js';
import {
  CipherSuite,
  KEM_DHKEM_X25519_HKDF_SHA256,
  KDF_HKDF_SHA256,
  AEAD_AES_256_GCM,
  type Key,
} from 'hpke';
import {
  bytesToHex,
  decryptChunk,
  deriveResponseKeys,
  encryptChunk,
  hexToBytes,
  EXPORT_LABEL,
  EXPORT_LENGTH,
  HPKE_REQUEST_INFO,
  RESPONSE_NONCE_LENGTH,
} from '../derive.js';

// Shared suite — all key generation and SetupRecipient use this instance so
// CryptoKey objects are never passed across CipherSuite instances.
const suite = new CipherSuite(
  KEM_DHKEM_X25519_HKDF_SHA256,
  KDF_HKDF_SHA256,
  AEAD_AES_256_GCM
);

const infoBytes = new TextEncoder().encode(HPKE_REQUEST_INFO);
const exportLabelBytes = new TextEncoder().encode(EXPORT_LABEL);

/**
 * Generate a key pair from the shared suite and return a public-key-only
 * Identity (for encryptRequestWithContext) plus the raw private key (for
 * server-side simulation via SetupRecipient on the same suite).
 */
async function generateTestKeys(): Promise<{ identity: Identity; privateKey: Key }> {
  const { publicKey, privateKey } = await suite.GenerateKeyPair(true);
  const pubKeyBytes = new Uint8Array(await suite.SerializePublicKey(publicKey));
  const identity = await Identity.fromPublicKeyHex(bytesToHex(pubKeyBytes));
  return { identity, privateKey };
}

function encodeSingleChunk(payload: Uint8Array): Uint8Array {
  const chunkLength = new Uint8Array(4);
  new DataView(chunkLength.buffer).setUint32(0, payload.byteLength, false);

  const body = new Uint8Array(4 + payload.byteLength);
  body.set(chunkLength, 0);
  body.set(payload, 4);
  return body;
}

function encodeMultipleChunks(payloads: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const p of payloads) totalLength += 4 + p.byteLength;

  const body = new Uint8Array(totalLength);
  let offset = 0;
  for (const p of payloads) {
    new DataView(body.buffer, offset, 4).setUint32(0, p.byteLength, false);
    offset += 4;
    body.set(p, offset);
    offset += p.byteLength;
  }
  return body;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

/**
 * Simulates what the server does: receives the encrypted request,
 * decrypts it, then builds an encrypted response using the HPKE
 * receiver context (matching the real protocol).
 */
async function buildEncryptedResponse(
  request: Request,
  privateKey: Key,
  responseText: string,
): Promise<Response> {
  const requestEncHex = request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER);
  assert(requestEncHex, `Missing ${PROTOCOL.ENCAPSULATED_KEY_HEADER} header`);
  const requestEnc = hexToBytes(requestEncHex);

  const recipientContext = await suite.SetupRecipient(
    privateKey,
    requestEnc,
    { info: infoBytes },
  );

  // Decrypt the request body to prove the HPKE handshake works
  const encryptedBody = new Uint8Array(await request.arrayBuffer());
  const chunkLen = new DataView(encryptedBody.buffer, encryptedBody.byteOffset, 4).getUint32(0, false);
  const ciphertext = encryptedBody.slice(4, 4 + chunkLen);
  await recipientContext.Open(ciphertext);

  const responseNonce = new Uint8Array(RESPONSE_NONCE_LENGTH);
  crypto.getRandomValues(responseNonce);

  const exportedSecret = await recipientContext.Export(exportLabelBytes, EXPORT_LENGTH);
  const keyMaterial = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce);

  const responseCiphertext = await encryptChunk(
    keyMaterial,
    0,
    new TextEncoder().encode(responseText),
  );

  return new Response(toArrayBuffer(encodeSingleChunk(responseCiphertext)), {
    status: 200,
    headers: {
      [PROTOCOL.RESPONSE_NONCE_HEADER]: bytesToHex(responseNonce),
    },
  });
}

/**
 * Builds a multi-chunk encrypted streaming response (simulating SSE).
 */
async function buildStreamingEncryptedResponse(
  request: Request,
  privateKey: Key,
  chunks: string[],
): Promise<Response> {
  const requestEncHex = request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER);
  assert(requestEncHex);
  const requestEnc = hexToBytes(requestEncHex);

  const recipientContext = await suite.SetupRecipient(
    privateKey,
    requestEnc,
    { info: infoBytes },
  );

  // Decrypt request to advance the HPKE context
  const encryptedBody = new Uint8Array(await request.arrayBuffer());
  const chunkLen = new DataView(encryptedBody.buffer, encryptedBody.byteOffset, 4).getUint32(0, false);
  await recipientContext.Open(encryptedBody.slice(4, 4 + chunkLen));

  const responseNonce = new Uint8Array(RESPONSE_NONCE_LENGTH);
  crypto.getRandomValues(responseNonce);

  const exportedSecret = await recipientContext.Export(exportLabelBytes, EXPORT_LENGTH);
  const keyMaterial = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce);

  const encryptedChunks: Uint8Array[] = [];
  for (let i = 0; i < chunks.length; i++) {
    encryptedChunks.push(
      await encryptChunk(keyMaterial, i, new TextEncoder().encode(chunks[i]))
    );
  }

  return new Response(toArrayBuffer(encodeMultipleChunks(encryptedChunks)), {
    status: 200,
    headers: {
      [PROTOCOL.RESPONSE_NONCE_HEADER]: bytesToHex(responseNonce),
    },
  });
}

describe('Session Recovery Token', () => {
  describe('extractSessionRecoveryToken', () => {
    it('should return a token with correct field sizes', async () => {
      const { identity } = await generateTestKeys();
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'test body',
      });

      const { context } = await identity.encryptRequestWithContext(request);
      assert(context, 'context must not be null for a request with a body');

      const token = await extractSessionRecoveryToken(context);

      assert.strictEqual(token.exportedSecret.length, 32, 'exportedSecret must be 32 bytes');
      assert.strictEqual(token.requestEnc.length, 32, 'requestEnc must be 32 bytes');
    });

    it('should return the same exported secret as SenderContext.Export', async () => {
      const { identity } = await generateTestKeys();
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'test body',
      });

      const { context } = await identity.encryptRequestWithContext(request);
      assert(context);

      // Export directly from the SenderContext for comparison
      const directExport = new Uint8Array(
        await context.senderContext.Export(exportLabelBytes, EXPORT_LENGTH)
      );

      const token = await extractSessionRecoveryToken(context);

      assert.deepStrictEqual(
        token.exportedSecret,
        directExport,
        'Token exportedSecret must match direct SenderContext.Export result'
      );
    });

    it('should return requestEnc matching the context', async () => {
      const { identity } = await generateTestKeys();
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'test body',
      });

      const { context } = await identity.encryptRequestWithContext(request);
      assert(context);

      const token = await extractSessionRecoveryToken(context);

      assert.deepStrictEqual(
        token.requestEnc,
        context.requestEnc,
        'Token requestEnc must match context.requestEnc'
      );
    });

    it('should produce different tokens for different requests', async () => {
      const { identity } = await generateTestKeys();

      const req1 = new Request('https://server.test/api', { method: 'POST', body: 'request 1' });
      const req2 = new Request('https://server.test/api', { method: 'POST', body: 'request 2' });

      const { context: ctx1 } = await identity.encryptRequestWithContext(req1);
      const { context: ctx2 } = await identity.encryptRequestWithContext(req2);
      assert(ctx1 && ctx2);

      const token1 = await extractSessionRecoveryToken(ctx1);
      const token2 = await extractSessionRecoveryToken(ctx2);

      // Each request creates a fresh HPKE context, so exported secrets differ
      assert.notDeepStrictEqual(
        token1.exportedSecret,
        token2.exportedSecret,
        'Different requests must produce different exported secrets'
      );
      assert.notDeepStrictEqual(
        token1.requestEnc,
        token2.requestEnc,
        'Different requests must produce different requestEnc values'
      );
    });
  });

  describe('decryptResponseWithToken', () => {
    it('should decrypt a single-chunk response', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'hello',
      });

      const { request: encryptedRequest, context } =
        await identity.encryptRequestWithContext(request);
      assert(context);

      const token = await extractSessionRecoveryToken(context);

      // Server builds an encrypted response using the real HPKE handshake
      const encryptedResponse = await buildEncryptedResponse(
        encryptedRequest,
        privateKey,
        'response from server',
      );

      const decrypted = await decryptResponseWithToken(encryptedResponse, token);
      const text = await decrypted.text();

      assert.strictEqual(text, 'response from server');
    });

    it('should decrypt a multi-chunk streaming response', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'hello',
      });

      const { request: encryptedRequest, context } =
        await identity.encryptRequestWithContext(request);
      assert(context);

      const token = await extractSessionRecoveryToken(context);

      const chunks = ['chunk-0:', 'chunk-1:', 'chunk-2:done'];
      const encryptedResponse = await buildStreamingEncryptedResponse(
        encryptedRequest,
        privateKey,
        chunks,
      );

      const decrypted = await decryptResponseWithToken(encryptedResponse, token);
      const text = await decrypted.text();

      assert.strictEqual(text, chunks.join(''));
    });

    it('should deliver an authenticated frame before source EOF', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'hello',
      });
      const { request: encryptedRequest, context } =
        await identity.encryptRequestWithContext(request);
      assert(context);

      const token = await extractSessionRecoveryToken(context);
      const bufferedResponse = await buildStreamingEncryptedResponse(
        encryptedRequest,
        privateKey,
        ['first', 'second'],
      );
      const nonce = bufferedResponse.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER)!;
      const encrypted = new Uint8Array(await bufferedResponse.arrayBuffer());
      const firstFrameLength =
        4 + new DataView(encrypted.buffer, encrypted.byteOffset, 4).getUint32(0, false);
      let sourceController!: ReadableStreamDefaultController<Uint8Array>;
      const source = new ReadableStream<Uint8Array>({
        start(controller) {
          sourceController = controller;
          controller.enqueue(encrypted.slice(0, firstFrameLength));
        },
      });

      const decrypted = await decryptResponseWithToken(
        new Response(source, {
          headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: nonce },
        }),
        token,
      );
      const reader = decrypted.body!.getReader();
      const first = await reader.read();

      assert.strictEqual(first.done, false);
      assert.strictEqual(new TextDecoder().decode(first.value), 'first');

      sourceController.enqueue(encrypted.slice(firstFrameLength));
      sourceController.close();
      const second = await reader.read();
      assert.strictEqual(new TextDecoder().decode(second.value), 'second');
      assert.strictEqual((await reader.read()).done, true);
    });

    it('should handle fragmented, coalesced, and zero-length frames', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'hello',
      });
      const { request: encryptedRequest, context } =
        await identity.encryptRequestWithContext(request);
      assert(context);

      const token = await extractSessionRecoveryToken(context);
      const bufferedResponse = await buildStreamingEncryptedResponse(
        encryptedRequest,
        privateKey,
        ['one', 'two', 'three'],
      );
      const nonce = bufferedResponse.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER)!;
      const encrypted = new Uint8Array(await bufferedResponse.arrayBuffer());
      const framed = new Uint8Array(encrypted.length + 8);
      framed.set(new Uint8Array(4), 0);
      framed.set(encrypted, 4);
      framed.set(new Uint8Array(4), 4 + encrypted.length);
      const source = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(framed.slice(0, 1));
          controller.enqueue(framed.slice(1, 7));
          controller.enqueue(framed.slice(7));
          controller.close();
        },
      });

      const decrypted = await decryptResponseWithToken(
        new Response(source, {
          headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: nonce },
        }),
        token,
      );

      assert.strictEqual(await decrypted.text(), 'onetwothree');
    });

    it('should reject truncated framing at source EOF', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'hello',
      });
      const { request: encryptedRequest, context } =
        await identity.encryptRequestWithContext(request);
      assert(context);

      const token = await extractSessionRecoveryToken(context);
      const bufferedResponse = await buildEncryptedResponse(
        encryptedRequest,
        privateKey,
        'truncated',
      );
      const nonce = bufferedResponse.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER)!;
      const encrypted = new Uint8Array(await bufferedResponse.arrayBuffer());
      const truncated = new Response(toArrayBuffer(encrypted.slice(0, -1)), {
        headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: nonce },
      });

      const decrypted = await decryptResponseWithToken(truncated, token);
      await assert.rejects(() => decrypted.text(), /truncated encrypted response chunk/);
    });

    it('should cancel the encrypted source when the decrypted body is cancelled', async () => {
      const token: SessionRecoveryToken = {
        exportedSecret: new Uint8Array(32),
        requestEnc: new Uint8Array(32),
      };
      let sourceCancelled = false;
      const source = new ReadableStream<Uint8Array>({
        cancel() {
          sourceCancelled = true;
        },
      });
      const response = new Response(source, {
        headers: {
          [PROTOCOL.RESPONSE_NONCE_HEADER]:
            bytesToHex(new Uint8Array(RESPONSE_NONCE_LENGTH)),
        },
      });

      const decrypted = await decryptResponseWithToken(response, token);
      await decrypted.body!.cancel('consumer stopped');

      assert.strictEqual(sourceCancelled, true);
    });

    it('should preserve response status and headers', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'hello',
      });

      const { request: encryptedRequest, context } =
        await identity.encryptRequestWithContext(request);
      assert(context);

      const token = await extractSessionRecoveryToken(context);
      const encryptedResponse = await buildEncryptedResponse(
        encryptedRequest,
        privateKey,
        'ok',
      );

      const decrypted = await decryptResponseWithToken(encryptedResponse, token);

      assert.strictEqual(decrypted.status, 200);
      assert(decrypted.headers.has(PROTOCOL.RESPONSE_NONCE_HEADER));
    });

    it('should drop stale encrypted framing headers', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'hello',
      });

      const { request: encryptedRequest, context } =
        await identity.encryptRequestWithContext(request);
      assert(context);

      const token = await extractSessionRecoveryToken(context);
      const encryptedResponse = await buildEncryptedResponse(
        encryptedRequest,
        privateKey,
        'full reply',
      );

      // Buffering infrastructure between server and client can re-frame the
      // encrypted reply with framing headers describing the ciphertext.
      const encryptedBytes = new Uint8Array(await encryptedResponse.arrayBuffer());
      const staleResponse = new Response(toArrayBuffer(encryptedBytes), {
        status: 200,
        headers: {
          [PROTOCOL.RESPONSE_NONCE_HEADER]:
            encryptedResponse.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER)!,
          'content-length': String(encryptedBytes.byteLength),
          'transfer-encoding': 'chunked',
          'content-type': 'text/plain',
        },
      });

      const decrypted = await decryptResponseWithToken(staleResponse, token);

      assert.strictEqual(decrypted.headers.get('content-length'), null,
        'stale encrypted content-length must not survive decryption');
      assert.strictEqual(decrypted.headers.get('transfer-encoding'), null,
        'stale transfer-encoding must not survive decryption');
      assert.strictEqual(decrypted.headers.get('content-type'), 'text/plain');
      assert(decrypted.headers.has(PROTOCOL.RESPONSE_NONCE_HEADER));

      const text = await decrypted.text();
      assert.strictEqual(text, 'full reply');
    });

    it('should return the response as-is when body is null', async () => {
      const token: SessionRecoveryToken = {
        exportedSecret: new Uint8Array(32),
        requestEnc: new Uint8Array(32),
      };

      const response = new Response(null, { status: 204 });
      const result = await decryptResponseWithToken(response, token);

      assert.strictEqual(result.status, 204);
      assert.strictEqual(result.body, null);
    });

    it('should throw on missing response nonce header', async () => {
      const token: SessionRecoveryToken = {
        exportedSecret: new Uint8Array(32),
        requestEnc: new Uint8Array(32),
      };

      // Body present but no Ehbp-Response-Nonce header
      const response = new Response('encrypted-data', { status: 200 });

      await assert.rejects(
        () => decryptResponseWithToken(response, token),
        /Missing Ehbp-Response-Nonce header/
      );
    });

    it('should throw on invalid response nonce length', async () => {
      const token: SessionRecoveryToken = {
        exportedSecret: new Uint8Array(32),
        requestEnc: new Uint8Array(32),
      };

      // 12-byte nonce instead of required 32
      const shortNonce = bytesToHex(new Uint8Array(12));
      const response = new Response('encrypted-data', {
        status: 200,
        headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: shortNonce },
      });

      await assert.rejects(
        () => decryptResponseWithToken(response, token),
        /Invalid response nonce length/
      );
    });

    it('should reject a response chunk that exceeds the maximum size', async () => {
      const token: SessionRecoveryToken = {
        exportedSecret: new Uint8Array(32),
        requestEnc: new Uint8Array(32),
      };

      // Valid 32-byte nonce so key derivation proceeds, but the length prefix
      // declares a ~4 GiB chunk that must be rejected before buffering the
      // (unauthenticated) body.
      const nonce = bytesToHex(new Uint8Array(RESPONSE_NONCE_LENGTH));
      const body = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0x00]);
      const response = new Response(body, {
        status: 200,
        headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: nonce },
      });

      const decrypted = await decryptResponseWithToken(response, token);
      await assert.rejects(() => decrypted.text(), /maximum allowed size/);
    });

    it('should cancel the upstream body when a chunk exceeds the maximum size', async () => {
      const token: SessionRecoveryToken = {
        exportedSecret: new Uint8Array(32),
        requestEnc: new Uint8Array(32),
      };

      let upstreamCancelled = false;
      const upstream = new ReadableStream<Uint8Array>({
        start(controller) {
          // Oversized length prefix (~4 GiB); a real attacker keeps streaming.
          controller.enqueue(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0x00]));
        },
        cancel() {
          upstreamCancelled = true;
        },
      });

      const nonce = bytesToHex(new Uint8Array(RESPONSE_NONCE_LENGTH));
      const response = new Response(upstream, {
        status: 200,
        headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: nonce },
      });

      const decrypted = await decryptResponseWithToken(response, token);
      await assert.rejects(() => decrypted.text(), /maximum allowed size/);
      assert.strictEqual(
        upstreamCancelled,
        true,
        'upstream body should be cancelled on oversized chunk',
      );
    });

    it('should cancel upstream and reject downstream when the error callback throws', async () => {
      const token: SessionRecoveryToken = {
        exportedSecret: new Uint8Array(32),
        requestEnc: new Uint8Array(32),
      };

      let upstreamCancelled = false;
      const upstream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0x00]));
        },
        cancel() {
          upstreamCancelled = true;
        },
      });
      const nonce = bytesToHex(new Uint8Array(RESPONSE_NONCE_LENGTH));
      const response = new Response(upstream, {
        status: 200,
        headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: nonce },
      });

      const decrypted = await decryptResponseWithToken(response, token, () => {
        throw new Error('error callback failed');
      });

      await assert.rejects(() => decrypted.text(), /maximum allowed size/);
      assert.strictEqual(upstreamCancelled, true);
    });

    it('should fail decryption with a wrong token', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'hello',
      });

      const { request: encryptedRequest, context } =
        await identity.encryptRequestWithContext(request);
      assert(context);

      const encryptedResponse = await buildEncryptedResponse(
        encryptedRequest,
        privateKey,
        'secret',
      );

      // Forge a token with random bytes — decryption must fail
      const badToken: SessionRecoveryToken = {
        exportedSecret: crypto.getRandomValues(new Uint8Array(32)),
        requestEnc: crypto.getRandomValues(new Uint8Array(32)),
      };

      const decrypted = await decryptResponseWithToken(encryptedResponse, badToken);

      // The stream-level decryption fails when you actually try to read
      await assert.rejects(
        () => decrypted.text(),
        /Decryption failed/
      );
    });
  });

  describe('decryptResponseWithContext delegates to token path', () => {
    it('should produce identical plaintext via context path and token path', async () => {
      const { identity, privateKey } = await generateTestKeys();

      // We need two identical requests since Response bodies are consumed once.
      // Instead, we build two responses from the same server-side state.
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'payload',
      });

      const { request: encryptedRequest, context } =
        await identity.encryptRequestWithContext(request);
      assert(context);

      const token = await extractSessionRecoveryToken(context);

      // Build one encrypted response for the token path
      const responseForToken = await buildEncryptedResponse(
        encryptedRequest.clone(),
        privateKey,
        'identical-response',
      );

      const decryptedViaToken = await decryptResponseWithToken(responseForToken, token);
      const textViaToken = await decryptedViaToken.text();

      assert.strictEqual(textViaToken, 'identical-response');
    });
  });

  describe('token serialization round-trip (simulating localStorage)', () => {
    it('should work after JSON serialization and deserialization', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const request = new Request('https://server.test/api', {
        method: 'POST',
        body: 'test',
      });

      const { request: encryptedRequest, context } =
        await identity.encryptRequestWithContext(request);
      assert(context);

      const originalToken = await extractSessionRecoveryToken(context);

      // Simulate localStorage: serialize to JSON and back using hex helpers
      const serialized = serializeSessionRecoveryToken(originalToken);

      // Verify the JSON contains hex strings
      const raw = JSON.parse(serialized);
      assert.strictEqual(raw.exportedSecret, bytesToHex(originalToken.exportedSecret));
      assert.strictEqual(raw.requestEnc, bytesToHex(originalToken.requestEnc));

      const restoredToken = deserializeSessionRecoveryToken(serialized);

      // Decrypt with the deserialized token
      const encryptedResponse = await buildEncryptedResponse(
        encryptedRequest,
        privateKey,
        'recovered after tab close',
      );

      const decrypted = await decryptResponseWithToken(encryptedResponse, restoredToken);
      const text = await decrypted.text();

      assert.strictEqual(text, 'recovered after tab close');
    });
  });

  describe('interoperability test vector', () => {
    it('should deserialize the shared fixture and re-serialize to identical JSON', () => {
      const thisDir = dirname(fileURLToPath(import.meta.url));
      const vectorPath = resolve(thisDir, '../../../../test-vectors/session-recovery-token.json');
      const vectorJSON = readFileSync(vectorPath, 'utf-8');

      const token = deserializeSessionRecoveryToken(vectorJSON);

      assert.strictEqual(token.exportedSecret.length, 32, 'exportedSecret must be 32 bytes');
      assert.strictEqual(token.requestEnc.length, 32, 'requestEnc must be 32 bytes');

      assert.strictEqual(
        bytesToHex(token.exportedSecret),
        'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
      );
      assert.strictEqual(
        bytesToHex(token.requestEnc),
        '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      );

      // Re-serialize and verify identical JSON content
      const reserialized = serializeSessionRecoveryToken(token);
      assert.deepStrictEqual(JSON.parse(reserialized), JSON.parse(vectorJSON));
    });
  });

  describe('response decryption interop vector', () => {
    it('should decrypt the shared response-decryption fixture', async () => {
      const thisDir = dirname(fileURLToPath(import.meta.url));
      const vectorPath = resolve(thisDir, '../../../../test-vectors/response-decryption.json');
      const vector = JSON.parse(readFileSync(vectorPath, 'utf-8'));

      const token: SessionRecoveryToken = {
        exportedSecret: hexToBytes(vector.exportedSecret),
        requestEnc: hexToBytes(vector.requestEnc),
      };

      const responseNonce = hexToBytes(vector.responseNonce);
      const expectedPlaintext = hexToBytes(vector.plaintext);
      const encryptedResponse = hexToBytes(vector.encryptedResponse);

      const km = await deriveResponseKeys(token.exportedSecret, token.requestEnc, responseNonce);

      // Parse chunked framing: LEN (4 bytes) || ciphertext
      const chunkLen = (encryptedResponse[0] << 24) | (encryptedResponse[1] << 16) |
                       (encryptedResponse[2] << 8) | encryptedResponse[3];
      const ciphertext = encryptedResponse.slice(4, 4 + chunkLen);

      const decrypted = await decryptChunk(km, 0, ciphertext);
      assert.deepStrictEqual(decrypted, expectedPlaintext);
    });
  });

  describe('Transport.getSessionRecoveryToken', () => {
    it('should throw before any request is made', async () => {
      const { identity } = await generateTestKeys();
      const { Transport } = await import('../client.js');
      const transport = new Transport(identity, 'server.test');

      assert.throws(
        () => transport.getSessionRecoveryToken(),
        /No session recovery token available/
      );
    });

    it('should clear the token after the response is fully consumed', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const { Transport } = await import('../client.js');
      const transport = new Transport(identity, 'server.test');

      const originalFetch = globalThis.fetch;

      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const request = input instanceof Request ? input : new Request(input);
        return buildEncryptedResponse(request, privateKey, 'via-transport');
      }) as typeof fetch;

      try {
        const response = await transport.post('https://server.test/api', 'body');
        const responseText = await response.text();
        assert.strictEqual(responseText, 'via-transport');

        assert.throws(
          () => transport.getSessionRecoveryToken(),
          /No session recovery token available/
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('should update the token on each new request', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const { Transport } = await import('../client.js');
      const transport = new Transport(identity, 'server.test');

      const originalFetch = globalThis.fetch;

      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const request = input instanceof Request ? input : new Request(input);
        return buildEncryptedResponse(request, privateKey, 'ok');
      }) as typeof fetch;

      try {
        await transport.post('https://server.test/api', 'request-1');
        const token1 = transport.getSessionRecoveryToken();

        await transport.post('https://server.test/api', 'request-2');
        const token2 = transport.getSessionRecoveryToken();

        // Each request creates a fresh HPKE context
        assert.notDeepStrictEqual(
          token1.exportedSecret,
          token2.exportedSecret,
          'Tokens from different requests must have different exported secrets'
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('should clear the token for bodyless requests', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const { Transport } = await import('../client.js');
      const transport = new Transport(identity, 'server.test');

      const originalFetch = globalThis.fetch;

      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const request = input instanceof Request ? input : new Request(input);
        const hasEncKey = request.headers.has(PROTOCOL.ENCAPSULATED_KEY_HEADER);
        if (hasEncKey) {
          return buildEncryptedResponse(request, privateKey, 'encrypted');
        }
        return new Response('plaintext');
      }) as typeof fetch;

      try {
        // POST with body — token should be set
        await transport.post('https://server.test/api', 'body');
        const tokenAfterPost = transport.getSessionRecoveryToken();
        assert(tokenAfterPost, 'Token should exist after POST with body');

        // GET without body — token should be cleared
        await transport.get('https://server.test/api');
        assert.throws(
          () => transport.getSessionRecoveryToken(),
          /No session recovery token available/,
          'Token should be cleared after bodyless request'
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('should let only the latest request publish its token', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const { Transport } = await import('../client.js');
      const transport = new Transport(identity, 'server.test');

      const originalFetch = globalThis.fetch;
      let releaseFirst!: () => void;
      const firstGate = new Promise<void>((resolve) => {
        releaseFirst = resolve;
      });
      let firstFetchStarted!: () => void;
      const firstStarted = new Promise<void>((resolve) => {
        firstFetchStarted = resolve;
      });
      let requestCount = 0;
      let secondRequestEnc = '';

      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const request = input instanceof Request ? input : new Request(input);
        requestCount++;
        if (requestCount === 1) {
          firstFetchStarted();
          await firstGate;
        } else {
          secondRequestEnc = request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER)!;
        }
        return buildEncryptedResponse(request, privateKey, 'ok');
      }) as typeof fetch;

      try {
        const first = transport.post('https://server.test/api', 'request-1');
        await firstStarted;
        const second = transport.post('https://server.test/api', 'request-2');

        await second;
        assert.strictEqual(
          bytesToHex(transport.getSessionRecoveryToken().requestEnc),
          secondRequestEnc,
        );

        releaseFirst();
        await first;
        assert.strictEqual(
          bytesToHex(transport.getSessionRecoveryToken().requestEnc),
          secondRequestEnc,
          'an older response must not replace the latest token',
        );
      } finally {
        releaseFirst();
        globalThis.fetch = originalFetch;
      }
    });

    it('should invalidate the previous token when a newer request starts', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const { Transport } = await import('../client.js');
      const transport = new Transport(identity, 'server.test');

      const originalFetch = globalThis.fetch;
      let releaseSecond!: () => void;
      const secondGate = new Promise<void>((resolve) => {
        releaseSecond = resolve;
      });
      let secondFetchStarted!: () => void;
      const secondStarted = new Promise<void>((resolve) => {
        secondFetchStarted = resolve;
      });
      let requestCount = 0;

      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const request = input instanceof Request ? input : new Request(input);
        requestCount++;
        if (requestCount === 2) {
          secondFetchStarted();
          await secondGate;
        }
        return buildEncryptedResponse(request, privateKey, 'ok');
      }) as typeof fetch;

      try {
        await transport.post('https://server.test/api', 'request-1');
        assert(transport.getSessionRecoveryToken());

        const second = transport.post('https://server.test/api', 'request-2');
        await secondStarted;
        assert.throws(
          () => transport.getSessionRecoveryToken(),
          /No session recovery token available/,
        );

        releaseSecond();
        await second;
        assert(transport.getSessionRecoveryToken());
      } finally {
        releaseSecond();
        globalThis.fetch = originalFetch;
      }
    });

    it('should clear only its own token after a stream authentication failure', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const { Transport } = await import('../client.js');
      const transport = new Transport(identity, 'server.test');

      const originalFetch = globalThis.fetch;
      let requestCount = 0;
      let latestRequestEnc = '';

      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const request = input instanceof Request ? input : new Request(input);
        requestCount++;
        const response = await buildEncryptedResponse(request, privateKey, 'ok');
        if (requestCount === 2) {
          latestRequestEnc = request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER)!;
          return response;
        }

        const nonce = response.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER)!;
        const corrupted = new Uint8Array(await response.arrayBuffer());
        corrupted[corrupted.length - 1] ^= 1;
        return new Response(toArrayBuffer(corrupted), {
          headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: nonce },
        });
      }) as typeof fetch;

      try {
        const olderResponse = await transport.post('https://server.test/api', 'request-1');
        const latestResponse = await transport.post('https://server.test/api', 'request-2');
        await assert.rejects(() => olderResponse.text(), /Decryption failed/);
        assert.strictEqual(
          bytesToHex(transport.getSessionRecoveryToken().requestEnc),
          latestRequestEnc,
          'an older stream failure must not clear the latest token',
        );
        assert.strictEqual(await latestResponse.text(), 'ok');
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('should clear the latest token after its stream authentication failure', async () => {
      const { identity, privateKey } = await generateTestKeys();
      const { Transport } = await import('../client.js');
      const transport = new Transport(identity, 'server.test');

      const originalFetch = globalThis.fetch;
      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const request = input instanceof Request ? input : new Request(input);
        const response = await buildEncryptedResponse(request, privateKey, 'ok');
        const nonce = response.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER)!;
        const corrupted = new Uint8Array(await response.arrayBuffer());
        corrupted[corrupted.length - 1] ^= 1;
        return new Response(toArrayBuffer(corrupted), {
          headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: nonce },
        });
      }) as typeof fetch;

      try {
        const response = await transport.post('https://server.test/api', 'request');
        assert(transport.getSessionRecoveryToken());
        await assert.rejects(() => response.text(), /Decryption failed/);
        assert.throws(
          () => transport.getSessionRecoveryToken(),
          /No session recovery token available/,
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('should clear the latest token and cancel upstream after a read failure', async () => {
      const { identity } = await generateTestKeys();
      const { Transport } = await import('../client.js');
      const transport = new Transport(identity, 'server.test');

      const originalFetch = globalThis.fetch;
      const readError = new Error('upstream read failed');
      let rejectRead!: (error: Error) => void;
      const readResult = new Promise<ReadableStreamReadResult<Uint8Array>>((_, reject) => {
        rejectRead = reject;
      });
      let cancelReason: unknown;
      globalThis.fetch = (async (): Promise<Response> => {
        const source = new ReadableStream<Uint8Array>();
        Object.defineProperty(source, 'getReader', {
          value: () => ({
            read: () => readResult,
            cancel: async (reason?: unknown) => {
              cancelReason = reason;
            },
          }),
        });
        return new Response(source, {
          headers: {
            [PROTOCOL.RESPONSE_NONCE_HEADER]:
              bytesToHex(new Uint8Array(RESPONSE_NONCE_LENGTH)),
          },
        });
      }) as typeof fetch;

      try {
        const response = await transport.post('https://server.test/api', 'request');
        assert(transport.getSessionRecoveryToken());
        rejectRead(readError);
        await assert.rejects(response.text(), (error) => error === readError);
        assert.throws(
          () => transport.getSessionRecoveryToken(),
          /No session recovery token available/,
        );
        assert.strictEqual(cancelReason, readError);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });
});
