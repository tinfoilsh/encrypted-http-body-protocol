// The session recovery token through the public API (SPEC 6): when it
// appears, which exchange owns it, and what consumes it, with real fetch
// concurrency. The token's format and the decryption it enables are the
// core's and pinned by the token-* and decrypt-response-* fixtures.
import { describe, it, before } from 'node:test';
import assert from 'node:assert';
import { Transport, PROTOCOL, core } from '../index.js';
import { type Key } from 'hpke';
import { serverKeys, encryptedResponse, hex, NONCE_LENGTH } from './support.js';

describe('sessionRecoveryToken', () => {
  let publicKey: Uint8Array;
  let privateKey: Key;
  before(async () => ({ publicKey, privateKey } = await serverKeys()));
  const transport = (fetch: typeof globalThis.fetch) => new Transport('https://server.test', { publicKey }, { fetch });
  const echo = async (input: RequestInfo | URL, init?: RequestInit) => encryptedResponse(privateKey, new Request(input, init));
  const gate = () => { let open!: () => void; const p = new Promise<void>((r) => { open = r; }); return { open, p }; };

  it('is undefined before any request and after a fully consumed response', async () => {
    const tp = transport(echo);
    assert.strictEqual(tp.sessionRecoveryToken(), undefined);
    const response = await tp.post('https://server.test/api', 'body');
    assert(tp.sessionRecoveryToken());
    assert.strictEqual(await response.text(), 'processed:body');
    assert.strictEqual(tp.sessionRecoveryToken(), undefined);
  });

  it('is fresh per request and cleared by a bodyless request', async () => {
    const tp = transport(async (input, init) => {
      const request = new Request(input, init);
      return request.headers.has(PROTOCOL.ENCAPSULATED_KEY_HEADER) ? encryptedResponse(privateKey, request) : new Response('plaintext');
    });
    await tp.post('https://server.test/api', 'request-1');
    const first = tp.sessionRecoveryToken()!;
    await tp.post('https://server.test/api', 'request-2');
    assert.notDeepStrictEqual(tp.sessionRecoveryToken()!.exportedSecret, first.exportedSecret, 'each request creates a fresh HPKE context');
    await tp.get('https://server.test/api');
    assert.strictEqual(tp.sessionRecoveryToken(), undefined);
  });

  it('lets only the latest request publish, and an older response never replaces it', async () => {
    const firstStarted = gate(), release = gate();
    let count = 0, secondEnc = '';
    const tp = transport(async (input, init) => {
      const request = new Request(input, init);
      if (++count === 1) { firstStarted.open(); await release.p; } else secondEnc = request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER)!;
      return encryptedResponse(privateKey, request);
    });
    const first = tp.post('https://server.test/api', 'request-1');
    await firstStarted.p;
    await tp.post('https://server.test/api', 'request-2');
    assert.strictEqual(hex(tp.sessionRecoveryToken()!.requestEnc), secondEnc);
    release.open();
    await first;
    assert.strictEqual(hex(tp.sessionRecoveryToken()!.requestEnc), secondEnc, 'an older response must not replace the latest token');
  });

  it('replaces the previous token as soon as a newer request is sealed, before any response', async () => {
    const secondStarted = gate(), release = gate();
    let count = 0;
    const tp = transport(async (input, init) => {
      if (++count === 2) { secondStarted.open(); await release.p; }
      return echo(input, init);
    });
    await tp.post('https://server.test/api', 'request-1');
    const first = tp.sessionRecoveryToken()!;
    const second = tp.post('https://server.test/api', 'request-2');
    await secondStarted.p;
    const inFlight = tp.sessionRecoveryToken()!;
    assert.notDeepStrictEqual(inFlight.requestEnc, first.requestEnc);
    release.open();
    await second;
    assert.deepStrictEqual(tp.sessionRecoveryToken()!.requestEnc, inFlight.requestEnc);
  });

  it('is cleared by its own stream authentication failure only', async () => {
    let count = 0, latestEnc = '';
    const corrupting = (every: boolean) => transport(async (input, init) => {
      const request = new Request(input, init);
      const response = await encryptedResponse(privateKey, request);
      if (!every && ++count === 2) { latestEnc = request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER)!; return response; }
      const corrupted = new Uint8Array(await response.arrayBuffer());
      corrupted[corrupted.length - 1] ^= 1;
      return new Response(corrupted, { headers: response.headers });
    });
    const tp = corrupting(false);
    const older = await tp.post('https://server.test/api', 'request-1');
    const latest = await tp.post('https://server.test/api', 'request-2');
    await assert.rejects(older.text(), /AEAD_DECRYPT_FAILED/);
    assert.strictEqual(hex(tp.sessionRecoveryToken()!.requestEnc), latestEnc, 'an older stream failure must not clear the latest token');
    assert.strictEqual(await latest.text(), 'processed:request-2');

    const only = corrupting(true);
    const response = await only.post('https://server.test/api', 'request');
    await assert.rejects(response.text(), /AEAD_DECRYPT_FAILED/);
    assert.strictEqual(only.sessionRecoveryToken(), undefined);
  });

  it('is cleared after a read failure, which cancels upstream with the cause and surfaces as FRAMING_TRUNCATED', async () => {
    const readError = new Error('upstream read failed');
    let rejectRead!: (error: Error) => void;
    const readResult = new Promise<ReadableStreamReadResult<Uint8Array>>((_, reject) => { rejectRead = reject; });
    let cancelReason: unknown;
    const tp = transport(async () => {
      const source = new ReadableStream<Uint8Array>();
      Object.defineProperty(source, 'getReader', { value: () => ({ read: () => readResult, cancel: async (reason?: unknown) => { cancelReason = reason; } }) });
      return new Response(source, { headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: '00'.repeat(NONCE_LENGTH) } });
    });
    const response = await tp.post('https://server.test/api', 'request');
    assert(tp.sessionRecoveryToken());
    rejectRead(readError);
    await assert.rejects(response.text(), (error: Error & { cause?: unknown }) => /FRAMING_TRUNCATED/.test(error.message) && error.cause === readError);
    assert.strictEqual(tp.sessionRecoveryToken(), undefined);
    assert.strictEqual((cancelReason as { cause?: unknown }).cause, readError);
  });

  describe('core.decryptWithToken', () => {
    const token = { exportedSecret: new Uint8Array(32), requestEnc: new Uint8Array(32) };
    const nonced = (source: ReadableStream<Uint8Array>) => new Response(source, { headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: '00'.repeat(NONCE_LENGTH) } });

    it('cancels the encrypted source when the decrypted body is cancelled', async () => {
      let cancelled = false;
      const decrypted = await core.decryptWithToken(nonced(new ReadableStream({ cancel() { cancelled = true; } })), token);
      await decrypted.body!.cancel('consumer stopped');
      assert.strictEqual(cancelled, true);
    });

    it('cancels the upstream body when a chunk exceeds the maximum size', async () => {
      let cancelled = false;
      const upstream = new ReadableStream<Uint8Array>({
        start(c) { c.enqueue(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0x00])); }, // ~4 GiB length prefix; a real attacker keeps streaming
        cancel() { cancelled = true; },
      });
      const decrypted = await core.decryptWithToken(nonced(upstream), token);
      await assert.rejects(decrypted.text(), /CHUNK_TOO_LARGE/);
      assert.strictEqual(cancelled, true);
    });

    it('reports a transport failure inside a frame as FRAMING_TRUNCATED with the native cause', async () => {
      const readError = new Error('connection reset');
      const source = new ReadableStream<Uint8Array>({
        start(c) { c.enqueue(new Uint8Array([0, 0, 0, 16, 1, 2])); }, // length prefix + partial ciphertext
        pull(c) { c.error(readError); },
      });
      const decrypted = await core.decryptWithToken(nonced(source), token);
      await assert.rejects(decrypted.text(), (error: Error & { cause?: unknown }) => /FRAMING_TRUNCATED/.test(error.message) && error.cause === readError);
    });
  });
});
