// Fetch- and stream-specific behaviour of the Transport: what the conformance
// fixtures cannot see from outside (custom fetch, cancellation, redirect modes,
// fetch option forwarding, browser upload spooling). Protocol decisions are the
// core's and are pinned by test-vectors/conformance.
import { describe, it, before } from 'node:test';
import assert from 'node:assert';
import { Transport, InvalidInputError, UnexpectedRedirectError, PROTOCOL, Code, EhbpError, codeOf, core } from '../index.js';
import { core as pure } from '../core.js';
import { code, error } from '../residue.js';
import { setSpoolThresholdForTests } from '../spool.js';
import { type Key } from 'hpke';
import { serverKeys, encryptedResponse, openFrames, hex, buf } from './support.js';

describe('Transport', () => {
  let publicKey: Uint8Array;
  let privateKey: Key;
  before(async () => ({ publicKey, privateKey } = await serverKeys()));
  const transport = (fetch: typeof globalThis.fetch) => new Transport('https://server.test', { publicKey }, { fetch });

  it('uses an isolated custom fetch for encrypted requests and streamed responses', async (t) => {
    t.mock.method(globalThis, 'fetch', async () => { throw new Error('unexpected global fetch'); });
    const make = (label: string) => transport(async (input, init) => {
      const request = new Request(input, init);
      assert(request.headers.has(PROTOCOL.ENCAPSULATED_KEY_HEADER));
      assert.strictEqual(request.headers.get('authorization'), `Bearer ${label}`);
      assert.strictEqual(request.credentials, 'omit');
      assert.strictEqual(request.redirect, 'error');
      assert(!(await request.clone().text()).includes(`private-${label}`));
      const encrypted = await encryptedResponse(privateKey, request);
      const bytes = new Uint8Array(await encrypted.arrayBuffer());
      return new Response(new ReadableStream({
        start(c) { c.enqueue(bytes.slice(0, 3)); c.enqueue(bytes.slice(3)); c.close(); },
      }), { headers: encrypted.headers });
    });
    const results = await Promise.all(['one', 'two'].map(async (label) => {
      const response = await make(label).post('https://server.test/test', `private-${label}`, {
        headers: { authorization: `Bearer ${label}` }, credentials: 'omit', redirect: 'error',
      });
      return response.text();
    }));
    assert.deepStrictEqual(results, ['processed:private-one', 'processed:private-two']);
  });

  it('calls an injected fetch without a receiver for encrypted and bodyless requests', async () => {
    const receivers: unknown[] = [];
    const tp = transport(async function (this: unknown, input, init) {
      receivers.push(this);
      const request = new Request(input, init);
      return request.body ? encryptedResponse(privateKey, request) : new Response('bodyless');
    });
    assert.strictEqual(await (await tp.post('https://server.test/test', 'hello')).text(), 'processed:hello');
    assert.strictEqual(await (await tp.get('https://server.test/test')).text(), 'bodyless');
    assert.deepStrictEqual(receivers, [undefined, undefined]);
  });

  it('forwards cancellation to a bodyless request', async () => {
    const controller = new AbortController();
    const tp = transport(async (input, init) => {
      const request = new Request(input, init);
      assert.strictEqual(request.body, null);
      assert.strictEqual(request.headers.has(PROTOCOL.ENCAPSULATED_KEY_HEADER), false);
      controller.abort();
      request.signal.throwIfAborted();
      return new Response();
    });
    await assert.rejects(tp.get('https://server.test/test', { signal: controller.signal }), { name: 'AbortError' });
  });

  it('propagates custom fetch errors as-is and clears the recovery token', async () => {
    const failure = new Error('network unavailable');
    const tp = transport(async () => { throw failure; });
    await assert.rejects(tp.post('https://server.test/test', 'secret'), (err) => err === failure);
    assert.strictEqual(tp.sessionRecoveryToken(), undefined);
  });

  it('discovers keys through the same fetch, with discoverInit, never following redirects', async (t) => {
    t.mock.method(globalThis, 'fetch', async () => { throw new Error('unexpected global fetch'); });
    const urls: string[] = [];
    const tp = await Transport.create('https://server.test', { discover: true }, {
      discoverInit: { credentials: 'include' },
      fetch: async function (this: unknown, input, init) {
        assert.strictEqual(this, undefined);
        const request = new Request(input, init);
        urls.push(request.url);
        if (!request.url.endsWith(PROTOCOL.KEYS_PATH)) return encryptedResponse(privateKey, request);
        assert.strictEqual(request.credentials, 'include');
        assert.strictEqual(request.redirect, 'manual'); // SPEC 3.1: discovery never follows redirects
        return new Response(buf(core.marshalConfig(publicKey)), { headers: { 'content-type': PROTOCOL.KEYS_MEDIA_TYPE } });
      },
    });
    assert.strictEqual(await (await tp.post('https://server.test/test', 'hello')).text(), 'processed:hello');
    assert.deepStrictEqual(urls, [`https://server.test${PROTOCOL.KEYS_PATH}`, 'https://server.test/test']);
  });

  it('requires an http(s) origin and a resolved key', async () => {
    for (const server of ['server.test', 'server.test:80', 'ftp://server.test', 'https://user:pass@server.test']) {
      assert.throws(() => new Transport(server, { publicKey }), InvalidInputError);
    }
    assert.throws(() => new Transport('https://server.test', { publicKey: publicKey.slice(1) }));
    const fromConfig = await Transport.create('https://server.test', { config: core.marshalConfig(publicKey) });
    assert.strictEqual(await (await fromConfig.get('data:,plain')).text(), 'plain');
  });

  it('refuses a redirect to an encrypted request, in every form fetch can report one', async () => {
    const cases: [string, () => Response][] = [
      ['see other', () => new Response(null, { status: 303, headers: { location: '/followed' } })],
      ['temporary redirect with a body', () => new Response('forged', { status: 307, headers: { location: '/followed' } })],
      ['made-up nonce', () => new Response(null, { status: 303, headers: { location: '/followed', [PROTOCOL.RESPONSE_NONCE_HEADER]: 'ab'.repeat(32) } })],
      // What a fetch that followed the redirect anyway hands back.
      ['already followed', () => Object.defineProperty(new Response('forged', { status: 200 }), 'redirected', { value: true })],
    ];
    for (const [name, response] of cases) {
      const modes: (string | undefined)[] = [];
      const tp = transport(async (_input, init) => { modes.push(init?.redirect); return response(); });
      await assert.rejects(tp.post('https://server.test/secure', 'hello'), UnexpectedRedirectError, name);
      assert.deepStrictEqual(modes, ['manual'], name);
      assert.strictEqual(tp.sessionRecoveryToken(), undefined, name);
    }
  });

  it('clears the recovery token when the consumer cancels before EOF', async () => {
    const tp = transport(async (input, init) => {
      const encrypted = await encryptedResponse(privateKey, new Request(input, init));
      const body = new Uint8Array(await encrypted.arrayBuffer());
      return new Response(new ReadableStream({ start(c) { c.enqueue(body.slice(0, -1)); } }), { headers: encrypted.headers });
    });
    const response = await tp.post('https://server.test/secure', 'hello');
    assert(tp.sessionRecoveryToken());
    await response.body!.cancel('consumer stopped');
    assert.strictEqual(tp.sessionRecoveryToken(), undefined); // SPEC 6.3: abandoning the body ends the exchange
  });

  it('does not let an older stream completion clear the latest recovery token', async () => {
    let finishFirst!: () => void;
    let secondEnc = '';
    let count = 0;
    const tp = transport(async (input, init) => {
      const request = new Request(input, init);
      const encrypted = await encryptedResponse(privateKey, request);
      if (++count === 2) { secondEnc = request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER)!; return encrypted; }
      const body = new Uint8Array(await encrypted.arrayBuffer());
      return new Response(new ReadableStream({ start(c) { c.enqueue(body); finishFirst = () => c.close(); } }), { headers: encrypted.headers });
    });
    const first = await tp.post('https://server.test/secure', 'first');
    const second = await tp.post('https://server.test/secure', 'second');
    assert.strictEqual(hex(tp.sessionRecoveryToken()!.requestEnc), secondEnc);
    const firstText = first.text();
    finishFirst();
    assert.strictEqual(await firstText, 'processed:first');
    assert.strictEqual(hex(tp.sessionRecoveryToken()!.requestEnc), secondEnc);
    await second.body!.cancel('test complete');
  });

  it('preserves fetch options on encrypted and pass-through requests', async () => {
    let captured!: Request;
    const tp = transport(async (input) => {
      captured = input as Request;
      return captured.body ? encryptedResponse(privateKey, captured.clone()) : new Response('plain');
    });
    const controller = new AbortController();
    const options: RequestInit = {
      cache: 'no-store', credentials: 'include', integrity: 'sha256-test', mode: 'cors', redirect: 'manual',
      referrer: 'https://client.test/page', referrerPolicy: 'origin', signal: controller.signal,
    };
    assert.strictEqual(await (await tp.post('https://server.test/secure', 'hello', options)).text(), 'processed:hello');
    for (const [k, v] of Object.entries(options)) if (k !== 'signal') assert.strictEqual(captured[k as keyof Request], v, k);
    assert.strictEqual(captured.signal.aborted, false);
    controller.abort();
    assert.strictEqual(captured.signal.aborted, true, 'the outgoing signal follows the caller\'s');
    assert.strictEqual(await (await tp.get('https://server.test/status', { credentials: 'include' })).text(), 'plain');
    assert.strictEqual(captured.credentials, 'include');
  });

  it('combines a Request input with init like fetch(): init wins, the rest falls back', async () => {
    let captured!: Request;
    const tp = transport(async (input) => { captured = input as Request; return encryptedResponse(privateKey, captured.clone()); });
    const request = new Request('https://server.test/secure', {
      method: 'POST', body: 'request body', headers: { 'x-source': 'request', 'x-replaced': 'request' },
      cache: 'reload', credentials: 'include', integrity: 'sha256-request', mode: 'cors', redirect: 'manual',
      referrer: 'https://client.test/request', referrerPolicy: 'strict-origin', duplex: 'half',
    } as RequestInit);
    const expected = new Request(request.clone(), { credentials: 'omit' });
    assert.strictEqual(await (await tp.request(request.clone(), { credentials: 'omit' })).text(), 'processed:request body');
    for (const k of ['cache', 'credentials', 'integrity', 'mode', 'redirect', 'referrer', 'referrerPolicy'] as const) assert.strictEqual(captured[k], expected[k], k);
    const response = await tp.request(request, { method: 'PUT', headers: { 'x-init': 'init', 'x-replaced': 'init' }, body: 'init body' });
    assert.strictEqual(await response.text(), 'processed:init body');
    assert.strictEqual(captured.method, 'PUT');
    assert.deepStrictEqual([captured.headers.get('x-init'), captured.headers.get('x-replaced'), captured.headers.get('x-source')], ['init', 'init', null]);
  });

  it('pulls a stream body incrementally rather than buffering it', async () => {
    let pulls = 0;
    const chunks = 8;
    const source = new ReadableStream<Uint8Array>({
      pull(c) { if (++pulls > chunks) c.close(); else c.enqueue(new Uint8Array(65536).fill(pulls)); },
    }, { highWaterMark: 0 });
    const tp = transport(async (input, init) => {
      const encrypted = new Request(input, init);
      assert(encrypted.body, 'Node sends the encrypted frames as a stream');
      const reader = encrypted.body.getReader();
      const first = await reader.read();
      assert(!first.done && first.value.byteLength === 65536 + (4 + 16), 'first read is the first 64 KiB source chunk sealed as one 64 KiB frame');
      assert(pulls < chunks, `source should not be drained up front (pulled ${pulls} of ${chunks})`);
      await reader.cancel();
      return new Response(null, { status: 502 });
    });
    await tp.request('https://server.test/upload', { method: 'POST', body: source, duplex: 'half' } as RequestInit);
  });

  it('preserves the request payload when Request.body is unavailable (Firefox), through the default global fetch', async (t) => {
    t.mock.method(globalThis, 'fetch', async (input: Request) => encryptedResponse(privateKey, input.clone()));
    const originalBody = Object.getOwnPropertyDescriptor(Request.prototype, 'body')!;
    Object.defineProperty(Request.prototype, 'body', { configurable: true, get: () => null });
    try {
      const response = await new Transport('https://server.test', { publicKey }).post('https://server.test/secure', 'firefox body');
      assert.strictEqual(await response.text(), 'processed:firefox body');
    } finally {
      Object.defineProperty(Request.prototype, 'body', originalBody);
    }
  });

  it('maps every core code to an error class carrying the spelling the core gives it', () => {
    for (const c of pure.Codes) {
      const err = error(c, 'x');
      assert.ok(err instanceof EhbpError, code(c));
      assert.equal(codeOf(err), code(c));
      assert.equal(Code[code(c) as Code], code(c));
    }
    assert.equal(pure.Codes.length, Object.keys(Code).length);
  });

  // Browser uploads: where fetch cannot stream a request body, the sealed
  // frames are buffered, spooled to OPFS past a threshold, or re-sealed.
  describe('where uploads cannot stream', () => {
    const original200k = () => new Uint8Array(200 * 1024).map((_, i) => (i * 7) & 0xff);
    // Forces the browser path (canStreamUpload keys off process.versions.node) with a
    // 100 KiB framed spool threshold so 200 KiB bodies cross it; null keeps the 64 MiB default.
    function browserMode(thresholdBytes: number | null = 100 * 1024) {
      setSpoolThresholdForTests(thresholdBytes ?? undefined);
      const versions = Object.getOwnPropertyDescriptor(process, 'versions')!;
      Object.defineProperty(process, 'versions', { value: {}, configurable: true });
      return () => { setSpoolThresholdForTests(undefined); Object.defineProperty(process, 'versions', versions); };
    }
    function fakeOpfs(opts: { quota?: number; failAfterWrites?: number; existing?: string[]; failClose?: boolean } = {}) {
      const state = { writes: [] as number[], removed: [] as string[], aborted: 0, closedAfterError: 0, openedAtWrites: -1 };
      const chunks: Uint8Array[] = [];
      const handle = {
        async createWritable() {
          state.openedAtWrites = state.writes.length;
          let errored = false;
          return {
            async write(v: Uint8Array) {
              if (opts.failAfterWrites !== undefined && state.writes.length >= opts.failAfterWrites) {
                errored = true; throw new DOMException('quota exceeded mid-body', 'QuotaExceededError');
              }
              state.writes.push(v.byteLength); chunks.push(new Uint8Array(v));
            },
            async abort() { state.aborted++; },
            async close() {
              if (errored) { state.closedAfterError++; throw new TypeError('Cannot close a ERRORED writable stream'); }
              if (opts.failClose) throw new DOMException('disk full at close', 'QuotaExceededError');
            },
          };
        },
        async getFile() { return new File(chunks as BlobPart[], 'spool'); },
      };
      const root = {
        async getFileHandle() { return handle; },
        async removeEntry(name: string) { state.removed.push(name); },
        async *keys() { for (const n of opts.existing ?? []) yield n; },
      };
      const nav = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
      Object.defineProperty(globalThis, 'navigator', {
        value: { storage: { getDirectory: async () => root, estimate: async () => ({ quota: opts.quota ?? 1e12, usage: 0 }) } },
        configurable: true,
      });
      const g = globalThis as Record<string, unknown>;
      const prevHandle = g.FileSystemFileHandle;
      g.FileSystemFileHandle = class { createWritable() {} };
      const restore = () => {
        if (nav) Object.defineProperty(globalThis, 'navigator', nav); else delete g.navigator;
        g.FileSystemFileHandle = prevHandle;
      };
      return { state, restore };
    }
    type Opfs = ReturnType<typeof fakeOpfs>;
    // A transport whose fetch captures the sealed request and answers a nonce-less 502 (pass-through).
    function capturing(state?: Opfs['state']) {
      const captured = { request: undefined as Request | undefined, removedAtFetch: -1 };
      const tp = transport(async (req) => {
        captured.removedAtFetch = state?.removed.length ?? -1;
        captured.request = (req as Request).clone();
        await (req as Request).arrayBuffer();
        return new Response('upstream', { status: 502 });
      });
      return { tp, captured, opened: () => openFrames(privateKey, captured.request!) };
    }
    // Each case runs in browser mode with a fake OPFS (unless `opfs: false`) and restores both after.
    const browserIt = (name: string, mode: { threshold?: number | null; opfs?: Parameters<typeof fakeOpfs>[0] | false },
      body: (ctx: { state: Opfs['state'] } & ReturnType<typeof capturing>) => Promise<void>) =>
      it(name, async () => {
        const restoreMode = browserMode(mode.threshold);
        const opfs = mode.opfs === false ? undefined : fakeOpfs(mode.opfs);
        try { await body({ state: opfs?.state!, ...capturing(opfs?.state) }); } finally { opfs?.restore(); restoreMode(); }
      });

    it('falls back to a single Blob built from the frame parts', async () => {
      const restoreMode = browserMode();
      const RealBlob = globalThis.Blob;
      const blobs: number[] = [];
      globalThis.Blob = class extends RealBlob {
        constructor(parts?: BlobPart[], options?: BlobPropertyBag) { super(parts, options); blobs.push(parts?.length ?? 0); }
      } as typeof Blob;
      try {
        const original = original200k();
        const { tp, opened } = capturing();
        await tp.request('https://server.test/upload', { method: 'POST', body: original });
        assert.strictEqual(blobs.length, 1, 'one Blob built from the frame parts');
        const { frames, plain } = await opened();
        assert.strictEqual(frames, 4);
        assert.deepStrictEqual(plain, Buffer.from(original));
      } finally {
        globalThis.Blob = RealBlob;
        restoreMode();
      }
    });

    browserIt('spools frames to OPFS incrementally and uploads the file', {}, async ({ tp, state, captured, opened }) => {
      const original = original200k();
      let streamed = 0;
      const source = new ReadableStream<Uint8Array>({
        pull(c) {
          if (streamed >= original.byteLength) { c.close(); return; }
          c.enqueue(original.subarray(streamed, streamed + 50 * 1024)); streamed += 50 * 1024;
        },
      });
      const response = await tp.request('https://server.test/upload', { method: 'POST', body: source });
      assert.strictEqual(response.status, 502);
      assert.deepStrictEqual(state.writes, new Array(4).fill(50 * 1024 + 20), 'one OPFS write per sealed read (a 50 KiB chunk is one frame)');
      assert.strictEqual(captured.removedAtFetch, 0, 'the spool file is alive while fetch runs');
      assert.strictEqual(state.removed.length, 1, 'the spool file is removed after the response');
      const { frames, plain } = await opened();
      assert.strictEqual(frames, 4);
      assert.deepStrictEqual(plain, Buffer.from(original));
    });

    browserIt('falls back to a Blob when the quota cannot hold a body of known size', { opfs: { quota: 1024 } }, async ({ tp, state, opened }) => {
      const original = original200k();
      let streamCalls = 0;
      const blob = new Blob([original]);
      const realStream = blob.stream.bind(blob);
      blob.stream = () => { streamCalls++; return realStream(); };
      blob.arrayBuffer = async () => { throw new Error('must not buffer the source'); };
      await tp.request('https://server.test/upload', { method: 'POST', body: blob });
      assert.strictEqual(state.writes.length, 0, 'no spool when quota is short');
      assert.strictEqual(streamCalls, 1, 'the Blob source is read as a stream');
      const { frames, plain } = await opened();
      assert.strictEqual(frames, 4);
      assert.deepStrictEqual(plain, Buffer.from(original));
    });

    browserIt('falls back to a Blob when the quota only fits the plaintext, not the framed body', { opfs: { quota: 200 * 1024 + 10 } }, async ({ tp, state, opened }) => {
      await tp.request('https://server.test/upload', { method: 'POST', body: new Blob([original200k()]) });
      assert.strictEqual(state.writes.length, 0, 'framed size exceeds quota: no spool');
      assert.strictEqual((await opened()).frames, 4);
    });

    browserIt('re-seals a Blob source into memory when the OPFS write fails mid-body', { opfs: { failAfterWrites: 0 } }, async ({ tp, state, opened }) => {
      const original = original200k();
      const response = await tp.request('https://server.test/upload', { method: 'POST', body: new Blob([original]) });
      assert.strictEqual(response.status, 502);
      assert.strictEqual(state.aborted, 1, 'the errored writer is aborted, not closed');
      assert.strictEqual(state.closedAfterError, 0);
      assert.strictEqual(state.removed.length, 1, 'the partial spool is removed');
      const { frames, plain } = await opened();
      assert.strictEqual(frames, 4);
      assert.deepStrictEqual(plain, Buffer.from(original), 'the retry sealed the whole body under a fresh context');
    });

    browserIt('surfaces the OPFS failure for a stream source that cannot be replayed', { opfs: { failAfterWrites: 0 } }, async ({ tp, state }) => {
      let cancelled: unknown;
      const source = new ReadableStream<Uint8Array>({ start(c) { c.enqueue(original200k()); }, cancel(reason) { cancelled = reason; } });
      await assert.rejects(tp.request('https://server.test/upload', { method: 'POST', body: source }),
        (err: unknown) => err instanceof DOMException && err.name === 'QuotaExceededError');
      assert.strictEqual(state.aborted, 1);
      assert.strictEqual(state.removed.length, 1);
      assert.ok(cancelled instanceof DOMException, 'the caller stream is cancelled with the failure');
    });

    const old = `ehbp-spool-${Date.now() - 2 * 60 * 60 * 1000}-dead`;
    const fresh = `ehbp-spool-${Date.now() - 1000}-live`;
    browserIt('removes orphaned spool files older than an hour and keeps fresh ones', { opfs: { existing: [old, fresh, 'unrelated-file'] } }, async ({ tp, state }) => {
      await tp.request('https://server.test/upload', { method: 'POST', body: new Blob([original200k()]) });
      assert.ok(state.removed.includes(old), 'stale spool swept');
      assert.ok(state.writes.length > 0, 'sweep happens before the quota check, so the upload still spools');
      assert.ok(!state.removed.includes(fresh), 'a concurrent upload\'s spool is left alone');
      assert.ok(!state.removed.includes('unrelated-file'));
    });

    browserIt('rejects a GET with a body before touching it, and keeps a typed Blob\'s Content-Type', {}, async ({ tp, state, captured }) => {
      let pulled = false;
      const source = new ReadableStream<Uint8Array>({ pull(c) { pulled = true; c.close(); } }, { highWaterMark: 0 });
      await assert.rejects(tp.request('https://server.test/x', { method: 'GET', body: source }), InvalidInputError);
      assert.strictEqual(pulled, false);
      assert.strictEqual(state.writes.length, 0);
      await tp.request('https://server.test/upload', { method: 'POST', body: new Blob([original200k()], { type: 'application/octet-stream' }) });
      assert.strictEqual(captured.request!.headers.get('content-type'), 'application/octet-stream');
    });

    browserIt('keeps bodies under the 64 MiB threshold in memory and never touches OPFS', { threshold: null }, async ({ tp, state, opened }) => {
      const original = original200k();
      await tp.request('https://server.test/upload', { method: 'POST', body: new Blob([original]) });
      assert.strictEqual(state.openedAtWrites, -1, 'no spool file was created');
      assert.deepStrictEqual([state.writes.length, state.removed.length], [0, 0], 'no sweep, no cleanup');
      const { frames, plain } = await opened();
      assert.strictEqual(frames, 4);
      assert.deepStrictEqual(plain, Buffer.from(original));
    });

    browserIt('spills a stream only once it crosses the threshold, writing the buffered prefix first', { threshold: 100 * 1024 }, async ({ tp, state, opened }) => {
      const original = original200k();
      await tp.request('https://server.test/upload', { method: 'POST', body: new ReadableStream({ start(c) { c.enqueue(original); c.close(); } }) });
      assert.strictEqual(state.openedAtWrites, 0, 'file opened once the buffer exceeded the threshold');
      assert.deepStrictEqual(state.writes, [...new Array(3).fill(64 * 1024 + 20), 8 * 1024 + 20], 'the buffered 64 KiB reads are written first, in order');
      const { frames, plain } = await opened();
      assert.strictEqual(frames, 4);
      assert.deepStrictEqual(plain, Buffer.from(original));
    });

    browserIt('spills a known-size Blob above the threshold from the first frame', { threshold: 1024 }, async ({ tp, state, opened }) => {
      const original = original200k();
      await tp.request('https://server.test/upload', { method: 'POST', body: new Blob([original]) });
      assert.strictEqual(state.openedAtWrites, 0);
      assert.ok(state.writes.length > 0);
      assert.deepStrictEqual((await opened()).plain, Buffer.from(original));
    });

    browserIt('stays in memory when the quota cannot take the spill', { threshold: 1024, opfs: { quota: 1500 } }, async ({ tp, state, opened }) => {
      const original = original200k();
      await tp.request('https://server.test/upload', { method: 'POST', body: new ReadableStream({ start(c) { c.enqueue(original); c.close(); } }) });
      assert.strictEqual(state.writes.length, 0, 'spill refused once, then buffered to the end');
      const { frames, plain } = await opened();
      assert.strictEqual(frames, 4);
      assert.deepStrictEqual(plain, Buffer.from(original));
    });

    browserIt('removes the spool when finalization fails and surfaces that error', { threshold: 1024, opfs: { failClose: true } }, async ({ tp, state }) => {
      await assert.rejects(tp.request('https://server.test/upload', { method: 'POST', body: new ReadableStream({ start(c) { c.enqueue(original200k()); c.close(); } }) }),
        (err: unknown) => err instanceof DOMException && err.message === 'disk full at close');
      assert.strictEqual(state.removed.length, 1, 'the spool file is removed after a failed close');
      assert.strictEqual(state.aborted, 1);
    });

    browserIt('falls back to a Blob where OPFS is absent', { opfs: false }, async ({ tp, opened }) => {
      const original = original200k();
      await tp.request('https://server.test/upload', { method: 'POST', body: new Blob([original]) });
      const { frames, plain } = await opened();
      assert.strictEqual(frames, 4);
      assert.deepStrictEqual(plain, Buffer.from(original));
    });
  });
});

describe('core', () => {
  it('rejects a sequence number outside uint64 before the core wraps it', () => {
    const base = new Uint8Array(12);
    assert.deepStrictEqual(core.nonceFor(base, 2n ** 64n - 1n).slice(4), new Uint8Array(8).fill(0xff));
    for (const seqNo of [-1, 1.5, Number.MAX_SAFE_INTEGER + 2, -1n, 2n ** 64n]) {
      assert.throws(() => core.nonceFor(base, seqNo), (err: unknown) => codeOf(err) === Code.INVALID_INPUT);
    }
  });
});
