// The JavaScript residue of the event-driven core (dafny/ehbp_events.dfy):
// one binding per action the core can emit, the pump of
// conformance/spec/handler.md section 5, and the conversions at the runtime
// boundary, in the order and under the names of handler.md section 4.
// Nothing here decides anything about the protocol; the layout mirrors the Go
// reference (internal/eventresidue/residue.go). fetch and WebCrypto are
// asynchronous, so the bindings and the pump await (section 5). Locals inside
// binding bodies are `let`: the checker's JS regex reads an indented `const`
// as a new declaration and would cut the binding's row in the matrix.
import type BigNumber from 'bignumber.js';
import { x25519 as curve } from '@noble/curves/ed25519.js';
import {
  type Action, type Bytes, type Code as CoreCode, type Datatype, type Event as CoreEvent, type HeadersSeq,
  type Origin, type Result, type SessionStore, type State, type Str, type Token as CoreToken,
  EHBP, EMPTY, Event, Seq, SessionAction, Stream, Token, Tuple, core, ev, int, num,
} from './core.js';
import {
  type EhbpError, AeadDecryptFailedError, ChunkTooLargeError, Code, DuplicateResponseNonceError, FramingTruncatedError,
  HpkeSetupFailedError, InvalidEncapsulatedKeyError, InvalidInputError, InvalidKeyConfigError, InvalidResponseNonceError,
  InvalidTokenError, KeyConfigMismatchError, MissingResponseNonceError, SequenceOverflowError, UnexpectedRedirectError,
  UnsupportedSuiteError,
} from './errors.js';
import { canStreamUpload, collect, spool } from './spool.js';

// crypto: one native call each, bytes in, bytes out. A failure is an empty
// result (or ok false for aeadOpen), which the core rejects by length.
// X25519 is @noble/curves (throws on a low-order point) because WebCrypto's X25519 is not
// universal; AES-GCM, HMAC-SHA256 and randomness are WebCrypto (crypto.subtle / getRandomValues).
// WebCrypto refuses an empty HMAC key; HMAC zero-pads keys to the block size, so 32 zero bytes is the same key.

const subtle = globalThis.crypto.subtle;
const buf = (b: Uint8Array): BufferSource => b as unknown as BufferSource;
const aesKey = (key: Uint8Array, nonce: Uint8Array, usage: KeyUsage): Promise<CryptoKey> => {
  if (nonce.length !== num(core.NonceLength)) throw new Error('nonce length'); // WebCrypto would accept any iv
  return subtle.importKey('raw', buf(key), 'AES-GCM', false, [usage]);
};

export function x25519(scalar: Uint8Array, point: Uint8Array): Uint8Array {
  try {
    return curve.getSharedSecret(scalar, point);
  } catch { return EMPTY; }
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  try {
    let k = await subtle.importKey('raw', buf(key.length ? key : new Uint8Array(32)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await subtle.sign('HMAC', k, buf(data)));
  } catch { return EMPTY; }
}

export async function aeadSeal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  try {
    return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: buf(nonce) }, await aesKey(key, nonce, 'encrypt'), buf(plaintext)));
  } catch { return EMPTY; }
}

export async function aeadOpen(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Promise<[boolean, Uint8Array]> {
  try {
    return [true, new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: buf(nonce) }, await aesKey(key, nonce, 'decrypt'), buf(ciphertext)))];
  } catch { return [false, EMPTY]; }
}

export function randomBytes(length: number): Uint8Array {
  try {
    return globalThis.crypto.getRandomValues(new Uint8Array(length));
  } catch { return EMPTY; }
}

// http: the only block holding native state. One Exchange per request or
// discovery; the bindings are its methods and the pump below drives it. Native
// policy (redirects, browser spooling, cancellation via the caller's signal in
// `template`) lives in send.

const ReadChunkBytes = 64 << 10;
const WriteBatchBytes = 64 << 10; // frames are batched, as Go's bufio: a frame header rides with its ciphertext

export class Exchange {
  private frames?: ReadableStream<Uint8Array>; // the encrypted upload, fed by write
  private sink?: ReadableStreamDefaultController<Uint8Array>;
  private sinkDead = false;
  private wake?: () => void;
  private held: Uint8Array[] = []; // writes not yet enqueued
  private heldBytes = 0;
  private bodyReader?: ReadableStreamDefaultReader<Uint8Array>;
  private pending?: Uint8Array; // the rest of a native chunk beyond ReadChunkBytes
  private respReader?: ReadableStreamDefaultReader<Uint8Array>;
  handed = false; // the upload lane owns body
  sendErr?: unknown; respErr?: unknown; bodyErr?: unknown; // native causes behind a Transport failure
  /** Set when the browser spool failed before anything was sent; a replayable body may be retried in memory. */
  spoolFailed = false;

  // The outcome, written by the terminal actions and read by the shim.
  response?: Response; // the native response, every field the stack set
  failure?: Error;
  passthrough = false; done = false; finished = false;
  prefix = EMPTY; publicKey?: Uint8Array; headers?: Headers;
  plain: Uint8Array[] = []; // EmitPlaintext since the last Read

  /** Binds a core state to the native pieces: fetchImpl performs one transaction from template; body is the caller's body or null. */
  constructor(
    public state: State, readonly session: Session, private readonly fetchImpl: typeof fetch, private readonly template: RequestInit,
    private readonly body: ReadableStream<Uint8Array> | null, private readonly bodySize?: number, private readonly memoryOnly = false,
  ) {
    if (body) this.frames = new ReadableStream<Uint8Array>({ start: (c) => { this.sink = c; }, pull: () => this.wake?.(), cancel: (reason) => this.dropSink(reason) });
  }

  // http: the four performers over fetch (send, write, read, close), written by hand.
  /** One transaction; with a body it awaits the response head while the upload lane feeds the frames. A redirect is never followed; a caller's 'error' mode stays. */
  async send(verb: string, url: string, headers: [string, string][], hasBody: boolean): Promise<[boolean, number, Headers, boolean]> {
    let init = { ...this.template, method: verb, headers: new Headers(headers), body: null as BodyInit | null, duplex: 'half' } as RequestInit;
    let cleanup: (() => Promise<void>) | undefined;
    try {
      if (hasBody && canStreamUpload()) init.body = this.frames!;
      else if (hasBody && this.memoryOnly) init.body = await collect(this.frames!);
      else if (hasBody) {
        try { ({ body: init.body, cleanup } = await spool(this.frames!, this.bodySize)); } catch (err) { this.spoolFailed = true; throw err; }
      }
      let request = new Request(url, init);
      let response = await this.fetchImpl(request, request.redirect === 'error' ? undefined : { redirect: 'manual' });
      this.response = response;
      // An opaqueredirect hides a 3xx the stack refused to follow; it is reported as one.
      return [true, response.status, response.headers, response.redirected || response.type === 'opaqueredirect'];
    } catch (err) {
      this.sendErr = err;
      this.dropSink(); // the transport gave up; unblock the upload lane
      return [false, 0, new Headers(), false];
    } finally {
      // Response headers mean the upload finished; a removal failure must neither fail the exchange nor mask an error.
      await cleanup?.().catch(() => {});
    }
  }

  /** Feeds one encrypted chunk; WriteBatchBytes are enqueued at a time and awaited by the stack's pull. Done closes the upload, Aborted errors it with the code; false once the transport is gone. */
  async write(data: Uint8Array, end: Datatype): Promise<boolean> {
    if (data.length > 0) { this.held.push(data); this.heldBytes += data.length; }
    if (end.is_More) return this.heldBytes < WriteBatchBytes || this.flush();
    if (!(await this.flush())) return false;
    let reason = end.is_Aborted ? error(end.dtor_code, 'request body failed', this.bodyErr) : undefined;
    try { if (reason) this.sink?.error(reason); else this.sink?.close(); } catch { /* already gone */ }
    this.closeBody(reason);
    return true;
  }

  /** Enqueues the held writes as one chunk and waits for the stack to pull it; false once the transport is gone. */
  private async flush(): Promise<boolean> {
    if (this.heldBytes === 0) return true;
    let chunk = this.held[0];
    if (this.held.length > 1) { chunk = new Uint8Array(this.heldBytes); let at = 0; for (let part of this.held) { chunk.set(part, at); at += part.length; } }
    this.held = []; this.heldBytes = 0;
    try { this.sink!.enqueue(chunk); } catch { this.closeBody(this.sendErr); return false; }
    if ((this.sink!.desiredSize ?? 1) <= 0) await new Promise<void>((r) => { this.wake = r; });
    return !this.sinkDead;
  }

  /** Reads once from the caller's body or the native response. The caller's body is read at most ReadChunkBytes at a time, as Go's readChunk: the core slices a chunk once per frame, so a 1 MiB native chunk would be copied 128 times. */
  async read(stream: Datatype): Promise<[Uint8Array, boolean, boolean]> {
    if (stream.is_ResponseBody) {
      let body = this.response?.body;
      if (!body) return [EMPTY, true, true];
      try {
        let { done, value } = await (this.respReader ??= body.getReader()).read();
        return [value ?? EMPTY, done, true];
      } catch (err) { this.respErr = err; return [EMPTY, false, false]; }
    }
    if (!this.body) return [EMPTY, true, true];
    if (this.heldBytes > 0 && !(await this.flush())) { this.bodyErr = this.sendErr; return [EMPTY, false, false]; } // nothing sealed is held while the lane waits for the caller
    try {
      let chunk = this.pending, eof = false;
      if (!chunk) ({ done: eof, value: chunk = EMPTY } = await (this.bodyReader ??= this.body.getReader()).read());
      this.pending = chunk.length > ReadChunkBytes ? chunk.subarray(ReadChunkBytes) : undefined;
      return [chunk.subarray(0, ReadChunkBytes), eof, true];
    } catch (err) { this.bodyErr = err; return [EMPTY, false, false]; }
  }

  /** Releases the native stream: the response body with the failure, if any, as the cancel reason; the caller's body. Idempotent. */
  close(stream: Datatype): void {
    if (stream.is_RequestBody) return this.closeBody();
    (this.respReader ??= this.response?.body?.getReader())?.cancel(this.failure).catch(() => {});
  }

  /** The stack stopped pulling the upload (cancelled with `reason`, or the transaction failed): the caller's body is released with the cause, which also ends a pending read of it. */
  private dropSink(reason?: unknown): void {
    this.sinkDead = true;
    this.sendErr ??= reason;
    this.wake?.();
    this.closeBody(this.sendErr);
  }

  /** Releases the caller's body; idempotent. */
  private closeBody(reason?: unknown): void {
    (this.bodyReader ??= this.body?.getReader())?.cancel(reason).catch(() => {});
  }
}

// session: one SessionStore value; every rule is SessionApply. JS is
// single-threaded, so no lock is needed around it.

export class Session {
  private store: SessionStore = ev.NewSession;

  private apply(a: Datatype): SessionStore {
    return (this.store = ev.SessionApply(this.store, a));
  }

  beginSession(): BigNumber {
    return this.apply(SessionAction.create_Begin()).dtor_generation;
  }

  publishToken(generation: BigNumber, exportedSecret: Uint8Array, requestEnc: Uint8Array): void {
    this.apply(SessionAction.create_Publish(generation, Token.create_Token(seq(exportedSecret), seq(requestEnc))));
  }

  clearToken(generation: BigNumber): void {
    this.apply(SessionAction.create_Clear(generation));
  }

  /** The stored token, or undefined. */
  token(): CoreToken | undefined {
    let t = this.store.dtor_token;
    return t.is_Some ? t.dtor_value : undefined;
  }
}

// pump: handler.md section 5, written by hand: perform awaits inside.

/** Maps one action to one binding call and returns the result event; undefined for none, null when the upload sink is gone and this lane ends. */
export async function perform(x: Exchange, a: Action): Promise<CoreEvent | undefined | null> {
  let E = Event;
  if (a.is_BeginSession) return E.create_SessionBegun(x.session.beginSession());
  if (a.is_PublishToken) return void x.session.publishToken(a.dtor_generation, bytes(a.dtor_exportedSecret), bytes(a.dtor_requestEnc));
  if (a.is_ClearToken) return void x.session.clearToken(a.dtor_generation);
  if (a.is_RandomBytes) return E.create_RandomResult(seq(randomBytes(num(a.dtor_length))));
  if (a.is_X25519) return E.create_X25519Result(seq(x25519(bytes(a.dtor_scalar), bytes(a.dtor_point))));
  if (a.is_HmacSha256) return E.create_HmacResult(seq(await hmacSha256(bytes(a.dtor_key), bytes(a.dtor_data))));
  if (a.is_AeadSeal) return E.create_AeadSealResult(seq(await aeadSeal(bytes(a.dtor_key), bytes(a.dtor_nonce), bytes(a.dtor_plaintext))));
  if (a.is_AeadOpen) { let [ok, plaintext] = await aeadOpen(bytes(a.dtor_key), bytes(a.dtor_nonce), bytes(a.dtor_ciphertext)); return E.create_AeadOpenResult(ok, seq(plaintext)); }
  if (a.is_Send) { let [ok, status, headers, redirected] = await x.send(string(a.dtor_verb), string(a.dtor_url), headerPairs(a.dtor_headers), a.dtor_hasBody); return ok ? E.create_ResponseHead(int(status), headerSeq(headers), redirected) : E.create_StreamFailed(Stream.create_ResponseBody()); }
  if (a.is_Write) return (await x.write(bytes(a.dtor_data), a.dtor_end)) ? undefined : null;
  if (a.is_Read) { let [data, eof, ok] = await x.read(a.dtor_stream); return ok ? E.create_Chunk(a.dtor_stream, seq(data), eof) : E.create_StreamFailed(a.dtor_stream); }
  if (a.is_Close) return void x.close(a.dtor_stream);
  return undefined;
}

/** Feeds events to Step until a terminal action. A Send with a body hands the rest of its action list, the upload, to a second lane (an unawaited promise) so the transaction can await the response head; this lane stops there. */
async function run(x: Exchange, acts: Action[]): Promise<void> {
  let events: CoreEvent[] = [];
  do {
    for (let i = 0; i < acts.length; i++) {
      let a = acts[i];
      if (a.is_EmitPlaintext) { x.plain.push(bytes(a.dtor_data)); continue; }
      if (a.is_Passthrough) { x.passthrough = true; x.prefix = bytes(a.dtor_prefix); return; }
      if (a.is_Done) { x.done = true; x.headers = new Headers(headerPairs(a.dtor_headers)); return; }
      if (a.is_Finished) { x.finished = true; return; }
      if (a.is_Discovered) { x.publicKey = bytes(a.dtor_publicKey); return; }
      if (a.is_Fail) { x.failure = error(a.dtor_code, string(a.dtor_message), x.sendErr ?? x.respErr ?? x.bodyErr); return; }
      if (a.is_Send && a.dtor_hasBody) { x.handed = true; void run(x, acts.slice(i + 1)); }
      let e = await perform(x, a);
      if (e === null) return;
      if (e) events.push(e);
      if (a.is_Send && a.dtor_hasBody) break;
    }
    if (events.length === 0) return;
    acts = step(x, events.pop()!);
  } while (true);
}

function step(x: Exchange, e: CoreEvent): Action[] {
  let [state, acts] = ev.Step(x.state, e);
  x.state = state;
  return Array.from(acts);
}

/** Runs the pump on one caller event: Start, DiscoverStart, CallerRead or CallerClose. */
export async function feed(x: Exchange, e: CoreEvent): Promise<void> {
  await run(x, step(x, e));
  if (!x.handed) x.close(Stream.create_RequestBody()); // the core never asked for it
}

/** A pass-through body: the bytes the core read ahead, then the rest of the native body. */
export function prefixed(x: Exchange): ReadableStream<Uint8Array> {
  let prefix: Uint8Array | undefined = x.prefix;
  return new ReadableStream<Uint8Array>({
    async pull(c) {
      if (prefix) { c.enqueue(prefix); prefix = undefined; return; }
      let [chunk, eof, ok] = await x.read(Stream.create_ResponseBody());
      if (!ok) return c.error(new Error('response body failed'));
      if (chunk.length > 0) c.enqueue(chunk);
      if (eof) c.close();
    },
    cancel: () => x.close(Stream.create_ResponseBody()),
  });
}

/** The decrypted body after Done: each pull drives the core with CallerRead until it emits plaintext, finishes or fails; cancel releases it. */
export function decrypted(x: Exchange): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    async pull(c) {
      await feed(x, Event.create_CallerRead());
      for (let chunk of x.plain.splice(0)) c.enqueue(chunk);
      if (x.finished) c.close();
      if (!x.failure) return;
      c.error(x.failure);
      await feed(x, Event.create_CallerClose()); // an errored stream is never cancelled by its consumer: release the native body now
    },
    cancel: () => feed(x, Event.create_CallerClose()),
  });
}

// conversions: the runtime boundary only.

export function seq(b: Uint8Array): Bytes {
  let s = new Seq<number>(b.length);
  for (let i = 0; i < b.length; i++) s[i] = b[i];
  return s;
}
export function bytes(s: Bytes): Uint8Array {
  let b = new Uint8Array(s.length);
  for (let i = 0; i < b.length; i++) b[i] = s[i];
  return b;
}
export const str = (s: string): Str => Seq.UnicodeFromString(s);
export const string = (s: Str): string => s.toVerbatimString(false);
/** Native headers to the core's seq<(string, string)>, one entry per value. */
export function headerSeq(h: Headers): HeadersSeq {
  let s = new Seq<[Str, Str]>();
  for (let [name, value] of h) s.push(Tuple.of(str(name), str(value)) as [Str, Str]);
  return s;
}
/** The core's header list back to name/value pairs (a `Headers` init). */
export function headerPairs(s: HeadersSeq): [string, string][] {
  return Array.from(s, ([name, value]) => [string(name), string(value)]);
}

export const hex = (b: Uint8Array): string => string(core.EncodeHex(seq(b)));
/** The parsed parts of a URL for MakeOrigin; a URL the platform cannot parse is InvalidInput. */
export function originOf(url: string, base?: string): Result<Origin> {
  let u: URL;
  try { u = new URL(url, base); } catch { return EHBP.Result.create_Err(EHBP.Code.create_InvalidInput(), str(`invalid URL: ${url}`)); }
  return core.MakeOrigin(str(u.protocol.slice(0, -1)), str(u.hostname), u.port ? EHBP.Option.create_Some(int(Number(u.port))) : EHBP.Option.create_None(), Boolean(u.username || u.password));
}

// mapping: from the core's CodeString; no table of strings.

/** The canonical code of a core code; "" for Transport, which has none. */
export const code = (c: CoreCode): string => string(core.CodeString(c));
const classes: Record<string, new (detail: string, options?: { cause?: unknown }) => EhbpError> = {
  [Code.INVALID_KEY_CONFIG]: InvalidKeyConfigError,
  [Code.UNSUPPORTED_SUITE]: UnsupportedSuiteError,
  [Code.INVALID_ENCAPSULATED_KEY]: InvalidEncapsulatedKeyError,
  [Code.HPKE_SETUP_FAILED]: HpkeSetupFailedError,
  [Code.MISSING_RESPONSE_NONCE]: MissingResponseNonceError,
  [Code.UNEXPECTED_REDIRECT]: UnexpectedRedirectError,
  [Code.INVALID_RESPONSE_NONCE]: InvalidResponseNonceError,
  [Code.DUPLICATE_RESPONSE_NONCE]: DuplicateResponseNonceError,
  [Code.KEY_CONFIG_MISMATCH]: KeyConfigMismatchError,
  [Code.FRAMING_TRUNCATED]: FramingTruncatedError,
  [Code.CHUNK_TOO_LARGE]: ChunkTooLargeError,
  [Code.AEAD_DECRYPT_FAILED]: AeadDecryptFailedError,
  [Code.SEQUENCE_OVERFLOW]: SequenceOverflowError,
  [Code.INVALID_TOKEN]: InvalidTokenError,
  [Code.INVALID_INPUT]: InvalidInputError,
};
/** A coded error for `c`; a Transport failure is the native cause itself. */
export function error(c: CoreCode, message: string, cause?: unknown): Error {
  let cls = classes[code(c)];
  if (cls) return new cls(message, { cause });
  return cause instanceof Error ? cause : new Error(message, { cause });
}

export function unwrap<T>(r: Result<T>, cause?: unknown): T {
  if (r.is_Err) throw error(r.dtor_code, string(r.dtor_message), cause);
  return r.dtor_value;
}

// Self-check: the core's primitive vectors through this residue.

export async function selfCheck(): Promise<string[]> {
  let x = new Exchange(null!, new Session(), null!, {}, null); // the vectors never step the core
  let results: CoreEvent[] = [];
  for (let a of ev.SelfCheckActions) results.push((await perform(x, a)) as CoreEvent);
  return Array.from(ev.SelfCheckJudge(Seq.of(...results)), string);
}
