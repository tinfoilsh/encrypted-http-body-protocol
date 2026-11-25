// The JavaScript API shim over the event-driven EHBP core (dafny/ehbp_events.dfy):
// fetch-shaped calls in, every exchange driven by residue.ts's pump, the
// core's outcome back out as a Response. Every protocol decision is the core's.
// The surface is conformance/spec/handler.md section 7 and nothing else.
import { type State, EHBP, EHBPEvents, EMPTY, Event, Token, core, ev, int } from './core.js';
import { Exchange, Session, bytes, decrypted, feed, headerSeq, originOf, prefixed, seq, str, string, unwrap } from './residue.js';
import { canStreamUpload } from './spool.js';
import { InvalidInputError } from './errors.js';
import type { SessionRecoveryToken } from './identity.js';
import { forwardedRequestInit } from './request-options.js';

/** Native transport options. */
export interface TransportOptions {
  /**
   * Fetch-compatible implementation for all network I/O, including key
   * discovery. Called with no `this`. Defaults to global fetch. See the
   * README's "Custom network transport" section.
   */
  fetch?: typeof fetch;
  /** Applied to the key discovery fetch only (e.g. credentials). */
  discoverInit?: RequestInit;
}

const fetchOf = (options: TransportOptions): typeof fetch => {
  const send = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  return (input, init) => send(input, init);
};

/**
 * The browser spool hook: where uploads cannot stream, a stream or Blob must
 * not reach the Request constructor (Firefox stringifies a stream), so it is
 * kept aside as the exchange's source and `init` loses its body.
 */
function divert(input: RequestInfo | URL, init: RequestInit | undefined, hasInitBody: boolean): [RequestInit | undefined, ReadableStream<Uint8Array> | Blob | undefined] {
  if (canStreamUpload() || !hasInitBody || !(init!.body instanceof ReadableStream || init!.body instanceof Blob)) return [init, undefined];
  const diverted = init!.body as ReadableStream<Uint8Array> | Blob;
  const headers = new Headers(init!.headers ?? (input instanceof Request ? input.headers : undefined));
  if (diverted instanceof Blob && diverted.type && !headers.has('content-type')) headers.set('content-type', diverted.type);
  return [{ ...init, body: null, headers }, diverted];
}

/** Decrypts a response from a SessionRecoveryToken alone (SPEC 6.2); exported through `core` for conformance and tests. */
export async function decryptWithToken(response: Response, token: SessionRecoveryToken): Promise<Response> {
  const { Phase, Upload, Response: Resp } = EHBPEvents;
  const s = ev.Initial(unwrap(core.MakeOrigin(str('https'), str('localhost'), EHBP.Option.create_None(), false)), seq(EMPTY)); // the response lane never reads the origin
  const state: State = EHBPEvents.State.create_State(Phase.create_Exchanging(Upload.create_NoUpload(), Resp.create_AwaitHead(true)),
    s.dtor_origin, s.dtor_publicKey, s.dtor_verb, s.dtor_url, s.dtor_headers, s.dtor_generation, false,
    Token.create_Token(seq(token.exportedSecret), seq(token.requestEnc)), s.dtor_ctx);
  const x = new Exchange(state, new Session(), null!, {}, null); // nothing is sent
  x.response = response;
  return outcome(x, Event.create_ResponseHead(int(response.status), headerSeq(response.headers), false));
}

// constructor: a Transport over one server origin and the key a KeySource yields.

/** The server's key, already resolved: an RFC 9458 key configuration or a 32-byte public key. */
export type ResolvedKeys = { config: Uint8Array } | { publicKey: Uint8Array };
/** `keys` for Transport.create: `discover` fetches `/.well-known/hpke-keys` (SPEC 3.1). */
export type KeySource = ResolvedKeys | { discover: true };

/** The native Response for an outcome: the stack's own when its body is untouched, else a rebuilt one over the exchange. */
async function outcome(x: Exchange, first: Event): Promise<Response> {
  await feed(x, first);
  if (x.failure) throw x.failure;
  const native = x.response!;
  const init = { status: native.status, statusText: native.statusText };
  if (x.passthrough && x.prefix.length === 0) return native;
  if (x.passthrough) return new Response(prefixed(x), { ...init, headers: native.headers });
  if (x.done) return new Response(decrypted(x), { ...init, headers: x.headers });
  throw new Error('exchange ended without an outcome');
}

// discover: the same discovery the constructor runs; the 32-byte public key.

/** The same discovery Transport.create runs (SPEC 3.1), for callers that cache keys: the server's 32-byte public key. */
export async function discover(server: string, options: TransportOptions = {}): Promise<Uint8Array> {
  const x = new Exchange(ev.Initial(unwrap(originOf(server)), seq(EMPTY)), new Session(), fetchOf(options), { ...options.discoverInit }, null);
  await feed(x, Event.create_DiscoverStart());
  if (x.failure) throw x.failure;
  return x.publicKey!;
}

export class Transport {
  private readonly fetchImpl: typeof fetch;
  private readonly origin;
  private readonly publicKey: Uint8Array;
  private readonly session = new Session();

  /** `server` is the http(s) origin every request must target (`https://example.com`); `keys` must already be resolved (see `create`). */
  constructor(server: string, keys: ResolvedKeys, options: TransportOptions = {}) {
    this.fetchImpl = fetchOf(options);
    this.origin = unwrap(originOf(server));
    this.publicKey = 'config' in keys ? bytes(unwrap(core.ParseConfig(seq(keys.config)))) : bytes(unwrap(core.CheckPublicKey(seq(keys.publicKey))));
  }

  /** The constructor path for every key source; `{ discover: true }` fetches the server's key configuration first. */
  static async create(server: string, keys: KeySource, options: TransportOptions = {}): Promise<Transport> {
    return new Transport(server, 'discover' in keys ? { publicKey: await discover(server, options) } : keys, options);
  }

  // token: the exchange in flight.

  /** The token of the exchange in flight (SPEC 6), or undefined. */
  sessionRecoveryToken(): SessionRecoveryToken | undefined {
    const t = this.session.token();
    return t && { exportedSecret: bytes(t.dtor_exportedSecret), requestEnc: bytes(t.dtor_requestEnc) };
  }

  // request: the one entry point with fetch() semantics; the verbs are one-line wrappers.

  /** One encrypted exchange with fetch() semantics for `input` and `init`. */
  async request(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const inputUrl = input instanceof Request ? input.url : String(input);
    // Non-network URLs skip EHBP and reach the fetch implementation as given.
    if (inputUrl.startsWith('data:') || inputUrl.startsWith('blob:')) return this.fetchImpl(input, init);
    const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    const hasInitBody = init?.body !== undefined && init?.body !== null;
    // The platform would reject this later with an uncoded TypeError, after the body was touched.
    if ((method === 'GET' || method === 'HEAD') && hasInitBody) throw new InvalidInputError(`request with ${method} method cannot have a body`);
    let diverted: ReadableStream<Uint8Array> | Blob | undefined;
    [init, diverted] = divert(input, init, hasInitBody);
    // The URL and headers exactly as fetch() would combine them, validated by the
    // core before the platform Request constructor can reject credentials uncoded
    // or a caller-supplied stream is touched.
    const u = new URL(inputUrl, string(core.OriginUrl(this.origin)));
    const headers = init?.headers !== undefined ? new Headers(init.headers) : input instanceof Request ? input.headers : new Headers();
    unwrap(core.ValidateRequest(this.origin, originOf(u.href), headerSeq(headers)));
    const normalized = new Request(input, init);
    const template = forwardedRequestInit(normalized);
    // Firefox does not expose Request.body even when payload bytes are present; buffer there.
    const source = diverted ?? normalized.body ?? new Blob([await normalized.arrayBuffer()]).stream();
    const start = Event.create_Start(str(normalized.method), str(u.href), str(u.protocol.slice(0, -1)), str(u.hostname),
      int(u.port ? Number(u.port) : 0), u.port !== '', Boolean(u.username || u.password), headerSeq(normalized.headers), true);
    const exchange = (body: ReadableStream<Uint8Array> | Blob, memoryOnly = false) =>
      new Exchange(ev.Initial(this.origin, seq(this.publicKey)), this.session, this.fetchImpl, template,
        body instanceof Blob ? body.stream() : body, body instanceof Blob ? body.size : undefined, memoryOnly);
    const x = exchange(source);
    try {
      return await outcome(x, start);
    } catch (err) {
      // A Blob can be re-read: seal it again under a fresh context into memory when the browser spool failed.
      if (!(diverted instanceof Blob) || !x.spoolFailed) throw err;
      return outcome(exchange(diverted, true), start);
    }
  }

  get(url: string | URL, init?: RequestInit): Promise<Response> { return this.request(url, { ...init, method: 'GET' }); }
  post(url: string | URL, body?: BodyInit, init?: RequestInit): Promise<Response> { return this.request(url, { ...init, method: 'POST', body }); }
  put(url: string | URL, body?: BodyInit, init?: RequestInit): Promise<Response> { return this.request(url, { ...init, method: 'PUT', body }); }
  delete(url: string | URL, init?: RequestInit): Promise<Response> { return this.request(url, { ...init, method: 'DELETE' }); }
}

// selfCheck: the core's primitive vectors through this residue.
export { selfCheck } from './residue.js';
