import { Identity } from './identity.js';
import { extractSessionRecoveryToken, decryptResponseWithToken } from './identity.js';
import type { SessionRecoveryToken } from './identity.js';
import { PROTOCOL } from './protocol.js';
import { forwardedRequestInit } from './request-options.js';
import { InvalidInputError, InvalidKeyConfigError, KeyConfigMismatchError, MissingResponseNonceError } from './errors.js';
import type { Key } from 'hpke';

interface ProblemDetails {
  type?: string;
  title?: string;
}

const MAX_PROBLEM_DETAILS_BYTES = 64 * 1024;

/**
 * HTTP transport for EHBP
 */
/** Headers the library owns; callers cannot set them (mirrors the Python client). */
const RESERVED_REQUEST_HEADERS = [
  'content-length',
  'transfer-encoding',
  'host',
  PROTOCOL.ENCAPSULATED_KEY_HEADER,
  PROTOCOL.RESPONSE_NONCE_HEADER,
];

export class Transport {
  private serverIdentity: Identity;
  private serverHost: string;
  private serverHostname: string;
  /** Explicit port from a host-only configuration; undefined means the scheme default. */
  private serverPort?: string;
  private serverOrigin?: string;
  private _lastSessionRecoveryToken?: SessionRecoveryToken;
  private requestGeneration = 0;

  /** `serverHost` is a host (`example.com:8443`) or an origin (`https://example.com`); an origin also pins the scheme. */
  constructor(serverIdentity: Identity, serverHost: string) {
    this.serverIdentity = serverIdentity;
    this.serverHost = serverHost;
    const originUrl = serverHost.includes('://') ? new URL(serverHost) : undefined;
    if (originUrl && (originUrl.username || originUrl.password)) {
      throw new InvalidInputError('base URL must not include credentials');
    }
    this.serverOrigin = originUrl?.origin;
    // Canonicalize the hostname (lower-case, IDNA) so the comparison in
    // request() is spelling-independent, but keep an explicit port as given:
    // URL would drop ":80" and let "example.com:80" match https on 443.
    const parsed = new URL(`http://${this.serverOrigin ? new URL(this.serverOrigin).host : serverHost}`);
    this.serverHostname = parsed.hostname;
    this.serverPort = /:(\d+)$/.exec(serverHost)?.[1];
  }

  getSessionRecoveryToken(): SessionRecoveryToken {
    if (!this._lastSessionRecoveryToken) {
      throw new Error('No session recovery token available — no request has been made yet');
    }
    return this._lastSessionRecoveryToken;
  }

  /**
   * Create a new transport by fetching server public key.
   * The optional init is applied to the key fetch (e.g. credentials).
   */
  static async create(serverURL: string, init?: RequestInit): Promise<Transport> {
    const url = new URL(serverURL);
    // Same canonical rejection as the constructor and request(), before the
    // key fetch can fail with an uncoded TypeError.
    if (url.username || url.password) {
      throw new InvalidInputError('base URL must not include credentials');
    }

    // Fetch server public key
    const keysURL = new URL(PROTOCOL.KEYS_PATH, serverURL);
    const response = await fetch(keysURL.toString(), init);

    if (!response.ok) {
      throw new InvalidKeyConfigError(`failed to get server public key: status ${response.status}`);
    }

    const contentType = response.headers.get('content-type');
    if (contentType !== PROTOCOL.KEYS_MEDIA_TYPE) {
      throw new InvalidKeyConfigError(`invalid key content type: ${contentType}`);
    }

    const keysData = new Uint8Array(await response.arrayBuffer());
    const serverIdentity = await Identity.unmarshalPublicConfig(keysData);

    return new Transport(serverIdentity, url.origin);
  }

  private static isProblemJSONContentType(contentType: string | null): boolean {
    if (!contentType) {
      return false;
    }
    const mediaType = contentType.split(';', 1)[0]?.trim().toLowerCase() ?? '';
    return mediaType === PROTOCOL.PROBLEM_JSON_MEDIA_TYPE;
  }

  private static async checkKeyConfigMismatch(response: Response): Promise<void> {
    if (response.status !== 422) return;
    if (!Transport.isProblemJSONContentType(response.headers.get('content-type'))) return;

    let problem: ProblemDetails | undefined;
    try {
      const clone = response.clone();
      if (!clone.body) return;

      const reader = clone.body.getReader();
      const chunks: Uint8Array[] = [];
      let length = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.byteLength;
        if (length > MAX_PROBLEM_DETAILS_BYTES) {
          reader.cancel().catch(() => {});
          return;
        }
        chunks.push(value);
      }

      const body = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        body.set(chunk, offset);
        offset += chunk.byteLength;
      }
      problem = JSON.parse(new TextDecoder().decode(body)) as ProblemDetails;
    } catch {
      return; // Not valid JSON — not a key config mismatch
    }
    if (problem?.type === PROTOCOL.KEY_CONFIG_PROBLEM_TYPE) {
      throw new KeyConfigMismatchError(
        typeof problem.title === 'string' ? problem.title : 'key configuration mismatch'
      );
    }
  }

  private static async shouldDecryptResponse(response: Response): Promise<boolean> {
    if (response.headers.has(PROTOCOL.RESPONSE_NONCE_HEADER)) {
      return true;
    }

    await Transport.checkKeyConfigMismatch(response);

    if (!response.ok) {
      return false;
    }

    throw new MissingResponseNonceError(`missing ${PROTOCOL.RESPONSE_NONCE_HEADER} header`);
  }

  /**
   * Get the server identity
   */
  getServerIdentity(): Identity {
    return this.serverIdentity;
  }

  /**
   * Get the server public key
   */
  getServerPublicKey(): Key {
    return this.serverIdentity.getPublicKey();
  }

  /**
   * Get the server public key as hex string
   */
  async getServerPublicKeyHex(): Promise<string> {
    return this.serverIdentity.getPublicKeyHex();
  }

  /**
   * Make an encrypted HTTP request.
   */
  private matchesConfiguredServer(url: URL): boolean {
    if (this.serverOrigin) return url.origin === this.serverOrigin;
    if (url.hostname !== this.serverHostname) return false;
    // url.port is '' for the scheme default; an explicit configured port must
    // match the effective port, and no configured port means the default.
    const effectivePort = url.port || (url.protocol === 'https:' ? '443' : url.protocol === 'http:' ? '80' : '');
    return this.serverPort === undefined ? url.port === '' : effectivePort === this.serverPort;
  }

  async request(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const generation = ++this.requestGeneration;
    this._lastSessionRecoveryToken = undefined;

    // Skip EHBP for non-network URLs (data:, blob:)
    const inputUrl = input instanceof Request ? input.url : String(input);
    if (inputUrl.startsWith('data:') || inputUrl.startsWith('blob:')) {
      return fetch(input, init);
    }
    // Reject credential-bearing URLs with the canonical code before the
    // platform Request constructor rejects them with an uncoded TypeError,
    // so every SDK reports the same error for the same input.
    // Resolve against the configured server so protocol-relative forms
    // ("//user:pass@host/x") are inspected too.
    const credentialed = (() => {
      try {
        const u = new URL(inputUrl, this.serverOrigin ?? `http://${this.serverHost}`);
        return Boolean(u.username || u.password);
      } catch { return false; }
    })();
    if (credentialed) {
      throw new InvalidInputError('request URL must not include credentials');
    }

    // Normalize through the platform Request constructor first so RequestInit
    // overrides a Request input with the same semantics as fetch().
    const normalizedRequest = new Request(input, init);

    // Validate before consuming the body so a rejected request never buffers
    // or waits on a caller-supplied stream.
    const url = new URL(normalizedRequest.url);
    if (!this.matchesConfiguredServer(url)) {
      throw new InvalidInputError(`request URL must use the configured origin: ${this.serverOrigin ?? this.serverHost}`);
    }
    for (const name of RESERVED_REQUEST_HEADERS) {
      if (normalizedRequest.headers.has(name)) {
        throw new InvalidInputError(`reserved request header cannot be set by callers: ${name}`);
      }
    }

    // Hand the body over as a stream where the runtime exposes one so large
    // uploads are sealed frame by frame; Firefox does not expose Request.body
    // even when payload bytes are present, so buffer there.
    let requestBody: BodyInit | null;
    if (normalizedRequest.body) {
      requestBody = normalizedRequest.body;
    } else {
      const requestBodyBytes = await normalizedRequest.arrayBuffer();
      requestBody = requestBodyBytes.byteLength > 0 ? requestBodyBytes : null;
    }

    const request = new Request(url.toString(), {
      ...forwardedRequestInit(normalizedRequest),
      method: normalizedRequest.method,
      headers: normalizedRequest.headers,
      body: requestBody,
      duplex: 'half',
    } as RequestInit);

    // Encrypt request (returns context for response decryption)
    // For bodyless requests, context will be null and request passes through unmodified
    const { request: encryptedRequest, context } =
      await this.serverIdentity.encryptRequestWithContext(request);

    const token = context
      ? await extractSessionRecoveryToken(context)
      : undefined;

    // Bodyless requests: context is null, response is plaintext
    if (!token) {
      return fetch(encryptedRequest);
    }

    // SPEC 6: the token exists once the body is sealed, before it is sent,
    // so a caller can persist it ahead of the response. Anything that ends
    // the exchange without an authenticated response consumes it.
    const clearToken = () => {
      if (this.requestGeneration === generation) {
        this._lastSessionRecoveryToken = undefined;
      }
    };
    if (this.requestGeneration === generation) {
      this._lastSessionRecoveryToken = token;
    }

    let response: Response;
    let shouldDecrypt: boolean;
    try {
      response = await fetch(encryptedRequest);
      shouldDecrypt = await Transport.shouldDecryptResponse(response);
    } catch (err) {
      clearToken();
      throw err;
    }
    if (!shouldDecrypt) {
      clearToken();
      return response;
    }

    try {
      return await decryptResponseWithToken(response, token, clearToken, clearToken);
    } catch (err) {
      clearToken();
      throw err;
    }
  }

  /**
   * Convenience method for GET requests
   */
  async get(url: string | URL, init?: RequestInit): Promise<Response> {
    return this.request(url, { ...init, method: 'GET' });
  }

  /**
   * Convenience method for POST requests
   */
  async post(url: string | URL, body?: BodyInit, init?: RequestInit): Promise<Response> {
    return this.request(url, { ...init, method: 'POST', body });
  }

  /**
   * Convenience method for PUT requests
   */
  async put(url: string | URL, body?: BodyInit, init?: RequestInit): Promise<Response> {
    return this.request(url, { ...init, method: 'PUT', body });
  }

  /**
   * Convenience method for DELETE requests
   */
  async delete(url: string | URL, init?: RequestInit): Promise<Response> {
    return this.request(url, { ...init, method: 'DELETE' });
  }
}

/**
 * Create a new transport instance.
 * The optional init is applied to the server key fetch (e.g. credentials).
 */
export async function createTransport(serverURL: string, init?: RequestInit): Promise<Transport> {
  return Transport.create(serverURL, init);
}
