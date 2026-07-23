import { Identity } from './identity.js';
import { extractSessionRecoveryToken, decryptResponseWithToken } from './identity.js';
import type { SessionRecoveryToken } from './identity.js';
import { PROTOCOL } from './protocol.js';
import { forwardedRequestInit } from './request-options.js';
import { KeyConfigMismatchError, ProtocolError } from './errors.js';
import type { Key } from 'hpke';

interface ProblemDetails {
  type?: string;
  title?: string;
}

const MAX_PROBLEM_DETAILS_BYTES = 64 * 1024;

/**
 * HTTP transport for EHBP
 */
export class Transport {
  private serverIdentity: Identity;
  private serverHost: string;
  private _lastSessionRecoveryToken?: SessionRecoveryToken;
  private requestGeneration = 0;

  constructor(serverIdentity: Identity, serverHost: string) {
    this.serverIdentity = serverIdentity;
    this.serverHost = serverHost;
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
    const serverHost = url.host;

    // Fetch server public key
    const keysURL = new URL(PROTOCOL.KEYS_PATH, serverURL);
    const response = await fetch(keysURL.toString(), init);

    if (!response.ok) {
      throw new Error(`Failed to get server public key: ${response.status}`);
    }

    const contentType = response.headers.get('content-type');
    if (contentType !== PROTOCOL.KEYS_MEDIA_TYPE) {
      throw new Error(`Invalid content type: ${contentType}`);
    }

    const keysData = new Uint8Array(await response.arrayBuffer());
    const serverIdentity = await Identity.unmarshalPublicConfig(keysData);

    return new Transport(serverIdentity, serverHost);
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
        typeof problem.title === 'string' ? problem.title : undefined
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

    throw new ProtocolError(`Missing ${PROTOCOL.RESPONSE_NONCE_HEADER} header`);
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
  async request(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const generation = ++this.requestGeneration;
    this._lastSessionRecoveryToken = undefined;

    // Skip EHBP for non-network URLs (data:, blob:)
    const inputUrl = input instanceof Request ? input.url : String(input);
    if (inputUrl.startsWith('data:') || inputUrl.startsWith('blob:')) {
      return fetch(input, init);
    }

    // Normalize through the platform Request constructor first so RequestInit
    // overrides a Request input with the same semantics as fetch().
    const normalizedRequest = new Request(input, init);
    const requestBody = normalizedRequest.body
      ? await normalizedRequest.arrayBuffer()
      : null;

    const url = new URL(normalizedRequest.url);
    url.host = this.serverHost;

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

    // Make the request
    const response = await fetch(encryptedRequest);

    // Bodyless requests: context is null, response is plaintext
    if (!token) {
      return response;
    }

    const shouldDecrypt = await Transport.shouldDecryptResponse(response);
    if (!shouldDecrypt) {
      return response;
    }

    // Decrypt response using the already-extracted token
    let streamTerminated = false;
    const clearToken = () => {
      streamTerminated = true;
      if (this.requestGeneration === generation) {
        this._lastSessionRecoveryToken = undefined;
      }
    };
    const decryptedResponse = await decryptResponseWithToken(
      response,
      token,
      clearToken,
      clearToken,
    );

    // Publish token only after confirming the response is valid
    if (this.requestGeneration === generation) {
      this._lastSessionRecoveryToken = streamTerminated ? undefined : token;
    }
    return decryptedResponse;
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
