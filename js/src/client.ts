import { Identity } from './identity.js';
import { extractSessionRecoveryToken, decryptResponseWithToken } from './identity.js';
import type { SessionRecoveryToken } from './identity.js';
import { PROTOCOL } from './protocol.js';
import { KeyConfigMismatchError, ProtocolError } from './errors.js';
import type { Key } from 'hpke';

interface ProblemDetails {
  type?: string;
  title?: string;
}

/**
 * HTTP transport for EHBP
 */
export class Transport {
  private serverIdentity: Identity;
  private serverHost: string;
  private _lastSessionRecoveryToken?: SessionRecoveryToken;

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
   */
  static async create(serverURL: string): Promise<Transport> {
    const url = new URL(serverURL);
    const serverHost = url.host;

    // Fetch server public key
    const keysURL = new URL(PROTOCOL.KEYS_PATH, serverURL);
    const response = await fetch(keysURL.toString());

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
      problem = (await response.clone().json()) as ProblemDetails;
    } catch {
      return; // Not valid JSON — not a key config mismatch
    }
    if (problem?.type === PROTOCOL.KEY_CONFIG_PROBLEM_TYPE) {
      throw new KeyConfigMismatchError(
        typeof problem.title === 'string' ? problem.title : undefined
      );
    }
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
    // Skip EHBP for non-network URLs (data:, blob:)
    const inputUrl = input instanceof Request ? input.url : String(input);
    if (inputUrl.startsWith('data:') || inputUrl.startsWith('blob:')) {
      return fetch(input, init);
    }

    // Extract body from init or original request before creating Request object
    let requestBody: BodyInit | null = null;

    if (input instanceof Request) {
      // If input is a Request, extract its body
      if (input.body) {
        requestBody = await input.arrayBuffer();
      }
    } else {
      // If input is URL/string, get body from init
      requestBody = init?.body || null;
    }

    // Create the URL with correct host
    let url: URL;
    let method: string;
    let headers: HeadersInit;

    if (input instanceof Request) {
      url = new URL(input.url);
      method = input.method;
      headers = input.headers;
    } else {
      url = new URL(input);
      method = init?.method || 'GET';
      headers = init?.headers || {};
    }

    url.host = this.serverHost;

    const request = new Request(url.toString(), {
      method,
      headers,
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
      this._lastSessionRecoveryToken = undefined;
      return response;
    }

    // Throws KeyConfigMismatchError if server returned 422 key-config mismatch
    await Transport.checkKeyConfigMismatch(response);

    // Check for response nonce header (required for response decryption)
    const responseNonceHeader = response.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER);
    if (!responseNonceHeader) {
      throw new ProtocolError(`Missing ${PROTOCOL.RESPONSE_NONCE_HEADER} header`);
    }

    // Publish token only after confirming the response is valid
    this._lastSessionRecoveryToken = token;

    // Decrypt response using the already-extracted token
    return await decryptResponseWithToken(response, token);
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
 */
export async function createTransport(serverURL: string): Promise<Transport> {
  return Transport.create(serverURL);
}
