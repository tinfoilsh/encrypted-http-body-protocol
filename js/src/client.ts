import { Identity } from './identity.js';
import { PROTOCOL } from './protocol.js';

/**
 * HTTP transport for EHBP
 */
export class Transport {
  private serverIdentity: Identity;
  private serverHost: string;

  constructor(serverIdentity: Identity, serverHost: string) {
    this.serverIdentity = serverIdentity;
    this.serverHost = serverHost;
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

  /**
   * Get the server identity
   */
  getServerIdentity(): Identity {
    return this.serverIdentity;
  }

  /**
   * Get the server public key
   */
  getServerPublicKey(): CryptoKey {
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

    let request = new Request(url.toString(), {
      method,
      headers,
      body: requestBody,
      duplex: 'half',
    } as RequestInit);

    // Encrypt request (returns context for response decryption)
    // For bodyless requests, context will be null and request passes through unmodified
    const { request: encryptedRequest, context } =
      await this.serverIdentity.encryptRequestWithContext(request);

    // Make the request
    const response = await fetch(encryptedRequest);

    if (!response.ok) {
      console.warn(`Server returned non-OK status: ${response.status}`);
    }

    // Bodyless requests: context is null, response is plaintext
    if (context === null) {
      return response;
    }

    // Check for fallback header - if set, server returned unencrypted response
    const fallbackHeader = response.headers.get(PROTOCOL.FALLBACK_HEADER);
    if (fallbackHeader === '1') {
      return response;
    }

    // Check for response nonce header (required for derived key decryption)
    const responseNonceHeader = response.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER);
    if (!responseNonceHeader) {
      throw new Error(`Missing ${PROTOCOL.RESPONSE_NONCE_HEADER} header`);
    }

    // Decrypt response using derived keys
    return await this.serverIdentity.decryptResponseWithContext(response, context);
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
