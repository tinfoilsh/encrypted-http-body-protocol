import { Identity, RequestContext } from './identity.js';
import { PROTOCOL } from './protocol.js';

/**
 * HTTP transport for EHBP
 */
export class Transport {
  private clientIdentity: Identity;
  private serverHost: string;
  private serverPublicKey: CryptoKey;

  constructor(clientIdentity: Identity, serverHost: string, serverPublicKey: CryptoKey) {
    this.clientIdentity = clientIdentity;
    this.serverHost = serverHost;
    this.serverPublicKey = serverPublicKey;
  }

  /**
   * Create a new transport by fetching server public key
   */
  static async create(serverURL: string, clientIdentity: Identity): Promise<Transport> {
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
    const serverPublicKey = serverIdentity.getPublicKey();

    return new Transport(clientIdentity, serverHost, serverPublicKey);
  }

  /**
   * Get the server public key
   */
  getServerPublicKey(): CryptoKey {
    return this.serverPublicKey;
  }

  /**
   * Get the server public key as hex string
   */
  async getServerPublicKeyHex(): Promise<string> {
    const exported = await crypto.subtle.exportKey('raw', this.serverPublicKey);
    const keyBytes = new Uint8Array(exported);
    return Array.from(keyBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Get the client public key
   */
  getClientPublicKey(): CryptoKey {
    return this.clientIdentity.getPublicKey();
  }

  /**
   * Make an encrypted HTTP request.
   * EHBP requires a request body for bidirectional encryption.
   * @throws Error if request has no body (e.g., GET requests)
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
      if (input.body) {
        requestBody = await input.arrayBuffer();
      }
    } else {
      requestBody = init?.body || null;
    }

    // EHBP requires a body for bidirectional encryption
    if (requestBody === null || requestBody === undefined) {
      throw new Error('EHBP requires a request body; GET requests are not supported');
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
      method = init?.method || 'POST';
      headers = init?.headers || {};
    }

    url.host = this.serverHost;

    const baseRequest = new Request(url.toString(), {
      method,
      headers,
      body: requestBody,
      duplex: 'half'
    } as RequestInit);

    const { request, context: reqContext } = await this.clientIdentity.encryptRequest(
      baseRequest,
      this.serverPublicKey
    );

    const response = await fetch(request);

    if (!response.ok) {
      console.warn(`Server returned non-OK status: ${response.status}`);
    }

    // Check for fallback header - if set, server returned unencrypted response
    const fallbackHeader = response.headers.get(PROTOCOL.FALLBACK_HEADER);
    if (fallbackHeader === '1') {
      return response;
    }

    // Decrypt response using key derived from request context
    return await this.clientIdentity.decryptResponse(response, reqContext);
  }

  /**
   * Convenience method for POST requests
   */
  async post(url: string | URL, body: BodyInit, init?: RequestInit): Promise<Response> {
    return this.request(url, { ...init, method: 'POST', body });
  }

  /**
   * Convenience method for PUT requests
   */
  async put(url: string | URL, body: BodyInit, init?: RequestInit): Promise<Response> {
    return this.request(url, { ...init, method: 'PUT', body });
  }

  /**
   * Convenience method for PATCH requests
   */
  async patch(url: string | URL, body: BodyInit, init?: RequestInit): Promise<Response> {
    return this.request(url, { ...init, method: 'PATCH', body });
  }
}

/**
 * Create a new transport instance
 */
export async function createTransport(serverURL: string, clientIdentity: Identity): Promise<Transport> {
  return Transport.create(serverURL, clientIdentity);
}
