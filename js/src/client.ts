import { Identity, RequestContext } from './identity.js';
import { PROTOCOL } from './protocol.js';

/**
 * HTTP transport for EHBP v2
 *
 * This transport uses the v2 protocol which derives response encryption keys
 * from the HPKE shared secret, preventing MitM key substitution attacks.
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
   * Make an encrypted HTTP request using v2 protocol.
   *
   * V2 protocol uses derived keys for response encryption, preventing
   * MitM key substitution attacks that were possible in v1.
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

    // Encrypt request using v2 protocol (returns context for response decryption)
    const { request: encryptedRequest, context } =
      await this.clientIdentity.encryptRequestWithContext(request, this.serverPublicKey);

    // Make the request
    const response = await fetch(encryptedRequest);

    if (!response.ok) {
      console.warn(`Server returned non-OK status: ${response.status}`);
    }

    // Check for fallback header - if set, server returned unencrypted response
    const fallbackHeader = response.headers.get(PROTOCOL.FALLBACK_HEADER);
    if (fallbackHeader === '1') {
      return response;
    }

    // V2: Check for response nonce header (derived key response)
    const responseNonceHeader = response.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER);
    if (!responseNonceHeader) {
      throw new Error(`Missing ${PROTOCOL.RESPONSE_NONCE_HEADER} header`);
    }

    // Decrypt response using derived keys (v2)
    return await this.clientIdentity.decryptResponseWithContext(response, context);
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
 * Create a new transport instance
 */
export async function createTransport(serverURL: string, clientIdentity: Identity): Promise<Transport> {
  return Transport.create(serverURL, clientIdentity);
}
