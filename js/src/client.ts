import { Identity } from './identity.js';
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
   * Make an encrypted HTTP request
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
      duplex: 'half'
    } as RequestInit);

    // Encrypt request body if present (check the original requestBody, not request.body)
    if (requestBody !== null && requestBody !== undefined) {
      request = await this.clientIdentity.encryptRequest(request, this.serverPublicKey);
    } else {
      // No body, just set client public key header
      const headers = new Headers(request.headers);
      headers.set(PROTOCOL.CLIENT_PUBLIC_KEY_HEADER, await this.clientIdentity.getPublicKeyHex());
      request = new Request(request.url, {
        method: request.method,
        headers,
        body: null
      });
    }

    // Make the request
    const response = await fetch(request);

    if (!response.ok) {
      console.warn(`Server returned non-OK status: ${response.status}`);
    }

    // Check for fallback header - if set, server returned unencrypted response
    const fallbackHeader = response.headers.get(PROTOCOL.FALLBACK_HEADER);
    if (fallbackHeader === '1') {
      return response;
    }

    // Check for encapsulated key header
    const encapKeyHeader = response.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER);
    if (!encapKeyHeader) {
      throw new Error(`Missing ${PROTOCOL.ENCAPSULATED_KEY_HEADER} encapsulated key header`);
    }

    // Validate hex encoding
    if (!/^[0-9a-fA-F]+$/.test(encapKeyHeader) || encapKeyHeader.length % 2 !== 0) {
      throw new Error(`Invalid ${PROTOCOL.ENCAPSULATED_KEY_HEADER} header: must be valid hex string with even length`);
    }

    // Decode encapsulated key
    const serverEncapKey = new Uint8Array(
      encapKeyHeader.match(/.{2}/g)!.map(byte => parseInt(byte, 16))
    );

    // Decrypt response
    return await this.clientIdentity.decryptResponse(response, serverEncapKey);
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
