import { Identity } from './identity.js';
import { PROTOCOL } from './protocol.js';
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

  constructor(serverIdentity: Identity, serverHost: string) {
    this.serverIdentity = serverIdentity;
    this.serverHost = serverHost;
  }

  /**
   * Create a new transport by fetching server public key.
   */
  static async create(serverURL: string): Promise<Transport> {
    const { serverIdentity, serverHost } = await Transport.fetchServerIdentity(serverURL);
    return new Transport(serverIdentity, serverHost);
  }

  private static async fetchServerIdentity(
    serverURL: string
  ): Promise<{ serverIdentity: Identity; serverHost: string }> {
    const url = new URL(serverURL);
    const serverHost = url.host;

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

    return { serverIdentity, serverHost };
  }

  private async refreshServerPublicKey(serverURL: string): Promise<void> {
    const { serverIdentity, serverHost } = await Transport.fetchServerIdentity(serverURL);
    this.serverIdentity = serverIdentity;
    this.serverHost = serverHost;
  }

  private static isProblemJSONContentType(contentType: string | null): boolean {
    if (!contentType) {
      return false;
    }
    const mediaType = contentType.split(';', 1)[0]?.trim().toLowerCase() ?? '';
    return mediaType === PROTOCOL.PROBLEM_JSON_MEDIA_TYPE;
  }

  private async isKeyConfigMismatchResponse(
    response: Response
  ): Promise<{ mismatch: boolean; title: string }> {
    if (response.status !== 422) {
      return { mismatch: false, title: '' };
    }

    if (!Transport.isProblemJSONContentType(response.headers.get('content-type'))) {
      return { mismatch: false, title: '' };
    }

    try {
      const problem = (await response.clone().json()) as ProblemDetails;
      if (problem?.type !== PROTOCOL.KEY_CONFIG_PROBLEM_TYPE) {
        return { mismatch: false, title: '' };
      }
      return { mismatch: true, title: typeof problem.title === 'string' ? problem.title : '' };
    } catch {
      return { mismatch: false, title: '' };
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

    const maxConfigRetries = 1;

    for (let attempt = 0; attempt <= maxConfigRetries; attempt++) {
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

      // Make the request
      const response = await fetch(encryptedRequest);

      // Bodyless requests: context is null, response is plaintext
      if (context === null) {
        return response;
      }

      const { mismatch, title } = await this.isKeyConfigMismatchResponse(response);
      if (mismatch) {
        if (attempt < maxConfigRetries) {
          await response.body?.cancel();
          await this.refreshServerPublicKey(url.origin);
          continue;
        }
        throw new Error(
          `Server key configuration mismatch after retry: ${title || 'key configuration mismatch'}`
        );
      }

      // Check for response nonce header (required for response decryption)
      const responseNonceHeader = response.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER);
      if (!responseNonceHeader) {
        throw new Error(`Missing ${PROTOCOL.RESPONSE_NONCE_HEADER} header`);
      }

      // Decrypt response
      return await this.serverIdentity.decryptResponseWithContext(response, context);
    }

    throw new Error('Request failed after key refresh retry');
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
