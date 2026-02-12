import { CipherSuite, type SenderContext, type Key } from 'hpke';
import { KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM } from '@panva/hpke-noble';
import { PROTOCOL, HPKE_CONFIG } from './protocol.js';
import {
  deriveResponseKeys,
  decryptChunk,
  hexToBytes,
  bytesToHex,
  HPKE_REQUEST_INFO,
  EXPORT_LABEL,
  EXPORT_LENGTH,
  RESPONSE_NONCE_LENGTH,
  ResponseKeyMaterial,
} from './derive.js';
import { ProtocolError, DecryptionError } from './errors.js';

/**
 * Request context for response decryption.
 * Holds the HPKE sender context needed to derive response keys.
 */
export interface RequestContext {
  senderContext: SenderContext;
  requestEnc: Uint8Array;
}

/**
 * Creates a new CipherSuite for X25519/HKDF-SHA256/AES-256-GCM
 */
function createSuite(): CipherSuite {
  return new CipherSuite(
    KEM_DHKEM_X25519_HKDF_SHA256,
    KDF_HKDF_SHA256,
    AEAD_AES_256_GCM
  );
}

/**
 * Identity class for managing HPKE key pairs and encryption/decryption
 */
export class Identity {
  private suite: CipherSuite;
  private publicKey: Key;
  private privateKey: Key;

  constructor(suite: CipherSuite, publicKey: Key, privateKey: Key) {
    this.suite = suite;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  /**
   * Generate a new identity with X25519 key pair
   */
  static async generate(): Promise<Identity> {
    const suite = createSuite();
    const { publicKey, privateKey } = await suite.GenerateKeyPair(true); // extractable

    return new Identity(suite, publicKey, privateKey);
  }

  /**
   * Create identity from JSON string
   */
  static async fromJSON(json: string): Promise<Identity> {
    const data = JSON.parse(json);
    const suite = createSuite();

    // Deserialize keys using the suite
    const publicKey = await suite.DeserializePublicKey(new Uint8Array(data.publicKey));
    const privateKey = await suite.DeserializePrivateKey(new Uint8Array(data.privateKey), true);

    return new Identity(suite, publicKey, privateKey);
  }

  /**
   * Convert identity to JSON string
   */
  async toJSON(): Promise<string> {
    const publicKeyBytes = await this.suite.SerializePublicKey(this.publicKey);
    const privateKeyBytes = await this.suite.SerializePrivateKey(this.privateKey);

    return JSON.stringify({
      publicKey: Array.from(publicKeyBytes),
      privateKey: Array.from(privateKeyBytes),
    });
  }

  /**
   * Get public key
   */
  getPublicKey(): Key {
    return this.publicKey;
  }

  /**
   * Get public key as hex string
   */
  async getPublicKeyHex(): Promise<string> {
    const exported = await this.suite.SerializePublicKey(this.publicKey);
    return bytesToHex(exported);
  }

  /**
   * Get private key
   */
  getPrivateKey(): Key {
    return this.privateKey;
  }

  /**
   * Marshal public key configuration for server key distribution
   * Implements RFC 9458 format
   */
  async marshalConfig(): Promise<Uint8Array> {
    const kemId = HPKE_CONFIG.KEM;
    const kdfId = HPKE_CONFIG.KDF;
    const aeadId = HPKE_CONFIG.AEAD;

    // Export public key as raw bytes
    const publicKeyBytes = await this.suite.SerializePublicKey(this.publicKey);

    // Key ID (1 byte) + KEM ID (2 bytes) + Public Key + Cipher Suites
    const keyId = 0;
    const publicKeySize = publicKeyBytes.length;
    const cipherSuitesSize = 2 + 2; // KDF ID + AEAD ID

    const buffer = new Uint8Array(1 + 2 + publicKeySize + 2 + cipherSuitesSize);
    let offset = 0;

    // Key ID
    buffer[offset++] = keyId;

    // KEM ID
    buffer[offset++] = (kemId >> 8) & 0xff;
    buffer[offset++] = kemId & 0xff;

    // Public Key
    buffer.set(publicKeyBytes, offset);
    offset += publicKeySize;

    // Cipher Suites Length (2 bytes)
    buffer[offset++] = (cipherSuitesSize >> 8) & 0xff;
    buffer[offset++] = cipherSuitesSize & 0xff;

    // KDF ID
    buffer[offset++] = (kdfId >> 8) & 0xff;
    buffer[offset++] = kdfId & 0xff;

    // AEAD ID
    buffer[offset++] = (aeadId >> 8) & 0xff;
    buffer[offset++] = aeadId & 0xff;

    return buffer;
  }

  /**
   * Unmarshal public configuration from server
   */
  static async unmarshalPublicConfig(data: Uint8Array): Promise<Identity> {
    let offset = 0;

    // Read Key ID
    const keyId = data[offset++];

    // Read KEM ID
    const kemId = (data[offset++] << 8) | data[offset++];

    // Read Public Key (32 bytes for X25519)
    const publicKeySize = 32;
    const publicKeyBytes = data.slice(offset, offset + publicKeySize);
    offset += publicKeySize;

    // Read Cipher Suites Length
    const cipherSuitesLength = (data[offset++] << 8) | data[offset++];

    // Parse all cipher suites (each suite is 4 bytes: 2 for KDF, 2 for AEAD)
    const suites = [];
    const cipherSuitesEnd = offset + cipherSuitesLength;
    while (offset < cipherSuitesEnd) {
      const kdfId = (data[offset++] << 8) | data[offset++];
      const aeadId = (data[offset++] << 8) | data[offset++];
      suites.push({ kdfId, aeadId });
    }

    if (suites.length === 0) {
      throw new ProtocolError('No cipher suites found in config');
    }

    // Use the first cipher suite
    const firstSuite = suites[0];

    // Validate that we support this cipher suite
    if (firstSuite.kdfId !== HPKE_CONFIG.KDF || firstSuite.aeadId !== HPKE_CONFIG.AEAD) {
      throw new ProtocolError(
        `Unsupported cipher suite: KDF=0x${firstSuite.kdfId.toString(16)}, AEAD=0x${firstSuite.aeadId.toString(16)}`
      );
    }

    return Identity.fromPublicKeyBytes(publicKeyBytes);
  }

  /**
   * Fetch and parse the server's public identity from its HPKE key endpoint.
   *
   * This fetches without out-of-band verification. For production use,
   * make sure this is sufficient or prefer using an attested key.
   */
  static async fetchFromServer(serverURL: string): Promise<Identity> {
    const keysURL = new URL(PROTOCOL.KEYS_PATH, serverURL);
    const response = await fetch(keysURL.toString());
    if (!response.ok) {
      throw new ProtocolError(`Failed to fetch server public key: HTTP ${response.status}`);
    }
    const contentType = response.headers.get('content-type');
    if (contentType !== PROTOCOL.KEYS_MEDIA_TYPE) {
      throw new ProtocolError(
        `Invalid content type from key endpoint: expected "${PROTOCOL.KEYS_MEDIA_TYPE}", got "${contentType}"`
      );
    }
    const keysData = new Uint8Array(await response.arrayBuffer());
    return Identity.unmarshalPublicConfig(keysData);
  }

  /**
   * Create an Identity from a raw public key hex string.
   * Uses the default cipher suite (X25519/HKDF-SHA256/AES-256-GCM).
   *
   * This is used by clients who already have the server's public key
   * and don't need to fetch it.
   */
  static async fromPublicKeyHex(publicKeyHex: string): Promise<Identity> {
    const publicKeyBytes = hexToBytes(publicKeyHex);
    if (publicKeyBytes.length !== 32) {
      throw new ProtocolError(`Invalid public key length: expected 32, got ${publicKeyBytes.length}`);
    }

    return Identity.fromPublicKeyBytes(publicKeyBytes);
  }

  /**
   * Create an Identity from raw public key bytes.
   * Uses the default cipher suite (X25519/HKDF-SHA256/AES-256-GCM).
   *
   * For public-key-only identities (client-side use), we create a placeholder
   * private key that won't be used. TODO: refactor Identity to not require
   * a private key for client-side use.
   */
  private static async fromPublicKeyBytes(publicKeyBytes: Uint8Array): Promise<Identity> {
    const suite = createSuite();
    const publicKey = await suite.DeserializePublicKey(publicKeyBytes);
    const placeholderPrivateKey = await suite.DeserializePrivateKey(new Uint8Array(32), false);

    return new Identity(suite, publicKey, placeholderPrivateKey);
  }

  /**
   * Encrypt request body and return context for response decryption.
   *
   * This method is called on the SERVER's identity (public key only).
   * It:
   * 1. Creates an HPKE sender context to this identity's public key
   * 2. Encrypts the request body
   * 3. Returns a RequestContext that must be used to decrypt the response
   */
  async encryptRequestWithContext(
    request: Request
  ): Promise<{ request: Request; context: RequestContext | null }> {
    const body = await request.arrayBuffer();

    // Bodyless requests pass through unmodified - no HPKE context needed.
    // See SPEC.md Section 5.1: "When the request has no payload body, an encrypted
    // response is not possible (since there is no HPKE context to derive response
    // keys from). Such requests pass through unmodified."
    if (body.byteLength === 0) {
      return {
        request: new Request(request.url, {
          method: request.method,
          headers: request.headers,
          body: null,
        }),
        context: null,
      };
    }

    // Create sender context for encryption with info parameter for domain separation
    const infoBytes = new TextEncoder().encode(HPKE_REQUEST_INFO);
    const { encapsulatedSecret, ctx } = await this.suite.SetupSender(this.publicKey, {
      info: infoBytes,
    });

    // Store context for response decryption
    const context: RequestContext = {
      senderContext: ctx,
      requestEnc: encapsulatedSecret,
    };

    // Set headers - only encapsulated key for requests with body
    const headers = new Headers(request.headers);
    headers.set(PROTOCOL.ENCAPSULATED_KEY_HEADER, bytesToHex(context.requestEnc));

    // Encrypt the body
    const encrypted = await ctx.Seal(new Uint8Array(body));

    // Create chunked format: 4-byte length header + encrypted data
    const chunkLength = new Uint8Array(4);
    new DataView(chunkLength.buffer).setUint32(0, encrypted.byteLength, false);

    const chunkedData = new Uint8Array(4 + encrypted.byteLength);
    chunkedData.set(chunkLength, 0);
    chunkedData.set(encrypted, 4);

    return {
      request: new Request(request.url, {
        method: request.method,
        headers,
        body: chunkedData,
        duplex: 'half',
      } as RequestInit),
      context,
    };
  }

  /**
   * Decrypt response using keys derived from request context.
   *
   * This method:
   * 1. Reads the response nonce from Ehbp-Response-Nonce header
   * 2. Exports a secret from the HPKE sender context
   * 3. Derives response keys using HKDF
   * 4. Decrypts the response body
   */
  async decryptResponseWithContext(
    response: Response,
    context: RequestContext
  ): Promise<Response> {
    if (!response.body) {
      return response;
    }

    // Get response nonce from header
    const responseNonceHex = response.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER);
    if (!responseNonceHex) {
      throw new ProtocolError(`Missing ${PROTOCOL.RESPONSE_NONCE_HEADER} header`);
    }

    const responseNonce = hexToBytes(responseNonceHex);
    if (responseNonce.length !== RESPONSE_NONCE_LENGTH) {
      throw new ProtocolError(
        `Invalid response nonce length: expected ${RESPONSE_NONCE_LENGTH}, got ${responseNonce.length}`
      );
    }

    // Export secret from request context
    const exportLabelBytes = new TextEncoder().encode(EXPORT_LABEL);
    const exportedSecret = await context.senderContext.Export(exportLabelBytes, EXPORT_LENGTH);

    // Derive response keys
    const km = await deriveResponseKeys(exportedSecret, context.requestEnc, responseNonce);

    // Create decrypting stream
    const decryptedStream = this.createDecryptStream(response.body, km);

    return new Response(decryptedStream, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  }

  /**
   * Creates a ReadableStream that decrypts response chunks.
   */
  private createDecryptStream(
    body: ReadableStream<Uint8Array>,
    km: ResponseKeyMaterial
  ): ReadableStream<Uint8Array> {
    let buffer = new Uint8Array(0);
    let seq = 0;
    const reader = body.getReader();

    return new ReadableStream({
      async pull(controller) {
        while (true) {
          // Try to read a complete chunk from buffer
          if (buffer.length >= 4) {
            const chunkLength =
              (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];

            if (chunkLength === 0) {
              // Skip empty chunk
              buffer = buffer.slice(4);
              continue;
            }

            if (buffer.length >= 4 + chunkLength) {
              const ciphertext = buffer.slice(4, 4 + chunkLength);
              buffer = buffer.slice(4 + chunkLength);

              try {
                const plaintext = await decryptChunk(km, seq++, ciphertext);
                controller.enqueue(plaintext);
                return;
              } catch (error) {
                controller.error(new DecryptionError(
                  `Decryption failed at chunk ${seq - 1}`,
                  { cause: error }
                ));
                return;
              }
            }
          }

          // Need more data
          const { done, value } = await reader.read();
          if (done) {
            controller.close();
            return;
          }

          // Append to buffer
          const newBuffer = new Uint8Array(buffer.length + value.length);
          newBuffer.set(buffer);
          newBuffer.set(value, buffer.length);
          buffer = newBuffer;
        }
      },
      cancel(reason) {
        // Release the underlying reader when the stream is cancelled
        return reader.cancel(reason);
      },
    });
  }
}
