import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm, SenderContext } from '@hpke/core';
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

/**
 * Request context for response decryption.
 * Holds the HPKE sender context needed to derive response keys.
 */
export interface RequestContext {
  senderContext: SenderContext;
  requestEnc: Uint8Array;
}

/**
 * Identity class for managing HPKE key pairs and encryption/decryption
 */
export class Identity {
  private suite: CipherSuite;
  private publicKey: CryptoKey;
  private privateKey: CryptoKey;

  constructor(suite: CipherSuite, publicKey: CryptoKey, privateKey: CryptoKey) {
    this.suite = suite;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  /**
   * Generate a new identity with X25519 key pair
   */
  static async generate(): Promise<Identity> {
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm()
    });

    const { publicKey, privateKey } = await suite.kem.generateKeyPair();
    
    // Make sure the public key is extractable for serialization
    const extractablePublicKey = await crypto.subtle.importKey(
      'raw',
      await crypto.subtle.exportKey('raw', publicKey),
      { name: 'X25519' },
      true, // extractable
      []
    );
    
    return new Identity(suite, extractablePublicKey, privateKey);
  }


  /**
   * Create identity from JSON string
   */
  static async fromJSON(json: string): Promise<Identity> {
    const data = JSON.parse(json);
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm()
    });

    // Import public key
    const publicKey = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(data.publicKey),
      { name: 'X25519' },
      true, // extractable
      []
    );

    // Deserialize private key using HPKE library
    const privateKey = await suite.kem.deserializePrivateKey(new Uint8Array(data.privateKey).buffer);

    return new Identity(suite, publicKey, privateKey);
  }


  /**
   * Convert identity to JSON string
   */
  async toJSON(): Promise<string> {
    const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', this.publicKey));
    
    // For X25519, we need to use the HPKE library's serialization for private keys
    const privateKeyBytes = await this.suite.kem.serializePrivateKey(this.privateKey);
    
    return JSON.stringify({
      publicKey: Array.from(publicKeyBytes),
      privateKey: Array.from(new Uint8Array(privateKeyBytes))
    });
  }

  /**
   * Get public key as CryptoKey
   */
  getPublicKey(): CryptoKey {
    return this.publicKey;
  }

  /**
   * Get public key as hex string
   */
  async getPublicKeyHex(): Promise<string> {
    const exported = await crypto.subtle.exportKey('raw', this.publicKey);
    return Array.from(new Uint8Array(exported))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Get private key as CryptoKey
   */
  getPrivateKey(): CryptoKey {
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
    const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', this.publicKey));

    // Key ID (1 byte) + KEM ID (2 bytes) + Public Key + Cipher Suites
    const keyId = 0;
    const publicKeySize = publicKeyBytes.length;
    const cipherSuitesSize = 2 + 2; // KDF ID + AEAD ID

    const buffer = new Uint8Array(1 + 2 + publicKeySize + 2 + cipherSuitesSize);
    let offset = 0;

    // Key ID
    buffer[offset++] = keyId;

    // KEM ID
    buffer[offset++] = (kemId >> 8) & 0xFF;
    buffer[offset++] = kemId & 0xFF;

    // Public Key
    buffer.set(publicKeyBytes, offset);
    offset += publicKeySize;

    // Cipher Suites Length (2 bytes)
    buffer[offset++] = (cipherSuitesSize >> 8) & 0xFF;
    buffer[offset++] = cipherSuitesSize & 0xFF;

    // KDF ID
    buffer[offset++] = (kdfId >> 8) & 0xFF;
    buffer[offset++] = kdfId & 0xFF;

    // AEAD ID
    buffer[offset++] = (aeadId >> 8) & 0xFF;
    buffer[offset++] = aeadId & 0xFF;

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
      throw new Error('No cipher suites found in config');
    }

    // Use the first cipher suite
    const firstSuite = suites[0];

    // Validate that we support this cipher suite
    if (firstSuite.kdfId !== HPKE_CONFIG.KDF || firstSuite.aeadId !== HPKE_CONFIG.AEAD) {
      throw new Error(`Unsupported cipher suite: KDF=0x${firstSuite.kdfId.toString(16)}, AEAD=0x${firstSuite.aeadId.toString(16)}`);
    }

    // Create cipher suite (currently only supports X25519/HKDF-SHA256/AES-256-GCM)
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm()
    });

    // Import public key using HPKE library
    const publicKey = await suite.kem.deserializePublicKey(publicKeyBytes.buffer);

    // For server config, we only have the public key, no private key
    // We'll create a dummy private key that won't be used
    const dummyPrivateKey = await suite.kem.deserializePrivateKey(new Uint8Array(32).buffer);
    
    return new Identity(suite, publicKey, dummyPrivateKey);
  }

  /**
   * Encrypt request body and set appropriate headers
   */
  async encryptRequest(request: Request, serverPublicKey: CryptoKey): Promise<Request> {
    const body = await request.arrayBuffer();
    if (body.byteLength === 0) {
      // No body to encrypt, just set client public key header
      const headers = new Headers(request.headers);
      headers.set(PROTOCOL.CLIENT_PUBLIC_KEY_HEADER, await this.getPublicKeyHex());
      return new Request(request.url, {
        method: request.method,
        headers,
        body: null
      });
    }

    // Create sender for encryption
    const sender = await this.suite.createSenderContext({
      recipientPublicKey: serverPublicKey
    });

    // Encrypt the body
    const encrypted = await sender.seal(body);

    // Get encapsulated key
    const encapKey = sender.enc;

    // Create chunked format: 4-byte length header + encrypted data
    const chunkLength = new Uint8Array(4);
    const view = new DataView(chunkLength.buffer);
    view.setUint32(0, encrypted.byteLength, false); // Big-endian
    
    const chunkedData = new Uint8Array(4 + encrypted.byteLength);
    chunkedData.set(chunkLength, 0);
    chunkedData.set(new Uint8Array(encrypted), 4);

    // Create new request with encrypted body and headers
    const headers = new Headers(request.headers);
    headers.set(PROTOCOL.CLIENT_PUBLIC_KEY_HEADER, await this.getPublicKeyHex());
    headers.set(PROTOCOL.ENCAPSULATED_KEY_HEADER, Array.from(new Uint8Array(encapKey))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(''));

    return new Request(request.url, {
      method: request.method,
      headers,
      body: chunkedData,
      duplex: 'half'
    } as RequestInit);
  }

  /**
   * Decrypt response body
   * @deprecated Use decryptResponseWithContext instead
   */
  async decryptResponse(response: Response, serverEncapKey: Uint8Array): Promise<Response> {
    if (!response.body) {
      return response;
    }

    // Create receiver for decryption
    const receiver = await this.suite.createRecipientContext({
      recipientKey: this.privateKey,
      enc: serverEncapKey.buffer as ArrayBuffer
    });

    // Create a readable stream that decrypts chunks as they arrive
    const decryptedStream = new ReadableStream({
      start(controller) {
        const reader = response.body!.getReader();
        let buffer = new Uint8Array(0);
        let offset = 0;

        async function pump() {
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;

              // Append new data to buffer
              const newBuffer = new Uint8Array(buffer.length + value.length);
              newBuffer.set(buffer);
              newBuffer.set(value, buffer.length);
              buffer = newBuffer;

              // Process complete chunks
              while (offset + 4 <= buffer.length) {
                // Read chunk length (4 bytes big-endian)
                const chunkLength = (buffer[offset] << 24) |
                                  (buffer[offset + 1] << 16) |
                                  (buffer[offset + 2] << 8) |
                                  buffer[offset + 3];
                offset += 4;

                if (chunkLength === 0) {
                  continue; // Empty chunk
                }

                // Check if we have the complete chunk
                if (offset + chunkLength > buffer.length) {
                  // Not enough data yet, rewind offset and wait for more
                  offset -= 4;
                  break;
                }

                // Extract and decrypt the chunk
                const encryptedChunk = buffer.slice(offset, offset + chunkLength);
                offset += chunkLength;

                try {
                  const decryptedChunk = await receiver.open(encryptedChunk.buffer);
                  controller.enqueue(new Uint8Array(decryptedChunk));
                } catch (error) {
                  controller.error(new Error(`Failed to decrypt chunk: ${error}`));
                  return;
                }
              }

              // Remove processed data from buffer
              if (offset > 0) {
                buffer = buffer.slice(offset);
                offset = 0;
              }
            }

            controller.close();
          } catch (error) {
            controller.error(error);
          }
        }

        pump();
      }
    });

    // Create new response with decrypted stream
    return new Response(decryptedStream, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    });
  }

  // ===========================================================================
  // Derived Key Methods - Use derived keys for response encryption
  // ===========================================================================

  /**
   * Encrypt request body and return context for response decryption.
   *
   * This method is called on the SERVER's identity (public key only).
   * It:
   * 1. Creates an HPKE sender context to this identity's public key
   * 2. Encrypts the request body
   * 3. Returns a RequestContext that must be used to decrypt the response
   *
   * IMPORTANT: Do NOT send Ehbp-Client-Public-Key header (vulnerable to MitM)
   */
  async encryptRequestWithContext(
    request: Request
  ): Promise<{ request: Request; context: RequestContext }> {
    const body = await request.arrayBuffer();

    // Create sender for encryption with info parameter for domain separation
    const infoBytes = new TextEncoder().encode(HPKE_REQUEST_INFO);
    const sender = await this.suite.createSenderContext({
      recipientPublicKey: this.publicKey, // Encrypt to this identity's public key (the server)
      info: infoBytes.buffer.slice(infoBytes.byteOffset, infoBytes.byteOffset + infoBytes.byteLength),
    });

    // Store context for response decryption
    const context: RequestContext = {
      senderContext: sender,
      requestEnc: new Uint8Array(sender.enc),
    };

    // Set headers - only encapsulated key, NOT client public key
    const headers = new Headers(request.headers);
    headers.set(PROTOCOL.ENCAPSULATED_KEY_HEADER, bytesToHex(context.requestEnc));
    // Note: Do NOT set CLIENT_PUBLIC_KEY_HEADER - vulnerable to MitM attack!

    if (body.byteLength === 0) {
      return {
        request: new Request(request.url, {
          method: request.method,
          headers,
          body: null,
        }),
        context,
      };
    }

    // Encrypt the body
    const encrypted = await sender.seal(body);

    // Create chunked format: 4-byte length header + encrypted data
    const chunkLength = new Uint8Array(4);
    new DataView(chunkLength.buffer).setUint32(0, encrypted.byteLength, false);

    const chunkedData = new Uint8Array(4 + encrypted.byteLength);
    chunkedData.set(chunkLength, 0);
    chunkedData.set(new Uint8Array(encrypted), 4);

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
   *
   * This prevents MitM key substitution attacks because the response keys
   * are derived from the shared secret between client and server.
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
      throw new Error(`Missing ${PROTOCOL.RESPONSE_NONCE_HEADER} header`);
    }

    const responseNonce = hexToBytes(responseNonceHex);
    if (responseNonce.length !== RESPONSE_NONCE_LENGTH) {
      throw new Error(
        `Invalid response nonce length: expected ${RESPONSE_NONCE_LENGTH}, got ${responseNonce.length}`
      );
    }

    // Export secret from request context
    const exportLabelBytes = new TextEncoder().encode(EXPORT_LABEL);
    const exportedSecret = new Uint8Array(
      await context.senderContext.export(
        exportLabelBytes.buffer.slice(exportLabelBytes.byteOffset, exportLabelBytes.byteOffset + exportLabelBytes.byteLength),
        EXPORT_LENGTH
      )
    );

    // Derive response keys
    const km = await deriveResponseKeys(
      exportedSecret,
      context.requestEnc,
      responseNonce
    );

    // Create decrypting stream
    const decryptedStream = this.createDecryptStream(response.body, km);

    return new Response(decryptedStream, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  }

  /**
   * Creates a ReadableStream that decrypts response chunks using derived keys.
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
                controller.error(
                  new Error(`Decryption failed at chunk ${seq - 1}: ${error}`)
                );
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
    });
  }
}
