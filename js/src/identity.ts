import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm, SenderContext } from '@hpke/core';
import { PROTOCOL, HPKE_CONFIG, RESPONSE_ENCRYPTION } from './protocol.js';

/**
 * Request context holding the HPKE sender context for deriving response decryption keys
 */
export interface RequestContext {
  senderContext: SenderContext;
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
   * Encrypt request body and set appropriate headers.
   * Returns both the encrypted request and a context needed to decrypt the response.
   * @throws Error if request has no body (EHBP requires a body for bidirectional encryption)
   */
  async encryptRequest(request: Request, serverPublicKey: CryptoKey): Promise<{ request: Request; context: RequestContext }> {
    const body = await request.arrayBuffer();

    if (body.byteLength === 0) {
      throw new Error('EHBP requires a request body');
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
    headers.set(PROTOCOL.ENCAPSULATED_KEY_HEADER, Array.from(new Uint8Array(encapKey))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(''));

    const encryptedRequest = new Request(request.url, {
      method: request.method,
      headers,
      body: chunkedData,
      duplex: 'half'
    } as RequestInit);

    return {
      request: encryptedRequest,
      context: { senderContext: sender }
    };
  }

  /**
   * Decrypt response body using key derived from the request context.
   * Uses HPKE Export interface for bidirectional encryption (RFC 9180 Section 9.8).
   */
  async decryptResponse(response: Response, reqContext: RequestContext): Promise<Response> {
    if (!response.body) {
      return response;
    }

    // Derive response key and nonce from request context using Export
    const exportLen = RESPONSE_ENCRYPTION.KEY_LENGTH + RESPONSE_ENCRYPTION.NONCE_LENGTH;
    const exported = await reqContext.senderContext.export(
      RESPONSE_ENCRYPTION.EXPORT_CONTEXT.buffer as ArrayBuffer,
      exportLen
    );
    const exportedBytes = new Uint8Array(exported);
    const responseKey = exportedBytes.slice(0, RESPONSE_ENCRYPTION.KEY_LENGTH);
    const baseNonce = exportedBytes.slice(RESPONSE_ENCRYPTION.KEY_LENGTH);

    // Import key for AES-GCM decryption
    const aesKey = await crypto.subtle.importKey(
      'raw',
      responseKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    let seq = 0n;

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

                if (chunkLength > PROTOCOL.MAX_CHUNK_SIZE) {
                  controller.error(new Error(`Chunk size ${chunkLength} exceeds maximum ${PROTOCOL.MAX_CHUNK_SIZE}`));
                  return;
                }

                // Check if we have the complete chunk
                if (offset + chunkLength > buffer.length) {
                  // Not enough data yet, rewind offset and wait for more
                  offset -= 4;
                  break;
                }

                // Extract the encrypted chunk
                const encryptedChunk = buffer.slice(offset, offset + chunkLength);
                offset += chunkLength;

                try {
                  // Compute nonce: XOR base nonce with sequence number
                  const nonce = new Uint8Array(baseNonce);
                  let tempSeq = seq;
                  for (let i = nonce.length - 1; i >= 0 && tempSeq > 0n; i--) {
                    nonce[i] ^= Number(tempSeq & 0xffn);
                    tempSeq >>= 8n;
                  }
                  seq++;

                  const decryptedChunk = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: nonce },
                    aesKey,
                    encryptedChunk
                  );
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

}
