import {
  CipherSuite,
  type SenderContext,
  type Key,
  KDF_HKDF_SHA256,
  AEAD_AES_256_GCM,
} from 'hpke';
import { KEM_DHKEM_X25519_HKDF_SHA256 } from '@panva/hpke-noble';
import { PROTOCOL, HPKE_CONFIG, REQUEST_FRAME_BYTES } from './protocol.js';
import {
  deriveResponseKeys,
  decryptChunk,
  hexToBytes,
  bytesToHex,
  HPKE_REQUEST_INFO,
  EXPORT_LABEL,
  EXPORT_LENGTH,
  REQUEST_ENC_LENGTH,
  RESPONSE_NONCE_LENGTH,
  ResponseKeyMaterial,
} from './derive.js';
import {
  AeadDecryptFailedError,
  ChunkTooLargeError,
  FramingTruncatedError,
  InvalidKeyConfigError,
  InvalidResponseNonceError,
  InvalidTokenError,
  MissingResponseNonceError,
  UnsupportedSuiteError,
} from './errors.js';
import { forwardedRequestInit } from './request-options.js';

/**
 * Request context for response decryption.
 * Holds the HPKE sender context needed to derive response keys.
 */
export interface RequestContext {
  senderContext: SenderContext;
  requestEnc: Uint8Array;
}

/**
 * Serializable token containing the pre-computed bytes needed to decrypt a response.
 */
export interface SessionRecoveryToken {
  exportedSecret: Uint8Array;
  requestEnc: Uint8Array;
}

/**
 * Creates a new CipherSuite for X25519/HKDF-SHA256/AES-256-GCM
 *
 * The KDF and AEAD come from the Web Cryptography implementations in `hpke`
 * so bulk work runs at native speed regardless of JIT availability. The KEM
 * stays on `@panva/hpke-noble` because Web Cryptography X25519 is not yet
 * available in every supported runtime, and it runs once per request.
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

    // Fixed header: key id (1) || KEM id (2) || X25519 key (32) || suites length (2)
    if (data.length < 37) {
      throw new InvalidKeyConfigError('truncated key config');
    }

    // Read Key ID
    const keyId = data[offset++];

    // Read KEM ID
    const kemId = (data[offset++] << 8) | data[offset++];
    if (kemId !== HPKE_CONFIG.KEM) {
      throw new UnsupportedSuiteError(`unsupported KEM: 0x${kemId.toString(16).padStart(4, '0')}`);
    }

    // Read Public Key (32 bytes for X25519)
    const publicKeySize = 32;
    const publicKeyBytes = data.slice(offset, offset + publicKeySize);
    offset += publicKeySize;

    // Read Cipher Suites Length
    const cipherSuitesLength = (data[offset++] << 8) | data[offset++];
    if (cipherSuitesLength % 4 !== 0) {
      throw new InvalidKeyConfigError('cipher suites length must be a multiple of 4');
    }
    if (offset + cipherSuitesLength > data.length) {
      throw new InvalidKeyConfigError('truncated cipher suites');
    }
    if (cipherSuitesLength === 0) {
      throw new InvalidKeyConfigError('no cipher suites found in config');
    }
    if (cipherSuitesLength !== 4) {
      throw new UnsupportedSuiteError(`expected exactly one cipher suite, got ${cipherSuitesLength / 4}`);
    }

    // Parse all cipher suites (each suite is 4 bytes: 2 for KDF, 2 for AEAD)
    const suites = [];
    const cipherSuitesEnd = offset + cipherSuitesLength;
    while (offset < cipherSuitesEnd) {
      const kdfId = (data[offset++] << 8) | data[offset++];
      const aeadId = (data[offset++] << 8) | data[offset++];
      suites.push({ kdfId, aeadId });
    }

    if (suites.length === 0) {
      throw new InvalidKeyConfigError('no cipher suites found in config');
    }

    // Use the first cipher suite
    const firstSuite = suites[0];

    // Validate that we support this cipher suite
    if (firstSuite.kdfId !== HPKE_CONFIG.KDF || firstSuite.aeadId !== HPKE_CONFIG.AEAD) {
      throw new UnsupportedSuiteError(
        `unsupported cipher suite: KDF=0x${firstSuite.kdfId.toString(16)}, AEAD=0x${firstSuite.aeadId.toString(16)}`
      );
    }

    return Identity.fromPublicKeyBytes(publicKeyBytes);
  }

  /**
   * Create an Identity from a raw public key hex string.
   * Uses the default cipher suite (X25519/HKDF-SHA256/AES-256-GCM).
   *
   * This is used by clients who already have the server's public key
   * and don't need to fetch it.
   */
  static async fromPublicKeyHex(publicKeyHex: string): Promise<Identity> {
    let publicKeyBytes: Uint8Array;
    try {
      publicKeyBytes = hexToBytes(publicKeyHex);
    } catch (error) {
      throw new InvalidKeyConfigError(`invalid public key hex: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
    }
    if (publicKeyBytes.length !== 32) {
      throw new InvalidKeyConfigError(`invalid public key length: expected 32, got ${publicKeyBytes.length}`);
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
    request: Request,
    source?: ReadableStream<Uint8Array> | Blob,
    options: { memoryOnly?: boolean } = {}
  ): Promise<{ request: Request; context: RequestContext | null; cleanup?: () => Promise<void> }> {
    // A caller-supplied source bypasses the Request body entirely: browsers
    // without upload streaming cannot carry a stream in a Request (Firefox
    // stringifies it), so the transport hands it over out of band. Otherwise
    // Node and Chromium expose Request.body as a stream; Firefox does not, so
    // buffer there. Either way the body is sealed frame by frame below.
    let reader: ReadableStreamDefaultReader<Uint8Array>;
    if (source) {
      reader = (source instanceof Blob ? source.stream() : source).getReader() as ReadableStreamDefaultReader<Uint8Array>;
    } else if (request.body) {
      reader = request.body.getReader();
    } else {
      const body = new Uint8Array(await request.arrayBuffer());
      reader = new ReadableStream<Uint8Array>({
        start(c) { if (body.byteLength > 0) c.enqueue(body); c.close(); },
      }).getReader();
    }
    const first = await firstNonEmptyChunk(reader);

    // Bodyless requests pass through unmodified - no HPKE context needed.
    // See SPEC.md Section 5.1: "When the request has no payload body, an encrypted
    // response is not possible (since there is no HPKE context to derive response
    // keys from). Such requests pass through unmodified."
    if (!first) {
      return {
        request: new Request(request.url, {
          ...forwardedRequestInit(request),
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

    const frames = encryptFrames(ctx, reader, first);
    // Only Node is trusted to stream an upload: Chromium accepts a stream body
    // but fails it over HTTP/1.1, Firefox stringifies it. Browsers spool the
    // frames to a private file and upload that, which both engines stream
    // from disk, or fall back to one Blob in memory.
    let sink: { body: BodyInit; cleanup?: () => Promise<void> };
    if (canStreamUpload()) {
      sink = { body: frames as BodyInit };
    } else if (options.memoryOnly) {
      sink = { body: await collect(frames) };
    } else {
      try {
        sink = await spool(frames, source instanceof Blob ? source.size : undefined);
      } catch (err) {
        // Abandoning the frame stream must release the caller's source too
        // (encryptFrames forwards the cancel to the reader it owns).
        await frames.cancel(err).catch(() => {});
        // The frames are consumed. A Blob source can be re-read, so seal it
        // again under a fresh context into the in-memory fallback; a stream
        // cannot be replayed and the failure surfaces as is.
        if (!(source instanceof Blob)) throw err;
        return this.encryptRequestWithContext(request, new Blob([source]), { memoryOnly: true });
      }
    }

    try {
      return {
        request: new Request(request.url, {
          ...forwardedRequestInit(request),
          method: request.method,
          headers,
          body: sink.body,
          duplex: 'half',
        } as RequestInit),
        context,
        cleanup: sink.cleanup,
      };
    } catch (err) {
      await sink.cleanup?.().catch(() => {});
      throw err;
    }
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
    const token = await extractSessionRecoveryToken(context);
    return decryptResponseWithToken(response, token);
  }
}

/**
 * Extract a serializable token from a RequestContext by exporting the HPKE secret.
 * The returned token contains only plain bytes and can be stored/serialized.
 */
export async function extractSessionRecoveryToken(context: RequestContext): Promise<SessionRecoveryToken> {
  const exportLabelBytes = new TextEncoder().encode(EXPORT_LABEL);
  const exportedSecret = new Uint8Array(await context.senderContext.Export(exportLabelBytes, EXPORT_LENGTH));
  return {
    exportedSecret,
    requestEnc: new Uint8Array(context.requestEnc),
  };
}

/**
 * Serialize a SessionRecoveryToken to a JSON string with hex-encoded fields.
 * See SPEC.md Section 6.1.1.
 */
export function serializeSessionRecoveryToken(token: SessionRecoveryToken): string {
  return JSON.stringify({
    exportedSecret: bytesToHex(token.exportedSecret),
    requestEnc: bytesToHex(token.requestEnc),
  });
}

/**
 * Deserialize a SessionRecoveryToken from a JSON string with hex-encoded fields.
 * See SPEC.md Section 6.1.1.
 */
export function deserializeSessionRecoveryToken(json: string): SessionRecoveryToken {
  try {
    const parsed = JSON.parse(json);
    const token = {
      exportedSecret: hexToBytes(parsed.exportedSecret),
      requestEnc: hexToBytes(parsed.requestEnc),
    };
    if (token.exportedSecret.length !== EXPORT_LENGTH) {
      throw new Error(`exported secret must be ${EXPORT_LENGTH} bytes, got ${token.exportedSecret.length}`);
    }
    if (token.requestEnc.length !== REQUEST_ENC_LENGTH) {
      throw new Error(`request enc must be ${REQUEST_ENC_LENGTH} bytes, got ${token.requestEnc.length}`);
    }
    return token;
  } catch (error) {
    throw new InvalidTokenError(`invalid session recovery token: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
  }
}

/**
 * Decrypt a response using a SessionRecoveryToken.
 *
 * The returned Response exposes an incremental authenticated plaintext stream:
 * each complete frame is available before the encrypted response reaches EOF.
 * Cancelling the returned body cancels the encrypted source body.
 */
export async function decryptResponseWithToken(
  response: Response,
  token: SessionRecoveryToken,
  onStreamError?: () => void,
  onStreamComplete?: () => void,
): Promise<Response> {
  const responseNonceHex = response.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER);
  if (!response.body && !responseNonceHex) {
    return response;
  }

  if (!responseNonceHex) {
    throw new MissingResponseNonceError(`missing ${PROTOCOL.RESPONSE_NONCE_HEADER} header`);
  }

  let responseNonce: Uint8Array;
  try {
    responseNonce = hexToBytes(responseNonceHex);
  } catch (error) {
    throw new InvalidResponseNonceError(`invalid response nonce hex: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
  }
  if (responseNonce.length !== RESPONSE_NONCE_LENGTH) {
    throw new InvalidResponseNonceError(`invalid response nonce length: expected ${RESPONSE_NONCE_LENGTH}, got ${responseNonce.length}`);
  }
  if (!response.body) {
    onStreamComplete?.();
    return response;
  }

  const km = await deriveResponseKeys(token.exportedSecret, token.requestEnc, responseNonce);
  const decryptedStream = createDecryptStream(
    response.body,
    km,
    onStreamError,
    onStreamComplete,
  );

  // Framing headers describe the encrypted body, not the decrypted stream.
  // Consumers that forward the response headers verbatim (for example a
  // proxy) would otherwise announce a body length that no longer matches
  // what is written, truncating the reply.
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  headers.delete('transfer-encoding');

  return new Response(decryptedStream, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

const MAX_RESPONSE_CHUNK_BYTES = 64 * 1024 * 1024;

function createDecryptStream(
  body: ReadableStream<Uint8Array>,
  km: ResponseKeyMaterial,
  onStreamError?: () => void,
  onStreamComplete?: () => void,
): ReadableStream<Uint8Array> {
  let buffer = new Uint8Array(0);
  let seq = 0;
  const reader = body.getReader();
  let consumerCancelled = false;

  return new ReadableStream({
    async pull(controller) {
      // Erroring the output stream does not invoke the cancel() handler below,
      // so the upstream body must be cancelled explicitly; otherwise a rejected
      // (e.g. oversized) chunk leaves the underlying response downloading.
      const fail = (error: Error) => {
        try {
          onStreamError?.();
        } catch {
          // Observer failures must not interrupt stream cleanup.
        }
        try {
          controller.error(error);
        } finally {
          reader.cancel(error).catch(() => {});
        }
      };

      while (true) {
        if (buffer.length >= 4) {
          const chunkLength =
            ((buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3]) >>> 0;

          if (chunkLength === 0) {
            buffer = buffer.slice(4);
            continue;
          }

          if (chunkLength > MAX_RESPONSE_CHUNK_BYTES) {
            fail(new ChunkTooLargeError('response chunk exceeds maximum allowed size'));
            return;
          }

          if (buffer.length >= 4 + chunkLength) {
            const ciphertext = buffer.slice(4, 4 + chunkLength);
            buffer = buffer.slice(4 + chunkLength);

            try {
              const plaintext = await decryptChunk(km, seq++, ciphertext);
              controller.enqueue(plaintext);
              return;
            } catch (error) {
              fail(new AeadDecryptFailedError(
                `Decryption failed at chunk ${seq - 1}`,
                { cause: error }
              ));
              return;
            }
          }
        }

        let result: ReadableStreamReadResult<Uint8Array>;
        try {
          result = await reader.read();
        } catch (error) {
          if (consumerCancelled) {
            return;
          }
          fail(error instanceof Error ? error : new Error('Encrypted response read failed', {
            cause: error,
          }));
          return;
        }
        const { done, value } = result;
        if (done) {
          if (consumerCancelled) {
            return;
          }
          if (buffer.length !== 0) {
            fail(new FramingTruncatedError('truncated encrypted response chunk'));
          } else {
            onStreamComplete?.();
            controller.close();
          }
          return;
        }

        const newBuffer = new Uint8Array(buffer.length + value.length);
        newBuffer.set(buffer);
        newBuffer.set(value, buffer.length);
        buffer = newBuffer;
      }
    },
    cancel(reason) {
      consumerCancelled = true;
      return reader.cancel(reason);
    },
  });
}

/** Reads until the first non-empty chunk; null means the stream was empty. */
async function firstNonEmptyChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>
): Promise<Uint8Array | null> {
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return null;
    if (value.byteLength > 0) return value;
  }
}

/**
 * Seals the plaintext stream into LEN || CIPHERTEXT frames of at most
 * REQUEST_FRAME_BYTES plaintext each (SPEC 4.3), one sender context for the
 * whole body, holding at most one frame of plaintext at a time.
 */
/** @internal exported for tests */
export function encryptFrames(
  ctx: SenderContext,
  reader: ReadableStreamDefaultReader<Uint8Array>,
  first: Uint8Array
): ReadableStream<Uint8Array> {
  // Cursor into the current source chunk (a view, never copied) plus one
  // frame-sized staging buffer for a partial frame spanning chunks. Nothing
  // allocated here is proportional to the chunk size.
  let chunk = first;
  let offset = 0;
  const staging = new Uint8Array(REQUEST_FRAME_BYTES);
  let staged = 0;
  let sourceDone = false;

  // Returns the next frame's plaintext (valid until the next call) or null at EOF.
  async function nextPlaintext(): Promise<Uint8Array | null> {
    for (;;) {
      if (offset >= chunk.byteLength) {
        if (sourceDone) break;
        const { done, value } = await reader.read();
        if (done) { sourceDone = true; break; }
        chunk = value;
        offset = 0;
        continue;
      }
      if (staged === 0 && chunk.byteLength - offset >= REQUEST_FRAME_BYTES) {
        const out = chunk.subarray(offset, offset + REQUEST_FRAME_BYTES);
        offset += REQUEST_FRAME_BYTES;
        return out;
      }
      const n = Math.min(REQUEST_FRAME_BYTES - staged, chunk.byteLength - offset);
      staging.set(chunk.subarray(offset, offset + n), staged);
      staged += n;
      offset += n;
      if (staged === REQUEST_FRAME_BYTES) {
        staged = 0;
        return staging;
      }
    }
    if (staged > 0) {
      const out = staging.subarray(0, staged);
      staged = 0;
      return out;
    }
    return null;
  }

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const plaintext = await nextPlaintext();
        if (plaintext === null) {
          controller.close();
          return;
        }
        const sealed = await ctx.Seal(plaintext);
        const frame = new Uint8Array(4 + sealed.byteLength);
        new DataView(frame.buffer).setUint32(0, sealed.byteLength, false);
        frame.set(sealed, 4);
        controller.enqueue(frame);
      } catch (err) {
        // Mirror createDecryptStream: a failed pull releases the source.
        reader.cancel(err).catch(() => {});
        throw err;
      }
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });
}

/**
 * Where the runtime cannot stream an upload, write the encrypted frames to an
 * Origin Private File System file as they are produced and upload the File:
 * browsers stream a File body from disk, so memory stays one frame deep.
 * Falls back to a single in-memory Blob when OPFS is missing or its quota
 * cannot hold a body of known size.
 * ponytail: Safari exposes OPFS only through sync access handles in a worker,
 * so it takes the Blob fallback; a worker-based spool is the upgrade path.
 */
async function spool(
  frames: ReadableStream<Uint8Array>,
  knownSize?: number
): Promise<{ body: BodyInit; cleanup?: () => Promise<void> }> {
  const storage = (globalThis as { navigator?: { storage?: StorageManager } }).navigator?.storage;
  const canSpool =
    typeof storage?.getDirectory === 'function' &&
    typeof (globalThis as { FileSystemFileHandle?: { prototype: { createWritable?: unknown } } })
      .FileSystemFileHandle?.prototype?.createWritable === 'function';
  if (!canSpool) return { body: await collect(frames) };
  const root = await storage.getDirectory();
  // Sweep first: a stale spool from a dead page could otherwise hold the
  // quota that this upload needs and push it into the memory fallback forever.
  await sweepOrphanedSpools(root);
  if (knownSize !== undefined && typeof storage.estimate === 'function') {
    const { quota = 0, usage = 0 } = await storage.estimate();
    if (quota - usage < framedSize(knownSize)) return { body: await collect(frames) };
  }

  const name = `${SPOOL_PREFIX}${Date.now()}-${Math.random().toString(16).slice(2)}`;
  // Removal failures propagate: a leftover file is ciphertext only, but the
  // caller should know it is still there rather than assume it is gone.
  const cleanup = () => root.removeEntry(name);
  try {
    const handle = await root.getFileHandle(name, { create: true });
    const writer = await handle.createWritable();
    const reader = frames.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        await writer.write(value as unknown as BufferSource); // awaited per frame: backpressure keeps memory at one frame
      }
    } catch (err) {
      // Release the caller's source (the frame stream forwards the cancel)
      // and abort the writable: an errored one cannot be closed, and
      // aborting keeps the original error (quota exhausted mid-body, I/O
      // failure) as the one that surfaces.
      await reader.cancel(err).catch(() => {});
      await writer.abort(err).catch(() => {});
      throw err;
    }
    await writer.close();
    return { body: await handle.getFile(), cleanup };
  } catch (err) {
    await cleanup().catch(() => {});
    throw err;
  }
}

const SPOOL_PREFIX = 'ehbp-spool-';
const SPOOL_ORPHAN_AGE_MS = 60 * 60 * 1000;

/** Encrypted size of a body of `size` plaintext bytes: 4-byte length and 16-byte tag per frame. */
function framedSize(size: number): number {
  return size + Math.max(1, Math.ceil(size / REQUEST_FRAME_BYTES)) * 20;
}

/**
 * A spool outlives its request only if the page died between upload and
 * cleanup. Such files hold ciphertext, never keys, but there is no reason to
 * keep them: remove ours that are older than an hour (younger ones may belong
 * to a concurrent upload in another tab of the same origin).
 */
async function sweepOrphanedSpools(root: FileSystemDirectoryHandle): Promise<void> {
  const entries = (root as unknown as { keys?: () => AsyncIterable<string> }).keys?.();
  if (!entries) return;
  const cutoff = Date.now() - SPOOL_ORPHAN_AGE_MS;
  for await (const name of entries) {
    if (!name.startsWith(SPOOL_PREFIX)) continue;
    const born = Number(name.slice(SPOOL_PREFIX.length).split('-')[0]);
    if (Number.isFinite(born) && born < cutoff) await root.removeEntry(name).catch(() => {});
  }
}

// One copy at most: the frames go into a Blob as parts instead of being
// concatenated into a second body-sized buffer.
async function collect(stream: ReadableStream<Uint8Array>): Promise<Blob> {
  const parts: Uint8Array[] = [];
  for (const reader = stream.getReader(); ;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  return new Blob(parts as BlobPart[]);
}

/** @internal true where fetch streams a ReadableStream body (Node). */
export function canStreamUpload(): boolean {
  const proc = (globalThis as { process?: { versions?: { node?: string } } }).process;
  return typeof proc?.versions?.node === 'string';
}
