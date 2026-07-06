/**
 * Minimal Noise NK implementation for EHBP-WS (SPEC Section 8).
 *
 * Implements exactly the Noise_NK_25519_AESGCM_SHA256 handshake from the
 * Noise Protocol Framework (revision 34) plus the transport cipher states,
 * using only browser-native WebCrypto so it runs in browsers and modern
 * Node alike.
 *
 * The record layer drives raw cipher states rather than Noise transport
 * messages because EHBP-WS records may exceed the Noise 65535-byte
 * transport cap.
 */

import { NOISE_WS } from './protocol.js';
import { DecryptionError, HandshakeError, ProtocolError } from './errors.js';

const DH_LENGTH = 32;
const KEY_LENGTH = 32;
const TAG_LENGTH = 16;
const NONCE_LENGTH = 12;
const HASH_LENGTH = 32;

/** Nonce reserved for the rekey operation (2^64 - 1). */
const REKEY_NONCE = 0xffffffffffffffffn;

const encoder = new TextEncoder();

/** DER prefix of a PKCS#8-encoded X25519 private key. */
const PKCS8_X25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * Narrows to the ArrayBuffer-backed view type WebCrypto expects. Every
 * array in this module is constructed over a plain ArrayBuffer.
 */
function bufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes as Uint8Array<ArrayBuffer>;
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** 96-bit Noise nonce: 4 zero bytes then the big-endian 64-bit counter. */
function noiseNonce(counter: bigint): Uint8Array {
  const nonce = new Uint8Array(NONCE_LENGTH);
  new DataView(nonce.buffer).setBigUint64(4, counter, false);
  return nonce;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bufferSource(data)));
}

async function hmacSHA256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const hmacKey = await crypto.subtle.importKey(
    'raw', bufferSource(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, bufferSource(data)));
}

/** Noise HKDF with two outputs (Noise spec Section 4.3). */
async function noiseHKDF(
  chainingKey: Uint8Array,
  input: Uint8Array,
): Promise<[Uint8Array, Uint8Array]> {
  const tempKey = await hmacSHA256(chainingKey, input);
  const output1 = await hmacSHA256(tempKey, Uint8Array.of(0x01));
  const output2 = await hmacSHA256(tempKey, concatBytes(output1, Uint8Array.of(0x02)));
  return [output1, output2];
}

async function importAESKey(key: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw', bufferSource(key), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function aeadSeal(
  key: CryptoKey,
  counter: bigint,
  associatedData: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: bufferSource(noiseNonce(counter)),
      additionalData: bufferSource(associatedData),
      tagLength: TAG_LENGTH * 8,
    },
    key,
    bufferSource(plaintext),
  ));
}

async function aeadOpen(
  key: CryptoKey,
  counter: bigint,
  associatedData: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: bufferSource(noiseNonce(counter)),
        additionalData: bufferSource(associatedData),
        tagLength: TAG_LENGTH * 8,
      },
      key,
      bufferSource(ciphertext),
    ));
  } catch (err) {
    throw new DecryptionError('record failed authentication', { cause: err });
  }
}

function base64UrlDecode(input: string): Uint8Array {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    out[index] = binary.charCodeAt(index);
  }
  return out;
}

/** X25519 key pair holding the private half as a WebCrypto key. */
export interface X25519KeyPair {
  privateKey: CryptoKey;
  publicKeyBytes: Uint8Array;
}

export async function generateX25519KeyPair(): Promise<X25519KeyPair> {
  const pair = await crypto.subtle.generateKey('X25519', false, ['deriveBits']) as CryptoKeyPair;
  const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return { privateKey: pair.privateKey, publicKeyBytes };
}

/**
 * Imports a raw 32-byte X25519 private key and recovers its public half
 * from the JWK export. Used by tests to run deterministic handshakes.
 */
export async function importX25519PrivateKey(rawPrivateKey: Uint8Array): Promise<X25519KeyPair> {
  if (rawPrivateKey.length !== DH_LENGTH) {
    throw new HandshakeError(`invalid X25519 private key length: ${rawPrivateKey.length}`);
  }
  const pkcs8 = concatBytes(PKCS8_X25519_PREFIX, rawPrivateKey);
  const privateKey = await crypto.subtle.importKey(
    'pkcs8', bufferSource(pkcs8), 'X25519', true, ['deriveBits']);
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  if (!jwk.x) {
    throw new HandshakeError('X25519 private key export missing public half');
  }
  return { privateKey, publicKeyBytes: base64UrlDecode(jwk.x) };
}

export async function x25519SharedSecret(
  privateKey: CryptoKey,
  publicKeyBytes: Uint8Array,
): Promise<Uint8Array> {
  const publicKey = await crypto.subtle.importKey(
    'raw', bufferSource(publicKeyBytes), 'X25519', false, []);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'X25519', public: publicKey }, privateKey, DH_LENGTH * 8));
}

/**
 * Noise symmetric state (Noise spec Section 5.2): the chaining key, the
 * handshake hash, and the handshake-phase cipher.
 */
export class NoiseSymmetricState {
  private chainingKey: Uint8Array;
  private hash: Uint8Array;
  private key: CryptoKey | null = null;
  private counter = 0n;

  private constructor(chainingKey: Uint8Array, hash: Uint8Array) {
    this.chainingKey = chainingKey;
    this.hash = hash;
  }

  static async create(protocolName: string): Promise<NoiseSymmetricState> {
    const name = encoder.encode(protocolName);
    let hash: Uint8Array;
    if (name.length <= HASH_LENGTH) {
      hash = new Uint8Array(HASH_LENGTH);
      hash.set(name);
    } else {
      hash = await sha256(name);
    }
    return new NoiseSymmetricState(hash.slice(), hash);
  }

  async mixHash(data: Uint8Array): Promise<void> {
    this.hash = await sha256(concatBytes(this.hash, data));
  }

  async mixKey(inputKeyMaterial: Uint8Array): Promise<void> {
    const [chainingKey, key] = await noiseHKDF(this.chainingKey, inputKeyMaterial);
    this.chainingKey = chainingKey;
    this.key = await importAESKey(key);
    this.counter = 0n;
  }

  async encryptAndHash(plaintext: Uint8Array): Promise<Uint8Array> {
    if (!this.key) {
      await this.mixHash(plaintext);
      return plaintext;
    }
    const ciphertext = await aeadSeal(this.key, this.counter, this.hash, plaintext);
    this.counter += 1n;
    await this.mixHash(ciphertext);
    return ciphertext;
  }

  async decryptAndHash(ciphertext: Uint8Array): Promise<Uint8Array> {
    if (!this.key) {
      await this.mixHash(ciphertext);
      return ciphertext;
    }
    const plaintext = await aeadOpen(this.key, this.counter, this.hash, ciphertext);
    this.counter += 1n;
    await this.mixHash(ciphertext);
    return plaintext;
  }

  /** Derives the two transport keys (initiator-to-responder first). */
  async split(): Promise<[Uint8Array, Uint8Array]> {
    return noiseHKDF(this.chainingKey, new Uint8Array(0));
  }

  get handshakeHash(): Uint8Array {
    return this.hash;
  }
}

/**
 * Initiator side of the Noise NK handshake:
 *
 *   NK:
 *     <- s
 *     ...
 *     -> e, es
 *     <- e, ee
 */
export class NoiseNKInitiator {
  private symmetric: NoiseSymmetricState;
  private ephemeral: X25519KeyPair;
  private serverStaticKey: Uint8Array;

  private constructor(
    symmetric: NoiseSymmetricState,
    ephemeral: X25519KeyPair,
    serverStaticKey: Uint8Array,
  ) {
    this.symmetric = symmetric;
    this.ephemeral = ephemeral;
    this.serverStaticKey = serverStaticKey;
  }

  static async create(
    serverStaticKey: Uint8Array,
    ephemeralForTesting?: X25519KeyPair,
  ): Promise<NoiseNKInitiator> {
    if (serverStaticKey.length !== DH_LENGTH) {
      throw new HandshakeError(`invalid server static key length: ${serverStaticKey.length}`);
    }
    const symmetric = await NoiseSymmetricState.create(NOISE_WS.PROTOCOL_NAME);
    await symmetric.mixHash(encoder.encode(NOISE_WS.PROLOGUE));
    await symmetric.mixHash(serverStaticKey);
    const ephemeral = ephemeralForTesting ?? await generateX25519KeyPair();
    return new NoiseNKInitiator(symmetric, ephemeral, serverStaticKey);
  }

  /** Produces message 1 (-> e, es) with an empty payload. */
  async writeMessage1(): Promise<Uint8Array> {
    await this.symmetric.mixHash(this.ephemeral.publicKeyBytes);
    await this.symmetric.mixKey(
      await x25519SharedSecret(this.ephemeral.privateKey, this.serverStaticKey));
    const encryptedPayload = await this.symmetric.encryptAndHash(new Uint8Array(0));
    return concatBytes(this.ephemeral.publicKeyBytes, encryptedPayload);
  }

  /** Consumes message 2 (<- e, ee) and returns [sendKey, recvKey]. */
  async readMessage2(message: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
    if (message.length < DH_LENGTH + TAG_LENGTH) {
      throw new HandshakeError(`handshake message too short: ${message.length} bytes`);
    }
    const remoteEphemeral = message.slice(0, DH_LENGTH);
    await this.symmetric.mixHash(remoteEphemeral);
    await this.symmetric.mixKey(
      await x25519SharedSecret(this.ephemeral.privateKey, remoteEphemeral));
    try {
      await this.symmetric.decryptAndHash(message.slice(DH_LENGTH));
    } catch (err) {
      throw new HandshakeError('handshake message failed authentication', { cause: err });
    }
    return this.symmetric.split();
  }

  get handshakeHash(): Uint8Array {
    return this.symmetric.handshakeHash;
  }
}

/**
 * One direction of the transport: AES-256-GCM with a 64-bit counter
 * nonce, ratcheted every `rekeyInterval` records via the Noise REKEY
 * construction (encrypt 32 zero bytes under the maximum nonce).
 */
export class NoiseRecordCipher {
  private key: CryptoKey;
  private counter = 0n;
  private rekeyInterval: bigint;
  // WebCrypto's encrypt/decrypt are genuinely asynchronous, so two
  // overlapping calls could otherwise both read `counter` before either
  // one advances it and reuse an AEAD nonce. Chaining every call through
  // this queue forces each one to wait for the previous to fully settle.
  private queue: Promise<void> = Promise.resolve();

  private constructor(key: CryptoKey, rekeyInterval: bigint, counterForTesting: bigint = 0n) {
    this.key = key;
    this.rekeyInterval = rekeyInterval;
    this.counter = counterForTesting;
  }

  static async create(
    key: Uint8Array,
    rekeyInterval: number,
    counterForTesting: bigint = 0n,
  ): Promise<NoiseRecordCipher> {
    if (key.length !== KEY_LENGTH) {
      throw new HandshakeError(`invalid transport key length: ${key.length}`);
    }
    if (!Number.isInteger(rekeyInterval) || rekeyInterval <= 0) {
      throw new HandshakeError(`invalid rekey interval: ${rekeyInterval}`);
    }
    return new NoiseRecordCipher(await importAESKey(key), BigInt(rekeyInterval), counterForTesting);
  }

  async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
    return this.serialized(async () => {
      this.checkCounter();
      const ciphertext = await aeadSeal(this.key, this.counter, new Uint8Array(0), plaintext);
      await this.advance();
      return ciphertext;
    });
  }

  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    if (ciphertext.length < TAG_LENGTH) {
      throw new DecryptionError(`record too short: ${ciphertext.length} bytes`);
    }
    return this.serialized(async () => {
      this.checkCounter();
      const plaintext = await aeadOpen(this.key, this.counter, new Uint8Array(0), ciphertext);
      await this.advance();
      return plaintext;
    });
  }

  /** The maximum nonce is reserved for rekeying, so an exhausted counter
   * must fail before any cryptographic use of the nonce. */
  private checkCounter(): void {
    if (this.counter >= REKEY_NONCE) {
      throw new ProtocolError('record counter exhausted');
    }
  }

  /** Runs `op` only once every previously queued encrypt/decrypt has
   * settled, so one call's counter read and advance can never interleave
   * with another's. */
  private serialized<T>(op: () => Promise<T>): Promise<T> {
    const result = this.queue.then(op, op);
    this.queue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async advance(): Promise<void> {
    this.counter += 1n;
    if (this.counter % this.rekeyInterval === 0n) {
      const block = await aeadSeal(this.key, REKEY_NONCE, new Uint8Array(0), new Uint8Array(KEY_LENGTH));
      this.key = await importAESKey(block.slice(0, KEY_LENGTH));
    }
  }
}
