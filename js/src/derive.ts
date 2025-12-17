/**
 * Response key derivation for EHBP
 *
 * This module implements the key derivation matching the Go implementation.
 * Uses Web Crypto for HKDF and @hpke/core for AEAD.
 *
 * The derivation follows OHTTP (RFC 9458):
 *   salt = concat(enc, response_nonce)
 *   prk = Extract(salt, secret)
 *   aead_key = Expand(prk, "key", Nk)
 *   aead_nonce = Expand(prk, "nonce", Nn)
 */

import { Aes256Gcm, type AeadEncryptionContext } from '@hpke/core';

// Instantiate AEAD primitive from @hpke/core
const aead = new Aes256Gcm();

// Constants matching the Go implementation exactly
export const HPKE_REQUEST_INFO = 'ehbp request';
export const EXPORT_LABEL = 'ehbp response';
export const EXPORT_LENGTH = 32;
export const RESPONSE_NONCE_LENGTH = 32; // max(Nn, Nk) = max(12, 32) = 32
export const AES256_KEY_LENGTH = 32;
export const AES_GCM_NONCE_LENGTH = 12;
export const REQUEST_ENC_LENGTH = 32; // X25519 enc size

// Labels for HKDF-Expand (must match Go)
const RESPONSE_KEY_LABEL = new TextEncoder().encode('key');
const RESPONSE_NONCE_LABEL = new TextEncoder().encode('nonce');

/**
 * Response key material for encryption/decryption
 */
export interface ResponseKeyMaterial {
  /** AEAD encryption context with seal/open methods */
  aeadContext: AeadEncryptionContext;
  /** Raw key bytes (for testing/interop verification) */
  keyBytes: Uint8Array;
  /** 12 bytes, XORed with sequence number for each chunk */
  nonceBase: Uint8Array;
}

/**
 * Helper to convert Uint8Array to ArrayBuffer safely
 */
function toArrayBuffer(arr: Uint8Array): ArrayBuffer {
  return arr.buffer.slice(arr.byteOffset, arr.byteOffset + arr.byteLength) as ArrayBuffer;
}

/**
 * Derives response encryption keys from the HPKE exported secret.
 *
 * Uses Web Crypto HKDF + @hpke/core AEAD:
 *   salt = concat(enc, response_nonce)
 *   prk = Extract(salt, secret)
 *   key = Expand(prk, "key", 32)
 *   nonceBase = Expand(prk, "nonce", 12)
 *
 * @param exportedSecret - 32 bytes exported from HPKE context
 * @param requestEnc - 32 bytes encapsulated key from request
 * @param responseNonce - 32 bytes random nonce from response
 * @returns Key material for response encryption/decryption
 */
export async function deriveResponseKeys(
  exportedSecret: Uint8Array,
  requestEnc: Uint8Array,
  responseNonce: Uint8Array
): Promise<ResponseKeyMaterial> {
  // Validate inputs (matching Go validation)
  if (exportedSecret.length !== EXPORT_LENGTH) {
    throw new Error(`exported secret must be ${EXPORT_LENGTH} bytes, got ${exportedSecret.length}`);
  }
  if (requestEnc.length !== REQUEST_ENC_LENGTH) {
    throw new Error(`request enc must be ${REQUEST_ENC_LENGTH} bytes, got ${requestEnc.length}`);
  }
  if (responseNonce.length !== RESPONSE_NONCE_LENGTH) {
    throw new Error(`response nonce must be ${RESPONSE_NONCE_LENGTH} bytes, got ${responseNonce.length}`);
  }

  // salt = concat(enc, response_nonce)
  const salt = new Uint8Array(requestEnc.length + responseNonce.length);
  salt.set(requestEnc, 0);
  salt.set(responseNonce, requestEnc.length);

  // Import exported secret as HKDF key material (Web Crypto)
  const ikm = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(exportedSecret),
    'HKDF',
    false,
    ['deriveBits']
  );

  // key = HKDF(secret, salt, "key", 32)
  const keyBytes = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: toArrayBuffer(salt),
        info: toArrayBuffer(RESPONSE_KEY_LABEL),
      },
      ikm,
      AES256_KEY_LENGTH * 8
    )
  );

  // nonceBase = HKDF(secret, salt, "nonce", 12)
  const nonceBase = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: toArrayBuffer(salt),
        info: toArrayBuffer(RESPONSE_NONCE_LABEL),
      },
      ikm,
      AES_GCM_NONCE_LENGTH * 8
    )
  );

  // Create AEAD encryption context from @hpke/core
  const aeadContext = aead.createEncryptionContext(toArrayBuffer(keyBytes));

  return { aeadContext, keyBytes, nonceBase };
}

/**
 * Computes the nonce for a specific sequence number.
 * nonce = nonceBase XOR sequence_number (big-endian in last 8 bytes)
 *
 * This matches the Go implementation:
 *   for i := 0; i < 8; i++ {
 *       nonce[len(nonce)-1-i] ^= byte(seq >> (i * 8))
 *   }
 */
export function computeNonce(nonceBase: Uint8Array, seq: number): Uint8Array {
  if (nonceBase.length !== AES_GCM_NONCE_LENGTH) {
    throw new Error(`nonce base must be ${AES_GCM_NONCE_LENGTH} bytes`);
  }

  const nonce = new Uint8Array(AES_GCM_NONCE_LENGTH);
  nonce.set(nonceBase);

  // XOR with sequence number in the last 8 bytes (big-endian)
  // Matches Go: nonce[len(nonce)-1-i] ^= byte(seq >> (i * 8))
  //
  // Note: JavaScript's >>> operator works on 32-bit integers and treats
  // shift amounts modulo 32 (so x >>> 32 === x, not 0). We handle this by
  // only XORing for shifts < 32. For seq < 2^32, higher bytes are always 0.
  for (let i = 0; i < 8; i++) {
    const shift = i * 8;
    if (shift < 32) {
      nonce[AES_GCM_NONCE_LENGTH - 1 - i] ^= (seq >>> shift) & 0xff;
    }
    // For shift >= 32, the byte is 0 for any seq < 2^32, so no XOR needed
  }

  return nonce;
}

/**
 * Encrypts a chunk using the response key material
 */
export async function encryptChunk(
  km: ResponseKeyMaterial,
  seq: number,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const nonce = computeNonce(km.nonceBase, seq);

  const ciphertext = await km.aeadContext.seal(
    toArrayBuffer(nonce),
    toArrayBuffer(plaintext),
    new ArrayBuffer(0) // empty AAD
  );

  return new Uint8Array(ciphertext);
}

/**
 * Decrypts a chunk using the response key material
 */
export async function decryptChunk(
  km: ResponseKeyMaterial,
  seq: number,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  const nonce = computeNonce(km.nonceBase, seq);

  const plaintext = await km.aeadContext.open(
    toArrayBuffer(nonce),
    toArrayBuffer(ciphertext),
    new ArrayBuffer(0) // empty AAD
  );

  return new Uint8Array(plaintext);
}

/**
 * Utility: Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have even length');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Utility: Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
