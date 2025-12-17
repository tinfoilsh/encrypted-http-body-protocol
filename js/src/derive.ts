/**
 * Response key derivation for EHBP
 *
 * This module implements the key derivation matching the Go implementation.
 *
 * The derivation follows OHTTP (RFC 9458):
 *   salt = concat(enc, response_nonce)
 *   prk = Extract(salt, secret)
 *   aead_key = Expand(prk, "key", Nk)
 *   aead_nonce = Expand(prk, "nonce", Nn)
 */

import { KDF_HKDF_SHA256, AEAD_AES_256_GCM, type KDF, type AEAD } from 'hpke';

const kdf: KDF = KDF_HKDF_SHA256();
const aead: AEAD = AEAD_AES_256_GCM();

export const HPKE_REQUEST_INFO = 'ehbp request';
export const EXPORT_LABEL = 'ehbp response';
export const EXPORT_LENGTH = 32;
export const RESPONSE_NONCE_LENGTH = 32; // max(Nn, Nk) = max(12, 32) = 32
export const AES256_KEY_LENGTH = 32;
export const AES_GCM_NONCE_LENGTH = 12;
export const REQUEST_ENC_LENGTH = 32; // X25519 enc size

// Labels for HKDF-Expand
const RESPONSE_KEY_LABEL = new TextEncoder().encode('key');
const RESPONSE_NONCE_LABEL = new TextEncoder().encode('nonce');

/**
 * Response key material for encryption/decryption
 */
export interface ResponseKeyMaterial {
  /** Raw key bytes for AEAD operations */
  keyBytes: Uint8Array;
  /** 12 bytes, XORed with sequence number for each chunk */
  nonceBase: Uint8Array;
}

/**
 * Derives response encryption keys from the HPKE exported secret.
 *
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
  // Validate inputs
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

  // prk = Extract(salt, secret)
  const prk = await kdf.Extract(salt, exportedSecret);

  // key = Expand(prk, "key", 32)
  const keyBytes = await kdf.Expand(prk, RESPONSE_KEY_LABEL, AES256_KEY_LENGTH);

  // nonceBase = Expand(prk, "nonce", 12)
  const nonceBase = await kdf.Expand(prk, RESPONSE_NONCE_LABEL, AES_GCM_NONCE_LENGTH);

  return { keyBytes, nonceBase };
}

/**
 * Computes the nonce for a specific sequence number.
 * nonce = nonceBase XOR sequence_number (big-endian in last 8 bytes)
 */
export function computeNonce(nonceBase: Uint8Array, seq: number): Uint8Array {
  if (nonceBase.length !== AES_GCM_NONCE_LENGTH) {
    throw new Error(`nonce base must be ${AES_GCM_NONCE_LENGTH} bytes`);
  }

  // Validate seq to prevent nonce reuse from integer overflow.
  // JavaScript's >>> operator only works correctly for 32-bit unsigned integers.
  // Values >= 2^32 wrap around (e.g., 2^32 >>> 0 === 0), causing nonce reuse.
  if (!Number.isInteger(seq) || seq < 0 || seq >= 0x100000000) {
    throw new Error(`sequence number must be an integer in range [0, 2^32): got ${seq}`);
  }

  const nonce = new Uint8Array(AES_GCM_NONCE_LENGTH);
  nonce.set(nonceBase);

  // XOR with sequence number in the last 8 bytes (big-endian)
  for (let i = 0; i < 8; i++) {
    const shift = i * 8;
    if (shift < 32) {
      nonce[AES_GCM_NONCE_LENGTH - 1 - i] ^= (seq >>> shift) & 0xff;
    }
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

  const ciphertext = await aead.Seal(km.keyBytes, nonce, new Uint8Array(0), plaintext);

  return ciphertext;
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

  const plaintext = await aead.Open(km.keyBytes, nonce, new Uint8Array(0), ciphertext);

  return plaintext;
}

/**
 * Utility: Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have even length');
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('Invalid hex character');
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
