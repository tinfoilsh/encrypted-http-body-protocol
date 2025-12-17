/**
 * Response key derivation for EHBP
 *
 * This module implements the key derivation matching the Go implementation.
 * The derivation follows OHTTP (RFC 9458):
 *   salt = concat(enc, response_nonce)
 *   prk = Extract(salt, secret)
 *   aead_key = Expand(prk, "key", Nk)
 *   aead_nonce = Expand(prk, "nonce", Nn)
 */

/**
 * Helper to convert Uint8Array to ArrayBuffer safely for Web Crypto API
 */
function toArrayBuffer(arr: Uint8Array): ArrayBuffer {
  return arr.buffer.slice(arr.byteOffset, arr.byteOffset + arr.byteLength) as ArrayBuffer;
}

// Constants matching the Go implementation exactly
export const HPKE_REQUEST_INFO = 'ehbp request';
export const EXPORT_LABEL = 'ehbp response';
export const EXPORT_LENGTH = 32;
export const RESPONSE_NONCE_LENGTH = 32; // max(Nn, Nk) = max(12, 32) = 32
export const AES256_KEY_LENGTH = 32;
export const AES_GCM_NONCE_LENGTH = 12;
export const REQUEST_ENC_LENGTH = 32; // X25519 enc size

// Labels for HKDF-Expand (must match Go)
const RESPONSE_KEY_LABEL = 'key';
const RESPONSE_NONCE_LABEL = 'nonce';

/**
 * Response key material for encryption/decryption
 */
export interface ResponseKeyMaterial {
  key: Uint8Array;      // 32 bytes for AES-256
  nonceBase: Uint8Array; // 12 bytes, XORed with sequence number for each chunk
}

/**
 * Derives response encryption keys from the HPKE exported secret.
 *
 * This matches the Go implementation exactly:
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

  // Import the exported secret as HMAC key for HKDF-Extract
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(salt),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // prk = HMAC-SHA256(salt, secret) - this is HKDF-Extract
  const prkBuffer = await crypto.subtle.sign(
    'HMAC',
    hmacKey,
    toArrayBuffer(exportedSecret)
  );
  const prk = new Uint8Array(prkBuffer);

  // key = HKDF-Expand(prk, "key", 32)
  const key = await hkdfExpand(prk, RESPONSE_KEY_LABEL, AES256_KEY_LENGTH);

  // nonceBase = HKDF-Expand(prk, "nonce", 12)
  const nonceBase = await hkdfExpand(prk, RESPONSE_NONCE_LABEL, AES_GCM_NONCE_LENGTH);

  return { key, nonceBase };
}

/**
 * HKDF-Expand implementation using Web Crypto HMAC
 * Matches Go's hkdf.Expand(sha256.New, prk, info)
 */
async function hkdfExpand(prk: Uint8Array, info: string, length: number): Promise<Uint8Array> {
  const infoBytes = new TextEncoder().encode(info);
  const hashLen = 32; // SHA-256 output length
  const n = Math.ceil(length / hashLen);

  const hmacKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(prk),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const okm = new Uint8Array(n * hashLen);
  let t = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    // T(i) = HMAC(PRK, T(i-1) || info || i)
    const input = new Uint8Array(t.length + infoBytes.length + 1);
    input.set(t, 0);
    input.set(infoBytes, t.length);
    input[t.length + infoBytes.length] = i;

    const tBuffer = await crypto.subtle.sign(
      'HMAC',
      hmacKey,
      toArrayBuffer(input)
    );
    t = new Uint8Array(tBuffer);
    okm.set(t, (i - 1) * hashLen);
  }

  return okm.slice(0, length);
}

/**
 * Computes the nonce for a specific sequence number.
 * nonce = nonceBase XOR sequence_number (big-endian, padded to 12 bytes)
 *
 * This matches the Go implementation exactly.
 */
export function computeNonce(nonceBase: Uint8Array, seq: number): Uint8Array {
  if (nonceBase.length !== AES_GCM_NONCE_LENGTH) {
    throw new Error(`nonce base must be ${AES_GCM_NONCE_LENGTH} bytes`);
  }

  const nonce = new Uint8Array(AES_GCM_NONCE_LENGTH);
  nonce.set(nonceBase);

  // XOR with sequence number in the last 8 bytes (big-endian)
  // Go uses: nonce[len(nonce)-8+i] ^= byte(seq >> (56 - 8*i))
  for (let i = 0; i < 8; i++) {
    const shift = 56 - 8 * i;
    if (shift >= 0) {
      nonce[AES_GCM_NONCE_LENGTH - 8 + i] ^= (seq >>> shift) & 0xFF;
    } else {
      nonce[AES_GCM_NONCE_LENGTH - 8 + i] ^= (seq << (-shift)) & 0xFF;
    }
  }

  return nonce;
}

/**
 * Creates an AES-GCM cipher for encryption/decryption
 */
export async function createAESGCM(key: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    toArrayBuffer(key),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a chunk using the response key material
 */
export async function encryptChunk(
  km: ResponseKeyMaterial,
  seq: number,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const aesKey = await createAESGCM(km.key);
  const nonce = computeNonce(km.nonceBase, seq);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(nonce) },
    aesKey,
    toArrayBuffer(plaintext)
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
  const aesKey = await createAESGCM(km.key);
  const nonce = computeNonce(km.nonceBase, seq);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(nonce) },
    aesKey,
    toArrayBuffer(ciphertext)
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
