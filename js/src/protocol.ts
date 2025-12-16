/**
 * Protocol constants for EHBP (Encrypted HTTP Body Protocol)
 */
export const PROTOCOL = {
  ENCAPSULATED_KEY_HEADER: 'Ehbp-Encapsulated-Key',
  KEYS_MEDIA_TYPE: 'application/ohttp-keys',
  KEYS_PATH: '/.well-known/hpke-keys',
  FALLBACK_HEADER: 'Ehbp-Fallback'
} as const;

/**
 * HPKE suite configuration matching the Go implementation
 */
export const HPKE_CONFIG = {
  KEM: 0x0020, // X25519 HKDF SHA256
  KDF: 0x0001, // HKDF SHA256
  AEAD: 0x0002 // AES-256-GCM
} as const;

/**
 * AEAD parameters per RFC 9180
 */
const AEAD_PARAMS: Record<number, { keyLength: number; nonceLength: number }> = {
  0x0001: { keyLength: 16, nonceLength: 12 }, // AES-128-GCM
  0x0002: { keyLength: 32, nonceLength: 12 }, // AES-256-GCM
  0x0003: { keyLength: 32, nonceLength: 12 }, // ChaCha20Poly1305
};

/**
 * Response encryption parameters (derived from HPKE Export interface)
 * See RFC 9180 Section 9.8 for bidirectional encryption
 */
export const RESPONSE_ENCRYPTION = {
  EXPORT_CONTEXT: new TextEncoder().encode('ehbp response'),
  KEY_LENGTH: AEAD_PARAMS[HPKE_CONFIG.AEAD].keyLength,
  NONCE_LENGTH: AEAD_PARAMS[HPKE_CONFIG.AEAD].nonceLength
} as const;
