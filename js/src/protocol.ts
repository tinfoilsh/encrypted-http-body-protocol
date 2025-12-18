/**
 * Protocol constants for EHBP (Encrypted HTTP Body Protocol)
 */
export const PROTOCOL = {
  ENCAPSULATED_KEY_HEADER: 'Ehbp-Encapsulated-Key',
  RESPONSE_NONCE_HEADER: 'Ehbp-Response-Nonce',
  KEYS_MEDIA_TYPE: 'application/ohttp-keys',
  KEYS_PATH: '/.well-known/hpke-keys',
} as const;

/**
 * HPKE suite configuration matching the Go implementation
 */
export const HPKE_CONFIG = {
  KEM: 0x0020, // X25519 HKDF SHA256
  KDF: 0x0001, // HKDF SHA256
  AEAD: 0x0002 // AES-256-GCM
} as const;
