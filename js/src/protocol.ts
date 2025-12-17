/**
 * Protocol constants for EHBP (Encrypted HTTP Body Protocol)
 */
export const PROTOCOL = {
  // Request header - contains the HPKE encapsulated key
  ENCAPSULATED_KEY_HEADER: 'Ehbp-Encapsulated-Key',

  // Response header - contains the random nonce for response key derivation
  RESPONSE_NONCE_HEADER: 'Ehbp-Response-Nonce',

  // Common headers
  KEYS_MEDIA_TYPE: 'application/ohttp-keys',
  KEYS_PATH: '/.well-known/hpke-keys',
  FALLBACK_HEADER: 'Ehbp-Fallback',

  /**
   * @deprecated This header is VULNERABLE to MitM key substitution attacks. Do NOT use.
   */
  CLIENT_PUBLIC_KEY_HEADER: 'Ehbp-Client-Public-Key',
} as const;

/**
 * HPKE suite configuration matching the Go implementation
 */
export const HPKE_CONFIG = {
  KEM: 0x0020, // X25519 HKDF SHA256
  KDF: 0x0001, // HKDF SHA256
  AEAD: 0x0002 // AES-256-GCM
} as const;
