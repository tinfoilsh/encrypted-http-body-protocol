/**
 * Protocol constants for EHBP (Encrypted HTTP Body Protocol)
 */
export const PROTOCOL = {
  ENCAPSULATED_KEY_HEADER: 'Ehbp-Encapsulated-Key',
  RESPONSE_NONCE_HEADER: 'Ehbp-Response-Nonce',
  KEYS_MEDIA_TYPE: 'application/ohttp-keys',
  KEYS_PATH: '/.well-known/hpke-keys',
  PROBLEM_JSON_MEDIA_TYPE: 'application/problem+json',
  KEY_CONFIG_PROBLEM_TYPE: 'urn:ietf:params:ehbp:error:key-config',
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
 * EHBP-WS constants (SPEC Section 8): encrypted WebSocket channels
 * secured with the Noise NK handshake, keyed by the server's X25519
 * identity key.
 */
export const NOISE_WS = {
  /** WebSocket subprotocol negotiated during the upgrade. */
  SUBPROTOCOL: 'ehbp.noise.v1',
  /** Noise protocol name; also the first input to the handshake hash. */
  PROTOCOL_NAME: 'Noise_NK_25519_AESGCM_SHA256',
  /** Prologue bound into the handshake hash. */
  PROLOGUE: 'ehbp noise websocket v1',
  /** Record type carrying application data. */
  RECORD_DATA: 0x01,
  /** Record type signaling authenticated channel termination. */
  RECORD_CLOSE: 0x02,
  /** Default cap on a record's plaintext payload (1 MiB). */
  DEFAULT_MAX_MESSAGE_SIZE: 1 << 20,
  /** Read-limit allowance for the record type byte and AEAD tag. */
  RECORD_OVERHEAD: 64,
  /** Cap on handshake message size. */
  HANDSHAKE_READ_LIMIT: 4096,
  /** Default cap on the dial-plus-handshake duration (SPEC Section 8). */
  HANDSHAKE_TIMEOUT_MS: 10_000,
  /** Records per direction before the sending key is ratcheted. */
  REKEY_INTERVAL: 1 << 16,
} as const;
