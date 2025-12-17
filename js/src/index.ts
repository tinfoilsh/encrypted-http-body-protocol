/**
 * JavaScript client for Encrypted HTTP Body Protocol (EHBP) using HPKE
 *
 * This library provides secure HTTP communication using Hybrid Public Key Encryption (HPKE)
 * as specified in RFC 9180. It automatically encrypts request bodies and decrypts response
 * bodies while preserving HTTP headers for routing.
 */

export { Identity } from './identity.js';
export type { RequestContext } from './identity.js';
export { Transport, createTransport } from './client.js';
export { PROTOCOL, HPKE_CONFIG } from './protocol.js';

// Export key derivation utilities for advanced usage
export {
  deriveResponseKeys,
  computeNonce,
  encryptChunk,
  decryptChunk,
  hexToBytes,
  bytesToHex,
  HPKE_REQUEST_INFO,
  EXPORT_LABEL,
  EXPORT_LENGTH,
  RESPONSE_NONCE_LENGTH,
  AES256_KEY_LENGTH,
  AES_GCM_NONCE_LENGTH,
} from './derive.js';
export type { ResponseKeyMaterial } from './derive.js';

export type { CipherSuite, SenderContext, RecipientContext, Key } from 'hpke';
