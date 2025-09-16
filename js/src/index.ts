/**
 * JavaScript client for Encrypted HTTP Body Protocol (EHBP) using HPKE
 * 
 * This library provides secure HTTP communication using Hybrid Public Key Encryption (HPKE)
 * as specified in RFC 9180. It automatically encrypts request bodies and decrypts response
 * bodies while preserving HTTP headers for routing.
 */

export { Identity } from './identity.js';
export { Transport, createTransport } from './client.js';
export { PROTOCOL, HPKE_CONFIG } from './protocol.js';

// Re-export commonly used types
export type { CipherSuite } from '@hpke/core';
