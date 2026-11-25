/**
 * JavaScript client for Encrypted HTTP Body Protocol (EHBP) using HPKE
 *
 * This library provides secure HTTP communication using Hybrid Public Key Encryption (HPKE)
 * as specified in RFC 9180. It automatically encrypts request bodies and decrypts response
 * bodies while preserving HTTP headers for routing.
 *
 * The public surface is conformance/spec/handler.md section 7: Transport
 * (create, request, sessionRecoveryToken), discover, selfCheck, the error
 * classes and the protocol constants. `core` is for conformance and tests only.
 */

export { Transport, discover, selfCheck } from './client.js';
export type { TransportOptions, KeySource, ResolvedKeys } from './client.js';
export { core } from './identity.js';
export type { SessionRecoveryToken } from './identity.js';
export { PROTOCOL, HPKE_CONFIG } from './protocol.js';
export {
  Code,
  codeOf,
  EhbpError,
  InvalidKeyConfigError,
  UnsupportedSuiteError,
  InvalidEncapsulatedKeyError,
  HpkeSetupFailedError,
  MissingResponseNonceError,
  UnexpectedRedirectError,
  InvalidResponseNonceError,
  DuplicateResponseNonceError,
  KeyConfigMismatchError,
  FramingTruncatedError,
  ChunkTooLargeError,
  AeadDecryptFailedError,
  SequenceOverflowError,
  InvalidTokenError,
  InvalidInputError,
} from './errors.js';
