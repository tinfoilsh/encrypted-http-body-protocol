/**
 * EHBP errors: one subclass per canonical, cross-SDK error class (SPEC §5.5), named
 * after its code. Every message is "<CODE>: <detail>". Codes are for the in-process
 * caller only and are never sent on the wire (SPEC §5.4.4).
 */

export const Code = {
  INVALID_KEY_CONFIG: 'INVALID_KEY_CONFIG',
  UNSUPPORTED_SUITE: 'UNSUPPORTED_SUITE',
  INVALID_ENCAPSULATED_KEY: 'INVALID_ENCAPSULATED_KEY',
  HPKE_SETUP_FAILED: 'HPKE_SETUP_FAILED',
  MISSING_RESPONSE_NONCE: 'MISSING_RESPONSE_NONCE',
  INVALID_RESPONSE_NONCE: 'INVALID_RESPONSE_NONCE',
  DUPLICATE_RESPONSE_NONCE: 'DUPLICATE_RESPONSE_NONCE',
  KEY_CONFIG_MISMATCH: 'KEY_CONFIG_MISMATCH',
  FRAMING_TRUNCATED: 'FRAMING_TRUNCATED',
  CHUNK_TOO_LARGE: 'CHUNK_TOO_LARGE',
  AEAD_DECRYPT_FAILED: 'AEAD_DECRYPT_FAILED',
  SEQUENCE_OVERFLOW: 'SEQUENCE_OVERFLOW',
  INVALID_TOKEN: 'INVALID_TOKEN',
  INVALID_INPUT: 'INVALID_INPUT',
} as const;
export type Code = (typeof Code)[keyof typeof Code];

type Opts = { cause?: unknown };

/** Base class; catch this for any EHBP failure. Only subclasses are thrown. */
export abstract class EhbpError extends Error {
  public readonly code: Code;
  protected constructor(code: Code, detail: string, options?: Opts) {
    super(`${code}: ${detail}`);
    this.code = code;
    if (options?.cause) this.cause = options.cause;
  }
}

export class InvalidKeyConfigError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.INVALID_KEY_CONFIG, detail, options); this.name = 'InvalidKeyConfigError'; }
}
export class UnsupportedSuiteError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.UNSUPPORTED_SUITE, detail, options); this.name = 'UnsupportedSuiteError'; }
}
export class InvalidEncapsulatedKeyError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.INVALID_ENCAPSULATED_KEY, detail, options); this.name = 'InvalidEncapsulatedKeyError'; }
}
export class HpkeSetupFailedError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.HPKE_SETUP_FAILED, detail, options); this.name = 'HpkeSetupFailedError'; }
}
export class MissingResponseNonceError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.MISSING_RESPONSE_NONCE, detail, options); this.name = 'MissingResponseNonceError'; }
}
export class InvalidResponseNonceError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.INVALID_RESPONSE_NONCE, detail, options); this.name = 'InvalidResponseNonceError'; }
}
export class DuplicateResponseNonceError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.DUPLICATE_RESPONSE_NONCE, detail, options); this.name = 'DuplicateResponseNonceError'; }
}
/** HTTP 422 key-configuration problem: refresh the key config and retry (SPEC §5.4.3). */
export class KeyConfigMismatchError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.KEY_CONFIG_MISMATCH, detail, options); this.name = 'KeyConfigMismatchError'; }
}
export class FramingTruncatedError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.FRAMING_TRUNCATED, detail, options); this.name = 'FramingTruncatedError'; }
}
export class ChunkTooLargeError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.CHUNK_TOO_LARGE, detail, options); this.name = 'ChunkTooLargeError'; }
}
export class AeadDecryptFailedError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.AEAD_DECRYPT_FAILED, detail, options); this.name = 'AeadDecryptFailedError'; }
}
export class SequenceOverflowError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.SEQUENCE_OVERFLOW, detail, options); this.name = 'SequenceOverflowError'; }
}
export class InvalidTokenError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.INVALID_TOKEN, detail, options); this.name = 'InvalidTokenError'; }
}
export class InvalidInputError extends EhbpError {
  constructor(detail: string, options?: Opts) { super(Code.INVALID_INPUT, detail, options); this.name = 'InvalidInputError'; }
}

/** The canonical code of any thrown value, or undefined for a non-EHBP error. */
export function codeOf(err: unknown): Code | undefined {
  return err instanceof EhbpError ? err.code : undefined;
}
