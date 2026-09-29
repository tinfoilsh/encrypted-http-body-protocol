/**
 * EHBP errors. Every error carries a canonical, cross-SDK `code` (SPEC §5.5) and a
 * message of the form "<CODE>: <detail>", so a caller switches on one key in any
 * language. Codes are for the in-process caller only and are never sent on the
 * wire (SPEC §5.4.4).
 *
 *   EhbpError (base, carries `code`)
 *   ├── KeyConfigMismatchError  - KEY_CONFIG_MISMATCH (422; re-key and retry is safe)
 *   ├── ProtocolError           - framing / header / config violation; `code` says which
 *   └── DecryptionError         - AEAD_DECRYPT_FAILED
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

export class EhbpError extends Error {
  public readonly code: Code;
  constructor(code: Code, detail: string, options?: { cause?: unknown }) {
    super(`${code}: ${detail}`);
    this.name = 'EhbpError';
    this.code = code;
    if (options?.cause) this.cause = options.cause;
  }
}

export class KeyConfigMismatchError extends EhbpError {
  public readonly title: string;
  constructor(title?: string) {
    super(Code.KEY_CONFIG_MISMATCH, title || 'Server key configuration mismatch');
    this.name = 'KeyConfigMismatchError';
    this.title = title || '';
  }
}

export class ProtocolError extends EhbpError {
  constructor(code: Code, detail: string, options?: { cause?: unknown }) {
    super(code, detail, options);
    this.name = 'ProtocolError';
  }
}

export class DecryptionError extends EhbpError {
  constructor(detail: string, options?: { cause?: unknown }) {
    super(Code.AEAD_DECRYPT_FAILED, detail, options);
    this.name = 'DecryptionError';
  }
}

/** The canonical code of any thrown value, or undefined for a non-EHBP error. */
export function codeOf(err: unknown): Code | undefined {
  return err instanceof EhbpError ? err.code : undefined;
}
