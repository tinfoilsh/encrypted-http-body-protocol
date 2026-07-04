/**
 * EHBP error hierarchy:
 *
 *   EhbpError (base)
 *   ├── KeyConfigMismatchError  - 422 key-config mismatch (stale key after rotation)
 *   ├── ProtocolError           - Malformed framing or crypto setup failure
 *   ├── DecryptionError         - AEAD authentication / decryption failure
 *   ├── HandshakeError          - Noise handshake or subprotocol negotiation failure
 *   ├── WebSocketError          - WebSocket dial or transport failure
 *   ├── ChannelClosedError      - Use of a locally closed encrypted channel
 *   └── ChannelTruncatedError   - Transport ended without an authenticated close
 */

export class EhbpError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = 'EhbpError';
    if (options?.cause) this.cause = options.cause;
  }
}

/**
 * Server returned 422 with problem+json key-config mismatch.
 * The request was never processed — re-sending after re-keying is safe.
 */
export class KeyConfigMismatchError extends EhbpError {
  public readonly title: string;
  constructor(title?: string) {
    super(title || 'Server key configuration mismatch');
    this.name = 'KeyConfigMismatchError';
    this.title = title || '';
  }
}

export class ProtocolError extends EhbpError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'ProtocolError';
  }
}

export class DecryptionError extends EhbpError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'DecryptionError';
  }
}

export class HandshakeError extends EhbpError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'HandshakeError';
  }
}

export class WebSocketError extends EhbpError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'WebSocketError';
  }
}

/**
 * The encrypted channel was closed locally; no further sends or
 * receives are possible.
 */
export class ChannelClosedError extends EhbpError {
  constructor(message?: string) {
    super(message || 'encrypted channel is closed');
    this.name = 'ChannelClosedError';
  }
}

/**
 * The WebSocket ended without the peer's authenticated close record, so
 * an attacker may have truncated the stream.
 */
export class ChannelTruncatedError extends EhbpError {
  constructor(message: string) {
    super(message);
    this.name = 'ChannelTruncatedError';
  }
}
