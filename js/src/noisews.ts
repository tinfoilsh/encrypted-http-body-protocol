/**
 * EHBP-WS: encrypted WebSocket channels (SPEC Section 8).
 *
 * A channel runs the Noise NK handshake over a WebSocket, keyed by the
 * server's X25519 identity key, then exchanges encrypted records:
 *
 *   record = AEAD(key, nonce, record_type || payload)
 *
 * Termination is authenticated with an encrypted close record; a
 * transport that ends without one surfaces ChannelTruncatedError.
 *
 * Only browser-native APIs (WebSocket, WebCrypto) are used.
 */

import { Identity } from './identity.js';
import { hexToBytes } from './derive.js';
import { NOISE_WS } from './protocol.js';
import {
  ChannelClosedError,
  ChannelTruncatedError,
  DecryptionError,
  EhbpError,
  HandshakeError,
  ProtocolError,
  WebSocketError,
} from './errors.js';
import { NoiseNKInitiator, NoiseRecordCipher } from './noise.js';

const CLOSE_CODE_NORMAL = 1000;
// The browser close() API only accepts 1000 or 3000-4999, so policy
// violations are signaled with an application code mirroring 1008.
const CLOSE_CODE_POLICY_VIOLATION = 4008;

type SocketEvent =
  | { kind: 'message'; data: unknown }
  | { kind: 'close'; detail: string }
  | { kind: 'error'; detail: string };

/** Buffers WebSocket events so they can be consumed with async reads. */
class SocketEventQueue {
  private events: SocketEvent[] = [];
  private waiters: ((event: SocketEvent) => void)[] = [];

  push(event: SocketEvent): void {
    const waiter = this.waiters.shift();
    if (waiter) {
      waiter(event);
    } else {
      this.events.push(event);
    }
  }

  next(): Promise<SocketEvent> {
    const event = this.events.shift();
    if (event) return Promise.resolve(event);
    return new Promise((resolve) => this.waiters.push(resolve));
  }
}

export interface NoiseWebSocketOptions {
  /**
   * Cap on a record's plaintext payload in bytes, for sending and
   * receiving. Defaults to NOISE_WS.DEFAULT_MAX_MESSAGE_SIZE (1 MiB).
   */
  maxMessageSize?: number;
  /**
   * Cap in milliseconds on the WebSocket dial plus Noise handshake.
   * Defaults to NOISE_WS.HANDSHAKE_TIMEOUT_MS (10 seconds).
   */
  handshakeTimeoutMs?: number;
  /**
   * Test-only override of the rekey interval. Peers that disagree on it
   * fail record authentication after the earlier boundary.
   */
  rekeyIntervalForTesting?: number;
}

function websocketUrl(url: string | URL): URL {
  const parsed = new URL(url.toString());
  if (parsed.protocol === 'http:') parsed.protocol = 'ws:';
  else if (parsed.protocol === 'https:') parsed.protocol = 'wss:';
  if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
    throw new WebSocketError(`unsupported URL scheme: ${parsed.protocol}`);
  }
  return parsed;
}

function errorDetail(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * An encrypted WebSocket channel. Create with NoiseWebSocket.connect;
 * after any protocol failure the channel is fail-closed and every
 * subsequent call reproduces the terminal error.
 */
export class NoiseWebSocket {
  private ws: WebSocket;
  private queue: SocketEventQueue;
  private sendCipher: NoiseRecordCipher;
  private recvCipher: NoiseRecordCipher;
  private maxMessageSize: number;
  private sticky: EhbpError | null = null;
  private peerClosed = false;
  private closeSent = false;
  private localClosed = false;

  private constructor(
    ws: WebSocket,
    queue: SocketEventQueue,
    sendCipher: NoiseRecordCipher,
    recvCipher: NoiseRecordCipher,
    maxMessageSize: number,
  ) {
    this.ws = ws;
    this.queue = queue;
    this.sendCipher = sendCipher;
    this.recvCipher = recvCipher;
    this.maxMessageSize = maxMessageSize;
  }

  /**
   * Dials the URL (http/https schemes are mapped to ws/wss), negotiates
   * the EHBP subprotocol, and runs the Noise NK handshake against the
   * server identity.
   */
  static async connect(
    url: string | URL,
    serverIdentity: Identity,
    options: NoiseWebSocketOptions = {},
  ): Promise<NoiseWebSocket> {
    const maxMessageSize =
      options.maxMessageSize && options.maxMessageSize > 0
        ? options.maxMessageSize
        : NOISE_WS.DEFAULT_MAX_MESSAGE_SIZE;
    const rekeyInterval =
      options.rekeyIntervalForTesting && options.rekeyIntervalForTesting > 0
        ? options.rekeyIntervalForTesting
        : NOISE_WS.REKEY_INTERVAL;
    const handshakeTimeoutMs =
      options.handshakeTimeoutMs && options.handshakeTimeoutMs > 0
        ? options.handshakeTimeoutMs
        : NOISE_WS.HANDSHAKE_TIMEOUT_MS;
    const serverStaticKey = hexToBytes(await serverIdentity.getPublicKeyHex());

    const target = websocketUrl(url);
    let ws: WebSocket;
    try {
      ws = new WebSocket(target, [NOISE_WS.SUBPROTOCOL]);
    } catch (err) {
      throw new WebSocketError(`dial ${target}: ${errorDetail(err)}`, { cause: err });
    }
    ws.binaryType = 'arraybuffer';

    const queue = new SocketEventQueue();
    let opened = false;
    const openPromise = new Promise<void>((resolve, reject) => {
      ws.onopen = () => {
        opened = true;
        resolve();
      };
      // Browsers surface subprotocol and dial failures only as generic
      // error/close events before open.
      ws.onerror = () => {
        if (!opened) {
          reject(new WebSocketError(`dial ${target} failed`));
        } else {
          queue.push({ kind: 'error', detail: 'websocket transport error' });
        }
      };
      ws.onclose = (event) => {
        const detail = `websocket closed (code ${event.code})`;
        if (!opened) {
          reject(new WebSocketError(`dial ${target} failed: ${detail}`));
        } else {
          queue.push({ kind: 'close', detail });
        }
      };
    });
    ws.onmessage = (event) => queue.push({ kind: 'message', data: event.data });

    // A stalled or malicious peer must not keep the dial pending forever,
    // so the socket is torn down once the deadline passes; the resulting
    // close/error event unblocks whichever step is being awaited.
    let timedOut = false;
    let handshakeDone = false;
    const timer = setTimeout(() => {
      if (handshakeDone) return;
      timedOut = true;
      try {
        ws.close(CLOSE_CODE_POLICY_VIOLATION, 'handshake timeout');
      } catch {
        // Best-effort teardown.
      }
    }, handshakeTimeoutMs);

    try {
      await openPromise;
      if (ws.protocol !== NOISE_WS.SUBPROTOCOL) {
        throw new HandshakeError(
          `server did not negotiate subprotocol ${NOISE_WS.SUBPROTOCOL}`);
      }

      const handshake = await NoiseNKInitiator.create(serverStaticKey);
      ws.send(await handshake.writeMessage1());

      const event = await queue.next();
      if (event.kind !== 'message') {
        throw new HandshakeError(`connection ended during handshake: ${event.detail}`);
      }
      if (!(event.data instanceof ArrayBuffer)) {
        throw new HandshakeError('handshake message must be binary');
      }
      if (event.data.byteLength > NOISE_WS.HANDSHAKE_READ_LIMIT) {
        throw new HandshakeError(
          `handshake message of ${event.data.byteLength} bytes exceeds read limit`);
      }
      const [sendKey, recvKey] = await handshake.readMessage2(new Uint8Array(event.data));

      handshakeDone = true;
      return new NoiseWebSocket(
        ws,
        queue,
        await NoiseRecordCipher.create(sendKey, rekeyInterval),
        await NoiseRecordCipher.create(recvKey, rekeyInterval),
        maxMessageSize,
      );
    } catch (err) {
      try {
        ws.close(CLOSE_CODE_POLICY_VIOLATION, 'handshake failed');
      } catch {
        // Best-effort teardown.
      }
      if (timedOut) {
        throw new HandshakeError(
          `handshake timed out after ${handshakeTimeoutMs}ms`, { cause: err });
      }
      if (err instanceof EhbpError) throw err;
      throw new HandshakeError(`handshake failed: ${errorDetail(err)}`, { cause: err });
    } finally {
      clearTimeout(timer);
    }
  }

  /** Encrypts payload as a data record and sends it. */
  async send(payload: Uint8Array): Promise<void> {
    if (this.sticky) throw this.sticky;
    if (this.localClosed || this.closeSent) throw new ChannelClosedError();
    if (payload.length > this.maxMessageSize) {
      throw new ProtocolError(
        `message of ${payload.length} bytes exceeds maximum of ${this.maxMessageSize}`);
    }
    const record = new Uint8Array(1 + payload.length);
    record[0] = NOISE_WS.RECORD_DATA;
    record.set(payload, 1);
    const ciphertext = await this.sendCipher.encrypt(record);
    try {
      this.ws.send(ciphertext);
    } catch (err) {
      throw new WebSocketError(`send: ${errorDetail(err)}`, { cause: err });
    }
  }

  /**
   * Receives and decrypts the next data record. Returns null once the
   * peer has performed an authenticated close.
   */
  async recv(): Promise<Uint8Array | null> {
    if (this.sticky) throw this.sticky;
    // After a local close the browser discards any still-inbound
    // messages, including the peer's close-record reply, so the channel
    // is simply drained.
    if (this.peerClosed || this.localClosed) return null;

    const event = await this.queue.next();
    if (event.kind !== 'message') {
      throw this.transportEnded(event.detail);
    }
    if (!(event.data instanceof ArrayBuffer)) {
      throw this.terminate(new ProtocolError('unexpected non-binary websocket message'));
    }
    const ciphertext = new Uint8Array(event.data);
    // Browsers expose no inbound frame size limit, so enforce the read
    // limit before decrypting.
    if (ciphertext.length > this.maxMessageSize + NOISE_WS.RECORD_OVERHEAD) {
      throw this.terminate(new ProtocolError(
        `received frame of ${ciphertext.length} bytes exceeds read limit`));
    }

    let record: Uint8Array;
    try {
      record = await this.recvCipher.decrypt(ciphertext);
    } catch (err) {
      throw this.terminate(
        err instanceof DecryptionError
          ? err
          : new DecryptionError('failed to decrypt record', { cause: err }));
    }
    if (record.length === 0) {
      throw this.terminate(new ProtocolError('received empty record'));
    }

    const recordType = record[0];
    const payload = record.slice(1);
    switch (recordType) {
      case NOISE_WS.RECORD_DATA:
        if (payload.length > this.maxMessageSize) {
          throw this.terminate(new ProtocolError(
            `message of ${payload.length} bytes exceeds maximum of ${this.maxMessageSize}`));
        }
        return payload;
      case NOISE_WS.RECORD_CLOSE:
        this.peerClosed = true;
        try {
          await this.closeInternal();
        } catch {
          // The reply close record is best-effort.
        }
        return null;
      default:
        throw this.terminate(new ProtocolError(`unknown record type ${recordType}`));
    }
  }

  /**
   * Performs an authenticated close: sends an encrypted close record and
   * closes the WebSocket. Safe to call multiple times.
   */
  async close(): Promise<void> {
    this.localClosed = true;
    await this.closeInternal();
  }

  private async closeInternal(): Promise<void> {
    if (this.closeSent) return;
    this.closeSent = true;
    this.localClosed = true;
    let sendError: unknown = null;
    try {
      const ciphertext = await this.sendCipher.encrypt(
        Uint8Array.of(NOISE_WS.RECORD_CLOSE));
      this.ws.send(ciphertext);
    } catch (err) {
      sendError = err;
    }
    try {
      this.ws.close(CLOSE_CODE_NORMAL, 'closing');
    } catch {
      // Best-effort teardown.
    }
    if (sendError) {
      throw new WebSocketError(
        `send close record: ${errorDetail(sendError)}`, { cause: sendError });
    }
  }

  /** Fails the connection and makes err the channel's terminal state. */
  private terminate(err: EhbpError): EhbpError {
    this.sticky = err;
    this.localClosed = true;
    this.closeSent = true;
    try {
      this.ws.close(CLOSE_CODE_POLICY_VIOLATION, 'protocol violation');
    } catch {
      // Best-effort teardown.
    }
    return err;
  }

  /** Maps a transport-level end of stream to the terminal channel state. */
  private transportEnded(detail: string): EhbpError {
    const err = this.localClosed
      ? new ChannelClosedError()
      : new ChannelTruncatedError(
          `connection ended without close record: ${detail}`);
    this.sticky = err;
    return err;
  }
}
