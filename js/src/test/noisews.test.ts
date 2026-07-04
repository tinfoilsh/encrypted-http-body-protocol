/**
 * Tests for EHBP-WS encrypted WebSocket channels.
 *
 * The in-process test server uses the `ws` package (dev dependency) and
 * runs the Noise NK responder side on top of the primitives exported by
 * noise.ts, so the client under test talks to an independent
 * implementation of the record layer.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';
import { WebSocketServer, type WebSocket as ServerSocket } from 'ws';

import { Identity } from '../identity.js';
import { NoiseWebSocket } from '../noisews.js';
import { NOISE_WS } from '../protocol.js';
import { hexToBytes, bytesToHex } from '../derive.js';
import {
  ChannelClosedError,
  ChannelTruncatedError,
  DecryptionError,
  EhbpError,
  HandshakeError,
  ProtocolError,
} from '../errors.js';
import {
  NoiseRecordCipher,
  NoiseSymmetricState,
  concatBytes,
  generateX25519KeyPair,
  importX25519PrivateKey,
  x25519SharedSecret,
  type X25519KeyPair,
} from '../noise.js';

const encoder = new TextEncoder();
const TEST_TIMEOUT = { timeout: 15_000 };

/** Responder side of Noise NK, used only by the test server. */
class NoiseNKResponder {
  private symmetric: NoiseSymmetricState;
  private staticPair: X25519KeyPair;
  private ephemeralPair: X25519KeyPair | null;
  private remoteEphemeral: Uint8Array | null = null;

  private constructor(
    symmetric: NoiseSymmetricState,
    staticPair: X25519KeyPair,
    ephemeralForTesting: X25519KeyPair | null,
  ) {
    this.symmetric = symmetric;
    this.staticPair = staticPair;
    this.ephemeralPair = ephemeralForTesting;
  }

  static async create(
    staticPair: X25519KeyPair,
    ephemeralForTesting?: X25519KeyPair,
  ): Promise<NoiseNKResponder> {
    const symmetric = await NoiseSymmetricState.create(NOISE_WS.PROTOCOL_NAME);
    await symmetric.mixHash(encoder.encode(NOISE_WS.PROLOGUE));
    await symmetric.mixHash(staticPair.publicKeyBytes);
    return new NoiseNKResponder(symmetric, staticPair, ephemeralForTesting ?? null);
  }

  async readMessage1(message: Uint8Array): Promise<void> {
    const remoteEphemeral = message.slice(0, 32);
    this.remoteEphemeral = remoteEphemeral;
    await this.symmetric.mixHash(remoteEphemeral);
    await this.symmetric.mixKey(
      await x25519SharedSecret(this.staticPair.privateKey, remoteEphemeral));
    await this.symmetric.decryptAndHash(message.slice(32));
  }

  async writeMessage2(): Promise<Uint8Array> {
    const ephemeral = this.ephemeralPair ?? await generateX25519KeyPair();
    this.ephemeralPair = ephemeral;
    await this.symmetric.mixHash(ephemeral.publicKeyBytes);
    await this.symmetric.mixKey(
      await x25519SharedSecret(ephemeral.privateKey, this.remoteEphemeral!));
    const encryptedPayload = await this.symmetric.encryptAndHash(new Uint8Array(0));
    return concatBytes(ephemeral.publicKeyBytes, encryptedPayload);
  }

  split(): Promise<[Uint8Array, Uint8Array]> {
    return this.symmetric.split();
  }

  get handshakeHash(): Uint8Array {
    return this.symmetric.handshakeHash;
  }
}

type ServerEvent =
  | { kind: 'message'; data: Uint8Array }
  | { kind: 'gone' };

class AsyncQueue<T> {
  private items: T[] = [];
  private waiters: ((item: T) => void)[] = [];

  push(item: T): void {
    const waiter = this.waiters.shift();
    if (waiter) waiter(item);
    else this.items.push(item);
  }

  next(): Promise<T> {
    const item = this.items.shift();
    if (item !== undefined) return Promise.resolve(item);
    return new Promise((resolveNext) => this.waiters.push(resolveNext));
  }
}

/** Encrypted record layer around one accepted server-side socket. */
class ServerConn {
  constructor(
    readonly socket: ServerSocket,
    private queue: AsyncQueue<ServerEvent>,
    private sendCipher: NoiseRecordCipher,
    private recvCipher: NoiseRecordCipher,
  ) {}

  async readRecord(): Promise<
    | { kind: 'data'; payload: Uint8Array }
    | { kind: 'close-record' }
    | { kind: 'gone' }
  > {
    const event = await this.queue.next();
    if (event.kind !== 'message') return { kind: 'gone' };
    const record = await this.recvCipher.decrypt(event.data);
    if (record[0] === NOISE_WS.RECORD_CLOSE) return { kind: 'close-record' };
    return { kind: 'data', payload: record.slice(1) };
  }

  async encryptData(payload: Uint8Array): Promise<Uint8Array> {
    return this.sendCipher.encrypt(
      concatBytes(Uint8Array.of(NOISE_WS.RECORD_DATA), payload));
  }

  async writeData(payload: Uint8Array): Promise<void> {
    this.socket.send(await this.encryptData(payload));
  }

  async writeCloseRecord(): Promise<void> {
    this.socket.send(await this.sendCipher.encrypt(Uint8Array.of(NOISE_WS.RECORD_CLOSE)));
  }

  sendRaw(data: Uint8Array | string): void {
    this.socket.send(data);
  }
}

type Behavior = (conn: ServerConn) => Promise<void>;

/** Echoes data records; answers a close record and closes the socket. */
const echoBehavior: Behavior = async (conn) => {
  for (;;) {
    const event = await conn.readRecord();
    if (event.kind === 'data') {
      await conn.writeData(event.payload);
      continue;
    }
    if (event.kind === 'close-record') {
      await conn.writeCloseRecord();
      conn.socket.close(1000);
    }
    return;
  }
};

interface TestServer {
  url: string;
  identity: Identity;
  close(): Promise<void>;
}

interface TestServerOptions {
  rekeyInterval?: number;
  negotiateSubprotocol?: boolean;
  /** Accept the upgrade but never answer the Noise handshake. */
  silentHandshake?: boolean;
}

async function runConnection(
  socket: ServerSocket,
  staticPair: X25519KeyPair,
  rekeyInterval: number,
  behavior: Behavior,
): Promise<void> {
  const queue = new AsyncQueue<ServerEvent>();
  socket.on('message', (data) => {
    queue.push({ kind: 'message', data: new Uint8Array(data as Buffer) });
  });
  socket.on('close', () => queue.push({ kind: 'gone' }));
  socket.on('error', () => queue.push({ kind: 'gone' }));

  try {
    const responder = await NoiseNKResponder.create(staticPair);
    const first = await queue.next();
    if (first.kind !== 'message') return;
    await responder.readMessage1(first.data);
    socket.send(await responder.writeMessage2());
    const [initiatorKey, responderKey] = await responder.split();
    const conn = new ServerConn(
      socket,
      queue,
      await NoiseRecordCipher.create(responderKey, rekeyInterval),
      await NoiseRecordCipher.create(initiatorKey, rekeyInterval),
    );
    await behavior(conn);
  } catch {
    socket.terminate();
  }
}

async function startServer(
  behavior: Behavior,
  options: TestServerOptions = {},
): Promise<TestServer> {
  const staticPair = await generateX25519KeyPair();
  const identity = await Identity.fromPublicKeyHex(bytesToHex(staticPair.publicKeyBytes));
  const rekeyInterval = options.rekeyInterval ?? NOISE_WS.REKEY_INTERVAL;

  const wss = new WebSocketServer({
    host: '127.0.0.1',
    port: 0,
    // Without negotiation the upgrade is refused, which the client
    // surfaces as a failed dial.
    handleProtocols:
      options.negotiateSubprotocol === false
        ? () => false
        : (protocols: Set<string>) =>
            protocols.has(NOISE_WS.SUBPROTOCOL) ? NOISE_WS.SUBPROTOCOL : false,
  });
  wss.on('connection', (socket) => {
    if (options.silentHandshake) {
      socket.on('message', () => {});
      socket.on('error', () => {});
      return;
    }
    void runConnection(socket, staticPair, rekeyInterval, behavior);
  });
  await new Promise<void>((resolveListening) =>
    wss.once('listening', () => resolveListening()));
  const port = (wss.address() as AddressInfo).port;

  return {
    url: `ws://127.0.0.1:${port}`,
    identity,
    close: () =>
      new Promise<void>((resolveClose) => {
        for (const client of wss.clients) client.terminate();
        wss.close(() => resolveClose());
      }),
  };
}

describe('NoiseWebSocket', () => {
  it('completes an echo round trip with a clean close', TEST_TIMEOUT, async () => {
    const server = await startServer(echoBehavior);
    try {
      const channel = await NoiseWebSocket.connect(server.url, server.identity);
      const payload = encoder.encode('hello encrypted websocket');
      await channel.send(payload);
      assert.deepStrictEqual(await channel.recv(), payload);

      await channel.close();
      assert.strictEqual(await channel.recv(), null);
      await assert.rejects(channel.send(payload), ChannelClosedError);
    } finally {
      await server.close();
    }
  });

  it('returns null after the peer closes, repeatedly', TEST_TIMEOUT, async () => {
    const server = await startServer(async (conn) => {
      const event = await conn.readRecord();
      if (event.kind !== 'data') return;
      await conn.writeCloseRecord();
      await conn.readRecord();
      conn.socket.close(1000);
    });
    try {
      const channel = await NoiseWebSocket.connect(server.url, server.identity);
      await channel.send(encoder.encode('one'));
      assert.strictEqual(await channel.recv(), null);
      assert.strictEqual(await channel.recv(), null);
      await assert.rejects(channel.send(encoder.encode('two')), ChannelClosedError);
    } finally {
      await server.close();
    }
  });

  it('rejects a handshake against the wrong server key', TEST_TIMEOUT, async () => {
    const server = await startServer(echoBehavior);
    try {
      const wrongPair = await generateX25519KeyPair();
      const wrongIdentity = await Identity.fromPublicKeyHex(
        bytesToHex(wrongPair.publicKeyBytes));
      await assert.rejects(
        NoiseWebSocket.connect(server.url, wrongIdentity), HandshakeError);
    } finally {
      await server.close();
    }
  });

  it('fails closed when a record is tampered with', TEST_TIMEOUT, async () => {
    const server = await startServer(async (conn) => {
      const event = await conn.readRecord();
      if (event.kind !== 'data') return;
      const ciphertext = await conn.encryptData(event.payload);
      ciphertext[0] ^= 0xff;
      conn.sendRaw(ciphertext);
      await conn.readRecord();
    });
    try {
      const channel = await NoiseWebSocket.connect(server.url, server.identity);
      await channel.send(encoder.encode('tamper me'));
      await assert.rejects(channel.recv(), DecryptionError);
      await assert.rejects(channel.recv(), DecryptionError);
      await assert.rejects(channel.send(encoder.encode('after')), DecryptionError);
    } finally {
      await server.close();
    }
  });

  it('detects truncation when the socket closes without a close record', TEST_TIMEOUT, async () => {
    const server = await startServer(async (conn) => {
      const event = await conn.readRecord();
      if (event.kind !== 'data') return;
      conn.socket.close(1000);
    });
    try {
      const channel = await NoiseWebSocket.connect(server.url, server.identity);
      await channel.send(encoder.encode('will be truncated'));
      await assert.rejects(channel.recv(), ChannelTruncatedError);
      await assert.rejects(channel.recv(), ChannelTruncatedError);
    } finally {
      await server.close();
    }
  });

  it('keeps both directions in sync across rekey boundaries', TEST_TIMEOUT, async () => {
    const server = await startServer(echoBehavior, { rekeyInterval: 3 });
    try {
      const channel = await NoiseWebSocket.connect(server.url, server.identity, {
        rekeyIntervalForTesting: 3,
      });
      for (let index = 0; index < 10; index++) {
        const payload = encoder.encode(`message ${index} across rekey`);
        await channel.send(payload);
        assert.deepStrictEqual(await channel.recv(), payload);
      }
      await channel.close();
    } finally {
      await server.close();
    }
  });

  it('rejects oversized writes without terminating the channel', TEST_TIMEOUT, async () => {
    const server = await startServer(echoBehavior);
    try {
      const channel = await NoiseWebSocket.connect(server.url, server.identity, {
        maxMessageSize: 1024,
      });
      await assert.rejects(channel.send(new Uint8Array(1025)), ProtocolError);

      const payload = encoder.encode('still works');
      await channel.send(payload);
      assert.deepStrictEqual(await channel.recv(), payload);
      await channel.close();
    } finally {
      await server.close();
    }
  });

  it('drains a pending recv to null when closed locally', TEST_TIMEOUT, async () => {
    const server = await startServer(async (conn) => {
      // Reads the client's close record without replying, so the pending
      // recv is woken by the socket teardown rather than a message.
      await conn.readRecord().catch(() => undefined);
    });
    try {
      const channel = await NoiseWebSocket.connect(server.url, server.identity);
      const pending = channel.recv();
      await channel.close();
      assert.strictEqual(await pending, null);
    } finally {
      await server.close();
    }
  });

  it('falls back to the default cap for a non-integer size limit', TEST_TIMEOUT, async () => {
    const server = await startServer(echoBehavior);
    try {
      const channel = await NoiseWebSocket.connect(server.url, server.identity, {
        maxMessageSize: Infinity,
      });
      // Infinity would silently disable the size guard, so it must fall
      // back to the default cap instead.
      await assert.rejects(
        channel.send(new Uint8Array(NOISE_WS.DEFAULT_MAX_MESSAGE_SIZE + 1)),
        ProtocolError);
      await channel.close();
    } finally {
      await server.close();
    }
  });

  it('fails the connection on an oversized inbound record', TEST_TIMEOUT, async () => {
    const server = await startServer(async (conn) => {
      const event = await conn.readRecord();
      if (event.kind !== 'data') return;
      await conn.writeData(new Uint8Array(4096));
      await conn.readRecord();
    });
    try {
      const channel = await NoiseWebSocket.connect(server.url, server.identity, {
        maxMessageSize: 1024,
      });
      await channel.send(encoder.encode('trigger'));
      await assert.rejects(channel.recv(), ProtocolError);
      await assert.rejects(channel.recv(), ProtocolError);
    } finally {
      await server.close();
    }
  });

  it('fails the connection on a non-binary message', TEST_TIMEOUT, async () => {
    const server = await startServer(async (conn) => {
      const event = await conn.readRecord();
      if (event.kind !== 'data') return;
      conn.sendRaw('plaintext frame');
      await conn.readRecord();
    });
    try {
      const channel = await NoiseWebSocket.connect(server.url, server.identity);
      await channel.send(encoder.encode('trigger'));
      await assert.rejects(channel.recv(), ProtocolError);
      await assert.rejects(channel.recv(), ProtocolError);
    } finally {
      await server.close();
    }
  });

  it('times out when the server never answers the handshake', TEST_TIMEOUT, async () => {
    const server = await startServer(echoBehavior, { silentHandshake: true });
    try {
      await assert.rejects(
        NoiseWebSocket.connect(server.url, server.identity, {
          handshakeTimeoutMs: 250,
        }),
        (err: unknown) =>
          err instanceof HandshakeError && /timed out/.test(err.message),
      );
    } finally {
      await server.close();
    }
  });

  it('requires the server to negotiate the subprotocol', TEST_TIMEOUT, async () => {
    const server = await startServer(echoBehavior, { negotiateSubprotocol: false });
    try {
      await assert.rejects(
        NoiseWebSocket.connect(server.url, server.identity),
        (err: unknown) => err instanceof EhbpError,
      );
    } finally {
      await server.close();
    }
  });
});

describe('NoiseRecordCipher', () => {
  it('serializes concurrent encrypts so nonces are never reused', async () => {
    const key = new Uint8Array(32).fill(7);
    const cipher = await NoiseRecordCipher.create(key, NOISE_WS.REKEY_INTERVAL);

    // Deliberately not awaited between calls: both encrypts start before
    // either advances the counter, exercising the interleaving window
    // WebCrypto's async encrypt/decrypt opens up.
    const first = cipher.encrypt(encoder.encode('first'));
    const second = cipher.encrypt(encoder.encode('second'));
    const [ciphertext1, ciphertext2] = await Promise.all([first, second]);

    const verifier = await NoiseRecordCipher.create(key, NOISE_WS.REKEY_INTERVAL);
    assert.deepStrictEqual(await verifier.decrypt(ciphertext1), encoder.encode('first'));
    assert.deepStrictEqual(await verifier.decrypt(ciphertext2), encoder.encode('second'));
  });

  it('serializes concurrent decrypts so nonces are never reused', async () => {
    const key = new Uint8Array(32).fill(9);
    const encrypter = await NoiseRecordCipher.create(key, NOISE_WS.REKEY_INTERVAL);
    const ciphertext1 = await encrypter.encrypt(encoder.encode('first'));
    const ciphertext2 = await encrypter.encrypt(encoder.encode('second'));

    const decrypter = await NoiseRecordCipher.create(key, NOISE_WS.REKEY_INTERVAL);
    const first = decrypter.decrypt(ciphertext1);
    const second = decrypter.decrypt(ciphertext2);
    assert.deepStrictEqual(await first, encoder.encode('first'));
    assert.deepStrictEqual(await second, encoder.encode('second'));
  });

  it('fails before reusing the reserved maximum nonce', async () => {
    const key = new Uint8Array(32).fill(3);
    const maxNonce = 0xffffffffffffffffn;

    const cipher = await NoiseRecordCipher.create(key, NOISE_WS.REKEY_INTERVAL, maxNonce - 1n);
    // The last usable nonce still works.
    await cipher.encrypt(encoder.encode('last record'));
    // The maximum nonce is reserved for rekeying and must never protect a
    // record.
    await assert.rejects(cipher.encrypt(encoder.encode('one too many')), ProtocolError);

    const exhausted = await NoiseRecordCipher.create(key, NOISE_WS.REKEY_INTERVAL, maxNonce);
    await assert.rejects(exhausted.decrypt(new Uint8Array(32)), ProtocolError);
  });
});

describe('cross-language interop', () => {
  it('matches the noisews test vector', TEST_TIMEOUT, async () => {
    const thisDir = dirname(fileURLToPath(import.meta.url));
    const vectorPath = resolve(thisDir, '../../../../test-vectors/noisews.json');
    const vector = JSON.parse(readFileSync(vectorPath, 'utf8')) as {
      protocolName: string;
      prologue: string;
      serverStaticPrivate: string;
      serverStaticPublic: string;
      clientEphemeralPrivate: string;
      serverEphemeralPrivate: string;
      message1: string;
      message2: string;
      handshakeHash: string;
      rekeyInterval: number;
      records: { dir: string; type: string; payload: string; ciphertext: string }[];
    };

    assert.strictEqual(NOISE_WS.PROTOCOL_NAME, vector.protocolName);
    assert.strictEqual(NOISE_WS.PROLOGUE, vector.prologue);
    assert.strictEqual(NOISE_WS.REKEY_INTERVAL, 1 << 16);

    const serverStatic = await importX25519PrivateKey(
      hexToBytes(vector.serverStaticPrivate));
    assert.strictEqual(
      bytesToHex(serverStatic.publicKeyBytes), vector.serverStaticPublic);
    const clientEphemeral = await importX25519PrivateKey(
      hexToBytes(vector.clientEphemeralPrivate));
    const serverEphemeral = await importX25519PrivateKey(
      hexToBytes(vector.serverEphemeralPrivate));

    const { NoiseNKInitiator } = await import('../noise.js');
    const initiator = await NoiseNKInitiator.create(
      hexToBytes(vector.serverStaticPublic), clientEphemeral);
    const responder = await NoiseNKResponder.create(serverStatic, serverEphemeral);

    const message1 = await initiator.writeMessage1();
    assert.strictEqual(bytesToHex(message1), vector.message1);
    await responder.readMessage1(message1);

    const message2 = await responder.writeMessage2();
    assert.strictEqual(bytesToHex(message2), vector.message2);
    const [clientSendKey, clientRecvKey] = await initiator.readMessage2(message2);

    assert.strictEqual(bytesToHex(initiator.handshakeHash), vector.handshakeHash);
    assert.strictEqual(bytesToHex(responder.handshakeHash), vector.handshakeHash);

    const [serverRecvKey, serverSendKey] = await responder.split();
    assert.deepStrictEqual(clientSendKey, serverRecvKey);
    assert.deepStrictEqual(clientRecvKey, serverSendKey);

    const clientSend = await NoiseRecordCipher.create(clientSendKey, vector.rekeyInterval);
    const clientRecv = await NoiseRecordCipher.create(clientRecvKey, vector.rekeyInterval);
    const serverSend = await NoiseRecordCipher.create(serverSendKey, vector.rekeyInterval);
    const serverRecv = await NoiseRecordCipher.create(serverRecvKey, vector.rekeyInterval);

    for (const [index, entry] of vector.records.entries()) {
      const payload = hexToBytes(entry.payload);
      let recordType: number;
      if (entry.type === 'data') recordType = NOISE_WS.RECORD_DATA;
      else if (entry.type === 'close') recordType = NOISE_WS.RECORD_CLOSE;
      else throw new Error(`record ${index}: unknown type ${entry.type}`);
      const record = concatBytes(Uint8Array.of(recordType), payload);

      const [send, recv] = entry.dir === 'c2s'
        ? [clientSend, serverRecv]
        : [serverSend, clientRecv];
      const ciphertext = await send.encrypt(record);
      assert.strictEqual(
        bytesToHex(ciphertext), entry.ciphertext, `record ${index} ciphertext`);
      const roundTrip = await recv.decrypt(ciphertext);
      assert.deepStrictEqual(roundTrip, record, `record ${index} round trip`);
    }
  });
});
