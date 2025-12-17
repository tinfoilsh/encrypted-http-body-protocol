import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  deriveResponseKeys,
  computeNonce,
  encryptChunk,
  decryptChunk,
  hexToBytes,
  bytesToHex,
  EXPORT_LENGTH,
  RESPONSE_NONCE_LENGTH,
  AES_GCM_NONCE_LENGTH,
  REQUEST_ENC_LENGTH,
} from '../derive.js';

describe('deriveResponseKeys', () => {
  it('should derive deterministic keys', async () => {
    const exportedSecret = new Uint8Array(32).fill(1);
    const requestEnc = new Uint8Array(32).fill(2);
    const responseNonce = new Uint8Array(32).fill(3);

    const km1 = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce);
    const km2 = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce);

    assert.deepStrictEqual(km1.key, km2.key, 'Keys should be identical');
    assert.deepStrictEqual(km1.nonceBase, km2.nonceBase, 'Nonce bases should be identical');
  });

  it('should produce different keys for different inputs', async () => {
    const exportedSecret = new Uint8Array(32).fill(1);
    const requestEnc = new Uint8Array(32).fill(2);
    const responseNonce1 = new Uint8Array(32).fill(3);
    const responseNonce2 = new Uint8Array(32).fill(4);

    const km1 = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce1);
    const km2 = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce2);

    assert.notDeepStrictEqual(km1.key, km2.key, 'Keys should differ for different nonces');
  });

  it('should reject invalid exported secret length', async () => {
    const shortSecret = new Uint8Array(16);
    const requestEnc = new Uint8Array(32);
    const responseNonce = new Uint8Array(32);

    await assert.rejects(
      async () => deriveResponseKeys(shortSecret, requestEnc, responseNonce),
      /exported secret must be 32 bytes/
    );
  });

  it('should reject invalid request enc length', async () => {
    const exportedSecret = new Uint8Array(32);
    const shortEnc = new Uint8Array(16);
    const responseNonce = new Uint8Array(32);

    await assert.rejects(
      async () => deriveResponseKeys(exportedSecret, shortEnc, responseNonce),
      /request enc must be 32 bytes/
    );
  });

  it('should reject invalid response nonce length', async () => {
    const exportedSecret = new Uint8Array(32);
    const requestEnc = new Uint8Array(32);
    const shortNonce = new Uint8Array(12); // Wrong - should be 32

    await assert.rejects(
      async () => deriveResponseKeys(exportedSecret, requestEnc, shortNonce),
      /response nonce must be 32 bytes/
    );
  });
});

describe('computeNonce', () => {
  it('should return base nonce for sequence 0', () => {
    const nonceBase = new Uint8Array(12).fill(0xFF);
    const nonce = computeNonce(nonceBase, 0);
    assert.deepStrictEqual(nonce, nonceBase, 'Nonce should equal base for seq 0');
  });

  it('should XOR correctly for sequence 1', () => {
    const nonceBase = new Uint8Array(12).fill(0xFF);
    const nonce = computeNonce(nonceBase, 1);
    assert.strictEqual(nonce[11], 0xFE, 'Last byte should be 0xFF XOR 0x01 = 0xFE');
  });

  it('should produce unique nonces for different sequences', () => {
    const nonceBase = new Uint8Array(12).fill(0);
    const seen = new Set<string>();

    for (let i = 0; i < 1000; i++) {
      const nonce = computeNonce(nonceBase, i);
      const key = bytesToHex(nonce);
      assert(!seen.has(key), `Nonce for seq ${i} should be unique`);
      seen.add(key);
    }
  });

  it('should handle large sequence numbers', () => {
    const nonceBase = new Uint8Array(12).fill(0);
    // Test doesn't throw for large numbers
    const nonce = computeNonce(nonceBase, 0xFFFFFFFF);
    assert.strictEqual(nonce.length, 12);
  });
});

describe('encrypt/decrypt round trip', () => {
  it('should round-trip successfully', async () => {
    const exportedSecret = new Uint8Array(32);
    crypto.getRandomValues(exportedSecret);
    const requestEnc = new Uint8Array(32);
    crypto.getRandomValues(requestEnc);
    const responseNonce = new Uint8Array(32);
    crypto.getRandomValues(responseNonce);

    const km = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce);

    const plaintext = new TextEncoder().encode('Hello, World!');
    const ciphertext = await encryptChunk(km, 0, plaintext);
    const decrypted = await decryptChunk(km, 0, ciphertext);

    assert.deepStrictEqual(decrypted, plaintext, 'Decrypted should match original');
  });

  it('should fail with wrong sequence number', async () => {
    const exportedSecret = new Uint8Array(32);
    crypto.getRandomValues(exportedSecret);
    const requestEnc = new Uint8Array(32);
    const responseNonce = new Uint8Array(32);

    const km = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce);

    const plaintext = new TextEncoder().encode('Hello, World!');
    const ciphertext = await encryptChunk(km, 0, plaintext);

    // Try to decrypt with wrong sequence
    await assert.rejects(
      async () => decryptChunk(km, 1, ciphertext),
      /error/i // AES-GCM decryption failure
    );
  });

  it('should encrypt multiple chunks with different nonces', async () => {
    const exportedSecret = new Uint8Array(32);
    crypto.getRandomValues(exportedSecret);
    const requestEnc = new Uint8Array(32);
    crypto.getRandomValues(requestEnc);
    const responseNonce = new Uint8Array(32);
    crypto.getRandomValues(responseNonce);

    const km = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce);

    const chunks = ['chunk1', 'chunk2', 'chunk3'].map((s) =>
      new TextEncoder().encode(s)
    );

    // Encrypt all chunks
    const encrypted = await Promise.all(
      chunks.map((chunk, i) => encryptChunk(km, i, chunk))
    );

    // Decrypt all chunks
    const decrypted = await Promise.all(
      encrypted.map((ct, i) => decryptChunk(km, i, ct))
    );

    for (let i = 0; i < chunks.length; i++) {
      assert.deepStrictEqual(decrypted[i], chunks[i], `Chunk ${i} should match`);
    }
  });
});

describe('hex utilities', () => {
  it('should convert hex to bytes correctly', () => {
    const hex = 'deadbeef';
    const bytes = hexToBytes(hex);
    assert.deepStrictEqual(bytes, new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it('should convert bytes to hex correctly', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const hex = bytesToHex(bytes);
    assert.strictEqual(hex, 'deadbeef');
  });

  it('should round-trip hex conversion', () => {
    const original = new Uint8Array(32);
    crypto.getRandomValues(original);
    const hex = bytesToHex(original);
    const restored = hexToBytes(hex);
    assert.deepStrictEqual(restored, original);
  });

  it('should reject odd-length hex strings', () => {
    assert.throws(() => hexToBytes('abc'), /even length/);
  });
});

describe('constants', () => {
  it('should have correct constant values', () => {
    assert.strictEqual(EXPORT_LENGTH, 32);
    assert.strictEqual(RESPONSE_NONCE_LENGTH, 32);
    assert.strictEqual(AES_GCM_NONCE_LENGTH, 12);
    assert.strictEqual(REQUEST_ENC_LENGTH, 32);
  });
});

describe('Go interoperability', () => {
  it('should derive same keys as Go implementation', async () => {
    // Test vectors from Go tests: exportedSecret[i] = i, requestEnc[i] = i+32, responseNonce[i] = i+64
    const exportedSecret = new Uint8Array(32);
    for (let i = 0; i < 32; i++) exportedSecret[i] = i;

    const requestEnc = new Uint8Array(32);
    for (let i = 0; i < 32; i++) requestEnc[i] = i + 32;

    const responseNonce = new Uint8Array(32);
    for (let i = 0; i < 32; i++) responseNonce[i] = i + 64;

    const km = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce);

    // Expected values from Go implementation
    const expectedKey = hexToBytes('40ec528847cd4e928449f2ed1a70a7d1e8ee317d5e900424fc1dd5b0475b97f7');
    const expectedNonceBase = hexToBytes('f8b0ce9466f27aa6243c65f9');

    assert.deepStrictEqual(
      km.key,
      expectedKey,
      `Key mismatch.\nExpected: ${bytesToHex(expectedKey)}\nGot: ${bytesToHex(km.key)}`
    );
    assert.deepStrictEqual(
      km.nonceBase,
      expectedNonceBase,
      `NonceBase mismatch.\nExpected: ${bytesToHex(expectedNonceBase)}\nGot: ${bytesToHex(km.nonceBase)}`
    );
  });
});
