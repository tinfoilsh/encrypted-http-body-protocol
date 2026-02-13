/**
 * Security Tests for EHBP
 *
 * These tests verify that the following MitM key substitution vulnerability cannot occur:
 * 1. MitM cannot derive the correct response decryption keys
 * 2. MitM cannot forge valid encrypted responses
 * 3. Modified headers cause decryption failures
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { CipherSuite } from 'hpke';
import { KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM } from '@panva/hpke-noble';
import {
  deriveResponseKeys,
  encryptChunk,
  decryptChunk,
  HPKE_REQUEST_INFO,
  EXPORT_LABEL,
  EXPORT_LENGTH,
} from '../derive.js';

describe('Security Tests', () => {
  const suite = new CipherSuite(
    KEM_DHKEM_X25519_HKDF_SHA256,
    KDF_HKDF_SHA256,
    AEAD_AES_256_GCM
  );

  const infoBytes = new TextEncoder().encode(HPKE_REQUEST_INFO);
  const exportLabelBytes = new TextEncoder().encode(EXPORT_LABEL);

  describe('MitM cannot read responses', () => {
    it('should derive different keys for attacker vs legitimate client', async () => {
      // Server keypair
      const serverKeyPair = await suite.GenerateKeyPair(true);

      // Client (Alice) creates request context with info parameter
      const { encapsulatedSecret: aliceEnc, ctx: aliceCtx } = await suite.SetupSender(
        serverKeyPair.publicKey,
        { info: infoBytes }
      );
      const requestEnc = aliceEnc;

      // Response nonce (public, sent in header)
      const responseNonce = new Uint8Array(32);
      crypto.getRandomValues(responseNonce);

      // Alice exports secret from her HPKE context
      const aliceExported = await aliceCtx.Export(exportLabelBytes, EXPORT_LENGTH);

      // Eve (attacker) creates her own HPKE context to the server
      // Even though Eve intercepts requestEnc, she cannot derive the shared secret
      const { ctx: eveCtx } = await suite.SetupSender(serverKeyPair.publicKey, { info: infoBytes });
      const eveExported = await eveCtx.Export(exportLabelBytes, EXPORT_LENGTH);

      // Alice derives correct keys
      const aliceKM = await deriveResponseKeys(aliceExported, requestEnc, responseNonce);

      // Eve derives WRONG keys (she has different HPKE shared secret)
      const eveKM = await deriveResponseKeys(eveExported, requestEnc, responseNonce);

      // Keys MUST be different - this is the core security property
      assert.notDeepStrictEqual(
        aliceKM.keyBytes,
        eveKM.keyBytes,
        'Alice and Eve must derive different keys'
      );
      assert.notDeepStrictEqual(
        aliceKM.nonceBase,
        eveKM.nonceBase,
        'Alice and Eve must derive different nonce bases'
      );
    });

    it('should prevent Eve from decrypting responses meant for Alice', async () => {
      const serverKeyPair = await suite.GenerateKeyPair(true);

      // Alice creates request
      const { encapsulatedSecret: aliceEnc, ctx: aliceCtx } = await suite.SetupSender(
        serverKeyPair.publicKey,
        { info: infoBytes }
      );
      const requestEnc = aliceEnc;

      // Server receives and creates receiver context
      const serverCtx = await suite.SetupRecipient(
        serverKeyPair.privateKey,
        aliceEnc,
        { info: infoBytes }
      );

      // Server generates response nonce and encrypts response
      const responseNonce = new Uint8Array(32);
      crypto.getRandomValues(responseNonce);

      const serverExported = await serverCtx.Export(exportLabelBytes, EXPORT_LENGTH);
      const serverKM = await deriveResponseKeys(serverExported, requestEnc, responseNonce);

      const secretMessage = new TextEncoder().encode('Secret API key: sk-12345');
      const encryptedResponse = await encryptChunk(serverKM, 0, secretMessage);

      // Alice can decrypt (she has matching exported secret)
      const aliceExported = await aliceCtx.Export(exportLabelBytes, EXPORT_LENGTH);
      const aliceKM = await deriveResponseKeys(aliceExported, requestEnc, responseNonce);
      const aliceDecrypted = await decryptChunk(aliceKM, 0, encryptedResponse);
      assert.deepStrictEqual(aliceDecrypted, secretMessage, 'Alice should decrypt successfully');

      // Eve creates her own context - she CANNOT decrypt
      const { ctx: eveCtx } = await suite.SetupSender(serverKeyPair.publicKey, { info: infoBytes });
      const eveExported = await eveCtx.Export(exportLabelBytes, EXPORT_LENGTH);
      const eveKM = await deriveResponseKeys(eveExported, requestEnc, responseNonce);

      // Eve's decryption MUST fail
      await assert.rejects(
        async () => decryptChunk(eveKM, 0, encryptedResponse),
        /error/i,
        'Eve must not be able to decrypt the response'
      );
    });
  });

  describe('MitM cannot forge responses', () => {
    it('should reject responses encrypted with wrong keys', async () => {
      const serverKeyPair = await suite.GenerateKeyPair(true);

      // Alice creates request
      const { encapsulatedSecret: aliceEnc, ctx: aliceCtx } = await suite.SetupSender(
        serverKeyPair.publicKey,
        { info: infoBytes }
      );
      const requestEnc = aliceEnc;
      const aliceExported = await aliceCtx.Export(exportLabelBytes, EXPORT_LENGTH);

      // Attacker creates forged response with random keys
      const attackerSecret = new Uint8Array(32);
      crypto.getRandomValues(attackerSecret);
      const forgedNonce = new Uint8Array(32);
      crypto.getRandomValues(forgedNonce);

      const attackerKM = await deriveResponseKeys(attackerSecret, requestEnc, forgedNonce);
      const forgedMessage = new TextEncoder().encode('Malicious message');
      const forgedCiphertext = await encryptChunk(attackerKM, 0, forgedMessage);

      // Alice tries to decrypt with her real keys
      const aliceKM = await deriveResponseKeys(aliceExported, requestEnc, forgedNonce);

      // Decryption MUST fail - attacker used wrong shared secret
      await assert.rejects(
        async () => decryptChunk(aliceKM, 0, forgedCiphertext),
        /error/i,
        'Forged response must be rejected'
      );
    });
  });

  describe('Modified headers cause failure', () => {
    it('should fail decryption if request enc is modified', async () => {
      const serverKeyPair = await suite.GenerateKeyPair(true);

      const { encapsulatedSecret: aliceEnc, ctx: aliceCtx } = await suite.SetupSender(
        serverKeyPair.publicKey,
        { info: infoBytes }
      );
      const originalEnc = aliceEnc;

      const serverCtx = await suite.SetupRecipient(
        serverKeyPair.privateKey,
        aliceEnc,
        { info: infoBytes }
      );

      // Server encrypts response using original enc
      const serverExported = await serverCtx.Export(exportLabelBytes, EXPORT_LENGTH);
      const responseNonce = new Uint8Array(32);
      crypto.getRandomValues(responseNonce);

      const serverKM = await deriveResponseKeys(serverExported, originalEnc, responseNonce);
      const plaintext = new TextEncoder().encode('Secret response');
      const ciphertext = await encryptChunk(serverKM, 0, plaintext);

      // Alice receives with MODIFIED enc (tampered by MitM)
      const modifiedEnc = new Uint8Array(originalEnc);
      modifiedEnc[0] ^= 0xff; // Flip bits

      const aliceExported = await aliceCtx.Export(exportLabelBytes, EXPORT_LENGTH);
      const aliceKM = await deriveResponseKeys(aliceExported, modifiedEnc, responseNonce);

      // Decryption MUST fail because enc was modified
      await assert.rejects(
        async () => decryptChunk(aliceKM, 0, ciphertext),
        /error/i,
        'Modified enc must cause decryption failure'
      );
    });

    it('should fail decryption if response nonce is modified', async () => {
      const serverKeyPair = await suite.GenerateKeyPair(true);

      const { encapsulatedSecret: aliceEnc, ctx: aliceCtx } = await suite.SetupSender(
        serverKeyPair.publicKey,
        { info: infoBytes }
      );
      const requestEnc = aliceEnc;

      const serverCtx = await suite.SetupRecipient(
        serverKeyPair.privateKey,
        aliceEnc,
        { info: infoBytes }
      );

      // Server encrypts response
      const serverExported = await serverCtx.Export(exportLabelBytes, EXPORT_LENGTH);
      const originalNonce = new Uint8Array(32);
      crypto.getRandomValues(originalNonce);

      const serverKM = await deriveResponseKeys(serverExported, requestEnc, originalNonce);
      const plaintext = new TextEncoder().encode('Secret response');
      const ciphertext = await encryptChunk(serverKM, 0, plaintext);

      // Alice receives with MODIFIED nonce (tampered by MitM)
      const modifiedNonce = new Uint8Array(originalNonce);
      modifiedNonce[0] ^= 0xff;

      const aliceExported = await aliceCtx.Export(exportLabelBytes, EXPORT_LENGTH);
      const aliceKM = await deriveResponseKeys(aliceExported, requestEnc, modifiedNonce);

      // Decryption MUST fail because nonce was modified
      await assert.rejects(
        async () => decryptChunk(aliceKM, 0, ciphertext),
        /error/i,
        'Modified nonce must cause decryption failure'
      );
    });
  });

  describe('Client public key header attack prevented', () => {
    it('should not use client public key for response encryption', async () => {
      const serverKeyPair = await suite.GenerateKeyPair(true);

      // Alice creates request
      const { encapsulatedSecret: aliceEnc, ctx: aliceCtx } = await suite.SetupSender(
        serverKeyPair.publicKey,
        { info: infoBytes }
      );
      const requestEnc = aliceEnc;

      // Server creates receiver from Alice's actual enc
      const serverCtx = await suite.SetupRecipient(
        serverKeyPair.privateKey,
        aliceEnc,
        { info: infoBytes }
      );

      const responseNonce = new Uint8Array(32);
      crypto.getRandomValues(responseNonce);

      const serverExported = await serverCtx.Export(exportLabelBytes, EXPORT_LENGTH);
      const serverKM = await deriveResponseKeys(serverExported, requestEnc, responseNonce);

      const secretData = new TextEncoder().encode('Sensitive API response');
      const encrypted = await encryptChunk(serverKM, 0, secretData);

      // Alice can decrypt using her HPKE context
      const aliceExported = await aliceCtx.Export(exportLabelBytes, EXPORT_LENGTH);
      const aliceKM = await deriveResponseKeys(aliceExported, requestEnc, responseNonce);
      const decrypted = await decryptChunk(aliceKM, 0, encrypted);
      assert.deepStrictEqual(decrypted, secretData);
    });
  });
});
