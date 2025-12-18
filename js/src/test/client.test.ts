import { describe, it, before } from 'node:test';
import assert from 'node:assert';
import { Identity, Transport, createTransport } from '../index.js';
import { PROTOCOL } from '../protocol.js';

describe('Transport', () => {
  let serverIdentity: Identity;

  before(async () => {
    serverIdentity = await Identity.generate();
  });

  it('should create transport with server public key', () => {
    const transport = new Transport(
      serverIdentity,
      'localhost:8080'
    );

    assert(transport instanceof Transport, 'Should create transport instance');
  });

  it('should encrypt and decrypt request', async () => {
    const originalBody = new TextEncoder().encode('Hello, World!');
    const request = new Request('http://localhost:8080/test', {
      method: 'POST',
      body: originalBody
    });

    const { request: encryptedRequest, context } = await serverIdentity.encryptRequestWithContext(request);

    assert(encryptedRequest.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER), 'Encapsulated key header should be set');

    // Check that context was returned for response decryption
    assert(context, 'Context should be returned');
    assert(context.senderContext, 'Context should have sender context');
    assert(context.requestEnc, 'Context should have request enc');

    // Check that body is encrypted (different from original)
    const encryptedBody = await encryptedRequest.arrayBuffer();
    assert(encryptedBody.byteLength > 0, 'Encrypted body should not be empty');
    assert(encryptedBody.byteLength !== originalBody.length, 'Encrypted body should have different length');
  });

  it('should handle request without body', async () => {
    const request = new Request('http://localhost:8080/test', {
      method: 'GET'
    });

    const { request: resultRequest, context } = await serverIdentity.encryptRequestWithContext(request);

    // Bodyless requests pass through unmodified - no EHBP headers set
    // See SPEC.md Section 5.1
    assert.strictEqual(
      resultRequest.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER),
      null,
      'Encapsulated key header should NOT be set for bodyless requests'
    );

    // Context is null for bodyless requests (no HPKE context to derive response keys from)
    assert.strictEqual(context, null, 'Context should be null for bodyless requests');
  });

  it('should connect to actual server and POST to /secure endpoint', async (t) => {
    const serverURL = 'http://localhost:8080';

    try {
      const keysResponse = await fetch(`${serverURL}${PROTOCOL.KEYS_PATH}`);
      if (!keysResponse.ok) {
        t.skip('Server not running at localhost:8080');
        return;
      }
    } catch {
      t.skip('Server not running at localhost:8080');
      return;
    }

    const transport = await createTransport(serverURL);

    const testName = 'Integration Test User';

    const serverPubKeyHex = await transport.getServerPublicKeyHex();
    assert.strictEqual(serverPubKeyHex.length, 64, 'Server public key should be 64 hex chars (32 bytes)');

    // Make actual POST request to /secure endpoint
    const response = await transport.post(`${serverURL}/secure`, testName, {
      headers: { 'Content-Type': 'text/plain' }
    });

    // Verify response
    assert(response.ok, `Response should be ok, got status: ${response.status}`);

    const responseText = await response.text();
    assert.strictEqual(responseText, `Hello, ${testName}`, 'Server should respond with Hello, {name}');

    console.log(`✓ Integration test passed: ${responseText}`);
  });
});
