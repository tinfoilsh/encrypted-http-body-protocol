import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { Identity, Transport, createTransport } from '../index.js';
import { PROTOCOL } from '../protocol.js';

describe('Transport', () => {
  let clientIdentity: Identity;
  let serverIdentity: Identity;

  before(async () => {
    clientIdentity = await Identity.generate();
    serverIdentity = await Identity.generate();
  });

  it('should create transport with server public key', () => {
    const transport = new Transport(
      clientIdentity,
      'localhost:8080',
      serverIdentity.getPublicKey()
    );
    
    assert(transport instanceof Transport, 'Should create transport instance');
  });

  it('should encrypt request with body', async () => {
    const serverPublicKey = serverIdentity.getPublicKey();
    const originalBody = new TextEncoder().encode('Hello, World!');
    const request = new Request('http://localhost:8080/test', {
      method: 'POST',
      body: originalBody
    });

    const { request: encryptedRequest, context } = await clientIdentity.encryptRequest(request, serverPublicKey);

    // Check that encapsulated key header is set
    assert(encryptedRequest.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER), 'Encapsulated key header should be set');

    // Check that body is encrypted (different from original)
    const encryptedBody = await encryptedRequest.arrayBuffer();
    assert(encryptedBody.byteLength > 0, 'Encrypted body should not be empty');
    assert(encryptedBody.byteLength !== originalBody.length, 'Encrypted body should have different length');

    // Context should be returned for response decryption
    assert(context.senderContext, 'Request context should contain sender context');
  });

  it('should reject request without body', async () => {
    const serverPublicKey = serverIdentity.getPublicKey();
    const request = new Request('http://localhost:8080/test', {
      method: 'GET'
    });

    await assert.rejects(
      () => clientIdentity.encryptRequest(request, serverPublicKey),
      { message: 'EHBP requires a request body' },
      'Should reject requests without a body'
    );
  });

  it('should connect to actual server and POST to /secure endpoint', async (t) => {
    const serverURL = 'http://localhost:8080';
    
    try {
      const keysResponse = await fetch(`${serverURL}${PROTOCOL.KEYS_PATH}`);
      if (!keysResponse.ok) {
        t.skip('Server not running at localhost:8080');
        return;
      }
    } catch (error) {
      t.skip('Server not running at localhost:8080');
      return;
    }

    // Create transport that will connect to the real server
    const transport = await createTransport(serverURL, clientIdentity);
    
    const testName = 'Integration Test User';

    const serverPubKeyHex = await transport.getServerPublicKeyHex();
    assert.strictEqual(serverPubKeyHex.length, 64, 'Server public key should be 64 bytes');

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
