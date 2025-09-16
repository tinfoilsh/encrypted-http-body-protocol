import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { Identity, Transport } from '../index.js';
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

  it('should encrypt and decrypt request', async () => {
    const serverPublicKey = serverIdentity.getPublicKey();
    const originalBody = new TextEncoder().encode('Hello, World!');
    const request = new Request('http://localhost:8080/test', {
      method: 'POST',
      body: originalBody
    });

    const encryptedRequest = await clientIdentity.encryptRequest(request, serverPublicKey);
    
    // Check that headers are set
    assert(encryptedRequest.headers.get(PROTOCOL.CLIENT_PUBLIC_KEY_HEADER), 'Client public key header should be set');
    assert(encryptedRequest.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER), 'Encapsulated key header should be set');
    
    // Check that body is encrypted (different from original)
    const encryptedBody = await encryptedRequest.arrayBuffer();
    assert(encryptedBody.byteLength > 0, 'Encrypted body should not be empty');
    assert(encryptedBody.byteLength !== originalBody.length, 'Encrypted body should have different length');
  });

  it('should handle request without body', async () => {
    const serverPublicKey = serverIdentity.getPublicKey();
    const request = new Request('http://localhost:8080/test', {
      method: 'GET'
    });

    const encryptedRequest = await clientIdentity.encryptRequest(request, serverPublicKey);
    
    // Check that only client public key header is set
    assert(encryptedRequest.headers.get(PROTOCOL.CLIENT_PUBLIC_KEY_HEADER), 'Client public key header should be set');
    assert(!encryptedRequest.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER), 'Encapsulated key header should not be set for empty body');
  });
});
