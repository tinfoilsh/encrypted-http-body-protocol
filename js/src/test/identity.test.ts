import { describe, it } from 'node:test';
import assert from 'node:assert';
import { Identity } from '../identity.js';

describe('Identity', () => {
  it('should generate a new identity', async () => {
    const identity = await Identity.generate();
    
    assert(identity.getPublicKey().type === 'public', 'Public key should have type "public"');
    assert(identity.getPrivateKey().type === 'private', 'Private key should have type "private"');
    const publicKeyHex = await identity.getPublicKeyHex();
    assert(publicKeyHex.length > 0, 'Public key hex should not be empty');
  });

  it('should serialize and deserialize identity', async () => {
    const original = await Identity.generate();
    const json = await original.toJSON();
    const restored = await Identity.fromJSON(json);
    
    const originalHex = await original.getPublicKeyHex();
    const restoredHex = await restored.getPublicKeyHex();
    assert(originalHex === restoredHex, 'Public keys should match');
    assert(original.getPrivateKey().type === 'private', 'Private key should have type "private"');
    assert(restored.getPrivateKey().type === 'private', 'Private key should have type "private"');
  });

  it('should marshal configuration', async () => {
    const identity = await Identity.generate();
    const config = await identity.marshalConfig();
    
    assert(config.length > 0, 'Config should not be empty');
    assert(config[0] === 0, 'Key ID should be 0');
    assert(config[1] === 0x00, 'KEM ID high byte should be 0x00');
    assert(config[2] === 0x20, 'KEM ID low byte should be 0x20');
  });

  it('should unmarshal public configuration', async () => {
    const identity = await Identity.generate();
    const config = await identity.marshalConfig();
    const restored = await Identity.unmarshalPublicConfig(config);
    
    const originalHex = await identity.getPublicKeyHex();
    const restoredHex = await restored.getPublicKeyHex();
    assert(restoredHex === originalHex, 'Public keys should match');
  });
});
