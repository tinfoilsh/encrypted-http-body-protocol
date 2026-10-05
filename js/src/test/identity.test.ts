import { describe, it } from 'node:test';
import assert from 'node:assert';
import { Identity } from '../identity.js';
import { UnsupportedSuiteError, InvalidKeyConfigError } from '../errors.js';

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

  it('should reject a config advertising a non-X25519 KEM', async () => {
    const config = await (await Identity.generate()).marshalConfig();
    config[2] = 0x10; // DHKEM(P-256)
    await assert.rejects(Identity.unmarshalPublicConfig(config), UnsupportedSuiteError);
    // A config too short to hold a KEM id is malformed, not an unsupported suite.
    await assert.rejects(Identity.unmarshalPublicConfig(config.slice(0, 2)), InvalidKeyConfigError);
    await assert.rejects(Identity.unmarshalPublicConfig(new Uint8Array(0)), InvalidKeyConfigError);
  });

  it('should reject a config advertising more than one cipher suite', async () => {
    const config = await (await Identity.generate()).marshalConfig();
    const two = new Uint8Array(config.length + 4);
    two.set(config);
    two[36] = 8; // suites length: two entries
    two.set([0x00, 0x01, 0x00, 0x02], config.length);
    await assert.rejects(Identity.unmarshalPublicConfig(two), UnsupportedSuiteError);
    // An empty list is malformed, not an unsupported suite.
    const none = new Uint8Array(config.slice(0, 37));
    none[36] = 0;
    await assert.rejects(Identity.unmarshalPublicConfig(none), InvalidKeyConfigError);
  });

  it('should reject a truncated or misaligned cipher-suites section', async () => {
    const config = await (await Identity.generate()).marshalConfig();
    await assert.rejects(Identity.unmarshalPublicConfig(config.slice(0, -1)), InvalidKeyConfigError);
    const odd = new Uint8Array(config);
    odd[36] = 3; // suites length 3: not a multiple of 4
    await assert.rejects(Identity.unmarshalPublicConfig(odd), InvalidKeyConfigError);
  });
});
