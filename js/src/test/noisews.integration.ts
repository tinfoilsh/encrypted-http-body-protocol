#!/usr/bin/env node

/**
 * Integration test for EHBP-WS encrypted WebSocket channels.
 * Requires a running EHBP example server at localhost:8080 (its /ws
 * endpoint replies "Hello, <message>").
 *
 * Run with: npm run test:integration:ws
 */

import { createTransport, NoiseWebSocket } from '../index.js';

async function noiseWebSocketIntegrationTest() {
  console.log('EHBP Noise WebSocket Integration Test');
  console.log('=====================================');

  try {
    const serverURL = 'http://localhost:8080';
    console.log('Fetching server identity...');
    const transport = await createTransport(serverURL);
    const identity = transport.getServerIdentity();
    console.log('Server key:', await identity.getPublicKeyHex());

    console.log('\nDialing encrypted WebSocket channel at /ws...');
    const channel = await NoiseWebSocket.connect(`${serverURL}/ws`, identity);
    console.log('Channel established');

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    for (const message of ['integration', 'round trip', 'goodbye']) {
      await channel.send(encoder.encode(message));
      const reply = await channel.recv();
      if (reply === null) {
        throw new Error('server closed the channel unexpectedly');
      }
      const text = decoder.decode(reply);
      console.log(`sent ${JSON.stringify(message)} -> received ${JSON.stringify(text)}`);
      if (text !== `Hello, ${message}`) {
        throw new Error(`unexpected reply: ${text}`);
      }
    }

    console.log('\nClosing channel...');
    await channel.close();
    const drained = await channel.recv();
    if (drained !== null) {
      throw new Error('expected channel to be drained after close');
    }
    console.log('Channel closed cleanly');

    console.log('\nAll Noise WebSocket integration tests completed successfully!');
  } catch (error) {
    console.error('Noise WebSocket integration test failed:', error);
    process.exit(1);
  }
}

// Run the integration test
noiseWebSocketIntegrationTest().catch(console.error);
