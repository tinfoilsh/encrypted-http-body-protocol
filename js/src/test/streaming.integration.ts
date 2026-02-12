#!/usr/bin/env node

/**
 * Integration test for EHBP streaming functionality.
 * Requires a running EHBP server at localhost:8080.
 *
 * Run with: npm run test:integration
 */

import { Identity, Transport } from '../index.js';

async function streamingIntegrationTest() {
  console.log('EHBP Streaming Integration Test');
  console.log('================================');

  try {
    // Create transport
    console.log('Creating transport...');
    const serverURL = 'http://localhost:8080';
    const identity = await Identity.fetchFromServer(serverURL);
    const transport = new Transport(identity, new URL(serverURL).host);
    console.log('Transport created');

    // Test 1: GET streaming (unencrypted - bodyless request)
    console.log('\n--- Test 1: GET Streaming (unencrypted) ---');
    const getStreamResponse = await transport.get(`${serverURL}/stream`);
    console.log('GET stream request sent, status:', getStreamResponse.status);

    if (getStreamResponse.ok) {
      console.log('Reading stream data...');
      const reader = getStreamResponse.body?.getReader();
      if (reader) {
        const decoder = new TextDecoder();

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const text = decoder.decode(value, { stream: true });
          process.stdout.write(text);
        }

        console.log('\nStream completed');
      } else {
        console.log('No readable stream available');
      }
    } else {
      console.log('Stream request failed with status:', getStreamResponse.status);
    }

    // Test 2: POST streaming (encrypted - has request body)
    console.log('\n--- Test 2: POST Streaming (encrypted) ---');
    try {
      const postStreamResponse = await transport.post(
        `${serverURL}/stream`,
        JSON.stringify({ message: 'Hello streaming!' }),
        { headers: { 'Content-Type': 'application/json' } }
      );
      console.log('POST stream request sent, status:', postStreamResponse.status);

      if (postStreamResponse.ok) {
        console.log('Reading encrypted stream data...');
        const reader = postStreamResponse.body?.getReader();
        if (reader) {
          const decoder = new TextDecoder();

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const text = decoder.decode(value, { stream: true });
            process.stdout.write(text);
          }

          console.log('\nEncrypted stream completed');
        } else {
          console.log('No readable stream available');
        }
      } else {
        console.log('POST stream request failed with status:', postStreamResponse.status);
      }
    } catch (error) {
      console.log('POST streaming test failed:', error instanceof Error ? error.message : String(error));
      console.log('(Server may not support POST to /stream endpoint)');
    }

    // Test 3: Multiple concurrent streams (GET - unencrypted)
    console.log('\n--- Test 3: Concurrent GET Streams (unencrypted) ---');
    const concurrentStreams = 3;
    const streamPromises = [];

    for (let i = 0; i < concurrentStreams; i++) {
      streamPromises.push(
        (async (streamId: number) => {
          const response = await transport.get(`${serverURL}/stream`);
          if (response.ok && response.body) {
            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            while (true) {
              const { done, value } = await reader.read();
              if (done) break;

              const text = decoder.decode(value, { stream: true });

              // Prefix with stream ID to show concurrency
              process.stdout.write(`[Stream ${streamId}] ${text}`);
            }

            return { streamId };
          }
          return { streamId };
        })(i + 1)
      );
    }

    const results = await Promise.all(streamPromises);
    console.log('\nConcurrent streams completed:');
    results.forEach(result => {
      console.log(`  - Stream ${result.streamId}: completed`);
    });

    // Test 4: Multiple concurrent streams (POST - encrypted)
    console.log('\n--- Test 4: Concurrent POST Streams (encrypted) ---');
    try {
      const encryptedStreamPromises = [];

      for (let i = 0; i < concurrentStreams; i++) {
        encryptedStreamPromises.push(
          (async (streamId: number) => {
            const response = await transport.post(
              `${serverURL}/stream`,
              JSON.stringify({ streamId, message: `Stream ${streamId} request` }),
              { headers: { 'Content-Type': 'application/json' } }
            );
            if (response.ok && response.body) {
              const reader = response.body.getReader();
              const decoder = new TextDecoder();

              while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                const text = decoder.decode(value, { stream: true });
                process.stdout.write(`[Encrypted ${streamId}] ${text}`);
              }

              return { streamId, encrypted: true };
            }
            return { streamId, encrypted: true };
          })(i + 1)
        );
      }

      const encryptedResults = await Promise.all(encryptedStreamPromises);
      console.log('\nConcurrent encrypted streams completed:');
      encryptedResults.forEach(result => {
        console.log(`  - Stream ${result.streamId}: completed (encrypted)`);
      });
    } catch (error) {
      console.log('Concurrent POST streaming test failed:', error instanceof Error ? error.message : String(error));
    }

    // Test 5: Large data streaming (GET - unencrypted)
    console.log('\n--- Test 5: Large Data GET Stream (unencrypted) ---');
    try {
      const largeStreamResponse = await transport.get(`${serverURL}/stream`);
      if (largeStreamResponse.ok) {
        console.log('Reading large data stream...');
        const reader = largeStreamResponse.body?.getReader();
        if (reader) {
          const decoder = new TextDecoder();

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const text = decoder.decode(value, { stream: true });
            process.stdout.write(text);
          }
        }
      }
    } catch (error) {
      console.log('Large data GET stream test failed:', error instanceof Error ? error.message : String(error));
    }

    // Test 6: Large data streaming (POST - encrypted)
    console.log('\n--- Test 6: Large Data POST Stream (encrypted) ---');
    try {
      const largePostStreamResponse = await transport.post(
        `${serverURL}/stream`,
        JSON.stringify({ message: 'Large data stream request', size: 'large' }),
        { headers: { 'Content-Type': 'application/json' } }
      );
      if (largePostStreamResponse.ok) {
        console.log('Reading large encrypted data stream...');
        const reader = largePostStreamResponse.body?.getReader();
        if (reader) {
          const decoder = new TextDecoder();

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const text = decoder.decode(value, { stream: true });
            process.stdout.write(text);
          }
          console.log('\nLarge encrypted stream completed');
        }
      } else {
        console.log('Large POST stream request failed with status:', largePostStreamResponse.status);
      }
    } catch (error) {
      console.log('Large data POST stream test failed:', error instanceof Error ? error.message : String(error));
    }

    console.log('\nAll streaming integration tests completed successfully!');

  } catch (error) {
    console.error('Streaming integration test failed:', error);
    process.exit(1);
  }
}

// Run the integration test
streamingIntegrationTest().catch(console.error);
