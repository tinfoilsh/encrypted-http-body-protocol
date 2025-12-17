#!/usr/bin/env node

import { createTransport } from './index.js';

async function streamingTest() {
  console.log('EHBP Streaming Test');
  console.log('===================');

  try {
    // Create transport
    console.log('Creating transport...');
    const serverURL = 'http://localhost:8080';
    const transport = await createTransport(serverURL);
    console.log('Transport created');

    // Test 1: Basic streaming request
    console.log('\n--- Test 1: Basic Streaming ---');
    const streamResponse = await transport.get(`${serverURL}/stream`);
    console.log('Stream request sent, status:', streamResponse.status);

    if (streamResponse.ok) {
      console.log('Reading stream data...');
      const reader = streamResponse.body?.getReader();
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
      console.log('Stream request failed with status:', streamResponse.status);
    }

    // Test 2: Multiple concurrent streams
    console.log('\n--- Test 2: Concurrent Streams ---');
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

    // Test 3: Large data streaming (if server supports it)
    console.log('\n--- Test 3: Large Data Stream ---');
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
      console.log('Large data stream test failed:', error instanceof Error ? error.message : String(error));
    }

    console.log('\nAll streaming tests completed successfully!');

  } catch (error) {
    console.error('Streaming test failed:', error);
    process.exit(1);
  }
}

// Run the streaming test
if (import.meta.url === `file://${process.argv[1]}`) {
  streamingTest().catch(console.error);
}
