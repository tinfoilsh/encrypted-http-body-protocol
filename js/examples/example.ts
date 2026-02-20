#!/usr/bin/env node

/**
 * Example usage of the EHBP JavaScript client
 */

import { Identity, Transport } from '../dist/esm/index.js';

async function main() {
  console.log('EHBP JavaScript Client Example');
  console.log('==============================');

  try {
    // Create transport (this will fetch server public key)
    console.log('Creating transport...');
    const serverURL = 'http://localhost:8080'; // Adjust as needed
    const identity = await Identity.fetchFromServer(serverURL);
    const transport = new Transport(identity);
    console.log('Transport created successfully');
    console.log('Server public key:', await identity.getPublicKeyHex());

    // Example 1: GET request to secure endpoint
    console.log('\n--- GET Request ---');
    try {
      const getResponse = await transport.get(`${serverURL}/secure`);
      console.log('GET Response status:', getResponse.status);
      if (getResponse.ok) {
        const getData = await getResponse.text();
        console.log('GET Response:', getData);
      } else {
        console.log('GET Request failed with status:', getResponse.status);
      }
    } catch (error) {
      console.log('GET Request failed:', error instanceof Error ? error.message : String(error));
    }

    // Example 2: POST request with JSON data
    console.log('\n--- POST Request ---');
    try {
      const postData = { message: 'Hello from JavaScript client!', timestamp: new Date().toISOString() };
      const postResponse = await transport.post(
        `${serverURL}/secure`,
        JSON.stringify(postData),
        { headers: { 'Content-Type': 'application/json' } }
      );
      console.log('POST Response status:', postResponse.status);
      if (postResponse.ok) {
        const responseData = await postResponse.text();
        console.log('POST Response:', responseData);
      } else {
        console.log('POST Request failed with status:', postResponse.status);
      }
    } catch (error) {
      console.log('POST Request failed:', error instanceof Error ? error.message : String(error));
    }

    // Example 3: PUT request
    console.log('\n--- PUT Request ---');
    try {
      const putData = { id: 1, name: 'Updated Item' };
      const putResponse = await transport.put(
        `${serverURL}/secure`,
        JSON.stringify(putData),
        { headers: { 'Content-Type': 'application/json' } }
      );
      console.log('PUT Response status:', putResponse.status);
      if (putResponse.ok) {
        const putResponseData = await putResponse.text();
        console.log('PUT Response:', putResponseData);
      } else {
        console.log('PUT Request failed with status:', putResponse.status);
      }
    } catch (error) {
      console.log('PUT Request failed:', error instanceof Error ? error.message : String(error));
    }

    // Example 4: Streaming request
    console.log('\n--- Streaming Request ---');
    try {
      const streamResponse = await transport.get(`${serverURL}/stream`);
      console.log('Stream Response status:', streamResponse.status);
      if (streamResponse.ok) {
        console.log('Streaming response (should show numbers 1-20):');
        const reader = streamResponse.body?.getReader();
        if (reader) {
          const decoder = new TextDecoder();
          let chunkCount = 0;

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const text = decoder.decode(value, { stream: true });
            process.stdout.write(text);
            chunkCount++;
          }

          console.log(`\nStream completed with ${chunkCount} chunks`);
        } else {
          console.log('No readable stream available');
        }
      } else {
        console.log('Stream Request failed with status:', streamResponse.status);
      }
    } catch (error) {
      console.log('Stream Request failed:', error instanceof Error ? error.message : String(error));
    }

    console.log('\nExample completed successfully!');
    console.log('\nTo test with a real server:');
    console.log('1. Start the Go server: go run pkg/server/main.go');
    console.log('2. Run this example: npm run example');

  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

// Run the example
main().catch(console.error);
