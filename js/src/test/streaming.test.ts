import { describe, it } from 'node:test';
import assert from 'node:assert';

describe('Streaming', () => {

  it('should handle streaming responses', async () => {
    // Create a mock streaming response
    const mockStreamData = 'Number: 1\nNumber: 2\nNumber: 3\n';
    const mockResponse = new Response(mockStreamData, {
      status: 200,
      headers: {
        'Content-Type': 'text/plain',
        'Ehbp-Encapsulated-Key': 'abcd1234' // Mock encapsulated key
      }
    });

    // Test that we can read from a stream
    const reader = mockResponse.body?.getReader();
    assert(reader, 'Response should have a readable stream');

    const decoder = new TextDecoder();
    let receivedData = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const text = decoder.decode(value, { stream: true });
      receivedData += text;
    }

    assert(receivedData === mockStreamData, 'Should receive all stream data');
  });

  it('should handle empty streams', async () => {
    const emptyResponse = new Response('', {
      status: 200,
      headers: {
        'Ehbp-Encapsulated-Key': 'abcd1234'
      }
    });

    const reader = emptyResponse.body?.getReader();
    assert(reader, 'Response should have a readable stream');

    const { done } = await reader.read();
    assert(done, 'Empty stream should be done immediately');
  });

  it('should handle chunked data correctly', async () => {
    // Simulate chunked data
    const chunks = ['Hello', ' ', 'World', '!'];
    const stream = new ReadableStream({
      start(controller) {
        chunks.forEach(chunk => {
          controller.enqueue(new TextEncoder().encode(chunk));
        });
        controller.close();
      }
    });

    const response = new Response(stream, {
      status: 200,
      headers: {
        'Ehbp-Encapsulated-Key': 'abcd1234'
      }
    });

    const reader = response.body?.getReader();
    assert(reader, 'Response should have a readable stream');

    const decoder = new TextDecoder();
    let receivedData = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const text = decoder.decode(value, { stream: true });
      receivedData += text;
    }

    assert(receivedData === 'Hello World!', 'Should receive all chunks correctly');
  });
});
