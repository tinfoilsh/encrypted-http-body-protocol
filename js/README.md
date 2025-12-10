# EHBP JavaScript Client

JavaScript/TypeScript client for [Encrypted HTTP Body Protocol (EHBP)](https://github.com/tinfoilsh/encrypted-http-body-protocol).

EHBP encrypts HTTP message bodies end-to-end using HPKE (RFC 9180) while leaving headers in cleartext for routing.

## Installation

```sh
npm install ehbp
```

## Requirements

- Node.js 20+
- Works in both Node.js and modern browsers

## Quick Start

```javascript
import { Identity, createTransport } from 'ehbp';

async function main() {
  // Create client identity
  const clientIdentity = await Identity.generate();

  // Create transport (fetches server public key automatically)
  const transport = await createTransport('http://localhost:8080', clientIdentity);

  // Make encrypted requests
  const response = await transport.post('/secure', 'Hello, World!');
  const data = await response.text();
  console.log('Response:', data);
}

main();
```

## API Reference

### `Identity`

Manages HPKE key pairs for encryption/decryption.

#### `Identity.generate(): Promise<Identity>`

Generates a new identity with X25519 key pair.

```javascript
const identity = await Identity.generate();
```

#### `identity.toJSON(): Promise<string>`

Serializes the identity to JSON for storage.

```javascript
const identityJSON = await identity.toJSON();
await writeFile('identity.json', identityJSON);
```

#### `Identity.fromJSON(json: string): Promise<Identity>`

Loads an identity from JSON.

```javascript
const json = await readFile('identity.json', 'utf-8');
const identity = await Identity.fromJSON(json);
```

#### `identity.getPublicKeyHex(): Promise<string>`

Returns the public key as a hex string.

```javascript
const pubKeyHex = await identity.getPublicKeyHex();
console.log('Public key:', pubKeyHex);
```

### `Transport`

HTTP transport that encrypts requests and decrypts responses.

#### `createTransport(serverURL: string, clientIdentity: Identity): Promise<Transport>`

Creates a new transport instance.

```javascript
const transport = await createTransport('http://localhost:8080', clientIdentity);
```

#### `transport.request(input: RequestInfo | URL, init?: RequestInit): Promise<Response>`

Makes an encrypted HTTP request. Supports all standard fetch options.

```javascript
const response = await transport.request('/api/data', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ message: 'hello' })
});
```

#### Convenience Methods

- `transport.get(url: string | URL, init?: RequestInit): Promise<Response>`
- `transport.post(url: string | URL, body?: BodyInit, init?: RequestInit): Promise<Response>`
- `transport.put(url: string | URL, body?: BodyInit, init?: RequestInit): Promise<Response>`
- `transport.delete(url: string | URL, init?: RequestInit): Promise<Response>`

## Examples

### Saving and Loading Identities

```javascript
import { Identity } from 'ehbp';
import { writeFile, readFile } from 'fs/promises';

// Generate and save
const identity = await Identity.generate();
const identityJSON = await identity.toJSON();
await writeFile('client_identity.json', identityJSON);

// Load from file
const loadedJSON = await readFile('client_identity.json', 'utf-8');
const loadedIdentity = await Identity.fromJSON(loadedJSON);
```

### Making Different Request Types

```javascript
// GET request
const getResponse = await transport.get('/api/users');
const users = await getResponse.json();

// POST with JSON
const postResponse = await transport.post(
  '/api/users',
  JSON.stringify({ name: 'Alice' }),
  { headers: { 'Content-Type': 'application/json' } }
);

// PUT request
const putResponse = await transport.put(
  '/api/users/123',
  JSON.stringify({ name: 'Bob' }),
  { headers: { 'Content-Type': 'application/json' } }
);

// DELETE request
const deleteResponse = await transport.delete('/api/users/123');
```

### Error Handling

```javascript
try {
  const response = await transport.post('/secure', 'data');
  if (!response.ok) {
    console.error('Request failed:', response.status, response.statusText);
  }
  const data = await response.text();
  console.log('Success:', data);
} catch (error) {
  console.error('Transport error:', error.message);
}
```

### Browser Usage

```html
<script type="module">
  import { Identity, createTransport } from './dist/browser/ehbp.js';

  const identity = await Identity.generate();
  const transport = await createTransport('http://localhost:8080', identity);

  const response = await transport.post('/secure', 'Hello from browser!');
  const data = await response.text();
  console.log(data);
</script>
```

## Development

```sh
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Build browser bundle
npm run build:browser
```

## Protocol Details

For the complete protocol specification, see [SPEC.md](../SPEC.md) in the root of the repository.

## License

MIT
