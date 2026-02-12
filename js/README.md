# EHBP JavaScript Client

JavaScript/TypeScript client for [Encrypted HTTP Body Protocol (EHBP)](https://github.com/tinfoilsh/encrypted-http-body-protocol).

EHBP encrypts HTTP request and response bodies end-to-end using HPKE ([RFC 9180](https://datatracker.ietf.org/doc/rfc9180/)) while leaving headers in cleartext for routing.

## Installation

```sh
npm install ehbp
```

## Compatible Runtimes

- **Node.js** 20+
- **Bun** 1.x+
- **Browsers** with ES2020 support

All HPKE key operations use [`@noble/curves`](https://github.com/paulmillr/noble-curves) (via `@panva/hpke-noble`) instead of WebCrypto, so X25519 support in the runtime's `crypto.subtle` is **not** required.

## Quick Start

```javascript
import { Identity, Transport } from 'ehbp';

// Fetch server identity (standalone usage without attestation)
const identity = await Identity.fetchFromServer('https://example.com');
const transport = new Transport(identity);

// Make encrypted requests - works like fetch()
const response = await transport.post('https://example.com/api/data', JSON.stringify({ message: 'hello' }), {
  headers: { 'Content-Type': 'application/json' }
});

const data = await response.json();
```

## API

### `new Transport(serverIdentity: Identity)`

Creates a transport that encrypts requests and decrypts responses using the given server identity.

```javascript
// With an attested key (recommended for production)
const identity = await Identity.fromPublicKeyHex(attestedPublicKey);
const transport = new Transport(identity);

// Or fetch directly (standalone usage, no verification)
const identity = await Identity.fetchFromServer('https://example.com');
const transport = new Transport(identity);
```

### `transport.request(input, init?): Promise<Response>`

General-purpose method supporting all fetch options.

```javascript
const response = await transport.request('/api/data', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ key: 'value' })
});
```

### Convenience Methods

```javascript
await transport.get('/users');
await transport.post('/users', body, options);
await transport.put('/users/123', body, options);
await transport.delete('/users/123');
```

## Browser Usage

```html
<script type="module">
  import { Identity, Transport } from './dist/browser.js';

  const identity = await Identity.fetchFromServer('https://example.com');
  const transport = new Transport(identity);
  const response = await transport.post('https://example.com/api', 'Hello!');
  console.log(await response.text());
</script>
```

## Development

```sh
npm install
npm run build
npm test
npm run build:browser  # Browser bundle
```

### Running Examples (Node.js)

The Node.js example requires a build and an EHBP server running at `http://localhost:8080`:

```sh
# Build first
npm run build

# Start the Go server (from parent directory)
go run pkg/server/main.go

# Run the example (in another terminal)
npm run example
```

### Running Examples (Browser)

Browser examples are located in `examples/` and require the browser bundle:

```sh
# Build the browser bundle
npm run build:browser

# Start the local dev server
npm run serve

# Start the Go EHBP server (from parent directory, in another terminal)
go run pkg/server/main.go
```

Then open in your browser:

| Example | URL | Description |
|---------|-----|-------------|
| `test.html` | http://localhost:3000/examples/test.html | POST and streaming tests (server: `localhost:8080`) |
| `chat.html` | http://localhost:3000/examples/chat.html | Chat interface demo (server: `localhost:8443`) |

**Note:** `chat.html` connects to port 8443 and expects an OpenAI-compatible chat completions API.

### Running Integration Tests

Integration tests verify streaming functionality against a live server:

```sh
# Start the Go server (from parent directory)
go run pkg/server/main.go

# Run integration tests (in another terminal)
npm run build
npm run test:integration
```

### Commands

| Command | Description |
|---------|-------------|
| `npm test` | Run unit tests (no server required) |
| `npm run test:integration` | Run streaming integration tests (requires server) |
| `npm run example` | Run Node.js API demo (requires server) |
| `npm run serve` | Start local server for browser examples |

## Protocol

See [SPEC.md](../SPEC.md) for the complete protocol specification.

## Security

Report vulnerabilities to [security@tinfoil.sh](mailto:security@tinfoil.sh) or open a GitHub issue.
