# EHBP JavaScript Client

JavaScript/TypeScript client for [Encrypted HTTP Body Protocol (EHBP)](https://github.com/tinfoilsh/encrypted-http-body-protocol).

EHBP encrypts HTTP request and response bodies end-to-end using HPKE ([RFC 9180](https://datatracker.ietf.org/doc/rfc9180/)) while leaving headers in cleartext for routing.

## Installation

```sh
npm install ehbp
```

## Quick Start

```javascript
import { createTransport } from 'ehbp';

// Create transport (fetches server public key automatically)
const transport = await createTransport('https://example.com');

// Make encrypted requests - works like fetch()
const response = await transport.post('/api/data', JSON.stringify({ message: 'hello' }), {
  headers: { 'Content-Type': 'application/json' }
});

const data = await response.json();
```

## API

### `createTransport(serverURL: string): Promise<Transport>`

Creates a transport that automatically encrypts requests and decrypts responses.

```javascript
const transport = await createTransport('https://example.com');
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
  import { createTransport } from './dist/browser.js';

  const transport = await createTransport('https://example.com');
  const response = await transport.post('/api', 'Hello!');
  console.log(await response.text());
</script>
```

## Requirements

- Node.js 20+ or modern browsers with Web Crypto API

## Development

```sh
npm install
npm run build
npm test
npm run build:browser  # Browser bundle
```

### Running Examples

The example requires a build and an EHBP server running at `http://localhost:8080`:

```sh
# Build first
npm run build

# Start the Go server (from parent directory)
go run pkg/server/main.go

# Run the example (in another terminal)
npm run example
```

### Running Integration Tests

Integration tests verify streaming functionality against a live server:

```sh
# Start the Go server (from parent directory)
go run pkg/server/main.go

# Run integration tests (in another terminal)
npm run build
npm run test:integration
```

### Test Commands

| Command | Description |
|---------|-------------|
| `npm test` | Run unit tests (no server required) |
| `npm run test:integration` | Run streaming integration tests (requires server) |
| `npm run example` | Run API usage demo (requires server) |

## Protocol

See [SPEC.md](../SPEC.md) for the complete protocol specification.

## Security

Report vulnerabilities to [security@tinfoil.sh](mailto:security@tinfoil.sh) or open a GitHub issue.
