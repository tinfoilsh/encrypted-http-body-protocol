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

The X25519 key encapsulation uses [`@noble/curves`](https://github.com/paulmillr/noble-curves) (via `@panva/hpke-noble`) instead of WebCrypto, so X25519 support in the runtime's `crypto.subtle` is **not** required. HKDF and AES-256-GCM use WebCrypto (`crypto.subtle`), which browsers only expose in secure contexts (HTTPS or localhost); response decryption runs at native speed even where the JavaScript JIT is disabled.

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

## Custom network transport

Pass a fetch-compatible implementation as the third argument to `Transport`,
`Transport.create`, or `createTransport` to use a native HTTP bridge or relay
without replacing global `fetch`:

```typescript
const transport = new Transport(verifiedIdentity, 'https://enclave.example', {
  fetch: nativeFetch,
});
```

The callback receives every request the transport sends, including server key
discovery in `Transport.create` and `createTransport`. It is always called with
no `this`, so pass `window.fetch` directly but bind methods
(`relay.fetch.bind(relay)`).

Requests with a body arrive as a single EHBP-encrypted `Request`. Bodyless
requests arrive unencrypted. `data:` and `blob:` URLs skip EHBP and arrive as
the caller's original `(input, init)`; handle them or forward them to
`globalThis.fetch`.

The callback must preserve the encrypted body and protocol headers, finish
reading the request body before resolving, return a standard `Response`, and
honor request cancellation and redirect policy.

Only encrypted request bodies and response bodies carrying `Ehbp-Response-Nonce`
are protected; a 2xx response to an encrypted request without that header is
rejected. Headers, including authorization, are visible to the callback. Error
responses without that header, responses to bodyless requests, and key
discovery are not authenticated, and the callback or anything it routes through
can forge them. Route only to
trusted destinations. For attested services, construct `Transport` with an
identity verified by your attestation layer.

Omitting the option preserves the default global `fetch` behavior.

## API

### `createTransport(serverURL: string, init?: RequestInit, options?: TransportOptions): Promise<Transport>`

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
