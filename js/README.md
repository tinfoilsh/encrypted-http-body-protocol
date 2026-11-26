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

The X25519 key encapsulation uses [`@noble/curves`](https://github.com/paulmillr/noble-curves) instead of WebCrypto, so X25519 support in the runtime's `crypto.subtle` is **not** required. HMAC-SHA256 (HKDF), AES-256-GCM and randomness use WebCrypto (`crypto.subtle`, `getRandomValues`), which browsers only expose in secure contexts (HTTPS or localhost); request sealing and response decryption run at native speed even where the JavaScript JIT is disabled. Everything else (HPKE, HKDF, framing, JSON) is the verified core.

## Quick Start

```javascript
import { Transport } from 'ehbp';

// Create transport (fetches the server's key configuration from /.well-known/hpke-keys)
const transport = await Transport.create('https://example.com', { discover: true });

// Make encrypted requests - works like fetch()
const response = await transport.post('/api/data', JSON.stringify({ message: 'hello' }), {
  headers: { 'Content-Type': 'application/json' }
});

const data = await response.json();
```

## API

The surface is the five entry points every EHBP SDK exposes
(`conformance/spec/handler.md` section 7), plus the error classes and
`PROTOCOL` constants.

### `Transport.create(server, keys, options?): Promise<Transport>`

`server` is the http(s) origin every request must target. `keys` is one of:

```javascript
{ discover: true }        // fetch /.well-known/hpke-keys (SPEC 3.1)
{ config: Uint8Array }    // an RFC 9458 key configuration you already hold
{ publicKey: Uint8Array } // a 32-byte X25519 public key, e.g. attestation-verified
```

`new Transport(server, keys, options?)` is the synchronous form for an already
resolved `config` or `publicKey`. For attested services, construct it with the
key your attestation layer verified.

### `transport.request(input, init?): Promise<Response>`

One entry point with fetch() semantics for `input` and `init`; `get`, `post`,
`put` and `delete` are one-line wrappers over it.

```javascript
const response = await transport.request('/api/data', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ key: 'value' })
});
await transport.get('/users');
await transport.post('/users', body, options);
```

### `transport.sessionRecoveryToken(): SessionRecoveryToken | undefined`

The token of the exchange in flight (SPEC 6), or `undefined` when there is none.

### `discover(server, options?): Promise<Uint8Array>`

The same discovery `Transport.create` runs, for callers that cache keys; the
result is a public key to pass as `{ publicKey }`.

### `selfCheck(): Promise<string[]>`

The core's primitive vectors through this runtime's crypto; empty when all pass.

### `core`

Helpers over the pure core (config parse and marshal, token parse and format,
key derivation, nonce, decrypting a response from a token) for the conformance
adapter and the tests only. Not part of the supported API.

## Custom network transport

Pass a fetch-compatible implementation in `options.fetch` to use a native HTTP
bridge or relay without replacing global `fetch`; `options.discoverInit` is a
`RequestInit` applied to the key discovery fetch only (e.g. credentials):

```typescript
const transport = await Transport.create('https://enclave.example', { discover: true }, {
  fetch: nativeFetch,
  discoverInit: { credentials: 'include' },
});
```

The callback receives every request the transport sends, including key
discovery. It is always called with no `this`, so pass `window.fetch` directly
but bind methods (`relay.fetch.bind(relay)`).

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
can forge them. Route only to trusted destinations.

Omitting the option preserves the default global `fetch` behavior.

## Browser Usage

```html
<script type="module">
  import { Transport } from './dist/browser.js';

  const transport = await Transport.create('https://example.com', { discover: true });
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
go run ./cmd/example/server -l :8080

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
go run ./cmd/example/server -l :8080
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
go run ./cmd/example/server -l :8080

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

See [SECURITY.md](../SECURITY.md).
