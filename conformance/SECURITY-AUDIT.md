# EHBP security audit notes

Scope: `SPEC.md`, the Go server/client, JavaScript, Python, Rust, Swift, and the
conformance harness. This change intentionally adds detection only. It does not
modify a production client, server, or the wire protocol.

## Findings with executable detection

### High — Go request length can force attacker-sized allocation

`identity.StreamingDecryptReader` converts the unauthenticated uint32 frame
length directly into `make([]byte, chunkLen)` without applying the response
side's 64 MiB limit. A remote peer can therefore request an allocation close to
4 GiB before any ciphertext is authenticated.

Detection: `server-request-oversized-frame` declares 64 MiB+1 and expects
`CHUNK_TOO_LARGE` before allocation. The probe runs in a disposable adapter
process. It currently exposes the issue as `FRAMING_TRUNCATED` after allocating.

### High — Go middleware can invoke application code before the full request authenticates

`identity.Identity.Middleware` authenticates one frame by probing one plaintext
byte, then invokes the application handler. If that handler does not drain the
body, a tampered later frame is never opened. Side effects based on an
authenticated prefix can therefore commit while the complete request is
invalid.

Detection: `server-middleware-trailing-tamper` constructs a valid multi-frame
request, corrupts the final frame, and uses a handler that consumes one byte.
The handler running is reported as a divergence.

### High — Swift URL concatenation permits authority confusion

`swift/Sources/EHBP/Client.swift` constructs a URL with `baseURL + path`. A path
such as `@attacker.invalid/x` turns `http://configured.example` into
`http://configured.example@attacker.invalid/x`; the configured host becomes
userinfo and the request authority becomes attacker-controlled. Caller headers
and the encrypted body can be sent to that authority. Credential-bearing base
URLs are also accepted.

Detection: `harden-cross-origin`, `harden-url-credentials`, and
`harden-reserved-header`. The Swift adapter uses a local `URLProtocol` sink, so
the exploit URL is observed without making an external request.

### High/medium — client request boundaries are not consistently enforced

The Go transport does not retain an allowed origin and accepts cross-origin
requests, URL credentials, and caller-supplied reserved protocol headers. The
JavaScript transport rewrites the host but accepts a caller-controlled origin
and reserved headers; in particular, a caller can influence scheme and cleartext
metadata independently of the discovered server URL. Swift has the authority
confusion described above. Python and Rust already reject these inputs.

Detection: the three `harden-*` fixtures now execute on all native clients. Go
uses an in-memory `RoundTripper`, JavaScript is confined to the local oracle,
and Swift uses an in-memory URL protocol. These were previously unconditional
skips, so the suite could not reveal the gap.

### Medium — duplicate security headers are accepted by some paths

Single-value security headers parsed through first-value APIs create ambiguity
between proxies, applications, and protocol endpoints. The Go server uses
`Header.Get` for `Ehbp-Encapsulated-Key`; the Go and JavaScript clients similarly
do not reject duplicate response nonce fields in every runtime.

Detection: `server-request-duplicate-encapsulated-key` and
`e2e-duplicate-nonce`. Browser duplicate-header coverage remains explicitly
inapplicable because Fetch coalesces fields.

### Medium — parser shape and length validation differs across clients

Malformed key configurations and session recovery token JSON are not rejected
uniformly. Notable cases include truncated suite declarations, unsupported
suites, JSON `null`, absent/non-string fields, odd hex, and decoded fields that
are not exactly 32 bytes. Accepting a malformed recovery token defers failure to
later cryptography and can create parser differentials across trust boundaries.

Detection: the `parse-config-*` and `token-*` fixture families now include these
shapes. The suite compares both outcome and canonical error class.

### Medium — empty-frame amplification is unbounded

Section 4.3 permits zero-length frames. All receivers must therefore skip them,
but no protocol budget limits how many may precede authenticated data. The Go
request reader implements skipping recursively, creating an eventual stack
exhaustion route; iterative clients still spend attacker-controlled CPU.

Detection: `decrypt-response-zero-frame-flood`, `e2e-zero-frame-flood`, and
`server-request-zero-frame-burst` provide bounded regression coverage under
adapter timeouts. They do not eliminate the protocol-level amplification.

## Protocol-level limitations without a pass/fail oracle

### High — clean frame-boundary truncation is undetectable

The entity-body EOF is the only message terminator and there is no authenticated
final marker or total-length commitment. Removing one or more complete final
frames therefore produces a valid shorter message; a receiver cannot distinguish
it from an intentionally shorter response. Partial-prefix and partial-ciphertext
truncation are now thoroughly tested, but exact frame-boundary truncation cannot
be represented as a conformance failure without changing the protocol.

### Medium — method, path, status, and headers are outside AEAD authentication

EHBP encrypts bodies with empty AAD. HTTP method/path and most headers remain
visible and mutable, and response status/headers are not cryptographically bound
to the body. Deployments must rely on TLS and application semantics for those
properties. A future protocol revision could bind selected metadata as AAD.

### Medium — discovery resource limits are uneven

Go, JavaScript, Python, and Swift discovery paths do not consistently impose
both a response-size cap and a deadline before parsing key configuration data.
An endpoint or intercepted non-TLS discovery response can consume unbounded
memory or hold a client open. Rust caps the body, but timeout policy remains a
caller/runtime concern. This needs a dedicated slow/streaming oracle mode before
it can become a deterministic, non-flaky conformance fixture.

## Harness issues closed by detection infrastructure

The previous harness warned but continued when a requested adapter was absent,
accepted arbitrary `skipped` results, had no adapter timeout, ignored malformed
browser output, accepted duplicate/missing/wrong-id results, used fixed ports,
and killed any process occupying them. These behaviors could conceal failures or
damage an unrelated local process.

The harness now fails closed for those conditions, validates fixtures/results,
requires exact per-fixture skip authorization, uses per-process timeouts, and
chooses unused loopback ports without killing unrelated processes. Unit tests in
`conformance/harness/test_run.py` cover these controls.
