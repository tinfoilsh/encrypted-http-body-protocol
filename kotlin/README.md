# EHBP Kotlin client

A Kotlin client for the [Encrypted HTTP Body Protocol](../SPEC.md) with the
same five entry points and the same error codes as every other SDK
(`conformance/spec/handler.md`, section 7). The protocol, HPKE,
HKDF and JSON are the verified Dafny core; the library binds only X25519 and
HMAC (BouncyCastle) and AES-GCM (the JDK). HTTP is OkHttp, so the same artifact runs on the JVM
(17+) and on Android (minSdk 21). Only the client side is ported: there is no
server middleware.

## Install

Releases are served by [JitPack](https://jitpack.io/#tinfoilsh/encrypted-http-body-protocol)
from the git tag, so the Kotlin client ships with the same `v<version>` tag as
Go and Swift and needs no separate publish step.

```kotlin
repositories { maven("https://jitpack.io") }
dependencies { implementation("com.github.tinfoilsh:encrypted-http-body-protocol:v0.7.0") }
```

The Kotlin client first ships in `v0.7.0`; earlier tags predate it.

CI compares JitPack's artifact against a clean local build of the same commit
on every push to `main` and every release tag.

## Build and test

```
./gradlew test                                   # JVM unit tests + interop vectors
ANDROID_HOME=... ./gradlew :android:assembleRelease :android:lintRelease
```

The `android/` module compiles the same sources as an Android library against
minSdk 21 and fails on any `NewApi` lint finding, so a JDK-only or too-new API
breaks the build here instead of in an app. It is only included when an Android
SDK is present (`ANDROID_HOME`, `ANDROID_SDK_ROOT` or `local.properties`); pass
`-PnoAndroid` to leave it out regardless.

The jar is reproducible: archive timestamps and entry order are fixed, and CI
(`.github/workflows/reproducibility.yml`) builds it twice from clean in two
directories and fails if the SHA-256 differs.

## Usage

```kotlin
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import sh.tinfoil.ehbp.client.KeySource
import sh.tinfoil.ehbp.client.Transport

// Fetches /.well-known/hpke-keys and pins requests to that origin.
val transport = Transport("https://api.example.com", KeySource.Discover)

val request = Request.Builder()
    .url("https://api.example.com/v1/chat")
    .header("Content-Type", "application/json")
    .post("""{"hello":"world"}""".toByteArray().toRequestBody())
    .build()

transport.roundTrip(request).use { response ->   // body is the decrypted plaintext stream
    println(response.body!!.string())
}
```

The other key sources make no network request and pin the same origin:

- `KeySource.Config(hpkeKeysBytes)` for a pre-fetched key configuration
  (RFC 9458 `application/ohttp-keys` bytes).
- `KeySource.PublicKey(bytes)` for an attestation-verified 32-byte public key.

`discover(server, httpClient)` runs the same discovery as the constructor and
returns the public key, for callers that cache keys. `selfCheck()` runs the
core's primitive vectors through this build's crypto bindings; an empty list
means pass. The constructor and `discover` take an optional `OkHttpClient`
(TLS pinning, timeouts, proxies, cookies). Like Go's `RoundTripper`,
`roundTrip` performs one HTTP
transaction with redirects disabled. An encrypted request that receives a 3xx
fails with `UNEXPECTED_REDIRECT`. A bodyless request returns the redirect to the caller.
Key discovery also rejects redirects, requests exactly `/.well-known/hpke-keys`
on the configured origin, and reads only the first key configuration.

## Semantics

- A request with a body is encrypted in 64 KiB frames while it streams; a
  bodyless request (no body, or a known zero-length body) passes through in
  plaintext, and so does its response. A known-empty body is frozen at preparation time.
  The transport checks unknown-length bodies as they stream. An empty source uses the bodyless path.
  Duplex request bodies are rejected with `INVALID_INPUT` before sending.
- A 1xx or 2xx response to an encrypted request requires `Ehbp-Response-Nonce`
  and at least one authenticated frame. A missing nonce yields `MISSING_RESPONSE_NONCE`.
  A body that ends before any frame authenticates yields `FRAMING_TRUNCATED`.
  An authenticated frame can carry empty plaintext. Statuses 204 and 205 cannot
  carry a frame. A 4xx or 5xx response without the header can pass through as an
  unauthenticated error.
- A 422 `application/problem+json` key-config problem throws `KeyConfigError`
  (code `KEY_CONFIG_MISMATCH`): refresh the key config and retry. Detection
  (SPEC 5.4.2) applies only to responses without `Ehbp-Response-Nonce`; the
  body must be a JSON object of at most 64 KiB whose exact, case-sensitive
  `type` member is the key-config URN. `title` is used when it is a string,
  otherwise the message is `key configuration mismatch`. Anything else passes
  through as a plaintext 422.
- `Ehbp-Encapsulated-Key`, `Ehbp-Response-Nonce` and `Host` are reserved
  (SPEC 5.1): a caller-set value is `INVALID_INPUT`. Caller-set
  `Content-Length` / `Transfer-Encoding` are dropped; the library frames the body.
- Response plaintext is released frame by frame as each frame authenticates;
  after a failure the body stream rethrows the same error forever.
- `sessionRecoveryToken()` is readable as soon as the request body is
  encrypted and before it is sent, so it can be persisted ahead of a crash
  (SPEC 6). It is cleared once the exchange is consumed (SPEC 6.3): the
  response was fully read, its body was closed before EOF, a newer request
  superseded it, or the exchange
  failed (pass-through, key-config problem, transport error, or a body that
  stopped authenticating). Persist the token beforehand if you need it
  afterwards.
- `sh.tinfoil.ehbp.Core` exposes the core's helpers (config and token parsing,
  key derivation, nonce, decryption with a token) for the conformance adapter
  and tests only; it is not part of the public API.

## Errors

All protocol failures carry a `sh.tinfoil.ehbp.protocol.ProtocolError`, an
`IOException` whose `code` is the SPEC 5.5 class and whose message is
`CODE: detail`. One wrapper exists, as in Go: a 422 key-config problem is
thrown as `KeyConfigError` with the `KEY_CONFIG_MISMATCH` `ProtocolError` as
its cause, so callers can catch the rekey case by type. `codeOf(throwable)`
finds the code anywhere in a cause chain and is the portable way to classify
either. Transport failures surface as OkHttp's own `IOException`s, uncoded.
