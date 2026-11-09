# EHBP Kotlin client

A Kotlin client for the [Encrypted HTTP Body Protocol](../SPEC.md) that mirrors
the Go reference client file for file (`protocol/`, `identity/`, `client/`),
with the same function names and the same error codes. Crypto is BouncyCastle
(HPKE, HKDF, AES-GCM); HTTP is OkHttp, so the same artifact runs on the JVM
(17+) and on Android (minSdk 21). Only the client side is ported: there is no
server middleware.

## Install

Releases are served by [JitPack](https://jitpack.io/#tinfoilsh/encrypted-http-body-protocol)
from the git tag, so the Kotlin client ships with the same `v<version>` tag as
Go and Swift and needs no separate publish step.

```kotlin
repositories { maven("https://jitpack.io") }
dependencies { implementation("com.github.tinfoilsh.encrypted-http-body-protocol:ehbp:v0.5.0") }
```

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
import sh.tinfoil.ehbp.client.newTransport

// Fetches /.well-known/hpke-keys and pins requests to that origin.
val transport = newTransport("https://api.example.com")

val request = Request.Builder()
    .url("https://api.example.com/v1/chat")
    .header("Content-Type", "application/json")
    .post("""{"hello":"world"}""".toByteArray().toRequestBody())
    .build()

transport.roundTrip(request).use { response ->   // body is the decrypted plaintext stream
    println(response.body!!.string())
}
```

Other constructors, as in Go:

- `newTransportWithConfig(server, hpkeKeysBytes)` for a pre-fetched key config.
- `newTransportWithIdentity(fromPublicKeyHex(hex))` for an attestation-verified
  public key; no network fetch and no origin pin.

Every constructor takes an optional `OkHttpClient` (TLS pinning, timeouts,
proxies, cookies). `roundTrip` is a single HTTP transaction like Go's
`RoundTripper`: the client is used with redirects disabled and a 3xx is returned
to the caller instead of being replayed against the new location.
Key discovery also rejects redirects, requests exactly `/.well-known/hpke-keys`
on the configured origin, and reads only the first key configuration.

## Semantics

- A request with a body is encrypted in 8 KiB frames while it streams; a
  bodyless request (no body, or a known zero-length body) passes through in
  plaintext, and so does its response.
- A 2xx response without `Ehbp-Response-Nonce` fails closed
  (`MISSING_RESPONSE_NONCE`); a non-2xx response without the header is returned
  as an unauthenticated pass-through.
- A 422 `application/problem+json` key-config problem throws `KeyConfigError`
  (code `KEY_CONFIG_MISMATCH`): refresh the key config and retry.
- Response plaintext is released frame by frame as each frame authenticates;
  after a failure the body stream rethrows the same error forever.
- `getSessionRecoveryToken()` is readable as soon as the request body is
  encrypted and before it is sent, so it can be persisted ahead of a crash
  (SPEC 6). It is cleared once the exchange is consumed: the response was
  fully read, a newer request superseded it, or the exchange failed
  (pass-through, key-config problem, transport error, or a body that stopped
  authenticating). Clearing on failure goes beyond SPEC 6.3, which names only
  full decryption and supersession; it is a deliberate choice shared by the
  Go, Python and Rust clients so that a failed exchange never leaves live key
  material behind. Persist the token beforehand if you need it afterwards.

## Errors

All protocol failures carry a `sh.tinfoil.ehbp.protocol.ProtocolError`, an
`IOException` whose `code` is the SPEC 5.5 class and whose message is
`CODE: detail`. One wrapper exists, as in Go: a 422 key-config problem is
thrown as `KeyConfigError` with the `KEY_CONFIG_MISMATCH` `ProtocolError` as
its cause, so callers can catch the rekey case by type. `codeOf(throwable)`
finds the code anywhere in a cause chain and is the portable way to classify
either. Transport failures surface as OkHttp's own `IOException`s, uncoded.
