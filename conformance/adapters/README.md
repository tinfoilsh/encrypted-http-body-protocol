# Adapters

Every adapter is the same program in a different language. Keeping them
structurally identical is what makes the results comparable and the suite
extensible: to add a language you copy this shape and fill in the public-API calls.

## Interface

- **Input:** one fixture JSON object on stdin.
- **Output:** one normalized result JSON object on stdout (see
  `../schema/result.schema.json`). Exit 0 even for `outcome: error`; reserve a
  non-zero exit and stderr for an adapter crash (a bug in the adapter itself).
- **Environment:** `ORACLE_URL` and the two loopback discovery endpoints
  `ORACLE_BAD_CT_URL` / `ORACLE_NON200_URL`.

## Required shape

1. Read and parse the fixture.
2. Dispatch on `operation` (listed in `../spec/operations.md`). Never branch on
   the fixture `id`.
3. Call only the library's public API — the entrypoints the README documents.
4. Byte outputs go to `body_hex` (lowercase hex).
5. On any library error, translate it in one place: a single `map_error` function
   that returns a canonical code from `../spec/errors.md`. Put the raw error in
   `native_error`; never assert on it. Each arm names the concrete native
   type/message it matches, and the mapping is mirrored in
   `../spec/error-mapping.md`.
6. Track fail-closed honestly: `plaintext_emitted_before_error` and
   `bytes_emitted_before_error` reflect bytes actually delivered before an error.
7. Return `skipped` only when the fixture authorizes that runner and exact reason
   in `allowed_skips`. A hard or failing case is never a capability skip.

## Operation output convention

| operation | success `body_hex` |
| --- | --- |
| `derive_keys` | `key` (32) `\|\|` `nonce_base` (12) |
| `decrypt_response`, `decrypt_response_streaming` | plaintext |
| `compute_nonce` | nonce (12) |
| `token_roundtrip` | decoded `exportedSecret` (32) `\|\|` `requestEnc` (32) |
| `parse_config` | public key (32) |
| `marshal_config` | marshaled config bytes |
| `request` | delivered body: decrypted plaintext, or a pass-through body |
| `decrypt_request` | decrypted request plaintext |
| `middleware_request` | none; success means application code ran |

## e2e result fields

For `operation: request` also set `status`, `response_headers` (lowercased subset:
`ehbp-response-nonce`, `content-length`, `transfer-encoding`, `content-type`), and
`passthrough` (true only for a non-2xx response with no nonce that the client hands
back unauthenticated).

## Which API layer

Use each library's primary client/transport — the path a real user calls to send a
request and get a decrypted response. That is the layer whose behavior must agree
across languages. Do not reach past it into internals to smooth over a difference;
a difference is a finding.

## Registry

| language | dir | run | toolchain here |
| --- | --- | --- | --- |
| Go | `go/` | built binary | yes |
| Python | `python/` | `.venv` python | yes |
| JavaScript (Node) | `js/` | built `dist` | yes |
| Swift | `swift/` | built binary | yes |
| Rust | `rust/` | cargo binary | CI only (no local toolchain) |
| JavaScript (browser) | `js-browser/` | Playwright page | Step 6 |
