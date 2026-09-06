# Operations

Each fixture names one `operation`. An adapter reads the fixture, performs the
operation through the library's public API, and reports the result. Byte outputs
go in `body_hex` (lowercase hex). All byte inputs are lowercase hex. `seqHex` is a
big-endian hex u64, carried as a string so no language loses precision.

A fixture file is a JSON array of fixture objects (see `../schema/fixture.schema.json`).

| operation | inputs | success `body_hex` | error codes |
| --- | --- | --- | --- |
| `derive_keys` | `exportedSecret`, `requestEnc`, `responseNonce` | `derivedKey` (32) `\|\|` `derivedNonceBase` (12) = 44 bytes | `INVALID_INPUT` on wrong input length |
| `decrypt_response` | `exportedSecret`, `requestEnc`, `responseNonce`, `encryptedResponse` (full framed body) | decrypted plaintext | `FRAMING_TRUNCATED`, `CHUNK_TOO_LARGE`, `AEAD_DECRYPT_FAILED`, `SEQUENCE_OVERFLOW`, `INVALID_RESPONSE_NONCE` |
| `decrypt_response_streaming` | same as `decrypt_response`, plus top-level `chunking` | decrypted plaintext | same as `decrypt_response` |
| `compute_nonce` | `nonceBase` (12), `seqHex` | nonce (12) | `INVALID_INPUT` |
| `token_roundtrip` | `json` (token JSON string) | decoded `exportedSecret` (32) `\|\|` `requestEnc` (32) | `INVALID_TOKEN` |
| `parse_config` | `config` (RFC 9458 key config) | parsed public key (32) | `INVALID_KEY_CONFIG`, `UNSUPPORTED_SUITE` |
| `marshal_config` | `publicKey` (32), optional `keyId` | marshaled config bytes | `INVALID_INPUT` |

## Rules

- `decrypt_response_streaming` MUST feed the framed body split at the byte offsets
  in `chunking`, in order, and MUST emit a chunk's plaintext only after that frame
  authenticates. On error it MUST report `plaintext_emitted_before_error` and
  `bytes_emitted_before_error` truthfully.
- `token_roundtrip` reports the decoded token bytes, not a re-serialized string, so
  JSON formatting differences never affect equality. A malformed token MUST yield
  `INVALID_TOKEN`, including a field whose decoded length is not 32 bytes.
- `parse_config` MUST parse the first key config and ignore any following configs.
- An adapter MUST NOT special-case a fixture id. It sees only `operation` and
  `inputs`.
