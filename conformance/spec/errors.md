# Canonical Error Codes

Every adapter maps its native error to exactly one code below and reports it as
`error_code`. The raw error is reported as `native_error` and MUST NOT be asserted.
The set is no coarser than SPEC.md Section 5.4.1, so distinct failures never merge.
Where a client cannot yet produce the expected code, the adapter reports what it
does produce; the mismatch is a fix target, not grounds to relax the fixture.

`side` marks where a code is observable: `client`, `server`, or `both`.

| Code | side | SPEC ref | Meaning |
| --- | --- | --- | --- |
| `OK` | both | — | No error. Reserved so success fixtures carry a code field. |
| `INVALID_KEY_CONFIG` | client | 3.1, 3.2 | Config unparseable: truncated, bad public key, no suites, or wrong discovery content type / status. |
| `UNSUPPORTED_SUITE` | client | 3.2 | Config advertises a KEM/KDF/AEAD other than X25519-HKDF-SHA256 / HKDF-SHA256 / AES-256-GCM. |
| `INVALID_ENCAPSULATED_KEY` | server | 4.1, 5.4.1 | Request `Ehbp-Encapsulated-Key` missing, not hex, or wrong length. |
| `HPKE_SETUP_FAILED` | both | 5.4.1 | HPKE setup or decapsulation failed. |
| `MISSING_RESPONSE_NONCE` | client | 4.2, 5.3 | `Ehbp-Response-Nonce` absent on a 2xx to an encrypted request. |
| `INVALID_RESPONSE_NONCE` | client | 4.2 | `Ehbp-Response-Nonce` not hex or not 32 bytes. |
| `DUPLICATE_RESPONSE_NONCE` | client | 4.2 | More than one `Ehbp-Response-Nonce` header. |
| `KEY_CONFIG_MISMATCH` | client | 5.4.2 | 422 `application/problem+json`, type `urn:ietf:params:ehbp:error:key-config`. |
| `FRAMING_TRUNCATED` | both | 4.3 | Stream ended mid-frame: partial length prefix or partial ciphertext. |
| `CHUNK_TOO_LARGE` | both | 4.3 | Frame length prefix exceeds the 64 MiB maximum. |
| `AEAD_DECRYPT_FAILED` | both | 4.3, 5.4.1 | AEAD authentication failed: tampered ciphertext, wrong key, wrong sequence. |
| `SEQUENCE_OVERFLOW` | both | 4.4.2 | Response chunk sequence exhausted (2^64). |
| `INVALID_TOKEN` | client | 6.1.1 | Session recovery token JSON: bad hex, missing field, or wrong length. |
| `INVALID_INPUT` | client | 5.1 | Caller misuse: reserved header set, cross-origin URL, credentials in URL, bad hex. |

## Fail-closed

For any code other than `OK`, `plaintext_emitted_before_error` MUST be `false` and
`bytes_emitted_before_error` MUST be `0`. A sanctioned pass-through (non-2xx, no
nonce) is reported `outcome: ok` with `passthrough: true`. It MUST NOT be reported
as a decrypted body.

## Granularity

- `INVALID_KEY_CONFIG` and `UNSUPPORTED_SUITE` are separate. A truncated config and
  a well-formed ChaCha20 config are different bugs.
- `MISSING`, `INVALID`, and `DUPLICATE_RESPONSE_NONCE` are three codes. Clients
  diverge on exactly these.
- `HPKE_SETUP_FAILED` is separate from `AEAD_DECRYPT_FAILED` so an oracle
  distinction shows as a code diff. Adapters MUST still not leak the distinction to
  the network (SPEC 5.4.4).
