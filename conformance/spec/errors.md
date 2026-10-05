# Canonical Error Codes

Every adapter maps a native error to exactly one code below and reports it as
`error_code`. The raw error is reported as `native_error` and MUST NOT be asserted.
The set is no coarser than SPEC.md Section 5.4.1, so distinct failures never merge.
Where a client cannot yet produce the expected code, the adapter reports what it
does produce; the mismatch is a fix target, not grounds to relax the fixture.

`side` marks where a code is observable: `client`, `server`, or `both`.

| Code | side | SPEC ref | Meaning |
| --- | --- | --- | --- |
| `INVALID_KEY_CONFIG` | client | 3.1, 3.2 | Config unparseable: truncated, bad public key, no suites, or wrong discovery content type / status. |
| `UNSUPPORTED_SUITE` | client | 3.2 | Config advertises a KEM/KDF/AEAD other than X25519-HKDF-SHA256 / HKDF-SHA256 / AES-256-GCM. |
| `INVALID_ENCAPSULATED_KEY` | server | 4.1, 4.2, 5.4.1 | Request `Ehbp-Encapsulated-Key` missing, duplicated, not hex, or wrong length. |
| `HPKE_SETUP_FAILED` | both | 5.4.1 | HPKE setup or decapsulation failed. |
| `MISSING_RESPONSE_NONCE` | client | 4.2, 5.3 | `Ehbp-Response-Nonce` absent on a 2xx to an encrypted request. |
| `INVALID_RESPONSE_NONCE` | client | 4.2 | `Ehbp-Response-Nonce` not hex or not 32 bytes. |
| `DUPLICATE_RESPONSE_NONCE` | client | 4.2 | More than one `Ehbp-Response-Nonce` header. |
| `KEY_CONFIG_MISMATCH` | client | 5.4.2 | 422 `application/problem+json`, type `urn:ietf:params:ehbp:error:key-config`. |
| `FRAMING_TRUNCATED` | both | 4.3 | Stream ended mid-frame: partial length prefix or partial ciphertext. |
| `CHUNK_TOO_LARGE` | both | 4.3 + suite security limit | Frame length prefix exceeds 64 MiB; reject before allocation. |
| `AEAD_DECRYPT_FAILED` | both | 4.3, 5.4.1 | AEAD authentication failed: tampered ciphertext, wrong key, wrong sequence. |
| `SEQUENCE_OVERFLOW` | both | 4.4.2 | Response chunk sequence exhausted (2^64). |
| `INVALID_TOKEN` | client | 6.1.1 | Session recovery token JSON: bad hex, missing field, or wrong length. |
| `INVALID_INPUT` | client | 5.1 | Caller misuse: reserved header set, cross-origin URL, credentials in URL, bad hex. |
| `ADAPTER_CRASH` | harness | — | Synthetic harness result for timeout, crash, missing/malformed output, or invalid result schema. Adapters do not emit it themselves. |

## Exposure in SDKs

Every SDK attaches the code to its native error (SPEC 5.5), so the suite asserts
the library's own classification and adapters perform no translation. Messages
are `<CODE>: <detail>`; the detail is diagnostic and not asserted.

| SDK | class exposed as | read it with |
| --- | --- | --- |
| Go | `protocol.Code` constants on `*protocol.Error` | `protocol.CodeOf(err)` |
| Python | one `EHBPError` subclass per code (`UnsupportedSuiteError`) | `ehbp.code_of(err)` / `err.code` |
| Rust | `Error::Coded(Code, detail)` | `err.code()` (`Option`) |
| JavaScript | one `EhbpError` subclass per code (`UnsupportedSuiteError`) | `codeOf(err)` / `err.code` |
| Swift | `EHBPError(code, detail)` struct | `(error as? EHBPError)?.code` |

Names are the code in each language's casing; acronyms follow the language
(`HPKESetupFailedError` in Python, `HpkeSetupFailedError` in JavaScript).

## Coded messages

Every SDK prefixes an error's message with its canonical code (`CODE: detail`,
SPEC 5.5). The harness enforces this on every `error` result: a `native_error`
that does not contain `error_code` followed by `:` (transports may wrap it with context) marks the cell divergent
with the label `UNCODED`. That is the signature of an error the library raised
uncoded and the adapter's `INVALID_INPUT` fallback masked, so it can never pass
by coincidence.

## Fail-closed

For any error code, `plaintext_emitted_before_error` MUST be `false` and
`bytes_emitted_before_error` MUST be `0`. A sanctioned pass-through (non-2xx, no
nonce) is reported `outcome: ok` with `passthrough: true`. It MUST NOT be reported
as a decrypted body.

Authenticated plaintext from a complete earlier frame may be reported before a
later framing/authentication error only when the fixture explicitly says so.
Server middleware fixtures follow the same per-chunk rule (SPEC 4.3, 5.2): the
server releases each request chunk to the application as it authenticates, so a
tampered trailing frame fails inside the handler's read. The fixture states the
authenticated prefix that was delivered; nothing from the failing frame or after
it may be.

## Granularity

- `INVALID_KEY_CONFIG` and `UNSUPPORTED_SUITE` are separate. A truncated config and
  a well-formed ChaCha20 config are different bugs.
- `MISSING`, `INVALID`, and `DUPLICATE_RESPONSE_NONCE` are three codes. Clients
  diverge on exactly these.
- `HPKE_SETUP_FAILED` is separate from `AEAD_DECRYPT_FAILED` so an oracle
  distinction shows as a code diff. Adapters MUST still not leak the distinction to
  the network (SPEC 5.4.4).
