# Native Error -> Canonical Code Mapping

Each adapter fills its column as it is built. This table is the audit trail for
requirement 1: the normalization must be explicit and reviewable. Empty cells mean
the adapter does not exist yet.

A cell MUST name the concrete native type, variant, or message the adapter matches
on, so a reviewer can confirm the mapping is not lossy. Where a language cannot yet
produce a code, write `MISSING` and link the tracking issue.

| Canonical code | Go | Python | Rust | JavaScript | Swift |
| --- | --- | --- | --- | --- | --- |
| `INVALID_KEY_CONFIG` | | `InvalidConfigError` | `Error::InvalidConfig` | | `EHBPError.invalidInput` (parse) |
| `UNSUPPORTED_SUITE` | | `InvalidConfigError` (suite) | `Error::InvalidConfig` (suite) | `ProtocolError` (suite); KEM `MISSING` | `EHBPError.invalidInput` (suite); KEM ok |
| `INVALID_ENCAPSULATED_KEY` | `ClientError` | — | — | — | — |
| `HPKE_SETUP_FAILED` | | `HPKEError` | `Error::Hpke` | | `EHBPError.encryptionFailed` |
| `MISSING_RESPONSE_NONCE` | | `ProtocolError` | `Error::Protocol` | `ProtocolError` | `EHBPError.missingHeader` |
| `INVALID_RESPONSE_NONCE` | | `ProtocolError` | `Error::Protocol` | `ProtocolError` | `EHBPError.invalidResponse` |
| `DUPLICATE_RESPONSE_NONCE` | `MISSING` | `ProtocolError` | `Error::Protocol` | `MISSING` | `MISSING` |
| `KEY_CONFIG_MISMATCH` | `KeyConfigError` | `KeyConfigMismatchError` | `Error::KeyConfigMismatch` | `KeyConfigMismatchError` | `MISSING` |
| `FRAMING_TRUNCATED` | (bare error) | `ProtocolError` | `Error::Protocol` | `ProtocolError` | `EHBPError.invalidResponse` |
| `CHUNK_TOO_LARGE` | (bare error) | `ProtocolError` | `Error::Protocol` | `ProtocolError` | `EHBPError.invalidResponse` |
| `AEAD_DECRYPT_FAILED` | (bare error) | `CryptoError` | `Error::Crypto` | `DecryptionError` | `EHBPError.decryptionFailed` |
| `SEQUENCE_OVERFLOW` | panic/error | `ProtocolError` | `Error::Protocol` | range error | `EHBPError.invalidResponse` |
| `INVALID_TOKEN` | (no length check) | `InvalidInputError` | serde error | (no length check) | `DecodingError` |
| `INVALID_INPUT` | — | `InvalidInputError` | `Error::InvalidInput` | — | `EHBPError.invalidInput` |

The cells already marked `MISSING` or "(bare error)" / "(no length check)" are the
divergences the earlier analysis found. They are recorded here now, before any code
runs, so the suite is expected to go red on them and the burndown is pre-scoped.
