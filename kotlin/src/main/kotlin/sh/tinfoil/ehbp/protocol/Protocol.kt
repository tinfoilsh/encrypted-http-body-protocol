// Mirrors protocol/protocol.go.
package sh.tinfoil.ehbp.protocol

/** EncapsulatedKeyHeader contains the HPKE encapsulated key for requests. */
const val EncapsulatedKeyHeader = "Ehbp-Encapsulated-Key"

/** ResponseNonceHeader contains the random nonce for response key derivation. */
const val ResponseNonceHeader = "Ehbp-Response-Nonce"

/** KeysMediaType is the content type for key configuration. */
const val KeysMediaType = "application/ohttp-keys"

/** KeysPath is the well-known path for key distribution. */
const val KeysPath = "/.well-known/hpke-keys"

/** ProblemJSONMediaType is the media type for RFC 7807-style problem details. */
const val ProblemJSONMediaType = "application/problem+json"

/** KeyConfigProblemType identifies EHBP key configuration mismatch errors. */
const val KeyConfigProblemType = "urn:ietf:params:ehbp:error:key-config"
