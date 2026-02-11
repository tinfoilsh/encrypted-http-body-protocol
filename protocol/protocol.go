package protocol

const (
	// EncapsulatedKeyHeader contains the HPKE encapsulated key for requests.
	// This is used by the client to send the encapsulated key to the server.
	EncapsulatedKeyHeader = "Ehbp-Encapsulated-Key"

	// ResponseNonceHeader contains the random nonce for response key derivation.
	// The server generates this and includes it in the response so the client
	// can derive the same response decryption keys.
	ResponseNonceHeader = "Ehbp-Response-Nonce"

	// KeysMediaType is the content type for key configuration
	KeysMediaType = "application/ohttp-keys"

	// KeysPath is the well-known path for key distribution
	KeysPath = "/.well-known/hpke-keys"

	// ProblemJSONMediaType is the media type for RFC 7807-style problem details.
	ProblemJSONMediaType = "application/problem+json"

	// KeyConfigProblemType identifies EHBP key configuration mismatch errors.
	// Clients can use this signal to refresh key config and retry safely.
	KeyConfigProblemType = "urn:ietf:params:ehbp:error:key-config"
)
