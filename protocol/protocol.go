package protocol

const (
	// EncapsulatedKeyHeader contains the HPKE encapsulated key for requests.
	// This is used by the client to send the encapsulated key to the server.
	EncapsulatedKeyHeader = "Ehbp-Encapsulated-Key"

	// ResponseNonceHeader contains the random nonce for response key derivation (v2).
	// The server generates this and includes it in the response so the client
	// can derive the same response decryption keys.
	ResponseNonceHeader = "Ehbp-Response-Nonce"

	// FallbackHeader indicates plaintext fallback was used
	FallbackHeader = "Ehbp-Fallback"

	// KeysMediaType is the content type for key configuration
	KeysMediaType = "application/ohttp-keys"

	// KeysPath is the well-known path for key distribution
	KeysPath = "/.well-known/hpke-keys"

	// ClientPublicKeyHeader is DEPRECATED and should not be used.
	// In v1, this header allowed clients to specify their public key for response
	// encryption. This was vulnerable to MitM attacks where an attacker could
	// replace the header with their own key. In v2, response keys are derived
	// from the request's HPKE context instead.
	ClientPublicKeyHeader = "Ehbp-Client-Public-Key" // DEPRECATED
)
