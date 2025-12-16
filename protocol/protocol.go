package protocol

const (
	EncapsulatedKeyHeader = "Ehbp-Encapsulated-Key"
	FallbackHeader        = "Ehbp-Fallback"
	KeysMediaType         = "application/ohttp-keys"
	KeysPath              = "/.well-known/hpke-keys"

	// MaxChunkSize limits the maximum size of a single encrypted chunk to prevent
	// memory exhaustion attacks. 64MB is generous for most use cases while still
	// providing protection against malicious chunk lengths.
	MaxChunkSize = 64 * 1024 * 1024
)

// ResponseExportContext is the HPKE exporter context used to derive response encryption keys
// from the request encryption context. This enables bidirectional authenticated encryption.
// See Section 9.8 of RFC 9180.
var ResponseExportContext = []byte("ehbp response")
