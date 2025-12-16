package protocol

const (
	EncapsulatedKeyHeader = "Ehbp-Encapsulated-Key"
	FallbackHeader        = "Ehbp-Fallback"
	KeysMediaType         = "application/ohttp-keys"
	KeysPath              = "/.well-known/hpke-keys"
)

// ResponseExportContext is the HPKE exporter context used to derive response encryption keys
// from the request encryption context. This enables bidirectional authenticated encryption.
// See Section 9.8 of RFC 9180.
var ResponseExportContext = []byte("ehbp response")
