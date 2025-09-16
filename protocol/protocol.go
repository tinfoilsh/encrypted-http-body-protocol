package protocol

const (
	EncapsulatedKeyHeader = "Ehbp-Encapsulated-Key"
	ClientPublicKeyHeader = "Ehbp-Client-Public-Key"
	FallbackHeader        = "Ehbp-Fallback"
	KeysMediaType         = "application/ohttp-keys"
	KeysPath              = "/.well-known/hpke-keys"
)
