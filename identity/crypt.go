package identity

import "errors"

const (
	// HPKERequestInfo is the info string for HPKE sender/receiver setup.
	HPKERequestInfo = "ehbp request"
	// ExportLabel is the context string for HPKE Export.
	ExportLabel = "ehbp response"
	// ExportLength is the length of the exported secret (Nk of AES-256-GCM).
	ExportLength = 32
	// RequestEncLength is the X25519 encapsulated key size.
	RequestEncLength = 32
	// ResponseNonceLength is the length of the random response nonce, max(Nn, Nk).
	ResponseNonceLength = 32
)

// ClientError represents an error caused by invalid client input
type ClientError struct {
	Err error
}

func (e ClientError) Error() string {
	return e.Err.Error()
}

func (e ClientError) Unwrap() error {
	return e.Err
}

// NewClientError wraps an error as a client-caused error
func NewClientError(err error) error {
	return ClientError{Err: err}
}

// IsClientError determines if an error is caused by invalid client input
func IsClientError(err error) bool {
	var clientErr ClientError
	return errors.As(err, &clientErr)
}

// KeyConfigError represents a client/server key configuration mismatch.
// This is used for stale or incompatible HPKE key material that requires rekey.
type KeyConfigError struct {
	Err error
}

func (e KeyConfigError) Error() string {
	return e.Err.Error()
}

func (e KeyConfigError) Unwrap() error {
	return e.Err
}

// NewKeyConfigError wraps an error as a key configuration mismatch.
func NewKeyConfigError(err error) error {
	return KeyConfigError{Err: err}
}

// IsKeyConfigError determines if an error indicates key configuration mismatch.
func IsKeyConfigError(err error) bool {
	var keyErr KeyConfigError
	return errors.As(err, &keyErr)
}
