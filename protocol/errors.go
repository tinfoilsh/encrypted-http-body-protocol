package protocol

import (
	"errors"
	"fmt"
)

// Code is the canonical, cross-SDK error class. The set is normative in
// conformance/spec/errors.md and every SDK exposes the same strings, so a
// caller's error handling ports between languages unchanged.
type Code string

const (
	InvalidKeyConfig       Code = "INVALID_KEY_CONFIG"
	UnsupportedSuite       Code = "UNSUPPORTED_SUITE"
	InvalidEncapsulatedKey Code = "INVALID_ENCAPSULATED_KEY"
	HPKESetupFailed        Code = "HPKE_SETUP_FAILED"
	MissingResponseNonce   Code = "MISSING_RESPONSE_NONCE"
	InvalidResponseNonce   Code = "INVALID_RESPONSE_NONCE"
	DuplicateResponseNonce Code = "DUPLICATE_RESPONSE_NONCE"
	KeyConfigMismatch      Code = "KEY_CONFIG_MISMATCH"
	FramingTruncated       Code = "FRAMING_TRUNCATED"
	ChunkTooLarge          Code = "CHUNK_TOO_LARGE"
	AEADDecryptFailed      Code = "AEAD_DECRYPT_FAILED"
	SequenceOverflow       Code = "SEQUENCE_OVERFLOW"
	InvalidToken           Code = "INVALID_TOKEN"
	InvalidInput           Code = "INVALID_INPUT"
)

// Error pairs a canonical Code with its native cause. Its message is
// "<CODE>: <cause>" so logs are greppable by code across SDKs. Codes are for
// the in-process caller only; servers MUST NOT echo them to the network
// (SPEC 5.4.4).
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Err.Error()
}
func (e *Error) Unwrap() error { return e.Err }

// Is makes errors.Is(err, &protocol.Error{Code: c}) match by code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t != nil && t.Code == e.Code
}

// Errorf builds a coded error; format and args behave as fmt.Errorf (use %w to chain).
func Errorf(code Code, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// CodeOf returns the canonical code found anywhere in err's chain, or "" if none.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
