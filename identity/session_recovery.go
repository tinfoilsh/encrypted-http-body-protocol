package identity

import (
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// SessionRecoveryToken contains the pre-computed bytes needed to decrypt a
// response without holding a live HPKE context. It can be serialized (e.g. to
// JSON) and used later or in a different process.
type SessionRecoveryToken struct {
	ExportedSecret []byte `json:"exportedSecret"`
	RequestEnc     []byte `json:"requestEnc"`
}

// ExtractSessionRecoveryToken exports the HPKE shared secret from a
// RequestContext and returns a serializable token that can decrypt the
// corresponding response independently.
func ExtractSessionRecoveryToken(ctx *RequestContext) *SessionRecoveryToken {
	exportedSecret := ctx.Sealer.Export([]byte(ExportLabel), uint(ExportLength))
	requestEnc := make([]byte, len(ctx.RequestEnc))
	copy(requestEnc, ctx.RequestEnc)
	return &SessionRecoveryToken{
		ExportedSecret: exportedSecret,
		RequestEnc:     requestEnc,
	}
}

// DecryptResponseWithToken decrypts an HTTP response using only a
// SessionRecoveryToken (no live HPKE context required).
func DecryptResponseWithToken(resp *http.Response, token *SessionRecoveryToken) error {
	if token == nil {
		return fmt.Errorf("session recovery token is nil")
	}

	responseNonceHex := resp.Header.Get(protocol.ResponseNonceHeader)
	if responseNonceHex == "" {
		return fmt.Errorf("missing %s header", protocol.ResponseNonceHeader)
	}

	responseNonce, err := hex.DecodeString(responseNonceHex)
	if err != nil {
		return fmt.Errorf("invalid response nonce: %w", err)
	}

	if len(responseNonce) != ResponseNonceLength {
		return fmt.Errorf("invalid response nonce length: expected %d, got %d",
			ResponseNonceLength, len(responseNonce))
	}

	km, err := DeriveResponseKeys(token.ExportedSecret, token.RequestEnc, responseNonce)
	if err != nil {
		return fmt.Errorf("failed to derive response keys: %w", err)
	}

	aead, err := km.NewResponseAEAD()
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %w", err)
	}

	resp.Body = &DerivedStreamingDecryptReader{
		reader: resp.Body,
		aead:   aead,
		buffer: nil,
		eof:    false,
	}
	resp.ContentLength = -1

	return nil
}
