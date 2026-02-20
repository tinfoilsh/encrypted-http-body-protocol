package identity

import (
	"encoding/hex"
	"encoding/json"
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

// MarshalJSON encodes both fields as lowercase hex strings for cross-language
// interoperability (see SPEC.md Section 6.1.1).
func (t *SessionRecoveryToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ExportedSecret string `json:"exportedSecret"`
		RequestEnc     string `json:"requestEnc"`
	}{
		ExportedSecret: hex.EncodeToString(t.ExportedSecret),
		RequestEnc:     hex.EncodeToString(t.RequestEnc),
	})
}

// UnmarshalJSON decodes both fields from lowercase hex strings.
func (t *SessionRecoveryToken) UnmarshalJSON(data []byte) error {
	var raw struct {
		ExportedSecret string `json:"exportedSecret"`
		RequestEnc     string `json:"requestEnc"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	var err error
	t.ExportedSecret, err = hex.DecodeString(raw.ExportedSecret)
	if err != nil {
		return fmt.Errorf("invalid exportedSecret hex: %w", err)
	}
	t.RequestEnc, err = hex.DecodeString(raw.RequestEnc)
	if err != nil {
		return fmt.Errorf("invalid requestEnc hex: %w", err)
	}
	return nil
}

// ExtractSessionRecoveryToken exports the HPKE shared secret from a
// RequestContext and returns a serializable token that can decrypt the
// corresponding response independently.
func ExtractSessionRecoveryToken(ctx *RequestContext) (*SessionRecoveryToken, error) {
	exportedSecret, err := ctx.Sender.Export(ExportLabel, ExportLength)
	if err != nil {
		return nil, fmt.Errorf("failed to export HPKE secret: %w", err)
	}
	requestEnc := make([]byte, len(ctx.RequestEnc))
	copy(requestEnc, ctx.RequestEnc)
	return &SessionRecoveryToken{
		ExportedSecret: exportedSecret,
		RequestEnc:     requestEnc,
	}, nil
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
