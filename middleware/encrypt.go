package middleware

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/cloudflare/circl/kem"
	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/stransport/identity"
)

func getClientPubKey(r *http.Request) (kem.PublicKey, error) {
	header := "Tinfoil-Client-Public-Key"
	keyHex := r.Header.Get(header)
	if keyHex == "" {
		return nil, fmt.Errorf("missing %s header", header)
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid %s header", header)
	}
	pk, err := identity.KEMScheme().UnmarshalBinaryPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid %s public key", header)
	}
	return pk, nil
}

func sendError(w http.ResponseWriter, err error, text string, status int) {
	log.Errorf("error: %s: %v", text, err)
	http.Error(w, text, status)
}

// EncryptMiddleware wraps an HTTP handler to encrypt the response body
func EncryptMiddleware(serverIdentity *identity.Identity, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientPubKey, err := getClientPubKey(r)
		if err != nil {
			sendError(w, err, "invalid client public key", http.StatusBadRequest)
			return
		}
		clientEncapKey, err := hex.DecodeString(r.Header.Get("Tinfoil-Encapsulated-Key"))
		if err != nil {
			sendError(w, err, "invalid encapsulated key", http.StatusBadRequest)
			return
		}
		receiver, err := identity.Suite().NewReceiver(serverIdentity.PrivateKey(), nil)
		if err != nil {
			sendError(w, err, "failed to create receiver", http.StatusInternalServerError)
			return
		}
		opener, err := receiver.Setup(clientEncapKey)
		if err != nil {
			sendError(w, err, "failed to setup decryption", http.StatusInternalServerError)
			return
		}
		// Decrypt request body
		requestBody, err := io.ReadAll(r.Body)
		if err != nil {
			sendError(w, err, "failed to read request body", http.StatusInternalServerError)
			return
		}
		decrypted, err := opener.Open(requestBody, nil)
		if err != nil {
			sendError(w, err, "failed to decrypt request body", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(decrypted))

		// Create a response writer that captures the response body
		responseWriter := &responseWriter{
			ResponseWriter: w,
			body:           &bytes.Buffer{},
		}
		next.ServeHTTP(responseWriter, r)

		// Setup encryption
		sender, err := identity.Suite().NewSender(clientPubKey, nil)
		if err != nil {
			sendError(w, err, "failed to create encryption context", http.StatusInternalServerError)
			return
		}
		encapKey, sealer, err := sender.Setup(nil)
		if err != nil {
			sendError(w, err, "failed to setup encryption", http.StatusInternalServerError)
			return
		}

		// Encrypt the response body
		encrypted, err := sealer.Seal(responseWriter.body.Bytes(), nil)
		if err != nil {
			sendError(w, err, "failed to encrypt response body", http.StatusInternalServerError)
			return
		}

		// Send to client
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Tinfoil-Encapsulated-Key", hex.EncodeToString(encapKey))
		w.Write(encrypted)
	})
}

// responseWriter captures the response body
type responseWriter struct {
	http.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}
