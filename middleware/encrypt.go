package middleware

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/cloudflare/circl/hpke"
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

		// Only decrypt request body if it exists and has content
		if r.Body != nil && r.ContentLength != 0 {
			log.Debug("Decrypting request body")
			requestBody, err := io.ReadAll(r.Body)
			if err != nil {
				sendError(w, err, "failed to read request body", http.StatusInternalServerError)
				return
			}
			decrypted, err := opener.Open(requestBody, nil)
			if err != nil {
				sendError(w, err, "failed to decrypt request body", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewBuffer(decrypted))
		} else {
			log.Debug("No request body to decrypt")
		}

		// Setup encryption for response
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

		// Set the encapsulated key header
		w.Header().Set("Tinfoil-Encapsulated-Key", hex.EncodeToString(encapKey))

		// Create a streaming response writer
		log.Debug("Passing to next handler")
		responseWriter := &streamingResponseWriter{
			ResponseWriter: w,
			sealer:         sealer,
		}
		next.ServeHTTP(responseWriter, r)
	})
}

// streamingResponseWriter handles streaming encrypted data
type streamingResponseWriter struct {
	http.ResponseWriter
	sealer hpke.Sealer
}

func (w *streamingResponseWriter) Write(data []byte) (int, error) {
	// Encrypt the chunk of data
	encrypted, err := w.sealer.Seal(data, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Write the encrypted data
	n, err := w.ResponseWriter.Write(encrypted)
	if err != nil {
		log.Errorf("Failed to write encrypted data: %v", err)
		return 0, err
	}
	log.Debugf("Wrote %d bytes of encrypted data", n)

	// Return the number of bytes we actually wrote
	return n, nil
}

// Flush implements http.Flusher
func (w *streamingResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
