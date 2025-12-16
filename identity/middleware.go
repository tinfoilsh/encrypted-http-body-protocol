package identity

import (
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

func sendError(w http.ResponseWriter, err error, text string, status int) {
	log.Debugf("ehbp middleware error: %s: %v", text, err)
	http.Error(w, text, status)
}

// Middleware wraps an HTTP handler to encrypt/decrypt requests and responses.
// All requests must have an encrypted body - GET requests without a body are rejected.
// Response encryption keys are derived from the request encryption context using
// HPKE's Export interface for bidirectional encryption.
func (i *Identity) Middleware(permitPlaintextFallback bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			encapKeyHex := r.Header.Get(protocol.EncapsulatedKeyHeader)
			if encapKeyHex == "" {
				if permitPlaintextFallback {
					log.Debugf("missing %s header", protocol.EncapsulatedKeyHeader)
					w.Header().Set(protocol.FallbackHeader, "1")
					next.ServeHTTP(w, r)
					return
				}
				sendError(w, nil, "encrypted request body required", http.StatusBadRequest)
				return
			}

			// Decrypt request body and get response context
			reqCtx, err := i.DecryptRequest(r)
			if err != nil {
				status := http.StatusInternalServerError
				if IsClientError(err) {
					status = http.StatusBadRequest
				}
				sendError(w, err, "failed to decrypt request", status)
				return
			}

			// Setup response encryption using key derived from request context
			encryptedWriter, err := i.SetupResponseEncryption(w, reqCtx)
			if err != nil {
				sendError(w, err, "failed to setup response encryption", http.StatusInternalServerError)
				return
			}
			// Pass with encrypted writer
			next.ServeHTTP(encryptedWriter, r)
		})
	}
}
