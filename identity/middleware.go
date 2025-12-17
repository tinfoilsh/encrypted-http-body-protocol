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

// Middleware wraps an HTTP handler to encrypt/decrypt requests and responses
func (i *Identity) Middleware(permitPlaintextFallback bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for request body - bodyless requests pass through unencrypted
			// See SPEC.md Section 6.4 for security rationale
			// Note: No fallback header is set - the client knows it sent a bodyless request
			if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
				log.Debugf("bodyless request, passing through unencrypted")
				next.ServeHTTP(w, r)
				return
			}

			// Check for request encryption header
			requestEncHex := r.Header.Get(protocol.EncapsulatedKeyHeader)
			if requestEncHex == "" {
				if permitPlaintextFallback {
					log.Debugf("missing %s header, using plaintext fallback", protocol.EncapsulatedKeyHeader)
					w.Header().Set(protocol.FallbackHeader, "1")
					next.ServeHTTP(w, r)
					return
				}
				sendError(w, nil, "missing request encryption header", http.StatusBadRequest)
				return
			}

			// Decrypt request body and get context for response
			respCtx, err := i.DecryptRequestWithContext(r)
			if err != nil {
				status := http.StatusInternalServerError
				if IsClientError(err) {
					status = http.StatusBadRequest
				}
				sendError(w, err, "failed to decrypt request", status)
				return
			}

			// Setup response encryption using derived keys
			encryptedWriter, err := i.SetupDerivedResponseEncryption(w, respCtx)
			if err != nil {
				status := http.StatusInternalServerError
				if IsClientError(err) {
					status = http.StatusBadRequest
				}
				sendError(w, err, "failed to setup response encryption", status)
				return
			}

			// Pass with encrypted writer
			next.ServeHTTP(encryptedWriter, r)
		})
	}
}
