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
// using the v2 protocol with request-response binding.
//
// In v2, response encryption keys are derived from the request's HPKE context,
// which prevents MitM attacks where an attacker could intercept responses.
func (i *Identity) Middleware(permitPlaintextFallback bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for request encryption header (v2 uses encapsulated key)
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
			var respCtx *ResponseContext
			var err error

			if r.Body != nil && r.Body != http.NoBody {
				respCtx, err = i.DecryptRequestWithContext(r)
				if err != nil {
					status := http.StatusInternalServerError
					if IsClientError(err) {
						status = http.StatusBadRequest
					}
					sendError(w, err, "failed to decrypt request", status)
					return
				}
			} else {
				// No body, but we still need to setup context for response
				// The client sends Ehbp-Encapsulated-Key even without a body
				respCtx, err = i.SetupResponseContextForEmptyBody(requestEncHex)
				if err != nil {
					status := http.StatusInternalServerError
					if IsClientError(err) {
						status = http.StatusBadRequest
					}
					sendError(w, err, "failed to setup response context", status)
					return
				}
			}

			// Setup response encryption using derived keys (v2)
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

