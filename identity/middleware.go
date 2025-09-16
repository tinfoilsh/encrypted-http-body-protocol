package identity

import (
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/stransport/protocol"
)

func sendError(w http.ResponseWriter, err error, text string, status int) {
	log.Debugf("ehbp middleware error: %s: %v", text, err)
	http.Error(w, text, status)
}

// Middleware wraps an HTTP handler to encrypt/decrypt requests and responses
func (i *Identity) Middleware(permitPlaintextFallback bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientPubKeyHex := r.Header.Get(protocol.ClientPublicKeyHeader)
			if clientPubKeyHex == "" {
				if permitPlaintextFallback {
					log.Debugf("missing %s header", protocol.ClientPublicKeyHeader)
					w.Header().Set(protocol.FallbackHeader, "1")
					next.ServeHTTP(w, r)
					return
				}
				sendError(w, nil, "missing client public key", http.StatusBadRequest)
				return
			}

			// Decrypt request body
			if r.Body != nil && r.Body != http.NoBody {
				err := i.DecryptRequest(r)
				if err != nil {
					status := http.StatusInternalServerError
					if IsClientError(err) {
						status = http.StatusBadRequest
					}
					sendError(w, err, "failed to decrypt request", status)
					return
				}
			}

			encryptedWriter, err := i.SetupResponseEncryption(w, clientPubKeyHex)
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
