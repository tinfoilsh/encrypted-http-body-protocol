package middleware

import (
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/stransport/identity"
	"github.com/tinfoilsh/stransport/protocol"
)

func sendError(w http.ResponseWriter, err error, text string, status int) {
	log.Errorf("error: %s: %v", text, err)
	http.Error(w, text, status)
}

type SecureServer struct {
	identity                *identity.Identity
	permitPlaintextFallback bool
}

func NewSecureServer(identity *identity.Identity, permitPlaintextFallback bool) *SecureServer {
	return &SecureServer{
		identity:                identity,
		permitPlaintextFallback: permitPlaintextFallback,
	}
}

// Middleware wraps an HTTP handler to encrypt/decrypt requests and responses
func (s *SecureServer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientPubKeyHex := r.Header.Get(protocol.ClientPublicKeyHeader)
		if clientPubKeyHex == "" {
			if s.permitPlaintextFallback {
				log.Debugf("missing %s header", protocol.ClientPublicKeyHeader)
				w.Header().Set("EHBP-Fallback", "1")
				next.ServeHTTP(w, r)
				return
			}
			sendError(w, nil, "missing client public key", http.StatusBadRequest)
			return
		}

		// Decrypt request body
		if r.Body != nil && r.ContentLength != 0 {
			err := s.identity.DecryptRequest(r)
			if err != nil {
				sendError(w, err, "failed to decrypt request", http.StatusBadRequest)
				return
			}
		}

		encryptedWriter, err := s.identity.SetupResponseEncryption(w, clientPubKeyHex)
		if err != nil {
			sendError(w, err, "failed to setup response encryption", http.StatusInternalServerError)
			return
		}

		// Pass with encrypted writer
		next.ServeHTTP(encryptedWriter, r)
	})
}
