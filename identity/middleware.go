package identity

import (
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

type problemDetails struct {
	Type  string `json:"type"`
	Title string `json:"title"`
}

func sendError(w http.ResponseWriter, err error, text string, status int) {
	log.Debugf("ehbp middleware error: %s: %v", text, err)

	if status == http.StatusUnprocessableEntity {
		w.Header().Set("Content-Type", protocol.ProblemJSONMediaType)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(problemDetails{
			Type:  protocol.KeyConfigProblemType,
			Title: text,
		})
		return
	}

	http.Error(w, text, status)
}

func statusForProtocolError(err error) int {
	if IsKeyConfigError(err) {
		return http.StatusUnprocessableEntity
	}
	if IsClientError(err) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// Middleware wraps an HTTP handler to encrypt/decrypt requests and responses.
// Requests with Ehbp-Encapsulated-Key header are decrypted and responses are encrypted.
// Requests without the header are passed through as plaintext.
func (i *Identity) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A present key requires authenticated request payload, even when
			// HTTP reports an empty body. Only an absent key selects plaintext.
			if len(r.Header.Values(protocol.EncapsulatedKeyHeader)) == 0 {
				log.Debugf("no %s header, passing through as plaintext", protocol.EncapsulatedKeyHeader)
				next.ServeHTTP(w, r)
				return
			}

			// Decrypt request body and get context for response
			respCtx, err := i.DecryptRequestWithContext(r)
			if err != nil {
				status := statusForProtocolError(err)
				sendError(w, err, "failed to decrypt request", status)
				return
			}

			// Require authenticated payload before invoking the handler.
			if err := respCtx.decryptor.requireRequestPayload(); err != nil {
				sendError(w, err, "failed to read decrypted request body", statusForProtocolError(err))
				_ = r.Body.Close()
				return
			}

			// Setup response encryption using derived keys
			encryptedWriter, err := i.SetupDerivedResponseEncryption(w, respCtx)
			if err != nil {
				status := statusForProtocolError(err)
				sendError(w, err, "failed to setup response encryption", status)
				return
			}

			// Pass with encrypted writer
			next.ServeHTTP(encryptedWriter, r)

			// SPEC 5.2: a chunk that failed after the handler started must not
			// let the exchange complete. If nothing has been sent yet this is a
			// normal protocol error; otherwise abort so the client sees a
			// transport failure instead of a complete message.
			if ferr := respCtx.decryptor.Err(); ferr != nil {
				if !encryptedWriter.wroteHeader {
					// Nothing has been sent: answer in plaintext, so drop the
					// response-encryption headers set up for the handler.
					w.Header().Del(protocol.ResponseNonceHeader)
					w.Header().Del("Transfer-Encoding")
					sendError(w, ferr, "failed to read decrypted request body", statusForProtocolError(ferr))
					return
				}
				panic(http.ErrAbortHandler)
			}
			if err := encryptedWriter.Finish(); err != nil {
				panic(http.ErrAbortHandler)
			}
		})
	}
}
