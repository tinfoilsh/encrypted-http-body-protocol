package identity

import (
	"bytes"
	"encoding/json"
	"io"
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

type prependReadCloser struct {
	io.Reader
	closer io.Closer
}

func (p *prependReadCloser) Close() error {
	if p.closer != nil {
		return p.closer.Close()
	}
	return nil
}

// Middleware wraps an HTTP handler to encrypt/decrypt requests and responses.
// Requests with Ehbp-Encapsulated-Key header are decrypted and responses are encrypted.
// Requests without the header are passed through as plaintext.
func (i *Identity) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for request body - bodyless requests pass through unencrypted
			// See SPEC.md Section 6.4 for security rationale
			if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
				log.Debugf("bodyless request, passing through unencrypted")
				next.ServeHTTP(w, r)
				return
			}

			// Check for request encryption header
			requestEncHex := r.Header.Get(protocol.EncapsulatedKeyHeader)
			if requestEncHex == "" {
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

			// Probe one byte to force early decrypt failure detection (e.g. stale key mismatch)
			// while preserving streaming request semantics for the remaining body.
			probe := make([]byte, 1)
			n, readErr := r.Body.Read(probe)
			if readErr != nil && readErr != io.EOF {
				status := statusForProtocolError(readErr)
				sendError(w, readErr, "failed to read decrypted request body", status)
				_ = r.Body.Close()
				return
			}

			originalBody := r.Body
			if n > 0 {
				r.Body = &prependReadCloser{
					Reader: io.MultiReader(bytes.NewReader(probe[:n]), originalBody),
					closer: originalBody,
				}
				// The body remains a stream, so content length is no longer known.
				r.ContentLength = -1
				r.Header.Del("Content-Length")
			} else if readErr == io.EOF {
				_ = originalBody.Close()
				r.Body = http.NoBody
				r.ContentLength = 0
				r.Header.Del("Content-Length")
			} else {
				r.Body = originalBody
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
		})
	}
}
