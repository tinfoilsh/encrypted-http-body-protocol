package middleware

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/cloudflare/circl/hpke"
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

// EncryptMiddleware wraps an HTTP handler to encrypt the response body
func (s *SecureServer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyHex := r.Header.Get(protocol.ClientPublicKeyHeader)
		if keyHex == "" {
			if s.permitPlaintextFallback {
				log.Debugf("missing %s header", protocol.ClientPublicKeyHeader)
				w.Header().Set("EHBP-Fallback", "1")
				next.ServeHTTP(w, r)
				return
			}
			sendError(w, nil, "missing client public key", http.StatusBadRequest)
			return
		}
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil {
			sendError(w, err, "invalid encapsulated key", http.StatusBadRequest)
			return
		}
		clientPubKey, err := s.identity.KEMScheme().UnmarshalBinaryPublicKey(keyBytes)
		if err != nil {
			sendError(w, err, "invalid encapsulated key", http.StatusBadRequest)
			return
		}

		clientEncapKey, err := hex.DecodeString(r.Header.Get(protocol.EncapsulatedKeyHeader))
		if err != nil {
			sendError(w, err, "invalid encapsulated key", http.StatusBadRequest)
			return
		}
		receiver, err := s.identity.Suite().NewReceiver(s.identity.PrivateKey(), nil)
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
			r.ContentLength = int64(len(decrypted))
		} else {
			log.Debug("No request body to decrypt")
		}

		// Setup encryption for response
		sender, err := s.identity.Suite().NewSender(clientPubKey, nil)
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
		w.Header().Set(protocol.EncapsulatedKeyHeader, hex.EncodeToString(encapKey))

		// Set transfer encoding to chunked and remove any Content-Length header
		w.Header().Set("Transfer-Encoding", "chunked")
		w.Header().Del("Content-Length")

		// Create a streaming response writer
		log.Debug("Passing to next handler")
		responseWriter := &streamingResponseWriter{
			ResponseWriter: w,
			sealer:         sealer,
			headers:        make(http.Header),
			wroteHeader:    false,
		}
		next.ServeHTTP(responseWriter, r)
	})
}

// streamingResponseWriter handles streaming encrypted data
type streamingResponseWriter struct {
	http.ResponseWriter
	sealer      hpke.Sealer
	headers     http.Header
	wroteHeader bool
	statusCode  int
}

// WriteHeader captures the status code and delegates to the underlying ResponseWriter
func (w *streamingResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		// Remove Content-Length as encryption will change the size
		w.ResponseWriter.Header().Del("Content-Length")
		w.statusCode = statusCode
		w.ResponseWriter.WriteHeader(statusCode)
		w.wroteHeader = true
	}
}

// Header returns the headers map to allow headers to be set before WriteHeader is called
func (w *streamingResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *streamingResponseWriter) Write(data []byte) (int, error) {
	// Ensure headers are written
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	// Encrypt the chunk of data
	encrypted, err := w.sealer.Seal(data, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Write the encrypted data
	_, err = w.ResponseWriter.Write(encrypted)
	if err != nil {
		log.Errorf("Failed to write encrypted data: %v", err)
		return 0, err
	}

	// Return the original data length, not the encrypted length
	return len(data), nil
}

// Flush implements http.Flusher
func (w *streamingResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
