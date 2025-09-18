package identity

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/stransport/protocol"
)

func TestMiddleware(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)
	clientIdentity, err := NewIdentity()
	require.NoError(t, err)

	middleware := serverIdentity.Middleware(false)

	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Hello, " + string(body)))
	})

	wrapped := middleware(testHandler)

	t.Run("successful encrypted request", func(t *testing.T) {
		requestBody := []byte("test message")

		// Create request with plaintext body first
		req := httptest.NewRequest("POST", "/test", bytes.NewBuffer(requestBody))
		req.Header.Set("Content-Type", "application/octet-stream")

		// Encrypt the request using the new streaming method
		serverPubKeyBytes := serverIdentity.MarshalPublicKey()
		err := clientIdentity.EncryptRequest(req, serverPubKeyBytes)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify response has encapsulated key header
		encapKeyHeader := w.Header().Get(protocol.EncapsulatedKeyHeader)
		assert.NotEmpty(t, encapKeyHeader)

		// Decrypt response using chunked format
		serverEncapKey, err := hex.DecodeString(encapKeyHeader)
		require.NoError(t, err)

		decryptedResponse, err := clientIdentity.DecryptChunkedResponse(w.Body.Bytes(), serverEncapKey)
		require.NoError(t, err)
		assert.Equal(t, "Hello, test message", string(decryptedResponse))
	})

	t.Run("missing client public key header", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "missing client public key")
	})

	t.Run("invalid client public key", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		req.Header.Set(protocol.ClientPublicKeyHeader, "invalid-hex")
		req.Header.Set(protocol.EncapsulatedKeyHeader, "deadbeef")
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "failed to decrypt request")
	})

	t.Run("missing encapsulated key header", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		req.Header.Set(protocol.ClientPublicKeyHeader, hex.EncodeToString(clientIdentity.MarshalPublicKey()))
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "failed to decrypt request")
	})

	t.Run("invalid encapsulated key", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		req.Header.Set(protocol.ClientPublicKeyHeader, hex.EncodeToString(clientIdentity.MarshalPublicKey()))
		req.Header.Set(protocol.EncapsulatedKeyHeader, "invalid-hex")
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "failed to decrypt request")
	})

	t.Run("empty request body", func(t *testing.T) {
		// Send request with no body
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(protocol.ClientPublicKeyHeader, hex.EncodeToString(clientIdentity.MarshalPublicKey()))

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestPlaintextFallback(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	middleware := serverIdentity.Middleware(true) // Enable plaintext fallback

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Hello, " + string(body)))
	})

	wrapped := middleware(testHandler)

	t.Run("plaintext fallback works", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "1", w.Header().Get(protocol.FallbackHeader))
		assert.Equal(t, "Hello, test", w.Body.String())
	})
}

func TestStreamingResponseWriter(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)
	clientIdentity, err := NewIdentity()
	require.NoError(t, err)

	middleware := serverIdentity.Middleware(false)

	// Create streaming test handler
	streamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)

		for i := 1; i <= 3; i++ {
			fmt.Fprintf(w, "chunk %d\n", i)
			flusher.Flush()
		}
	})

	wrapped := middleware(streamHandler)

	t.Run("streaming response", func(t *testing.T) {
		// Set up encryption from the client side
		sender, err := clientIdentity.Suite().NewSender(serverIdentity.PublicKey(), nil)
		require.NoError(t, err)
		clientEncapKey, _, err := sender.Setup(nil)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/stream", nil)
		req.Header.Set(protocol.ClientPublicKeyHeader, hex.EncodeToString(clientIdentity.MarshalPublicKey()))
		req.Header.Set(protocol.EncapsulatedKeyHeader, hex.EncodeToString(clientEncapKey))

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "chunked", w.Header().Get("Transfer-Encoding"))
		assert.Empty(t, w.Header().Get("Content-Length"))

		// Verify response can be decrypted
		encapKeyHeader := w.Header().Get(protocol.EncapsulatedKeyHeader)
		assert.NotEmpty(t, encapKeyHeader)

		serverEncapKey, err := hex.DecodeString(encapKeyHeader)
		require.NoError(t, err)

		// Decrypt chunked response
		responseBody := w.Body.Bytes()
		decryptedResponse, err := clientIdentity.DecryptChunkedResponse(responseBody, serverEncapKey)
		require.NoError(t, err)

		expectedContent := "chunk 1\nchunk 2\nchunk 3\n"
		assert.Equal(t, expectedContent, string(decryptedResponse))
	})
}

func TestSendError(t *testing.T) {
	w := httptest.NewRecorder()
	testError := fmt.Errorf("test error")

	sendError(w, testError, "test message", http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "test message")
}

func TestChunkEncryptionDecryption(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)
	clientIdentity, err := NewIdentity()
	require.NoError(t, err)

	middleware := serverIdentity.Middleware(false)

	t.Run("multiple chunks are encrypted separately", func(t *testing.T) {
		// Create handler that writes multiple chunks
		chunkHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			chunks := []string{"chunk1", "chunk2", "chunk3"}
			for i, chunk := range chunks {
				w.Write([]byte(chunk))
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				// Add a small identifier to distinguish chunks
				if i < len(chunks)-1 {
					w.Write([]byte("|"))
				}
			}
		})

		wrapped := middleware(chunkHandler)

		req := httptest.NewRequest("GET", "/chunks", nil)
		req.Header.Set(protocol.ClientPublicKeyHeader, hex.EncodeToString(clientIdentity.MarshalPublicKey()))

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Decrypt response
		encapKeyHeader := w.Header().Get(protocol.EncapsulatedKeyHeader)
		assert.NotEmpty(t, encapKeyHeader)

		serverEncapKey, err := hex.DecodeString(encapKeyHeader)
		require.NoError(t, err)

		decryptedResponse, err := clientIdentity.DecryptChunkedResponse(w.Body.Bytes(), serverEncapKey)
		require.NoError(t, err)
		assert.Equal(t, "chunk1|chunk2|chunk3", string(decryptedResponse))
	})

	t.Run("empty chunks are handled correctly", func(t *testing.T) {
		// Create handler that writes empty data
		emptyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte{}) // Empty write
			w.Write([]byte("after empty"))
		})

		wrapped := middleware(emptyHandler)

		req := httptest.NewRequest("GET", "/empty", nil)
		req.Header.Set(protocol.ClientPublicKeyHeader, hex.EncodeToString(clientIdentity.MarshalPublicKey()))

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Decrypt response
		encapKeyHeader := w.Header().Get(protocol.EncapsulatedKeyHeader)
		assert.NotEmpty(t, encapKeyHeader)

		serverEncapKey, err := hex.DecodeString(encapKeyHeader)
		require.NoError(t, err)

		decryptedResponse, err := clientIdentity.DecryptChunkedResponse(w.Body.Bytes(), serverEncapKey)
		require.NoError(t, err)
		assert.Equal(t, "after empty", string(decryptedResponse))
	})

	t.Run("large chunks are encrypted correctly", func(t *testing.T) {
		largeData := strings.Repeat("A", 10000) // 10KB of data

		largeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(largeData))
		})

		wrapped := middleware(largeHandler)

		req := httptest.NewRequest("GET", "/large", nil)
		req.Header.Set(protocol.ClientPublicKeyHeader, hex.EncodeToString(clientIdentity.MarshalPublicKey()))

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Decrypt response
		encapKeyHeader := w.Header().Get(protocol.EncapsulatedKeyHeader)
		assert.NotEmpty(t, encapKeyHeader)

		serverEncapKey, err := hex.DecodeString(encapKeyHeader)
		require.NoError(t, err)

		decryptedResponse, err := clientIdentity.DecryptChunkedResponse(w.Body.Bytes(), serverEncapKey)
		require.NoError(t, err)
		assert.Equal(t, largeData, string(decryptedResponse))
	})
}

func BenchmarkMiddlewareEncryption(b *testing.B) {
	serverIdentity, err := NewIdentity()
	require.NoError(b, err)
	clientIdentity, err := NewIdentity()
	require.NoError(b, err)

	middleware := serverIdentity.Middleware(false)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	wrapped := middleware(testHandler)

	// Set up encryption from the client side
	sender, err := clientIdentity.Suite().NewSender(serverIdentity.PublicKey(), nil)
	require.NoError(b, err)
	clientEncapKey, sealer, err := sender.Setup(nil)
	require.NoError(b, err)

	requestBody := []byte("benchmark test data")
	encryptedBody, err := sealer.Seal(requestBody, nil)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/test", bytes.NewBuffer(encryptedBody))
		req.Header.Set(protocol.ClientPublicKeyHeader, hex.EncodeToString(clientIdentity.MarshalPublicKey()))
		req.Header.Set(protocol.EncapsulatedKeyHeader, hex.EncodeToString(clientEncapKey))

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
	}
}
