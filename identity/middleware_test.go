package identity

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// v2TestClient is a test helper that simulates a v2 client with request/response encryption.
// It stores the HPKE sealer from request encryption so it can derive response decryption keys.
type v2TestClient struct {
	identity   *Identity
	sealer     hpke.Sealer
	requestEnc []byte
}

// newV2TestClient creates a new v2 test client
func newV2TestClient(t *testing.T) *v2TestClient {
	identity, err := NewIdentity()
	require.NoError(t, err)
	return &v2TestClient{identity: identity}
}

// encryptRequest encrypts a request to the server and stores the context for response decryption
func (c *v2TestClient) encryptRequest(t *testing.T, req *http.Request, serverPubKey []byte) {
	// Set up encryption to server
	pk, err := c.identity.KEMScheme().UnmarshalBinaryPublicKey(serverPubKey)
	require.NoError(t, err)

	sender, err := c.identity.Suite().NewSender(pk, nil)
	require.NoError(t, err)

	encapKey, sealer, err := sender.Setup(rand.Reader)
	require.NoError(t, err)

	// Store for response decryption
	c.sealer = sealer
	c.requestEnc = encapKey

	// Set the request header
	req.Header.Set(protocol.EncapsulatedKeyHeader, hex.EncodeToString(encapKey))

	// If there's a body, encrypt it
	if req.Body != nil && req.ContentLength != 0 {
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		if len(body) > 0 {
			encrypted, err := sealer.Seal(body, nil)
			require.NoError(t, err)

			// Create chunked format
			chunkHeader := make([]byte, 4)
			binary.BigEndian.PutUint32(chunkHeader, uint32(len(encrypted)))
			chunkedBody := append(chunkHeader, encrypted...)

			req.Body = io.NopCloser(bytes.NewReader(chunkedBody))
			req.ContentLength = int64(len(chunkedBody))
		} else {
			req.Body = io.NopCloser(bytes.NewReader(nil))
		}
	}
}

// decryptResponse decrypts a v2 response using derived keys
func (c *v2TestClient) decryptResponse(t *testing.T, resp *httptest.ResponseRecorder) []byte {
	// Get response nonce from header
	responseNonceHex := resp.Header().Get(protocol.ResponseNonceHeader)
	require.NotEmpty(t, responseNonceHex, "missing response nonce header")

	responseNonce, err := hex.DecodeString(responseNonceHex)
	require.NoError(t, err)

	// Export secret from sealer context
	exportedSecret := c.sealer.Export([]byte(ExportLabel), uint(ExportLength))

	// Derive response keys
	km, err := DeriveResponseKeys(exportedSecret, c.requestEnc, responseNonce)
	require.NoError(t, err)

	// Create AEAD for decryption
	aead, err := km.NewResponseAEAD()
	require.NoError(t, err)

	// Decrypt chunks
	var result bytes.Buffer
	reader := bytes.NewReader(resp.Body.Bytes())
	seq := uint64(0)

	for reader.Len() > 0 {
		// Read chunk length
		var chunkLen uint32
		if err := binary.Read(reader, binary.BigEndian, &chunkLen); err != nil {
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}

		if chunkLen == 0 {
			continue
		}

		// Read encrypted chunk
		encryptedChunk := make([]byte, chunkLen)
		_, err = io.ReadFull(reader, encryptedChunk)
		require.NoError(t, err)

		// Compute nonce
		nonce := km.ComputeNonce(seq)
		seq++

		// Decrypt
		decrypted, err := aead.Open(nil, nonce, encryptedChunk, nil)
		require.NoError(t, err)

		result.Write(decrypted)
	}

	return result.Bytes()
}

func TestMiddleware(t *testing.T) {
	serverIdentity, err := NewIdentity()
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
		client := newV2TestClient(t)
		requestBody := []byte("test message")

		// Create request with body
		req := httptest.NewRequest("POST", "/test", bytes.NewBuffer(requestBody))
		req.Header.Set("Content-Type", "application/octet-stream")

		// Encrypt the request
		client.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify response has nonce header (v2)
		responseNonceHeader := w.Header().Get(protocol.ResponseNonceHeader)
		assert.NotEmpty(t, responseNonceHeader)

		// Decrypt response
		decryptedResponse := client.decryptResponse(t, w)
		assert.Equal(t, "Hello, test message", string(decryptedResponse))
	})

	t.Run("missing encapsulated key header", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "missing request encryption header")
	})

	t.Run("invalid encapsulated key", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		req.Header.Set(protocol.EncapsulatedKeyHeader, "invalid-hex")
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "failed to decrypt request")
	})

	t.Run("wrong length encapsulated key", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		req.Header.Set(protocol.EncapsulatedKeyHeader, "deadbeef") // Too short
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "failed to decrypt request")
	})

	t.Run("empty request body with valid enc header", func(t *testing.T) {
		client := newV2TestClient(t)

		// Send request with no body but valid encryption header
		req := httptest.NewRequest("GET", "/test", nil)
		client.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Should still be able to decrypt response
		responseNonceHeader := w.Header().Get(protocol.ResponseNonceHeader)
		assert.NotEmpty(t, responseNonceHeader)

		decryptedResponse := client.decryptResponse(t, w)
		assert.Equal(t, "Hello, ", string(decryptedResponse))
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
		client := newV2TestClient(t)

		req := httptest.NewRequest("GET", "/stream", nil)
		client.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "chunked", w.Header().Get("Transfer-Encoding"))
		assert.Empty(t, w.Header().Get("Content-Length"))

		// Verify response nonce header exists (v2)
		responseNonceHeader := w.Header().Get(protocol.ResponseNonceHeader)
		assert.NotEmpty(t, responseNonceHeader)

		// Decrypt response
		decryptedResponse := client.decryptResponse(t, w)
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

	middleware := serverIdentity.Middleware(false)

	t.Run("multiple chunks are encrypted separately", func(t *testing.T) {
		client := newV2TestClient(t)

		// Create handler that writes multiple chunks
		chunkHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			chunks := []string{"chunk1", "chunk2", "chunk3"}
			for i, chunk := range chunks {
				w.Write([]byte(chunk))
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				if i < len(chunks)-1 {
					w.Write([]byte("|"))
				}
			}
		})

		wrapped := middleware(chunkHandler)

		req := httptest.NewRequest("GET", "/chunks", nil)
		client.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Decrypt response
		decryptedResponse := client.decryptResponse(t, w)
		assert.Equal(t, "chunk1|chunk2|chunk3", string(decryptedResponse))
	})

	t.Run("empty chunks are handled correctly", func(t *testing.T) {
		client := newV2TestClient(t)

		// Create handler that writes empty data
		emptyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte{}) // Empty write
			w.Write([]byte("after empty"))
		})

		wrapped := middleware(emptyHandler)

		req := httptest.NewRequest("GET", "/empty", nil)
		client.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Decrypt response
		decryptedResponse := client.decryptResponse(t, w)
		assert.Equal(t, "after empty", string(decryptedResponse))
	})

	t.Run("large chunks are encrypted correctly", func(t *testing.T) {
		client := newV2TestClient(t)
		largeData := strings.Repeat("A", 10000) // 10KB of data

		largeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(largeData))
		})

		wrapped := middleware(largeHandler)

		req := httptest.NewRequest("GET", "/large", nil)
		client.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Decrypt response
		decryptedResponse := client.decryptResponse(t, w)
		assert.Equal(t, largeData, string(decryptedResponse))
	})
}

func TestDerivedResponseEncryptionSecurity(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	middleware := serverIdentity.Middleware(false)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret response"))
	})

	wrapped := middleware(testHandler)

	t.Run("different clients cannot decrypt each others responses", func(t *testing.T) {
		client1 := newV2TestClient(t)
		client2 := newV2TestClient(t)

		// Client 1 makes a request
		req := httptest.NewRequest("GET", "/test", nil)
		client1.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Client 1 can decrypt
		decrypted := client1.decryptResponse(t, w)
		assert.Equal(t, "secret response", string(decrypted))

		// Client 2 cannot decrypt (using their own keys with client 1's response)
		responseNonceHex := w.Header().Get(protocol.ResponseNonceHeader)
		responseNonce, _ := hex.DecodeString(responseNonceHex)

		// Client 2 tries to derive keys with their sealer (wrong shared secret)
		// First set up client2's sealer by encrypting a dummy request
		dummyReq := httptest.NewRequest("GET", "/dummy", nil)
		client2.encryptRequest(t, dummyReq, serverIdentity.MarshalPublicKey())

		client2ExportedSecret := client2.sealer.Export([]byte(ExportLabel), uint(ExportLength))
		client2KM, _ := DeriveResponseKeys(client2ExportedSecret, client1.requestEnc, responseNonce)
		client2AEAD, _ := client2KM.NewResponseAEAD()

		// Try to decrypt first chunk
		reader := bytes.NewReader(w.Body.Bytes())
		var chunkLen uint32
		binary.Read(reader, binary.BigEndian, &chunkLen)
		encryptedChunk := make([]byte, chunkLen)
		io.ReadFull(reader, encryptedChunk)

		nonce := client2KM.ComputeNonce(0)
		_, err := client2AEAD.Open(nil, nonce, encryptedChunk, nil)
		assert.Error(t, err, "client 2 should not be able to decrypt client 1's response")
	})
}

func BenchmarkMiddlewareEncryption(b *testing.B) {
	serverIdentity, err := NewIdentity()
	require.NoError(b, err)

	middleware := serverIdentity.Middleware(false)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	wrapped := middleware(testHandler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create a fresh client for each iteration (realistic scenario)
		clientIdentity, _ := NewIdentity()
		sender, _ := clientIdentity.Suite().NewSender(serverIdentity.PublicKey(), nil)
		encapKey, _, _ := sender.Setup(rand.Reader)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(protocol.EncapsulatedKeyHeader, hex.EncodeToString(encapKey))

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
	}
}

