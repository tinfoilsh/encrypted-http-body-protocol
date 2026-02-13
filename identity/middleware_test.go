package identity

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

// TestClient is a test helper that simulates a client with request/response encryption.
// It stores the HPKE sealer from request encryption so it can derive response decryption keys.
type TestClient struct {
	identity   *Identity
	sealer     hpke.Sealer
	requestEnc []byte
}

// newTestClient creates a new test client
func newTestClient(t *testing.T) *TestClient {
	identity, err := NewIdentity()
	require.NoError(t, err)
	return &TestClient{identity: identity}
}

// encryptRequest encrypts a request to the server and stores the context for response decryption
func (c *TestClient) encryptRequest(t *testing.T, req *http.Request, serverPubKey []byte) {
	// Set up encryption to server
	pk, err := c.identity.KEMScheme().UnmarshalBinaryPublicKey(serverPubKey)
	require.NoError(t, err)

	// Use HPKERequestInfo for domain separation (must match server's info)
	sender, err := c.identity.Suite().NewSender(pk, []byte(HPKERequestInfo))
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

// decryptResponse decrypts a response using derived keys
func (c *TestClient) decryptResponse(t *testing.T, resp *httptest.ResponseRecorder) []byte {
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

	// Decrypt chunks (aead.Open auto-increments the sequence)
	var result bytes.Buffer
	reader := bytes.NewReader(resp.Body.Bytes())

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

		// Decrypt
		decrypted, err := aead.Open(encryptedChunk, nil)
		require.NoError(t, err)

		result.Write(decrypted)
	}

	return result.Bytes()
}

func TestMiddleware(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	middleware := serverIdentity.Middleware()

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
		client := newTestClient(t)
		requestBody := []byte("test message")

		// Create request with body
		req := httptest.NewRequest("POST", "/test", bytes.NewBuffer(requestBody))
		req.Header.Set("Content-Type", "application/octet-stream")

		// Encrypt the request
		client.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify response has nonce header
		responseNonceHeader := w.Header().Get(protocol.ResponseNonceHeader)
		assert.NotEmpty(t, responseNonceHeader)

		// Decrypt response
		decryptedResponse := client.decryptResponse(t, w)
		assert.Equal(t, "Hello, test message", string(decryptedResponse))
	})

	t.Run("missing encapsulated key header passes through as plaintext", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "Hello, test", w.Body.String())
		// No response nonce header since request was plaintext
		assert.Empty(t, w.Header().Get(protocol.ResponseNonceHeader))
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

	t.Run("stale key mismatch returns 422 problem details", func(t *testing.T) {
		client := newTestClient(t)
		otherServer, err := NewIdentity()
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		// Encrypt to a different server key to simulate stale key config.
		client.encryptRequest(t, req, otherServer.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
		assert.Equal(t, protocol.ProblemJSONMediaType, w.Header().Get("Content-Type"))

		var problem map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &problem)
		require.NoError(t, err)
		assert.Equal(t, protocol.KeyConfigProblemType, problem["type"])
		assert.Equal(t, "failed to read decrypted request body", problem["title"])
	})

	t.Run("probe eof clears stale content-length header", func(t *testing.T) {
		client := newTestClient(t)

		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		client.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		staleLength := req.ContentLength
		assert.Greater(t, staleLength, int64(0))

		// Force probe read to hit EOF immediately while preserving a stale encrypted length.
		req.Body = io.NopCloser(bytes.NewReader(nil))
		req.ContentLength = staleLength
		req.Header.Set("Content-Length", fmt.Sprintf("%d", staleLength))

		var seenHeaderValue string
		var seenContentLength int64

		inspectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenHeaderValue = r.Header.Get("Content-Length")
			seenContentLength = r.ContentLength

			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Empty(t, body)

			w.Write([]byte("ok"))
		})

		wrappedInspect := middleware(inspectHandler)
		w := httptest.NewRecorder()
		wrappedInspect.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, seenHeaderValue)
		assert.Equal(t, int64(0), seenContentLength)

		decryptedResponse := client.decryptResponse(t, w)
		assert.Equal(t, "ok", string(decryptedResponse))
	})
}

func TestPlaintextPassthrough(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	middleware := serverIdentity.Middleware()

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Hello, " + string(body)))
	})

	wrapped := middleware(testHandler)

	t.Run("plaintext passthrough works", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		// No Ehbp-Response-Nonce header since request was plaintext
		assert.Empty(t, w.Header().Get(protocol.ResponseNonceHeader))
		assert.Equal(t, "Hello, test", w.Body.String())
	})
}

func TestStreamingResponseWriter(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	middleware := serverIdentity.Middleware()

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
		client := newTestClient(t)

		req := httptest.NewRequest("POST", "/stream", strings.NewReader("test body"))
		client.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "chunked", w.Header().Get("Transfer-Encoding"))
		assert.Empty(t, w.Header().Get("Content-Length"))

		// Verify response nonce header exists
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

func TestSendErrorKeyConfigProblem(t *testing.T) {
	w := httptest.NewRecorder()
	testError := fmt.Errorf("key mismatch")

	sendError(w, testError, "failed to decrypt request", http.StatusUnprocessableEntity)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Equal(t, protocol.ProblemJSONMediaType, w.Header().Get("Content-Type"))

	var problem map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &problem)
	require.NoError(t, err)
	assert.Equal(t, protocol.KeyConfigProblemType, problem["type"])
	assert.Equal(t, "failed to decrypt request", problem["title"])
}

func TestChunkEncryptionDecryption(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	middleware := serverIdentity.Middleware()

	t.Run("multiple chunks are encrypted separately", func(t *testing.T) {
		client := newTestClient(t)

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

		req := httptest.NewRequest("POST", "/chunks", strings.NewReader("test body"))
		client.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Decrypt response
		decryptedResponse := client.decryptResponse(t, w)
		assert.Equal(t, "chunk1|chunk2|chunk3", string(decryptedResponse))
	})

	t.Run("empty chunks are handled correctly", func(t *testing.T) {
		client := newTestClient(t)

		// Create handler that writes empty data
		emptyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte{}) // Empty write
			w.Write([]byte("after empty"))
		})

		wrapped := middleware(emptyHandler)

		req := httptest.NewRequest("POST", "/empty", strings.NewReader("test body"))
		client.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Decrypt response
		decryptedResponse := client.decryptResponse(t, w)
		assert.Equal(t, "after empty", string(decryptedResponse))
	})

	t.Run("large chunks are encrypted correctly", func(t *testing.T) {
		client := newTestClient(t)
		largeData := strings.Repeat("A", 10000) // 10KB of data

		largeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(largeData))
		})

		wrapped := middleware(largeHandler)

		req := httptest.NewRequest("POST", "/large", strings.NewReader("test body"))
		client.encryptRequest(t, req, serverIdentity.MarshalPublicKey())

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Decrypt response
		decryptedResponse := client.decryptResponse(t, w)
		assert.Equal(t, largeData, string(decryptedResponse))
	})
}

// TestBodylessHTTPMethods verifies that GET, HEAD, DELETE, and OPTIONS pass through
// unencrypted - see SPEC.md Section 6.4 for security rationale.
func TestBodylessHTTPMethods(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	middleware := serverIdentity.Middleware()

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back the method used
		w.Write([]byte("Method: " + r.Method))
	})

	wrapped := middleware(testHandler)

	bodylessMethods := []string{"GET", "HEAD", "DELETE", "OPTIONS"}

	for _, method := range bodylessMethods {
		t.Run(method+" request passes through unencrypted", func(t *testing.T) {
			req := httptest.NewRequest(method, "/test", nil)

			w := httptest.NewRecorder()
			wrapped.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "%s request should succeed", method)

			// Verify response does NOT have encryption headers
			responseNonceHeader := w.Header().Get(protocol.ResponseNonceHeader)
			assert.Empty(t, responseNonceHeader, "%s response should not have nonce header", method)

			// HEAD responses have no body
			if method != "HEAD" {
				// Response should be plaintext
				assert.Equal(t, "Method: "+method, w.Body.String(),
					"%s response should be plaintext", method)
			}
		})
	}
}

func TestDerivedResponseEncryptionSecurity(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	middleware := serverIdentity.Middleware()

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret response"))
	})

	wrapped := middleware(testHandler)

	t.Run("different clients cannot decrypt each others responses", func(t *testing.T) {
		client1 := newTestClient(t)
		client2 := newTestClient(t)

		// Client 1 makes a request
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test body"))
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
		dummyReq := httptest.NewRequest("POST", "/dummy", strings.NewReader("dummy body"))
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

		_, err := client2AEAD.Open(encryptedChunk, nil)
		assert.Error(t, err, "client 2 should not be able to decrypt client 1's response")
	})
}

func BenchmarkMiddlewareEncryption(b *testing.B) {
	serverIdentity, err := NewIdentity()
	require.NoError(b, err)

	middleware := serverIdentity.Middleware()

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	wrapped := middleware(testHandler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create a fresh client for each iteration (realistic scenario)
		clientIdentity, _ := NewIdentity()
		sender, _ := clientIdentity.Suite().NewSender(serverIdentity.PublicKey(), []byte(HPKERequestInfo))
		encapKey, _, _ := sender.Setup(rand.Reader)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(protocol.EncapsulatedKeyHeader, hex.EncodeToString(encapKey))

		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
	}
}
