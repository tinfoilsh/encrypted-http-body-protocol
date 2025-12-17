package identity

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

func TestStreamingEncryption(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("big streaming request encryption", func(t *testing.T) {
		largeData := strings.Repeat("A", 1024*1024)

		req := httptest.NewRequest("POST", "/test", strings.NewReader(largeData))
		originalLength := req.ContentLength

		// Encrypt to server's public key
		reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)
		require.NotNil(t, reqCtx)

		// Verify headers are set
		assert.NotEmpty(t, req.Header.Get(protocol.EncapsulatedKeyHeader))
		assert.Equal(t, "chunked", req.Header.Get("Transfer-Encoding"))
		assert.Equal(t, int64(-1), req.ContentLength) // Unknown length for streaming

		// Read the encrypted body in chunks
		encryptedData := make([]byte, 0)
		buffer := make([]byte, 8192) // 8KB buffer
		for {
			n, err := req.Body.Read(buffer)
			if n > 0 {
				encryptedData = append(encryptedData, buffer[:n]...)
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}

		assert.Greater(t, len(encryptedData), int(originalLength))
	})

	t.Run("streaming request round trip", func(t *testing.T) {
		testData := "Hello, streaming world!"

		req := httptest.NewRequest("POST", "/test", strings.NewReader(testData))
		_, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		respCtx, err := serverIdentity.DecryptRequestWithContext(req)
		require.NoError(t, err)
		require.NotNil(t, respCtx)

		decryptedBody, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		assert.Equal(t, testData, string(decryptedBody))
	})

	t.Run("streaming readers handle partial reads", func(t *testing.T) {
		testData := "This is a test of partial reads with streaming encryption"

		req := httptest.NewRequest("POST", "/test", strings.NewReader(testData))
		_, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		// Read in very small chunks to test partial read handling
		var encryptedData []byte
		buffer := make([]byte, 10) // Small buffer to force partial reads

		for {
			n, err := req.Body.Read(buffer)
			if n > 0 {
				encryptedData = append(encryptedData, buffer[:n]...)
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}

		assert.Greater(t, len(encryptedData), len(testData))
	})
}

func TestStreamingReaderEdgeCases(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("empty request body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader(""))
		_, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)
		assert.Equal(t, int64(0), req.ContentLength)
	})

	t.Run("nil request body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", nil)
		_, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)
	})
}

func TestV2EncryptDecryptRoundTrip(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("full round trip with body", func(t *testing.T) {
		testData := "Hello, encrypted world!"

		// Client encrypts request to server's public key
		req := httptest.NewRequest("POST", "/test", strings.NewReader(testData))
		reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		// Server decrypts request
		respCtx, err := serverIdentity.DecryptRequestWithContext(req)
		require.NoError(t, err)

		// Verify decrypted body
		decryptedBody, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, testData, string(decryptedBody))

		// Server sets up response encryption
		w := httptest.NewRecorder()
		writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
		require.NoError(t, err)

		// Server writes response
		responseData := "Hello back!"
		_, err = writer.Write([]byte(responseData))
		require.NoError(t, err)
		writer.Flush()

		// Verify response has nonce header
		assert.NotEmpty(t, w.Header().Get(protocol.ResponseNonceHeader))

		// Client decrypts response
		responseNonceHex := w.Header().Get(protocol.ResponseNonceHeader)
		responseNonce, err := hex.DecodeString(responseNonceHex)
		require.NoError(t, err)

		// Export secret from client's sealer
		exportedSecret := reqCtx.Sealer.Export([]byte(ExportLabel), uint(ExportLength))

		// Derive response keys
		km, err := DeriveResponseKeys(exportedSecret, reqCtx.RequestEnc, responseNonce)
		require.NoError(t, err)

		// Create AEAD for decryption
		aead, err := km.NewResponseAEAD()
		require.NoError(t, err)

		// Decrypt chunks (aead.Open auto-increments the sequence)
		var result bytes.Buffer
		reader := bytes.NewReader(w.Body.Bytes())

		for reader.Len() > 0 {
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

			encryptedChunk := make([]byte, chunkLen)
			_, err = io.ReadFull(reader, encryptedChunk)
			require.NoError(t, err)

			decrypted, err := aead.Open(encryptedChunk, nil)
			require.NoError(t, err)

			result.Write(decrypted)
		}

		assert.Equal(t, responseData, result.String())
	})

	t.Run("empty body request with response", func(t *testing.T) {
		// Client encrypts request with no body (to server's public key)
		req := httptest.NewRequest("GET", "/test", nil)
		reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		// Server sets up response context for empty body
		encHex := req.Header.Get(protocol.EncapsulatedKeyHeader)
		respCtx, err := serverIdentity.SetupResponseContextForEmptyBody(encHex)
		require.NoError(t, err)

		// Server sets up response encryption
		w := httptest.NewRecorder()
		writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
		require.NoError(t, err)

		// Server writes response
		responseData := "Response to empty body request"
		_, err = writer.Write([]byte(responseData))
		require.NoError(t, err)
		writer.Flush()

		// Client can decrypt
		responseNonceHex := w.Header().Get(protocol.ResponseNonceHeader)
		responseNonce, err := hex.DecodeString(responseNonceHex)
		require.NoError(t, err)

		exportedSecret := reqCtx.Sealer.Export([]byte(ExportLabel), uint(ExportLength))
		km, err := DeriveResponseKeys(exportedSecret, reqCtx.RequestEnc, responseNonce)
		require.NoError(t, err)

		aead, err := km.NewResponseAEAD()
		require.NoError(t, err)

		// Decrypt first chunk
		reader := bytes.NewReader(w.Body.Bytes())
		var chunkLen uint32
		err = binary.Read(reader, binary.BigEndian, &chunkLen)
		require.NoError(t, err)

		encryptedChunk := make([]byte, chunkLen)
		_, err = io.ReadFull(reader, encryptedChunk)
		require.NoError(t, err)

		decrypted, err := aead.Open(encryptedChunk, nil)
		require.NoError(t, err)

		assert.Equal(t, responseData, string(decrypted))
	})
}

func TestSetupResponseContextForEmptyBody(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("valid encapsulated key", func(t *testing.T) {
		// Client creates an HPKE context (using server's suite/public key)
		sender, err := serverIdentity.Suite().NewSender(serverIdentity.PublicKey(), []byte(HPKERequestInfo))
		require.NoError(t, err)
		encapKey, _, err := sender.Setup(rand.Reader)
		require.NoError(t, err)

		encHex := hex.EncodeToString(encapKey)
		respCtx, err := serverIdentity.SetupResponseContextForEmptyBody(encHex)
		require.NoError(t, err)
		assert.NotNil(t, respCtx)
		assert.Equal(t, encapKey, respCtx.RequestEnc)
	})

	t.Run("invalid hex", func(t *testing.T) {
		_, err := serverIdentity.SetupResponseContextForEmptyBody("not-hex")
		require.Error(t, err)
	})

	t.Run("invalid encapsulated key length", func(t *testing.T) {
		_, err := serverIdentity.SetupResponseContextForEmptyBody("deadbeef")
		require.Error(t, err)
	})
}

// =============================================================================
// ClientError Tests
// =============================================================================

func TestClientError(t *testing.T) {
	t.Run("Error returns wrapped error message", func(t *testing.T) {
		innerErr := errors.New("invalid input from client")
		clientErr := ClientError{Err: innerErr}

		assert.Equal(t, "invalid input from client", clientErr.Error())
	})

	t.Run("Unwrap returns the inner error", func(t *testing.T) {
		innerErr := errors.New("bad request data")
		clientErr := ClientError{Err: innerErr}

		unwrapped := clientErr.Unwrap()
		assert.Equal(t, innerErr, unwrapped)
	})

	t.Run("NewClientError creates ClientError", func(t *testing.T) {
		innerErr := errors.New("malformed header")
		err := NewClientError(innerErr)

		var clientErr ClientError
		assert.True(t, errors.As(err, &clientErr))
		assert.Equal(t, innerErr, clientErr.Err)
	})

	t.Run("IsClientError identifies ClientError", func(t *testing.T) {
		clientErr := NewClientError(errors.New("client fault"))
		serverErr := errors.New("server fault")

		assert.True(t, IsClientError(clientErr))
		assert.False(t, IsClientError(serverErr))
	})

	t.Run("IsClientError works with wrapped errors", func(t *testing.T) {
		innerErr := NewClientError(errors.New("original"))
		wrappedErr := errors.Join(errors.New("context"), innerErr)

		assert.True(t, IsClientError(wrappedErr))
	})
}

// =============================================================================
// Streaming Reader Close Tests
// =============================================================================

// mockCloser tracks whether Close was called
type mockCloser struct {
	io.Reader
	closed    bool
	closeErr  error
}

func (m *mockCloser) Close() error {
	m.closed = true
	return m.closeErr
}

func TestStreamingEncryptReaderClose(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("Close propagates to underlying closeable reader", func(t *testing.T) {
		underlying := &mockCloser{Reader: strings.NewReader("test data")}

		sender, err := serverIdentity.Suite().NewSender(serverIdentity.PublicKey(), []byte(HPKERequestInfo))
		require.NoError(t, err)
		_, sealer, err := sender.Setup(rand.Reader)
		require.NoError(t, err)

		reader := &StreamingEncryptReader{
			reader: underlying,
			sealer: sealer,
		}

		err = reader.Close()
		assert.NoError(t, err)
		assert.True(t, underlying.closed, "underlying reader should be closed")
	})

	t.Run("Close returns error from underlying reader", func(t *testing.T) {
		expectedErr := errors.New("close failed")
		underlying := &mockCloser{
			Reader:   strings.NewReader("test"),
			closeErr: expectedErr,
		}

		sender, err := serverIdentity.Suite().NewSender(serverIdentity.PublicKey(), []byte(HPKERequestInfo))
		require.NoError(t, err)
		_, sealer, err := sender.Setup(rand.Reader)
		require.NoError(t, err)

		reader := &StreamingEncryptReader{
			reader: underlying,
			sealer: sealer,
		}

		err = reader.Close()
		assert.Equal(t, expectedErr, err)
	})

	t.Run("Close succeeds when underlying reader is not closeable", func(t *testing.T) {
		// strings.Reader does not implement io.Closer
		underlying := strings.NewReader("test data")

		sender, err := serverIdentity.Suite().NewSender(serverIdentity.PublicKey(), []byte(HPKERequestInfo))
		require.NoError(t, err)
		_, sealer, err := sender.Setup(rand.Reader)
		require.NoError(t, err)

		reader := &StreamingEncryptReader{
			reader: underlying,
			sealer: sealer,
		}

		err = reader.Close()
		assert.NoError(t, err)
	})
}

func TestStreamingDecryptReaderClose(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("Close propagates to underlying closeable reader", func(t *testing.T) {
		underlying := &mockCloser{Reader: strings.NewReader("")}

		receiver, err := serverIdentity.Suite().NewReceiver(serverIdentity.PrivateKey(), []byte(HPKERequestInfo))
		require.NoError(t, err)

		sender, err := serverIdentity.Suite().NewSender(serverIdentity.PublicKey(), []byte(HPKERequestInfo))
		require.NoError(t, err)
		encapKey, _, err := sender.Setup(rand.Reader)
		require.NoError(t, err)

		opener, err := receiver.Setup(encapKey)
		require.NoError(t, err)

		reader := NewStreamingDecryptReader(underlying, opener)

		err = reader.Close()
		assert.NoError(t, err)
		assert.True(t, underlying.closed)
	})

	t.Run("Close returns error from underlying reader", func(t *testing.T) {
		expectedErr := errors.New("underlying close error")
		underlying := &mockCloser{
			Reader:   strings.NewReader(""),
			closeErr: expectedErr,
		}

		receiver, err := serverIdentity.Suite().NewReceiver(serverIdentity.PrivateKey(), []byte(HPKERequestInfo))
		require.NoError(t, err)

		sender, err := serverIdentity.Suite().NewSender(serverIdentity.PublicKey(), []byte(HPKERequestInfo))
		require.NoError(t, err)
		encapKey, _, err := sender.Setup(rand.Reader)
		require.NoError(t, err)

		opener, err := receiver.Setup(encapKey)
		require.NoError(t, err)

		reader := NewStreamingDecryptReader(underlying, opener)

		err = reader.Close()
		assert.Equal(t, expectedErr, err)
	})

	t.Run("Close succeeds when underlying reader is not closeable", func(t *testing.T) {
		// strings.Reader does not implement io.Closer
		underlying := strings.NewReader("")

		receiver, err := serverIdentity.Suite().NewReceiver(serverIdentity.PrivateKey(), []byte(HPKERequestInfo))
		require.NoError(t, err)

		sender, err := serverIdentity.Suite().NewSender(serverIdentity.PublicKey(), []byte(HPKERequestInfo))
		require.NoError(t, err)
		encapKey, _, err := sender.Setup(rand.Reader)
		require.NoError(t, err)

		opener, err := receiver.Setup(encapKey)
		require.NoError(t, err)

		reader := NewStreamingDecryptReader(underlying, opener)

		err = reader.Close()
		assert.NoError(t, err)
	})
}

// =============================================================================
// DecryptRequestWithContext Error Path Tests
// =============================================================================

func TestDecryptRequestWithContextErrors(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("missing encapsulated key header returns ClientError", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("body"))
		// Don't set the header

		_, err := serverIdentity.DecryptRequestWithContext(req)
		require.Error(t, err)
		assert.True(t, IsClientError(err), "should be a ClientError")
		assert.Contains(t, err.Error(), protocol.EncapsulatedKeyHeader)
	})

	t.Run("invalid hex in encapsulated key returns ClientError", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("body"))
		req.Header.Set(protocol.EncapsulatedKeyHeader, "not-valid-hex!")

		_, err := serverIdentity.DecryptRequestWithContext(req)
		require.Error(t, err)
		assert.True(t, IsClientError(err))
		assert.Contains(t, err.Error(), "invalid encapsulated key")
	})

	t.Run("wrong length encapsulated key returns ClientError", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("body"))
		req.Header.Set(protocol.EncapsulatedKeyHeader, "deadbeef") // Too short

		_, err := serverIdentity.DecryptRequestWithContext(req)
		require.Error(t, err)
		assert.True(t, IsClientError(err))
	})

	t.Run("encapsulated key from different sender returns ClientError", func(t *testing.T) {
		// Create an encapsulated key for a DIFFERENT server
		otherServer, err := NewIdentity()
		require.NoError(t, err)

		sender, err := otherServer.Suite().NewSender(otherServer.PublicKey(), []byte(HPKERequestInfo))
		require.NoError(t, err)
		encapKey, sealer, err := sender.Setup(rand.Reader)
		require.NoError(t, err)

		// Encrypt some data
		ciphertext, err := sealer.Seal([]byte("secret"), nil)
		require.NoError(t, err)

		// Build chunk format
		var buf bytes.Buffer
		binary.Write(&buf, binary.BigEndian, uint32(len(ciphertext)))
		buf.Write(ciphertext)

		// Try to decrypt with the wrong server
		req := httptest.NewRequest("POST", "/test", &buf)
		req.Header.Set(protocol.EncapsulatedKeyHeader, hex.EncodeToString(encapKey))

		respCtx, err := serverIdentity.DecryptRequestWithContext(req)
		require.NoError(t, err) // Setup succeeds, decryption fails on read

		// Reading the body should fail because the keys don't match
		_, err = io.ReadAll(req.Body)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decrypt")
		assert.NotNil(t, respCtx) // Context is returned even though decryption will fail
	})

	t.Run("returns nil for nil body", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Body = nil

		respCtx, err := serverIdentity.DecryptRequestWithContext(req)
		assert.NoError(t, err)
		assert.Nil(t, respCtx)
	})

	t.Run("returns nil for http.NoBody", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Body = http.NoBody

		respCtx, err := serverIdentity.DecryptRequestWithContext(req)
		assert.NoError(t, err)
		assert.Nil(t, respCtx)
	})
}

// =============================================================================
// DecryptResponse Error Path Tests
// =============================================================================

func TestDecryptResponseErrors(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("nil request context returns error", func(t *testing.T) {
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(strings.NewReader("")),
		}
		resp.Header.Set(protocol.ResponseNonceHeader, hex.EncodeToString(make([]byte, 32)))

		var nilCtx *RequestContext
		err := nilCtx.DecryptResponse(resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is nil")
	})

	t.Run("missing response nonce header returns error", func(t *testing.T) {
		// Create a valid request context
		req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
		reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(strings.NewReader("")),
		}
		// Don't set ResponseNonceHeader

		err = reqCtx.DecryptResponse(resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), protocol.ResponseNonceHeader)
	})

	t.Run("invalid hex in response nonce returns error", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
		reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(strings.NewReader("")),
		}
		resp.Header.Set(protocol.ResponseNonceHeader, "not-valid-hex!")

		err = reqCtx.DecryptResponse(resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid response nonce")
	})

	t.Run("wrong length response nonce returns error", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
		reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(strings.NewReader("")),
		}
		resp.Header.Set(protocol.ResponseNonceHeader, "deadbeef") // Too short

		err = reqCtx.DecryptResponse(resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid response nonce length")
	})
}

// =============================================================================
// Corrupt Data and Tampered Response Tests
// =============================================================================

func TestCorruptDataHandling(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("tampered ciphertext fails decryption", func(t *testing.T) {
		// Encrypt a request
		req := httptest.NewRequest("POST", "/test", strings.NewReader("secret data"))
		_, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		// Read the encrypted body
		encryptedBody, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		// Tamper with the ciphertext (flip some bits after the length prefix)
		if len(encryptedBody) > 10 {
			encryptedBody[8] ^= 0xFF
			encryptedBody[9] ^= 0xFF
		}

		// Try to decrypt the tampered data
		tamperedReq := httptest.NewRequest("POST", "/test", bytes.NewReader(encryptedBody))
		tamperedReq.Header.Set(protocol.EncapsulatedKeyHeader, req.Header.Get(protocol.EncapsulatedKeyHeader))

		_, err = serverIdentity.DecryptRequestWithContext(tamperedReq)
		require.NoError(t, err) // Setup succeeds

		// Reading should fail due to authentication failure
		_, err = io.ReadAll(tamperedReq.Body)
		require.Error(t, err)
	})

	t.Run("truncated chunk fails gracefully", func(t *testing.T) {
		// Create valid encrypted data
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test data"))
		_, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		encryptedBody, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		// Truncate the data (keep length prefix but cut the actual data)
		truncated := encryptedBody[:8] // Just the length prefix + a few bytes

		truncatedReq := httptest.NewRequest("POST", "/test", bytes.NewReader(truncated))
		truncatedReq.Header.Set(protocol.EncapsulatedKeyHeader, req.Header.Get(protocol.EncapsulatedKeyHeader))

		_, err = serverIdentity.DecryptRequestWithContext(truncatedReq)
		require.NoError(t, err)

		// Reading should fail
		_, err = io.ReadAll(truncatedReq.Body)
		require.Error(t, err)
	})

	t.Run("response with wrong keys fails decryption", func(t *testing.T) {
		// Client encrypts request
		req := httptest.NewRequest("POST", "/test", strings.NewReader("request"))
		reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		// Server decrypts and responds
		respCtx, err := serverIdentity.DecryptRequestWithContext(req)
		require.NoError(t, err)
		io.ReadAll(req.Body) // Consume body

		w := httptest.NewRecorder()
		writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
		require.NoError(t, err)
		writer.Write([]byte("response"))
		writer.Flush()

		// Create a fake response with DIFFERENT nonce
		fakeResp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(w.Body.Bytes())),
		}
		// Use a random nonce instead of the real one
		fakeNonce := make([]byte, 32)
		rand.Read(fakeNonce)
		fakeResp.Header.Set(protocol.ResponseNonceHeader, hex.EncodeToString(fakeNonce))

		// Client tries to decrypt with wrong nonce
		err = reqCtx.DecryptResponse(fakeResp)
		require.NoError(t, err) // Setup succeeds

		// Reading should fail
		_, err = io.ReadAll(fakeResp.Body)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decrypt")
	})
}

// =============================================================================
// DerivedResponseWriter Tests
// =============================================================================

func TestDerivedResponseWriter(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	setupWriter := func(t *testing.T) (*DerivedResponseWriter, *httptest.ResponseRecorder, *RequestContext) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("request"))
		reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		respCtx, err := serverIdentity.DecryptRequestWithContext(req)
		require.NoError(t, err)
		io.ReadAll(req.Body)

		w := httptest.NewRecorder()
		writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
		require.NoError(t, err)

		return writer, w, reqCtx
	}

	t.Run("WriteHeader sets custom status code", func(t *testing.T) {
		writer, w, _ := setupWriter(t)

		writer.WriteHeader(http.StatusCreated)
		writer.Write([]byte("created"))

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("WriteHeader only called once", func(t *testing.T) {
		writer, w, _ := setupWriter(t)

		writer.WriteHeader(http.StatusCreated)
		writer.WriteHeader(http.StatusBadRequest) // Should be ignored
		writer.Write([]byte("data"))

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("Write without WriteHeader defaults to 200", func(t *testing.T) {
		writer, w, _ := setupWriter(t)

		writer.Write([]byte("data"))

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("empty Write returns zero", func(t *testing.T) {
		writer, _, _ := setupWriter(t)

		n, err := writer.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("multiple writes produce valid chunks", func(t *testing.T) {
		writer, w, reqCtx := setupWriter(t)

		// Write multiple chunks
		writer.Write([]byte("chunk1"))
		writer.Write([]byte("chunk2"))
		writer.Write([]byte("chunk3"))
		writer.Flush()

		// Verify we can decrypt all chunks
		resp := &http.Response{
			Header: w.Header(),
			Body:   io.NopCloser(bytes.NewReader(w.Body.Bytes())),
		}

		err := reqCtx.DecryptResponse(resp)
		require.NoError(t, err)

		decrypted, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "chunk1chunk2chunk3", string(decrypted))
	})

	t.Run("Flush works without panic on non-flusher", func(t *testing.T) {
		writer, _, _ := setupWriter(t)

		// This should not panic even if underlying writer doesn't implement Flusher
		assert.NotPanics(t, func() {
			writer.Flush()
		})
	})
}

func TestSetupDerivedResponseEncryptionErrors(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("nil response context returns error", func(t *testing.T) {
		w := httptest.NewRecorder()
		_, err := serverIdentity.SetupDerivedResponseEncryption(w, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is nil")
	})
}

// =============================================================================
// Multi-Chunk Buffer Handling Tests
// =============================================================================

func TestMultiChunkBufferHandling(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("StreamingEncryptReader buffers when output smaller than chunk", func(t *testing.T) {
		testData := strings.Repeat("X", 1000)
		req := httptest.NewRequest("POST", "/test", strings.NewReader(testData))
		_, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		// Read with very small buffer to force buffering
		var result []byte
		smallBuf := make([]byte, 5)
		for {
			n, err := req.Body.Read(smallBuf)
			if n > 0 {
				result = append(result, smallBuf[:n]...)
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}

		assert.Greater(t, len(result), len(testData))
	})

	t.Run("StreamingDecryptReader buffers when output smaller than decrypted chunk", func(t *testing.T) {
		testData := "This is a message that will be encrypted and then read in small pieces"

		// Encrypt
		req := httptest.NewRequest("POST", "/test", strings.NewReader(testData))
		_, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		encryptedBody, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		// Set up decryption
		decryptReq := httptest.NewRequest("POST", "/test", bytes.NewReader(encryptedBody))
		decryptReq.Header.Set(protocol.EncapsulatedKeyHeader, req.Header.Get(protocol.EncapsulatedKeyHeader))

		_, err = serverIdentity.DecryptRequestWithContext(decryptReq)
		require.NoError(t, err)

		// Read with very small buffer
		var result []byte
		smallBuf := make([]byte, 3)
		for {
			n, err := decryptReq.Body.Read(smallBuf)
			if n > 0 {
				result = append(result, smallBuf[:n]...)
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}

		assert.Equal(t, testData, string(result))
	})

	t.Run("DerivedStreamingDecryptReader handles partial reads correctly", func(t *testing.T) {
		// Full round trip with small read buffer
		testData := "Response data that will be read in small chunks"

		req := httptest.NewRequest("POST", "/test", strings.NewReader("request"))
		reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		respCtx, err := serverIdentity.DecryptRequestWithContext(req)
		require.NoError(t, err)
		io.ReadAll(req.Body)

		w := httptest.NewRecorder()
		writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
		require.NoError(t, err)
		writer.Write([]byte(testData))
		writer.Flush()

		resp := &http.Response{
			Header: w.Header(),
			Body:   io.NopCloser(bytes.NewReader(w.Body.Bytes())),
		}

		err = reqCtx.DecryptResponse(resp)
		require.NoError(t, err)

		// Read with tiny buffer
		var result []byte
		tinyBuf := make([]byte, 2)
		for {
			n, err := resp.Body.Read(tinyBuf)
			if n > 0 {
				result = append(result, tinyBuf[:n]...)
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}

		assert.Equal(t, testData, string(result))
	})
}

// =============================================================================
// Empty Chunk Handling Tests
// =============================================================================

func TestEmptyChunkHandling(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("StreamingDecryptReader skips empty chunks", func(t *testing.T) {
		// Create a valid encrypted chunk
		testData := "real data after empty chunk"

		req := httptest.NewRequest("POST", "/test", strings.NewReader(testData))
		_, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		// Read the encrypted data
		encryptedBody, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		// Prepend an empty chunk (4 bytes of zeros = length 0)
		emptyChunk := make([]byte, 4) // chunkLen = 0
		dataWithEmptyChunk := append(emptyChunk, encryptedBody...)

		// Set up decryption with the modified data
		decryptReq := httptest.NewRequest("POST", "/test", bytes.NewReader(dataWithEmptyChunk))
		decryptReq.Header.Set(protocol.EncapsulatedKeyHeader, req.Header.Get(protocol.EncapsulatedKeyHeader))

		_, err = serverIdentity.DecryptRequestWithContext(decryptReq)
		require.NoError(t, err)

		// Should skip empty chunk and decrypt the real data
		decrypted, err := io.ReadAll(decryptReq.Body)
		require.NoError(t, err)
		assert.Equal(t, testData, string(decrypted))
	})

	t.Run("DerivedStreamingDecryptReader skips empty chunks", func(t *testing.T) {
		// Full round trip setup
		req := httptest.NewRequest("POST", "/test", strings.NewReader("request"))
		reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		respCtx, err := serverIdentity.DecryptRequestWithContext(req)
		require.NoError(t, err)
		io.ReadAll(req.Body)

		w := httptest.NewRecorder()
		writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
		require.NoError(t, err)

		responseData := "response after empty chunk"
		writer.Write([]byte(responseData))
		writer.Flush()

		// Get the encrypted response and prepend an empty chunk
		encryptedResponse := w.Body.Bytes()
		emptyChunk := make([]byte, 4) // chunkLen = 0
		dataWithEmptyChunk := append(emptyChunk, encryptedResponse...)

		// Decrypt with empty chunk prepended
		resp := &http.Response{
			Header: w.Header(),
			Body:   io.NopCloser(bytes.NewReader(dataWithEmptyChunk)),
		}

		err = reqCtx.DecryptResponse(resp)
		require.NoError(t, err)

		// Should skip empty chunk and decrypt the real data
		decrypted, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, responseData, string(decrypted))
	})

	t.Run("multiple consecutive empty chunks are skipped", func(t *testing.T) {
		testData := "data after multiple empty chunks"

		req := httptest.NewRequest("POST", "/test", strings.NewReader(testData))
		_, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		encryptedBody, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		// Prepend multiple empty chunks
		emptyChunks := make([]byte, 12) // 3 empty chunks (3 * 4 bytes)
		dataWithEmptyChunks := append(emptyChunks, encryptedBody...)

		decryptReq := httptest.NewRequest("POST", "/test", bytes.NewReader(dataWithEmptyChunks))
		decryptReq.Header.Set(protocol.EncapsulatedKeyHeader, req.Header.Get(protocol.EncapsulatedKeyHeader))

		_, err = serverIdentity.DecryptRequestWithContext(decryptReq)
		require.NoError(t, err)

		decrypted, err := io.ReadAll(decryptReq.Body)
		require.NoError(t, err)
		assert.Equal(t, testData, string(decrypted))
	})
}

// =============================================================================
// DerivedStreamingDecryptReader Close Test
// =============================================================================

func TestDerivedStreamingDecryptReaderClose(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("Close propagates to underlying closeable reader", func(t *testing.T) {
		// Set up a full encrypted response
		req := httptest.NewRequest("POST", "/test", strings.NewReader("request"))
		reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		respCtx, err := serverIdentity.DecryptRequestWithContext(req)
		require.NoError(t, err)
		io.ReadAll(req.Body)

		w := httptest.NewRecorder()
		writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
		require.NoError(t, err)
		writer.Write([]byte("response"))
		writer.Flush()

		// Use mockCloser as the underlying reader
		underlying := &mockCloser{Reader: bytes.NewReader(w.Body.Bytes())}

		resp := &http.Response{
			Header: w.Header(),
			Body:   underlying,
		}

		err = reqCtx.DecryptResponse(resp)
		require.NoError(t, err)

		// Close the decrypted body
		err = resp.Body.Close()
		assert.NoError(t, err)
		assert.True(t, underlying.closed)
	})

	t.Run("Close succeeds when underlying reader is not closeable", func(t *testing.T) {
		// Set up encrypted response
		req := httptest.NewRequest("POST", "/test", strings.NewReader("request"))
		reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		respCtx, err := serverIdentity.DecryptRequestWithContext(req)
		require.NoError(t, err)
		io.ReadAll(req.Body)

		w := httptest.NewRecorder()
		writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
		require.NoError(t, err)
		writer.Write([]byte("response"))
		writer.Flush()

		// Create a DerivedStreamingDecryptReader with non-closeable underlying reader
		exportedSecret := reqCtx.Sealer.Export([]byte(ExportLabel), uint(ExportLength))
		responseNonce, _ := hex.DecodeString(w.Header().Get(protocol.ResponseNonceHeader))
		km, err := DeriveResponseKeys(exportedSecret, reqCtx.RequestEnc, responseNonce)
		require.NoError(t, err)
		aead, err := km.NewResponseAEAD()
		require.NoError(t, err)

		// Use bytes.Reader which doesn't implement io.Closer
		reader := &DerivedStreamingDecryptReader{
			reader: bytes.NewReader(w.Body.Bytes()),
			aead:   aead,
		}

		err = reader.Close()
		assert.NoError(t, err)
	})
}
