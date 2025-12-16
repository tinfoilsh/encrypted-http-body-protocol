package identity

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
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
	clientIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("big streaming request encryption", func(t *testing.T) {
		largeData := strings.Repeat("A", 1024*1024)

		req := httptest.NewRequest("POST", "/test", strings.NewReader(largeData))
		originalLength := req.ContentLength

		// Encrypt
		reqCtx, err := clientIdentity.EncryptRequestWithContext(req, serverIdentity.MarshalPublicKey())
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
		_, err := clientIdentity.EncryptRequestWithContext(req, serverIdentity.MarshalPublicKey())
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
		_, err := clientIdentity.EncryptRequestWithContext(req, serverIdentity.MarshalPublicKey())
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
	clientIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("empty request body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader(""))
		_, err := clientIdentity.EncryptRequestWithContext(req, serverIdentity.MarshalPublicKey())
		require.NoError(t, err)
		assert.Equal(t, int64(0), req.ContentLength)
	})

	t.Run("nil request body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", nil)
		_, err := clientIdentity.EncryptRequestWithContext(req, serverIdentity.MarshalPublicKey())
		require.NoError(t, err)
	})
}

func TestV2EncryptDecryptRoundTrip(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)
	clientIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("full round trip with body", func(t *testing.T) {
		testData := "Hello, encrypted world!"

		// Client encrypts request
		req := httptest.NewRequest("POST", "/test", strings.NewReader(testData))
		reqCtx, err := clientIdentity.EncryptRequestWithContext(req, serverIdentity.MarshalPublicKey())
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
		// Client encrypts request with no body
		req := httptest.NewRequest("GET", "/test", nil)
		reqCtx, err := clientIdentity.EncryptRequestWithContext(req, serverIdentity.MarshalPublicKey())
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
	clientIdentity, err := NewIdentity()
	require.NoError(t, err)

	t.Run("valid encapsulated key", func(t *testing.T) {
		// Client creates an HPKE context
		sender, err := clientIdentity.Suite().NewSender(serverIdentity.PublicKey(), nil)
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

func TestInvalidServerPublicKey(t *testing.T) {
	clientIdentity, err := NewIdentity()
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))

	// Invalid public key
	_, err = clientIdentity.EncryptRequestWithContext(req, []byte("invalid"))
	require.Error(t, err)
}
