package identity

import (
	"bytes"
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
	serverPubKey, err := serverIdentity.MarshalPublicKey()
	require.NoError(t, err)

	t.Run("big streaming request encryption", func(t *testing.T) {
		largeData := strings.Repeat("A", 1024*1024)

		req := httptest.NewRequest("POST", "/test", strings.NewReader(largeData))
		originalLength := req.ContentLength

		// Encrypt
		_, err := clientIdentity.EncryptRequest(req, serverPubKey)
		require.NoError(t, err)

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

	t.Run("streaming request decryption", func(t *testing.T) {
		testData := "Hello, streaming world!"

		req := httptest.NewRequest("POST", "/test", strings.NewReader(testData))
		_, err := clientIdentity.EncryptRequest(req, serverPubKey)
		require.NoError(t, err)

		_, err = serverIdentity.DecryptRequest(req)
		require.NoError(t, err)

		decryptedBody, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		assert.Equal(t, testData, string(decryptedBody))
	})

	t.Run("response encryption requires context", func(t *testing.T) {
		w := httptest.NewRecorder()

		_, err := serverIdentity.SetupResponseEncryption(w, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "response context required")
	})

	t.Run("chunked response decryption", func(t *testing.T) {
		testData := "chunk1chunk2chunk3"

		// Set up encryption
		sender, err := serverIdentity.Suite().NewSender(clientIdentity.PublicKey(), nil)
		require.NoError(t, err)
		encapKey, sealer, err := sender.Setup(nil)
		require.NoError(t, err)

		var buffer bytes.Buffer
		chunks := []string{"chunk1", "chunk2", "chunk3"}

		for _, chunk := range chunks {
			encrypted, err := sealer.Seal([]byte(chunk), nil)
			require.NoError(t, err)

			// Write chunk len (4 bytes big-endian) + encrypted data
			chunkLen := uint32(len(encrypted))
			buffer.WriteByte(byte(chunkLen >> 24))
			buffer.WriteByte(byte(chunkLen >> 16))
			buffer.WriteByte(byte(chunkLen >> 8))
			buffer.WriteByte(byte(chunkLen))
			buffer.Write(encrypted)
		}

		// Decrypt
		decrypted, err := clientIdentity.DecryptChunkedResponse(buffer.Bytes(), encapKey)
		require.NoError(t, err)

		assert.Equal(t, testData, string(decrypted))
	})

	t.Run("streaming readers handle partial reads", func(t *testing.T) {
		testData := "This is a test of partial reads with streaming encryption"

		req := httptest.NewRequest("POST", "/test", strings.NewReader(testData))
		_, err := clientIdentity.EncryptRequest(req, serverPubKey)
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
	serverPubKey, err := serverIdentity.MarshalPublicKey()
	require.NoError(t, err)

	t.Run("empty request body requires error", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader(""))
		_, err := clientIdentity.EncryptRequest(req, serverPubKey)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "EHBP requires a request body")
	})

	t.Run("nil request body requires error", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", nil)
		_, err := clientIdentity.EncryptRequest(req, serverPubKey)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "EHBP requires a request body")
	})

	t.Run("decrypt empty encrypted stream", func(t *testing.T) {
		emptyData := []byte{}

		sender, err := serverIdentity.Suite().NewSender(clientIdentity.PublicKey(), nil)
		require.NoError(t, err)
		encapKey, _, err := sender.Setup(nil)
		require.NoError(t, err)

		decrypted, err := clientIdentity.DecryptChunkedResponse(emptyData, encapKey)
		require.NoError(t, err)
		assert.Empty(t, decrypted)
	})
}
