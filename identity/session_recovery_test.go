package identity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

func TestSessionRecoveryTokenFields(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/test", strings.NewReader("test body"))
	reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
	require.NoError(t, err)
	require.NotNil(t, reqCtx)

	token, err := ExtractSessionRecoveryToken(reqCtx)
	require.NoError(t, err)

	assert.Len(t, token.ExportedSecret, ExportLength, "ExportedSecret must be 32 bytes")
	assert.Len(t, token.RequestEnc, 32, "RequestEnc must be 32 bytes")
}

func TestSessionRecoveryTokenMatchesDirectExport(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/test", strings.NewReader("test body"))
	reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
	require.NoError(t, err)

	directExport, err := reqCtx.Sender.Export(ExportLabel, ExportLength)
	require.NoError(t, err)
	token, err := ExtractSessionRecoveryToken(reqCtx)
	require.NoError(t, err)

	assert.Equal(t, directExport, token.ExportedSecret,
		"Token exportedSecret must match direct Sender.Export result")
	assert.Equal(t, reqCtx.RequestEnc, token.RequestEnc,
		"Token requestEnc must match context requestEnc")
}

func TestSessionRecoveryTokenDiffersPerRequest(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	req1 := httptest.NewRequest("POST", "/test", strings.NewReader("request 1"))
	ctx1, err := serverIdentity.EncryptRequestWithContext(req1)
	require.NoError(t, err)

	req2 := httptest.NewRequest("POST", "/test", strings.NewReader("request 2"))
	ctx2, err := serverIdentity.EncryptRequestWithContext(req2)
	require.NoError(t, err)

	token1, err := ExtractSessionRecoveryToken(ctx1)
	require.NoError(t, err)
	token2, err := ExtractSessionRecoveryToken(ctx2)
	require.NoError(t, err)

	assert.NotEqual(t, token1.ExportedSecret, token2.ExportedSecret,
		"Different requests must produce different exported secrets")
	assert.NotEqual(t, token1.RequestEnc, token2.RequestEnc,
		"Different requests must produce different requestEnc values")
}

func TestSessionRecoveryTokenDoesNotMutateContext(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/test", strings.NewReader("body"))
	reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
	require.NoError(t, err)

	token, err := ExtractSessionRecoveryToken(reqCtx)
	require.NoError(t, err)

	// Mutate the token's slices — the context should be unaffected
	token.RequestEnc[0] ^= 0xFF
	token.ExportedSecret[0] ^= 0xFF

	token2, err := ExtractSessionRecoveryToken(reqCtx)
	require.NoError(t, err)
	assert.NotEqual(t, token.RequestEnc[0], token2.RequestEnc[0],
		"Mutating token must not affect the original context")
}

func TestDecryptResponseWithTokenSingleChunk(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	responseData := "response from server"

	// Client encrypts request
	req := httptest.NewRequest("POST", "/test", strings.NewReader("request"))
	reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
	require.NoError(t, err)

	token, err := ExtractSessionRecoveryToken(reqCtx)
	require.NoError(t, err)

	// Server decrypts and responds
	respCtx, err := serverIdentity.DecryptRequestWithContext(req)
	require.NoError(t, err)
	io.ReadAll(req.Body)

	w := httptest.NewRecorder()
	writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
	require.NoError(t, err)
	writer.Write([]byte(responseData))
	writer.Flush()

	// Decrypt using only the token
	resp := &http.Response{
		Header: w.Header(),
		Body:   io.NopCloser(bytes.NewReader(w.Body.Bytes())),
	}

	err = DecryptResponseWithToken(resp, token)
	require.NoError(t, err)

	decrypted, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, responseData, string(decrypted))
}

func TestDecryptResponseWithTokenMultiChunk(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	// Client encrypts request
	req := httptest.NewRequest("POST", "/test", strings.NewReader("request"))
	reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
	require.NoError(t, err)

	token, err := ExtractSessionRecoveryToken(reqCtx)
	require.NoError(t, err)

	// Server decrypts and responds with multiple chunks
	respCtx, err := serverIdentity.DecryptRequestWithContext(req)
	require.NoError(t, err)
	io.ReadAll(req.Body)

	w := httptest.NewRecorder()
	writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
	require.NoError(t, err)
	writer.Write([]byte("chunk1"))
	writer.Write([]byte("chunk2"))
	writer.Write([]byte("chunk3"))
	writer.Flush()

	resp := &http.Response{
		Header: w.Header(),
		Body:   io.NopCloser(bytes.NewReader(w.Body.Bytes())),
	}

	err = DecryptResponseWithToken(resp, token)
	require.NoError(t, err)

	decrypted, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "chunk1chunk2chunk3", string(decrypted))
}

func TestDecryptResponseWithTokenEquivalentToContextPath(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	responseData := "identical-response"

	// First: encrypt request and extract token
	req := httptest.NewRequest("POST", "/test", strings.NewReader("request"))
	reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
	require.NoError(t, err)

	token, err := ExtractSessionRecoveryToken(reqCtx)
	require.NoError(t, err)

	// Server decrypts and builds response
	respCtx, err := serverIdentity.DecryptRequestWithContext(req)
	require.NoError(t, err)
	io.ReadAll(req.Body)

	w := httptest.NewRecorder()
	writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
	require.NoError(t, err)
	writer.Write([]byte(responseData))
	writer.Flush()

	// Decrypt via context path (DecryptResponse delegates to token internally)
	resp1 := &http.Response{
		Header: w.Header(),
		Body:   io.NopCloser(bytes.NewReader(w.Body.Bytes())),
	}
	err = reqCtx.DecryptResponse(resp1)
	require.NoError(t, err)
	text1, err := io.ReadAll(resp1.Body)
	require.NoError(t, err)

	// Decrypt via token path
	resp2 := &http.Response{
		Header: w.Header(),
		Body:   io.NopCloser(bytes.NewReader(w.Body.Bytes())),
	}
	err = DecryptResponseWithToken(resp2, token)
	require.NoError(t, err)
	text2, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)

	assert.Equal(t, string(text1), string(text2))
	assert.Equal(t, responseData, string(text1))
}

func TestDecryptResponseWithTokenErrors(t *testing.T) {
	t.Run("nil token returns error", func(t *testing.T) {
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(strings.NewReader("")),
		}
		resp.Header.Set(protocol.ResponseNonceHeader, hex.EncodeToString(make([]byte, 32)))

		err := DecryptResponseWithToken(resp, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token is nil")
	})

	t.Run("missing response nonce header returns error", func(t *testing.T) {
		token := &SessionRecoveryToken{
			ExportedSecret: make([]byte, 32),
			RequestEnc:     make([]byte, 32),
		}
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(strings.NewReader("")),
		}

		err := DecryptResponseWithToken(resp, token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), protocol.ResponseNonceHeader)
	})

	t.Run("invalid hex in response nonce returns error", func(t *testing.T) {
		token := &SessionRecoveryToken{
			ExportedSecret: make([]byte, 32),
			RequestEnc:     make([]byte, 32),
		}
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(strings.NewReader("")),
		}
		resp.Header.Set(protocol.ResponseNonceHeader, "not-valid-hex!")

		err := DecryptResponseWithToken(resp, token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid response nonce")
	})

	t.Run("wrong length response nonce returns error", func(t *testing.T) {
		token := &SessionRecoveryToken{
			ExportedSecret: make([]byte, 32),
			RequestEnc:     make([]byte, 32),
		}
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(strings.NewReader("")),
		}
		resp.Header.Set(protocol.ResponseNonceHeader, "deadbeef")

		err := DecryptResponseWithToken(resp, token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid response nonce length")
	})

	t.Run("wrong token fails decryption on read", func(t *testing.T) {
		serverIdentity, err := NewIdentity()
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/test", strings.NewReader("request"))
		_, err = serverIdentity.EncryptRequestWithContext(req)
		require.NoError(t, err)

		respCtx, err := serverIdentity.DecryptRequestWithContext(req)
		require.NoError(t, err)
		io.ReadAll(req.Body)

		w := httptest.NewRecorder()
		writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
		require.NoError(t, err)
		writer.Write([]byte("secret"))
		writer.Flush()

		badToken := &SessionRecoveryToken{
			ExportedSecret: make([]byte, 32),
			RequestEnc:     make([]byte, 32),
		}

		resp := &http.Response{
			Header: w.Header(),
			Body:   io.NopCloser(bytes.NewReader(w.Body.Bytes())),
		}

		err = DecryptResponseWithToken(resp, badToken)
		require.NoError(t, err)

		_, err = io.ReadAll(resp.Body)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decrypt")
	})
}

func TestSessionRecoveryTokenJSONRoundTrip(t *testing.T) {
	serverIdentity, err := NewIdentity()
	require.NoError(t, err)

	responseData := "recovered after serialization"

	req := httptest.NewRequest("POST", "/test", strings.NewReader("request"))
	reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
	require.NoError(t, err)

	originalToken, err := ExtractSessionRecoveryToken(reqCtx)
	require.NoError(t, err)

	// Serialize to JSON and back
	jsonBytes, err := json.Marshal(originalToken)
	require.NoError(t, err)

	// Verify the JSON contains hex strings, not base64
	var raw map[string]any
	err = json.Unmarshal(jsonBytes, &raw)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(originalToken.ExportedSecret), raw["exportedSecret"])
	assert.Equal(t, hex.EncodeToString(originalToken.RequestEnc), raw["requestEnc"])

	var restoredToken SessionRecoveryToken
	err = json.Unmarshal(jsonBytes, &restoredToken)
	require.NoError(t, err)

	assert.Equal(t, originalToken.ExportedSecret, restoredToken.ExportedSecret)
	assert.Equal(t, originalToken.RequestEnc, restoredToken.RequestEnc)

	// Server decrypts and responds
	respCtx, err := serverIdentity.DecryptRequestWithContext(req)
	require.NoError(t, err)
	io.ReadAll(req.Body)

	w := httptest.NewRecorder()
	writer, err := serverIdentity.SetupDerivedResponseEncryption(w, respCtx)
	require.NoError(t, err)
	writer.Write([]byte(responseData))
	writer.Flush()

	// Decrypt with the deserialized token
	resp := &http.Response{
		Header: w.Header(),
		Body:   io.NopCloser(bytes.NewReader(w.Body.Bytes())),
	}

	err = DecryptResponseWithToken(resp, &restoredToken)
	require.NoError(t, err)

	decrypted, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, responseData, string(decrypted))
}

func TestResponseDecryptionInteropVector(t *testing.T) {
	vectorJSON, err := os.ReadFile("../test-vectors/response-decryption.json")
	require.NoError(t, err)

	var vector struct {
		ExportedSecret    string `json:"exportedSecret"`
		RequestEnc        string `json:"requestEnc"`
		ResponseNonce     string `json:"responseNonce"`
		Plaintext         string `json:"plaintext"`
		EncryptedResponse string `json:"encryptedResponse"`
	}
	require.NoError(t, json.Unmarshal(vectorJSON, &vector))

	exportedSecret, _ := hex.DecodeString(vector.ExportedSecret)
	requestEnc, _ := hex.DecodeString(vector.RequestEnc)
	responseNonce, _ := hex.DecodeString(vector.ResponseNonce)
	expectedPlaintext, _ := hex.DecodeString(vector.Plaintext)
	encryptedResponse, _ := hex.DecodeString(vector.EncryptedResponse)

	km, err := DeriveResponseKeys(exportedSecret, requestEnc, responseNonce)
	require.NoError(t, err)

	aead, err := km.NewResponseAEAD()
	require.NoError(t, err)

	// Parse chunked framing: LEN (4 bytes) || ciphertext
	chunkLen := int(encryptedResponse[0])<<24 | int(encryptedResponse[1])<<16 |
		int(encryptedResponse[2])<<8 | int(encryptedResponse[3])
	ciphertext := encryptedResponse[4 : 4+chunkLen]

	decrypted, err := aead.Open(ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, expectedPlaintext, decrypted)
}

func TestSessionRecoveryTokenInterop(t *testing.T) {
	vectorJSON, err := os.ReadFile("../test-vectors/session-recovery-token.json")
	require.NoError(t, err)

	var token SessionRecoveryToken
	err = json.Unmarshal(vectorJSON, &token)
	require.NoError(t, err)

	// Verify deserialized byte lengths
	assert.Len(t, token.ExportedSecret, 32, "exportedSecret must be 32 bytes")
	assert.Len(t, token.RequestEnc, 32, "requestEnc must be 32 bytes")

	// Verify expected byte values from the hex in the fixture
	assert.Equal(t, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		hex.EncodeToString(token.ExportedSecret))
	assert.Equal(t, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		hex.EncodeToString(token.RequestEnc))

	// Re-serialize and verify it produces identical JSON
	reserializedBytes, err := json.Marshal(&token)
	require.NoError(t, err)

	var original map[string]any
	var reserialized map[string]any
	require.NoError(t, json.Unmarshal(vectorJSON, &original))
	require.NoError(t, json.Unmarshal(reserializedBytes, &reserialized))
	assert.Equal(t, original, reserialized)
}
