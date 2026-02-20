package identity

import (
	"bytes"
	"crypto/hpke"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// =============================================================================
// Security Tests for EHBP
//
// These tests verify that the MitM vulnerability is not present:
// 1. MitM cannot derive the correct response decryption keys
// 2. MitM cannot forge valid encrypted responses
// 3. Modified headers cause decryption failures
// 4. Old vulnerable headers are ignored
// =============================================================================

// TestMitMCannotReadResponse verifies that a man-in-the-middle cannot
// decrypt responses even if they intercept all headers.
//
// Attack scenario:
// - Eve intercepts the request from Alice to Server
// - Eve sees: requestEnc (public header), responseNonce (public header)
// - Eve does NOT have: the HPKE shared secret between Alice and Server
// - Eve cannot derive the response decryption keys
func TestMitMCannotReadResponse(t *testing.T) {
	// Setup identities
	serverIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create server identity: %v", err)
	}

	clientIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create client identity: %v", err)
	}

	eveIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create Eve identity: %v", err)
	}

	// Client (Alice) encrypts a request to server
	requestEnc, clientSender, err := hpke.NewSender(serverIdentity.PublicKey(), clientIdentity.KDF(), clientIdentity.AEAD(), []byte(HPKERequestInfo))
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}

	// Server receives and decrypts (simulated by setting up recipient)
	serverRecipient, err := hpke.NewRecipient(requestEnc, serverIdentity.PrivateKey(), serverIdentity.KDF(), serverIdentity.AEAD(), []byte(HPKERequestInfo))
	if err != nil {
		t.Fatalf("Failed to setup recipient: %v", err)
	}

	// Server creates response encryption context
	respCtx := &ResponseContext{
		recipient:  serverRecipient,
		RequestEnc: requestEnc,
	}

	recorder := httptest.NewRecorder()
	_, err = serverIdentity.SetupDerivedResponseEncryption(recorder, respCtx)
	if err != nil {
		t.Fatalf("Server setup failed: %v", err)
	}

	// Get response nonce (this is public, Eve can see it)
	responseNonceHex := recorder.Header().Get(protocol.ResponseNonceHeader)
	responseNonce, err := hex.DecodeString(responseNonceHex)
	if err != nil {
		t.Fatalf("Failed to decode response nonce: %v", err)
	}

	// CLIENT (Alice) can derive the correct keys
	clientExported, err := clientSender.Export(ExportLabel, ExportLength)
	if err != nil {
		t.Fatalf("Client export failed: %v", err)
	}
	clientKM, err := DeriveResponseKeys(clientExported, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("Client key derivation failed: %v", err)
	}

	// EVE tries to derive keys - she doesn't have the shared secret
	// She only has: requestEnc (public), responseNonce (public)
	// She does NOT have: the HPKE shared secret

	// Eve tries to create her own HPKE context to the server
	// Even with correct info, Eve's shared secret is different from Alice's
	_, eveSender, err := hpke.NewSender(serverIdentity.PublicKey(), eveIdentity.KDF(), eveIdentity.AEAD(), []byte(HPKERequestInfo))
	if err != nil {
		t.Fatalf("Eve failed to create sender: %v", err)
	}

	// Eve exports from HER context (wrong shared secret)
	eveExported, err := eveSender.Export(ExportLabel, ExportLength)
	if err != nil {
		t.Fatalf("Eve export failed: %v", err)
	}
	eveKM, err := DeriveResponseKeys(eveExported, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("Eve key derivation failed unexpectedly: %v", err)
	}

	// Verify Eve's keys are DIFFERENT from client's keys
	if bytes.Equal(clientKM.Key, eveKM.Key) {
		t.Error("SECURITY FAILURE: Eve derived the same key as client!")
	}
	if bytes.Equal(clientKM.NonceBase, eveKM.NonceBase) {
		t.Error("SECURITY FAILURE: Eve derived the same nonce base as client!")
	}

	t.Log("SUCCESS: MitM cannot derive correct response keys")
}

// TestMitMCannotForgeResponse verifies that a MitM cannot create valid
// encrypted responses that the client will accept.
//
// Attack scenario:
// - Eve intercepts request from Alice
// - Eve wants to send a fake response to Alice
// - Eve creates her own encrypted message
// - Alice's decryption MUST fail
func TestMitMCannotForgeResponse(t *testing.T) {
	serverIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create server identity: %v", err)
	}

	clientIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create client identity: %v", err)
	}

	// Client encrypts request
	requestEnc, clientSender, err := hpke.NewSender(serverIdentity.PublicKey(), clientIdentity.KDF(), clientIdentity.AEAD(), []byte(HPKERequestInfo))
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}

	// Client's expected key derivation
	clientExported, err := clientSender.Export(ExportLabel, ExportLength)
	if err != nil {
		t.Fatalf("Client export failed: %v", err)
	}

	// Attacker tries to forge a response
	// They can create any nonce they want
	forgedNonce := make([]byte, ResponseNonceLength)
	if _, err := rand.Read(forgedNonce); err != nil {
		t.Fatalf("Failed to generate forged nonce: %v", err)
	}

	// Attacker derives keys with their own secret (not the real shared secret)
	attackerSecret := make([]byte, ExportLength)
	if _, err := rand.Read(attackerSecret); err != nil {
		t.Fatalf("Failed to generate attacker secret: %v", err)
	}

	attackerKM, err := DeriveResponseKeys(attackerSecret, requestEnc, forgedNonce)
	if err != nil {
		t.Fatalf("Attacker key derivation failed: %v", err)
	}
	attackerAEAD, err := attackerKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Attacker AEAD creation failed: %v", err)
	}

	// Attacker encrypts a forged message (sequence auto-increments)
	forgedMessage := []byte("Malicious response from attacker - transfer $1M to Eve")
	forgedCiphertext := attackerAEAD.Seal(forgedMessage, nil)

	// Client tries to decrypt with the real keys
	clientKM, err := DeriveResponseKeys(clientExported, requestEnc, forgedNonce)
	if err != nil {
		t.Fatalf("Client key derivation failed: %v", err)
	}
	clientAEAD, err := clientKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Client AEAD creation failed: %v", err)
	}

	// Decryption MUST fail because keys don't match
	_, err = clientAEAD.Open(forgedCiphertext, nil)
	if err == nil {
		t.Error("SECURITY FAILURE: Forged response was accepted!")
	} else {
		t.Log("SUCCESS: Forged response rejected with error:", err)
	}
}

// TestModifiedRequestEncCausesFailure verifies that if a MitM modifies
// the Ehbp-Encapsulated-Key header in transit, decryption fails.
//
// Attack scenario:
// - Eve intercepts request, modifies the enc header
// - Server uses the modified enc
// - Client has the original enc
// - Key derivation produces different keys -> decryption fails
func TestModifiedRequestEncCausesFailure(t *testing.T) {
	serverIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create server identity: %v", err)
	}

	clientIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create client identity: %v", err)
	}

	// Original request encryption
	originalEnc, clientSender, err := hpke.NewSender(serverIdentity.PublicKey(), clientIdentity.KDF(), clientIdentity.AEAD(), []byte(HPKERequestInfo))
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}

	// Server decrypts with original enc (in real scenario, it would use modified enc
	// but that would fail decryption - here we test key derivation mismatch)
	serverRecipient, err := hpke.NewRecipient(originalEnc, serverIdentity.PrivateKey(), serverIdentity.KDF(), serverIdentity.AEAD(), []byte(HPKERequestInfo))
	if err != nil {
		t.Fatalf("Failed to setup recipient: %v", err)
	}

	// Server creates response
	serverExported, err := serverRecipient.Export(ExportLabel, ExportLength)
	if err != nil {
		t.Fatalf("Server export failed: %v", err)
	}
	responseNonce := make([]byte, ResponseNonceLength)
	if _, err := rand.Read(responseNonce); err != nil {
		t.Fatalf("Failed to generate response nonce: %v", err)
	}

	serverKM, err := DeriveResponseKeys(serverExported, originalEnc, responseNonce)
	if err != nil {
		t.Fatalf("Server key derivation failed: %v", err)
	}
	serverAEAD, err := serverKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Server AEAD creation failed: %v", err)
	}

	plaintext := []byte("Secret server response")
	ciphertext := serverAEAD.Seal(plaintext, nil)

	// Simulate: Client has a MODIFIED enc (header was tampered)
	modifiedEnc := make([]byte, len(originalEnc))
	copy(modifiedEnc, originalEnc)
	modifiedEnc[0] ^= 0xFF // Flip some bits

	// Client derives keys with wrong enc
	clientExported, err := clientSender.Export(ExportLabel, ExportLength)
	if err != nil {
		t.Fatalf("Client export failed: %v", err)
	}
	clientKM, err := DeriveResponseKeys(clientExported, modifiedEnc, responseNonce)
	if err != nil {
		t.Fatalf("Client key derivation failed: %v", err)
	}
	clientAEAD, err := clientKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Client AEAD creation failed: %v", err)
	}

	// Decryption MUST fail
	_, err = clientAEAD.Open(ciphertext, nil)
	if err == nil {
		t.Error("SECURITY FAILURE: Decryption succeeded with modified enc!")
	} else {
		t.Log("SUCCESS: Modified enc causes decryption failure")
	}
}

// TestModifiedNonceCausesFailure verifies that if a MitM modifies
// the Ehbp-Response-Nonce header, decryption fails.
func TestModifiedNonceCausesFailure(t *testing.T) {
	serverIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create server identity: %v", err)
	}

	clientIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create client identity: %v", err)
	}

	requestEnc, clientSender, err := hpke.NewSender(serverIdentity.PublicKey(), clientIdentity.KDF(), clientIdentity.AEAD(), []byte(HPKERequestInfo))
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}

	serverRecipient, err := hpke.NewRecipient(requestEnc, serverIdentity.PrivateKey(), serverIdentity.KDF(), serverIdentity.AEAD(), []byte(HPKERequestInfo))
	if err != nil {
		t.Fatalf("Failed to setup recipient: %v", err)
	}

	// Server creates response with specific nonce
	serverExported, err := serverRecipient.Export(ExportLabel, ExportLength)
	if err != nil {
		t.Fatalf("Server export failed: %v", err)
	}
	originalNonce := make([]byte, ResponseNonceLength)
	if _, err := rand.Read(originalNonce); err != nil {
		t.Fatalf("Failed to generate original nonce: %v", err)
	}

	serverKM, err := DeriveResponseKeys(serverExported, requestEnc, originalNonce)
	if err != nil {
		t.Fatalf("Server key derivation failed: %v", err)
	}
	serverAEAD, err := serverKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Server AEAD creation failed: %v", err)
	}

	plaintext := []byte("Secret server response")
	ciphertext := serverAEAD.Seal(plaintext, nil)

	// Client receives but with MODIFIED nonce (header tampered)
	modifiedNonce := make([]byte, ResponseNonceLength)
	copy(modifiedNonce, originalNonce)
	modifiedNonce[0] ^= 0xFF

	// Client derives keys with wrong nonce
	clientExported, err := clientSender.Export(ExportLabel, ExportLength)
	if err != nil {
		t.Fatalf("Client export failed: %v", err)
	}
	clientKM, err := DeriveResponseKeys(clientExported, requestEnc, modifiedNonce)
	if err != nil {
		t.Fatalf("Client key derivation failed: %v", err)
	}
	clientAEAD, err := clientKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Client AEAD creation failed: %v", err)
	}

	// Decryption MUST fail
	_, err = clientAEAD.Open(ciphertext, nil)
	if err == nil {
		t.Error("SECURITY FAILURE: Decryption succeeded with modified nonce!")
	} else {
		t.Log("SUCCESS: Modified nonce causes decryption failure")
	}
}

// TestEndToEndSecureRoundTrip verifies the complete secure round-trip:
// Client encrypts -> Server decrypts -> Server encrypts response -> Client decrypts
// with proper key derivation at each step.
func TestEndToEndSecureRoundTrip(t *testing.T) {
	serverIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create server identity: %v", err)
	}

	secretResponse := "This is a secret response that only the legitimate client should see"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(secretResponse))
	})

	wrappedHandler := serverIdentity.Middleware()(handler)

	// Client creates request with encryption to server's public key
	req := httptest.NewRequest("POST", "/secret", strings.NewReader("test body"))
	reqCtx, err := serverIdentity.EncryptRequestWithContext(req)
	if err != nil {
		t.Fatalf("Failed to encrypt request: %v", err)
	}

	recorder := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Request failed with status %d: %s", recorder.Code, recorder.Body.String())
	}

	// Create a fake response to decrypt
	resp := &http.Response{
		StatusCode: recorder.Code,
		Header:     recorder.Header(),
		Body:       &readCloserWrapper{bytes.NewReader(recorder.Body.Bytes())},
	}

	// Client decrypts response using the request context
	err = reqCtx.DecryptResponse(resp)
	if err != nil {
		t.Fatalf("Failed to decrypt response: %v", err)
	}

	// Read decrypted response
	decryptedBody := make([]byte, 1024)
	n, err := resp.Body.Read(decryptedBody)
	if err != nil && err.Error() != "EOF" {
		t.Fatalf("Failed to read decrypted response: %v", err)
	}

	if string(decryptedBody[:n]) != secretResponse {
		t.Errorf("Decrypted response mismatch.\nExpected: %s\nGot: %s", secretResponse, string(decryptedBody[:n]))
	}

	t.Log("SUCCESS: End-to-end secure round-trip completed")
}

// readCloserWrapper wraps a Reader to implement io.ReadCloser
type readCloserWrapper struct {
	*bytes.Reader
}

func (r *readCloserWrapper) Close() error {
	return nil
}
