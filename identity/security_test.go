package identity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// =============================================================================
// Security Tests for EHBP v2
//
// These tests verify that the MitM vulnerability is fixed by testing:
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
	sender, err := clientIdentity.Suite().NewSender(serverIdentity.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	requestEnc, clientSealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to setup sender: %v", err)
	}

	// Server receives and decrypts (simulated by setting up receiver)
	receiver, err := serverIdentity.Suite().NewReceiver(serverIdentity.PrivateKey(), nil)
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}
	serverOpener, err := receiver.Setup(requestEnc)
	if err != nil {
		t.Fatalf("Failed to setup receiver: %v", err)
	}

	// Server creates response encryption context
	respCtx := &ResponseContext{
		opener:     serverOpener,
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
	clientExported := clientSealer.Export([]byte(ExportLabel), uint(ExportLength))
	clientKM, err := DeriveResponseKeys(clientExported, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("Client key derivation failed: %v", err)
	}

	// EVE tries to derive keys - she doesn't have the shared secret
	// She only has: requestEnc (public), responseNonce (public)
	// She does NOT have: the HPKE shared secret

	// Eve tries to create her own HPKE context to the server
	eveSender, err := eveIdentity.Suite().NewSender(serverIdentity.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Eve failed to create sender: %v", err)
	}
	_, eveSealer, err := eveSender.Setup(rand.Reader)
	if err != nil {
		t.Fatalf("Eve failed to setup sender: %v", err)
	}

	// Eve exports from HER context (wrong shared secret)
	eveExported := eveSealer.Export([]byte(ExportLabel), uint(ExportLength))
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
	sender, err := clientIdentity.Suite().NewSender(serverIdentity.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	requestEnc, clientSealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to setup sender: %v", err)
	}

	// Client's expected key derivation
	clientExported := clientSealer.Export([]byte(ExportLabel), uint(ExportLength))

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

	// Attacker encrypts a forged message
	forgedMessage := []byte("Malicious response from attacker - transfer $1M to Eve")
	nonce := attackerKM.ComputeNonce(0)
	forgedCiphertext := attackerAEAD.Seal(nil, nonce, forgedMessage, nil)

	// Client tries to decrypt with the real keys
	clientKM, err := DeriveResponseKeys(clientExported, requestEnc, forgedNonce)
	if err != nil {
		t.Fatalf("Client key derivation failed: %v", err)
	}
	clientAEAD, err := clientKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Client AEAD creation failed: %v", err)
	}
	clientNonce := clientKM.ComputeNonce(0)

	// Decryption MUST fail because keys don't match
	_, err = clientAEAD.Open(nil, clientNonce, forgedCiphertext, nil)
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
	sender, err := clientIdentity.Suite().NewSender(serverIdentity.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	originalEnc, clientSealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to setup sender: %v", err)
	}

	// Server decrypts with original enc (in real scenario, it would use modified enc
	// but that would fail decryption - here we test key derivation mismatch)
	receiver, err := serverIdentity.Suite().NewReceiver(serverIdentity.PrivateKey(), nil)
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}
	serverOpener, err := receiver.Setup(originalEnc)
	if err != nil {
		t.Fatalf("Failed to setup receiver: %v", err)
	}

	// Server creates response
	serverExported := serverOpener.Export([]byte(ExportLabel), uint(ExportLength))
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
	serverNonce := serverKM.ComputeNonce(0)
	ciphertext := serverAEAD.Seal(nil, serverNonce, plaintext, nil)

	// Simulate: Client has a MODIFIED enc (header was tampered)
	modifiedEnc := make([]byte, len(originalEnc))
	copy(modifiedEnc, originalEnc)
	modifiedEnc[0] ^= 0xFF // Flip some bits

	// Client derives keys with wrong enc
	clientExported := clientSealer.Export([]byte(ExportLabel), uint(ExportLength))
	clientKM, err := DeriveResponseKeys(clientExported, modifiedEnc, responseNonce)
	if err != nil {
		t.Fatalf("Client key derivation failed: %v", err)
	}
	clientAEAD, err := clientKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Client AEAD creation failed: %v", err)
	}
	clientNonce := clientKM.ComputeNonce(0)

	// Decryption MUST fail
	_, err = clientAEAD.Open(nil, clientNonce, ciphertext, nil)
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

	sender, err := clientIdentity.Suite().NewSender(serverIdentity.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	requestEnc, clientSealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to setup sender: %v", err)
	}

	receiver, err := serverIdentity.Suite().NewReceiver(serverIdentity.PrivateKey(), nil)
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}
	serverOpener, err := receiver.Setup(requestEnc)
	if err != nil {
		t.Fatalf("Failed to setup receiver: %v", err)
	}

	// Server creates response with specific nonce
	serverExported := serverOpener.Export([]byte(ExportLabel), uint(ExportLength))
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
	ciphertext := serverAEAD.Seal(nil, serverKM.ComputeNonce(0), plaintext, nil)

	// Client receives but with MODIFIED nonce (header tampered)
	modifiedNonce := make([]byte, ResponseNonceLength)
	copy(modifiedNonce, originalNonce)
	modifiedNonce[0] ^= 0xFF

	// Client derives keys with wrong nonce
	clientExported := clientSealer.Export([]byte(ExportLabel), uint(ExportLength))
	clientKM, err := DeriveResponseKeys(clientExported, requestEnc, modifiedNonce)
	if err != nil {
		t.Fatalf("Client key derivation failed: %v", err)
	}
	clientAEAD, err := clientKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Client AEAD creation failed: %v", err)
	}

	// Decryption MUST fail
	_, err = clientAEAD.Open(nil, clientKM.ComputeNonce(0), ciphertext, nil)
	if err == nil {
		t.Error("SECURITY FAILURE: Decryption succeeded with modified nonce!")
	} else {
		t.Log("SUCCESS: Modified nonce causes decryption failure")
	}
}

// TestOldClientPublicKeyHeaderIgnored verifies that even if someone
// sends the deprecated Ehbp-Client-Public-Key header, the v2 middleware
// ignores it and uses derived keys instead.
//
// This ensures backward compatibility headers don't introduce vulnerabilities.
func TestOldClientPublicKeyHeaderIgnored(t *testing.T) {
	serverIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create server identity: %v", err)
	}

	eveIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create Eve identity: %v", err)
	}

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		// Verify that server does NOT use the client public key header
		clientPubKeyHeader := r.Header.Get(protocol.ClientPublicKeyHeader)
		if clientPubKeyHeader != "" {
			t.Log("Old header present but should be ignored by v2 middleware")
		}
		w.Write([]byte("OK"))
	})

	wrappedHandler := serverIdentity.Middleware(false)(handler)

	// Create request with BOTH old and new headers
	// Eve tries to inject her public key via the old header
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set(protocol.ClientPublicKeyHeader, hex.EncodeToString(eveIdentity.MarshalPublicKey()))

	// Also need valid request enc for v2
	sender, err := eveIdentity.Suite().NewSender(serverIdentity.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	requestEnc, _, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to setup sender: %v", err)
	}
	req.Header.Set(protocol.EncapsulatedKeyHeader, hex.EncodeToString(requestEnc))

	recorder := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(recorder, req)

	// Request should succeed
	if recorder.Code != http.StatusOK {
		t.Errorf("Request failed with status %d: %s", recorder.Code, recorder.Body.String())
	}

	if !handlerCalled {
		t.Error("Handler was not called")
	}

	// Response should use derived keys (ResponseNonceHeader), NOT EncapsulatedKeyHeader
	responseNonce := recorder.Header().Get(protocol.ResponseNonceHeader)
	if responseNonce == "" {
		t.Error("Response missing ResponseNonceHeader - not using v2 protocol")
	}

	// The old EncapsulatedKeyHeader should NOT be in the response (v2 doesn't set it)
	oldEncapHeader := recorder.Header().Get(protocol.EncapsulatedKeyHeader)
	if oldEncapHeader != "" {
		t.Error("Response has EncapsulatedKeyHeader - should be using v2 ResponseNonceHeader instead")
	}

	t.Log("SUCCESS: Old ClientPublicKeyHeader is ignored, v2 protocol used")
}

// TestEndToEndSecureRoundTrip verifies the complete secure round-trip:
// Client encrypts -> Server decrypts -> Server encrypts response -> Client decrypts
// with proper key derivation at each step.
func TestEndToEndSecureRoundTrip(t *testing.T) {
	serverIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create server identity: %v", err)
	}

	clientIdentity, err := NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create client identity: %v", err)
	}

	secretResponse := "This is a secret response that only the legitimate client should see"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(secretResponse))
	})

	wrappedHandler := serverIdentity.Middleware(false)(handler)

	// Client creates request with v2 encryption
	req := httptest.NewRequest("GET", "/secret", nil)
	reqCtx, err := clientIdentity.EncryptRequestWithContext(req, serverIdentity.MarshalPublicKey())
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
	err = clientIdentity.DecryptResponseWithContext(resp, reqCtx)
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
