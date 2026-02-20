package identity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestDeriveResponseKeys(t *testing.T) {
	// Test vectors with sequential byte values for reproducibility
	exportedSecret := make([]byte, 32)
	for i := range exportedSecret {
		exportedSecret[i] = byte(i)
	}

	requestEnc := make([]byte, 32)
	for i := range requestEnc {
		requestEnc[i] = byte(i + 32)
	}

	responseNonce := make([]byte, ResponseNonceLength)
	for i := range responseNonce {
		responseNonce[i] = byte(i + 64)
	}

	km, err := DeriveResponseKeys(exportedSecret, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("DeriveResponseKeys failed: %v", err)
	}

	// Verify key length
	if len(km.Key) != AES256KeyLength {
		t.Errorf("Expected key length %d, got %d", AES256KeyLength, len(km.Key))
	}

	// Verify nonce base length
	if len(km.NonceBase) != AESGCMNonceLength {
		t.Errorf("Expected nonce base length %d, got %d", AESGCMNonceLength, len(km.NonceBase))
	}

	// Verify determinism: same inputs should produce same outputs
	km2, err := DeriveResponseKeys(exportedSecret, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("Second DeriveResponseKeys failed: %v", err)
	}
	if !bytes.Equal(km.Key, km2.Key) {
		t.Error("Key derivation is not deterministic")
	}
	if !bytes.Equal(km.NonceBase, km2.NonceBase) {
		t.Error("Nonce base derivation is not deterministic")
	}

	// Verify different inputs produce different outputs
	differentNonce := make([]byte, ResponseNonceLength)
	copy(differentNonce, responseNonce)
	differentNonce[0] ^= 0xFF

	km3, err := DeriveResponseKeys(exportedSecret, requestEnc, differentNonce)
	if err != nil {
		t.Fatalf("Third DeriveResponseKeys failed: %v", err)
	}
	if bytes.Equal(km.Key, km3.Key) {
		t.Error("Different nonces should produce different keys")
	}
	if bytes.Equal(km.NonceBase, km3.NonceBase) {
		t.Error("Different nonces should produce different nonce bases")
	}

	// Verify different request enc produces different keys
	differentEnc := make([]byte, 32)
	copy(differentEnc, requestEnc)
	differentEnc[0] ^= 0xFF

	km4, err := DeriveResponseKeys(exportedSecret, differentEnc, responseNonce)
	if err != nil {
		t.Fatalf("Fourth DeriveResponseKeys failed: %v", err)
	}
	if bytes.Equal(km.Key, km4.Key) {
		t.Error("Different request enc should produce different keys")
	}

	// Verify different exported secret produces different keys
	differentSecret := make([]byte, 32)
	copy(differentSecret, exportedSecret)
	differentSecret[0] ^= 0xFF

	km5, err := DeriveResponseKeys(differentSecret, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("Fifth DeriveResponseKeys failed: %v", err)
	}
	if bytes.Equal(km.Key, km5.Key) {
		t.Error("Different exported secret should produce different keys")
	}
}

func TestNonceComputation(t *testing.T) {
	// Create a ResponseAEAD with a known nonce base
	km := &ResponseKeyMaterial{
		Key:       make([]byte, 32), // Valid AES-256 key
		NonceBase: make([]byte, 12),
	}
	for i := range km.NonceBase {
		km.NonceBase[i] = 0xFF
	}

	aead, err := km.NewResponseAEAD()
	if err != nil {
		t.Fatalf("NewResponseAEAD failed: %v", err)
	}

	// Sequence 0 should return the base nonce
	nonce0 := aead.NonceForSeq(0)
	if !bytes.Equal(nonce0, km.NonceBase) {
		t.Error("Sequence 0 should return base nonce")
	}

	// Sequence 1 should differ in the last byte
	nonce1 := aead.NonceForSeq(1)
	if nonce1[11] != 0xFE { // 0xFF XOR 0x01
		t.Errorf("Expected last byte to be 0xFE, got 0x%02X", nonce1[11])
	}

	// Verify first 4 bytes are unchanged for small sequence numbers
	for i := range 4 {
		if nonce1[i] != 0xFF {
			t.Errorf("Byte %d should be 0xFF for seq=1, got 0x%02X", i, nonce1[i])
		}
	}

	// Verify all nonces are unique for first 1000 sequences
	seen := make(map[string]bool)
	for i := range uint64(1000) {
		nonce := aead.NonceForSeq(i)
		key := string(nonce)
		if seen[key] {
			t.Errorf("Duplicate nonce at sequence %d", i)
		}
		seen[key] = true
	}
}

func TestNonceLargeSequence(t *testing.T) {
	km := &ResponseKeyMaterial{
		Key:       make([]byte, 32), // Valid AES-256 key
		NonceBase: make([]byte, 12),
	}

	aead, err := km.NewResponseAEAD()
	if err != nil {
		t.Fatalf("NewResponseAEAD failed: %v", err)
	}

	// Test with a large sequence number that uses multiple bytes
	seq := uint64(0x0102030405060708)
	nonce := aead.NonceForSeq(seq)

	// Verify XOR was applied correctly to last 8 bytes
	expected := []byte{0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(nonce, expected) {
		t.Errorf("Large sequence nonce incorrect.\nExpected: %x\nGot:      %x", expected, nonce)
	}
}

func TestDeriveResponseKeysValidation(t *testing.T) {
	validSecret := make([]byte, 32)
	validEnc := make([]byte, 32)
	validNonce := make([]byte, ResponseNonceLength)

	// Test invalid secret length
	_, err := DeriveResponseKeys(make([]byte, 16), validEnc, validNonce)
	if err == nil {
		t.Error("Expected error for invalid secret length")
	}

	// Test invalid enc length
	_, err = DeriveResponseKeys(validSecret, make([]byte, 16), validNonce)
	if err == nil {
		t.Error("Expected error for invalid enc length")
	}

	// Test invalid nonce length
	_, err = DeriveResponseKeys(validSecret, validEnc, make([]byte, 8))
	if err == nil {
		t.Error("Expected error for invalid nonce length")
	}

	// Test empty inputs
	_, err = DeriveResponseKeys(nil, validEnc, validNonce)
	if err == nil {
		t.Error("Expected error for nil secret")
	}

	_, err = DeriveResponseKeys(validSecret, nil, validNonce)
	if err == nil {
		t.Error("Expected error for nil enc")
	}

	_, err = DeriveResponseKeys(validSecret, validEnc, nil)
	if err == nil {
		t.Error("Expected error for nil nonce")
	}
}

func TestNewResponseAEAD(t *testing.T) {
	exportedSecret := make([]byte, 32)
	requestEnc := make([]byte, 32)
	responseNonce := make([]byte, ResponseNonceLength)

	km, err := DeriveResponseKeys(exportedSecret, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("DeriveResponseKeys failed: %v", err)
	}

	aead, err := km.NewResponseAEAD()
	if err != nil {
		t.Fatalf("NewResponseAEAD failed: %v", err)
	}

	// Verify AEAD has correct properties
	if aead.NonceSize() != AESGCMNonceLength {
		t.Errorf("Expected nonce size %d, got %d", AESGCMNonceLength, aead.NonceSize())
	}

	// Verify overhead is 16 bytes (GCM tag)
	if aead.Overhead() != 16 {
		t.Errorf("Expected overhead 16, got %d", aead.Overhead())
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	exportedSecret := make([]byte, 32)
	requestEnc := make([]byte, 32)
	responseNonce := make([]byte, ResponseNonceLength)

	// Fill with non-zero values for a more realistic test
	for i := range exportedSecret {
		exportedSecret[i] = byte(i * 3)
	}
	for i := range requestEnc {
		requestEnc[i] = byte(i * 5)
	}
	for i := range responseNonce {
		responseNonce[i] = byte(i * 7)
	}

	// Use same derivation for both "server" and "client"
	serverKM, err := DeriveResponseKeys(exportedSecret, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("Server DeriveResponseKeys failed: %v", err)
	}

	clientKM, err := DeriveResponseKeys(exportedSecret, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("Client DeriveResponseKeys failed: %v", err)
	}

	serverAEAD, err := serverKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Server NewResponseAEAD failed: %v", err)
	}

	clientAEAD, err := clientKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Client NewResponseAEAD failed: %v", err)
	}

	// Server encrypts (sequence auto-increments internally)
	plaintext := []byte("Hello, this is a secret response!")
	ciphertext := serverAEAD.Seal(plaintext, nil)

	// Client decrypts (sequence auto-increments internally)
	decrypted, err := clientAEAD.Open(ciphertext, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestMultipleChunksRoundTrip(t *testing.T) {
	exportedSecret := make([]byte, 32)
	requestEnc := make([]byte, 32)
	responseNonce := make([]byte, ResponseNonceLength)

	km, err := DeriveResponseKeys(exportedSecret, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("DeriveResponseKeys failed: %v", err)
	}

	// Create separate AEAD instances for server and client
	// (both derived from the same key material)
	serverAEAD, err := km.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Server NewResponseAEAD failed: %v", err)
	}

	clientAEAD, err := km.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Client NewResponseAEAD failed: %v", err)
	}

	// Encrypt multiple chunks (sequence auto-increments: 0, 1, 2)
	chunks := [][]byte{
		[]byte("First chunk of data"),
		[]byte("Second chunk"),
		[]byte("Third and final chunk with more data"),
	}

	var ciphertexts [][]byte
	for _, chunk := range chunks {
		ct := serverAEAD.Seal(chunk, nil)
		ciphertexts = append(ciphertexts, ct)
	}

	// Verify server sequence is now 3
	if serverAEAD.Seq() != 3 {
		t.Errorf("Expected server sequence 3, got %d", serverAEAD.Seq())
	}

	// Decrypt all chunks (sequence auto-increments: 0, 1, 2)
	for i, ct := range ciphertexts {
		decrypted, err := clientAEAD.Open(ct, nil)
		if err != nil {
			t.Fatalf("Failed to decrypt chunk %d: %v", i, err)
		}
		if !bytes.Equal(decrypted, chunks[i]) {
			t.Errorf("Chunk %d mismatch.\nExpected: %s\nGot: %s", i, chunks[i], decrypted)
		}
	}

	// Verify client sequence is now 3
	if clientAEAD.Seq() != 3 {
		t.Errorf("Expected client sequence 3, got %d", clientAEAD.Seq())
	}
}

func TestWrongSequenceNumberFails(t *testing.T) {
	exportedSecret := make([]byte, 32)
	requestEnc := make([]byte, 32)
	responseNonce := make([]byte, ResponseNonceLength)

	km, err := DeriveResponseKeys(exportedSecret, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("DeriveResponseKeys failed: %v", err)
	}

	aead, err := km.NewResponseAEAD()
	if err != nil {
		t.Fatalf("NewResponseAEAD failed: %v", err)
	}

	// Encrypt with sequence 0 (auto-incremented)
	plaintext := []byte("Secret message")
	ciphertext := aead.Seal(plaintext, nil)

	// Try to decrypt with wrong sequence number using OpenWithSeq
	_, err = aead.OpenWithSeq(1, ciphertext, nil)
	if err == nil {
		t.Error("Decryption should fail with wrong sequence number")
	}

	// Verify correct sequence works
	_, err = aead.OpenWithSeq(0, ciphertext, nil)
	if err != nil {
		t.Errorf("Decryption should succeed with correct sequence number: %v", err)
	}
}

func TestDifferentKeysCannotDecrypt(t *testing.T) {
	// Server's key material
	serverSecret := make([]byte, 32)
	for i := range serverSecret {
		serverSecret[i] = byte(i)
	}

	requestEnc := make([]byte, 32)
	responseNonce := make([]byte, ResponseNonceLength)

	serverKM, err := DeriveResponseKeys(serverSecret, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("Server DeriveResponseKeys failed: %v", err)
	}

	serverAEAD, err := serverKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Server NewResponseAEAD failed: %v", err)
	}

	// Attacker's key material (different secret)
	attackerSecret := make([]byte, 32)
	for i := range attackerSecret {
		attackerSecret[i] = byte(i + 100) // Different values
	}

	attackerKM, err := DeriveResponseKeys(attackerSecret, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("Attacker DeriveResponseKeys failed: %v", err)
	}

	attackerAEAD, err := attackerKM.NewResponseAEAD()
	if err != nil {
		t.Fatalf("Attacker NewResponseAEAD failed: %v", err)
	}

	// Server encrypts (sequence auto-increments)
	plaintext := []byte("Secret response only for legitimate client")
	ciphertext := serverAEAD.Seal(plaintext, nil)

	// Attacker tries to decrypt with their keys (using sequence 0)
	_, err = attackerAEAD.Open(ciphertext, nil)
	if err == nil {
		t.Error("Attacker should not be able to decrypt with different keys")
	}
}

func TestDeriveInteropVector(t *testing.T) {
	vectorJSON, err := os.ReadFile("../test-vectors/derive.json")
	if err != nil {
		t.Fatalf("Failed to read vector file: %v", err)
	}

	var vector struct {
		ExportedSecret string `json:"exportedSecret"`
		RequestEnc     string `json:"requestEnc"`
		ResponseNonce  string `json:"responseNonce"`
		DerivedKey     string `json:"derivedKey"`
		DerivedNonce   string `json:"derivedNonceBase"`
	}
	if err := json.Unmarshal(vectorJSON, &vector); err != nil {
		t.Fatalf("Failed to parse vector JSON: %v", err)
	}

	exportedSecret, _ := hex.DecodeString(vector.ExportedSecret)
	requestEnc, _ := hex.DecodeString(vector.RequestEnc)
	responseNonce, _ := hex.DecodeString(vector.ResponseNonce)
	expectedKey, _ := hex.DecodeString(vector.DerivedKey)
	expectedNonce, _ := hex.DecodeString(vector.DerivedNonce)

	km, err := DeriveResponseKeys(exportedSecret, requestEnc, responseNonce)
	if err != nil {
		t.Fatalf("DeriveResponseKeys failed: %v", err)
	}

	if !bytes.Equal(km.Key, expectedKey) {
		t.Errorf("Key mismatch.\nExpected: %s\nGot:      %s", vector.DerivedKey, hex.EncodeToString(km.Key))
	}
	if !bytes.Equal(km.NonceBase, expectedNonce) {
		t.Errorf("NonceBase mismatch.\nExpected: %s\nGot:      %s", vector.DerivedNonce, hex.EncodeToString(km.NonceBase))
	}
}
