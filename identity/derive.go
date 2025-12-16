package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// ResponseKeyLabel is the info string for deriving the response encryption key
	ResponseKeyLabel = "ehbp response key"
	// ResponseIVLabel is the info string for deriving the response IV/nonce base
	ResponseIVLabel = "ehbp response iv"
	// ExportLabel is the context string for HPKE Export
	ExportLabel = "ehbp response"
	// ExportLength is the length of the exported secret (32 bytes for SHA-256)
	ExportLength = 32
	// ResponseNonceLength is the length of the random response nonce
	ResponseNonceLength = 12
	// AES256KeyLength is the length of an AES-256 key
	AES256KeyLength = 32
	// AESGCMNonceLength is the length of an AES-GCM nonce
	AESGCMNonceLength = 12
)

// ResponseKeyMaterial holds the derived key material for response encryption/decryption
type ResponseKeyMaterial struct {
	Key       []byte // 32 bytes for AES-256
	NonceBase []byte // 12 bytes, XORed with sequence number for each chunk
}

// DeriveResponseKeys derives the response encryption key and nonce base from:
// - exportedSecret: The secret exported from the HPKE context (32 bytes)
// - requestEnc: The encapsulated key from the request (32 bytes for X25519)
// - responseNonce: The random nonce for this response (12 bytes)
//
// The derivation follows the pattern from OHTTP (RFC 9458):
//
//	salt = request_enc || response_nonce
//	key = HKDF(exportedSecret, salt, "ehbp response key", 32)
//	iv = HKDF(exportedSecret, salt, "ehbp response iv", 12)
func DeriveResponseKeys(exportedSecret, requestEnc, responseNonce []byte) (*ResponseKeyMaterial, error) {
	if len(exportedSecret) != ExportLength {
		return nil, fmt.Errorf("exported secret must be %d bytes, got %d", ExportLength, len(exportedSecret))
	}
	if len(requestEnc) != 32 { // X25519 enc is 32 bytes
		return nil, fmt.Errorf("request enc must be 32 bytes, got %d", len(requestEnc))
	}
	if len(responseNonce) != ResponseNonceLength {
		return nil, fmt.Errorf("response nonce must be %d bytes, got %d", ResponseNonceLength, len(responseNonce))
	}

	// Construct salt: request_enc || response_nonce
	salt := make([]byte, len(requestEnc)+len(responseNonce))
	copy(salt, requestEnc)
	copy(salt[len(requestEnc):], responseNonce)

	// Derive the response key using HKDF with key label as info
	keyReader := hkdf.New(sha256.New, exportedSecret, salt, []byte(ResponseKeyLabel))
	key := make([]byte, AES256KeyLength)
	if _, err := io.ReadFull(keyReader, key); err != nil {
		return nil, fmt.Errorf("failed to derive response key: %w", err)
	}

	// Derive the nonce base using HKDF with IV label as info
	ivReader := hkdf.New(sha256.New, exportedSecret, salt, []byte(ResponseIVLabel))
	nonceBase := make([]byte, AESGCMNonceLength)
	if _, err := io.ReadFull(ivReader, nonceBase); err != nil {
		return nil, fmt.Errorf("failed to derive response nonce base: %w", err)
	}

	return &ResponseKeyMaterial{
		Key:       key,
		NonceBase: nonceBase,
	}, nil
}

// NewResponseAEAD creates an AES-256-GCM AEAD instance from the key material
func (km *ResponseKeyMaterial) NewResponseAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(km.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return aead, nil
}

// ComputeNonce computes the nonce for a given sequence number.
// nonce = nonceBase XOR sequence_number (big-endian in the last 8 bytes)
//
// This ensures each chunk gets a unique nonce while maintaining
// deterministic nonce generation for both sender and receiver.
func (km *ResponseKeyMaterial) ComputeNonce(seq uint64) []byte {
	nonce := make([]byte, AESGCMNonceLength)
	copy(nonce, km.NonceBase)

	// XOR with sequence number in the last 8 bytes (big-endian)
	for i := 0; i < 8; i++ {
		nonce[AESGCMNonceLength-1-i] ^= byte(seq >> (i * 8))
	}
	return nonce
}
