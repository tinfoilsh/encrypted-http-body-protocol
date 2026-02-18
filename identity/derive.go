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
	// HPKERequestInfo is the info string for HPKE sender/receiver setup.
	// This provides domain separation for the HPKE key schedule.
	HPKERequestInfo = "ehbp request"
	// ResponseKeyLabel is the info string for HKDF-Expand to derive the response key.
	ResponseKeyLabel = "key"
	// ResponseNonceLabel is the info string for HKDF-Expand to derive the response nonce.
	ResponseNonceLabel = "nonce"
	// ExportLabel is the context string for HPKE Export.
	ExportLabel = "ehbp response"
	// ExportLength is the length of the exported secret.
	// Nk (AEAD key size) = 32 bytes for AES-256-GCM.
	ExportLength = 32
	// ResponseNonceLength is the length of the random response nonce.
	// max(Nn, Nk) = max(12, 32) = 32 for AES-256-GCM.
	ResponseNonceLength = 32
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
// - responseNonce: The random nonce for this response (32 bytes, matching OHTTP's max(Nn, Nk))
//
// The derivation follows OHTTP (RFC 9458) exactly:
//
//	salt = concat(enc, response_nonce)
//	prk = Extract(salt, secret)
//	aead_key = Expand(prk, "key", Nk)
//	aead_nonce = Expand(prk, "nonce", Nn)
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

	// salt = concat(enc, response_nonce)
	salt := make([]byte, len(requestEnc)+len(responseNonce))
	copy(salt, requestEnc)
	copy(salt[len(requestEnc):], responseNonce)

	// prk = Extract(salt, secret)
	prk := hkdf.Extract(sha256.New, exportedSecret, salt)

	// aead_key = Expand(prk, "key", Nk)
	keyReader := hkdf.Expand(sha256.New, prk, []byte(ResponseKeyLabel))
	key := make([]byte, AES256KeyLength)
	if _, err := io.ReadFull(keyReader, key); err != nil {
		return nil, fmt.Errorf("failed to derive response key: %w", err)
	}

	// aead_nonce = Expand(prk, "nonce", Nn)
	nonceReader := hkdf.Expand(sha256.New, prk, []byte(ResponseNonceLabel))
	nonceBase := make([]byte, AESGCMNonceLength)
	if _, err := io.ReadFull(nonceReader, nonceBase); err != nil {
		return nil, fmt.Errorf("failed to derive response nonce: %w", err)
	}

	return &ResponseKeyMaterial{
		Key:       key,
		NonceBase: nonceBase,
	}, nil
}

// ResponseAEAD provides authenticated encryption with automatic nonce management.
// It wraps cipher.AEAD and tracks the sequence number internally, computing
// unique nonces for each operation by XORing the sequence with the nonce base.
//
// This follows the pattern from OHTTP (RFC 9458) where nonces are derived as:
//
//	nonce = nonce_base XOR sequence_number (big-endian in last 8 bytes)
//
// The sequence number is automatically incremented after each Seal/Open operation,
// ensuring nonce uniqueness without requiring caller management.
type ResponseAEAD struct {
	aead      cipher.AEAD
	nonceBase []byte
	seq       uint64
}

// NewResponseAEAD creates an AES-256-GCM AEAD instance with automatic nonce management.
// The returned ResponseAEAD tracks sequence numbers internally and computes
// unique nonces for each Seal/Open operation.
func (km *ResponseKeyMaterial) NewResponseAEAD() (*ResponseAEAD, error) {
	block, err := aes.NewCipher(km.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	// Copy nonceBase to avoid sharing the underlying array
	nonceBase := make([]byte, len(km.NonceBase))
	copy(nonceBase, km.NonceBase)
	return &ResponseAEAD{
		aead:      aead,
		nonceBase: nonceBase,
		seq:       0,
	}, nil
}

// Seal encrypts plaintext with the given additional authenticated data.
// It automatically computes the nonce from the current sequence number
// and increments the sequence for the next operation.
func (r *ResponseAEAD) Seal(plaintext, aad []byte) []byte {
	nonce := r.computeNonce()
	r.seq++
	return r.aead.Seal(nil, nonce, plaintext, aad)
}

// Open decrypts ciphertext with the given additional authenticated data.
// It automatically computes the nonce from the current sequence number
// and increments the sequence for the next operation.
// Returns an error if authentication fails.
func (r *ResponseAEAD) Open(ciphertext, aad []byte) ([]byte, error) {
	nonce := r.computeNonce()
	r.seq++
	return r.aead.Open(nil, nonce, ciphertext, aad)
}

// OpenWithSeq decrypts ciphertext using a specific sequence number without
// affecting the internal sequence counter. This is primarily useful for testing.
// Following the pattern from OHTTP's open_seq() function.
func (r *ResponseAEAD) OpenWithSeq(seq uint64, ciphertext, aad []byte) ([]byte, error) {
	nonce := r.nonceForSeq(seq)
	return r.aead.Open(nil, nonce, ciphertext, aad)
}

// NonceForSeq returns the nonce that would be used for the given sequence number.
// This does not affect the internal sequence counter. Useful for testing.
func (r *ResponseAEAD) NonceForSeq(seq uint64) []byte {
	return r.nonceForSeq(seq)
}

// computeNonce computes the nonce for the current sequence number.
func (r *ResponseAEAD) computeNonce() []byte {
	return r.nonceForSeq(r.seq)
}

// nonceForSeq computes the nonce for a given sequence number.
// nonce = nonceBase XOR sequence_number (big-endian in the last 8 bytes)
func (r *ResponseAEAD) nonceForSeq(seq uint64) []byte {
	nonce := make([]byte, AESGCMNonceLength)
	copy(nonce, r.nonceBase)
	// XOR with sequence number in the last 8 bytes (big-endian)
	for i := range 8 {
		nonce[AESGCMNonceLength-1-i] ^= byte(seq >> (i * 8))
	}
	return nonce
}

// NonceSize returns the nonce size of the underlying AEAD.
func (r *ResponseAEAD) NonceSize() int {
	return r.aead.NonceSize()
}

// Overhead returns the maximum difference between plaintext and ciphertext lengths.
func (r *ResponseAEAD) Overhead() int {
	return r.aead.Overhead()
}

// Seq returns the current sequence number. Useful for testing.
func (r *ResponseAEAD) Seq() uint64 {
	return r.seq
}
