package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Opener is an interface for AEAD decryption with automatic nonce management
type Opener interface {
	Open(ct, aad []byte) ([]byte, error)
}

// exportedSealer wraps an AES-GCM cipher with automatic nonce management.
// Used for response encryption with keys derived from HPKE Export.
type exportedSealer struct {
	aead  cipher.AEAD
	nonce []byte
	seq   uint64
}

func newExportedSealer(key, baseNonce []byte) (*exportedSealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return &exportedSealer{
		aead:  aead,
		nonce: baseNonce,
		seq:   0,
	}, nil
}

func (s *exportedSealer) Seal(pt, aad []byte) ([]byte, error) {
	nonce := make([]byte, len(s.nonce))
	copy(nonce, s.nonce)
	// XOR sequence number into nonce (big-endian, from the right)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(s.seq >> (8 * i))
	}
	s.seq++
	return s.aead.Seal(nil, nonce, pt, aad), nil
}

// exportedOpener wraps an AES-GCM cipher for decryption with automatic nonce management.
// Used for response decryption with keys derived from HPKE Export.
type exportedOpener struct {
	aead  cipher.AEAD
	nonce []byte
	seq   uint64
}

func newExportedOpener(key, baseNonce []byte) (*exportedOpener, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return &exportedOpener{
		aead:  aead,
		nonce: baseNonce,
		seq:   0,
	}, nil
}

func (o *exportedOpener) Open(ct, aad []byte) ([]byte, error) {
	nonce := make([]byte, len(o.nonce))
	copy(nonce, o.nonce)
	// XOR sequence number into nonce (big-endian, from the right)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(o.seq >> (8 * i))
	}
	o.seq++
	return o.aead.Open(nil, nonce, ct, aad)
}
