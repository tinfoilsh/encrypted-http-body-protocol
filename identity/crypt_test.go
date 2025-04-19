package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIdentityCrypt(t *testing.T) {
	alice, err := NewIdentity()
	assert.NoError(t, err)

	bob, err := NewIdentity()
	assert.NoError(t, err)

	// Alice encrypts a message for Bob
	aliceCiphertext := []byte("hello bob")
	aliceAAD := []byte("how are you")
	encap, ciphertext, err := alice.Encrypt(bob.MarshalPublicKey(), aliceCiphertext, aliceAAD)
	assert.NoError(t, err)

	// Bob decrypts the message
	plaintext, err := bob.Decrypt(encap, ciphertext, aliceAAD)
	assert.NoError(t, err)
	assert.Equal(t, aliceCiphertext, plaintext)

	// Bob encrypts a message for Alice
	bobCiphertext := []byte("hello alice")
	bobAAD := []byte("how are you")
	encap, ciphertext, err = bob.Encrypt(alice.MarshalPublicKey(), bobCiphertext, bobAAD)
	assert.NoError(t, err)

	// Alice decrypts the message
	plaintext, err = alice.Decrypt(encap, ciphertext, bobAAD)
	assert.NoError(t, err)
	assert.Equal(t, bobCiphertext, plaintext)

	// Can't decrypt a bad message
	_, err = alice.Decrypt(encap, []byte("malformed"), bobAAD)
	assert.Error(t, err)

	// Can't decrypted with bad AAD
	_, err = alice.Decrypt(encap, ciphertext, []byte("bad aad"))
	assert.Error(t, err)
}
