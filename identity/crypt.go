package identity

import (
	"crypto/rand"
)

// Encrypt the plaintext with the provided aad for the given public key
func (i *Identity) Encrypt(receipientPk, plaintext, aad []byte) ([]byte, []byte, error) {
	pk, err := kemScheme.UnmarshalBinaryPublicKey(receipientPk)
	if err != nil {
		return nil, nil, err
	}

	sender, err := suite.NewSender(pk, nil)
	if err != nil {
		return nil, nil, err
	}
	encap, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	return encap, ciphertext, nil
}

// Decrypt ciphertext with the provided info and aad
func (i *Identity) Decrypt(encap, ciphertext, aad []byte) ([]byte, error) {
	recv, err := suite.NewReceiver(i.sk, nil)
	if err != nil {
		return nil, err
	}
	opener, err := recv.Setup(encap)
	if err != nil {
		return nil, err
	}
	plaintext, err := opener.Open(ciphertext, aad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
