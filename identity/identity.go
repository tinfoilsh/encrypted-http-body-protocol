package identity

import (
	"encoding/json"
	"os"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	hpkekem "github.com/cloudflare/circl/kem"
)

var (
	suite     = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	k, _, _   = suite.Params()
	kemScheme = k.Scheme()
)

// Suite returns the HPKE suite
func Suite() hpke.Suite {
	return suite
}

// KEMScheme returns the KEM scheme
func KEMScheme() hpkekem.Scheme {
	return kemScheme
}

type Identity struct {
	pk hpkekem.PublicKey
	sk hpkekem.PrivateKey
}

// IdentityStore is a serializable representation of an Identity
type IdentityStore struct {
	PublicKey []byte
	SecretKey []byte
}

// NewIdentity generates a new key pair
func NewIdentity() (*Identity, error) {
	i := &Identity{}

	var err error
	i.pk, i.sk, err = kemScheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	return i, nil
}

// FromFile loads an identity from a file or creates a new one if it doesn't exist
func FromFile(filename string) (*Identity, error) {
	var i *Identity
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		i, err = NewIdentity()
		if err != nil {
			return nil, err
		}
		identityBytes, err := i.Export()
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filename, identityBytes, 0644); err != nil {
			return nil, err
		}
	} else {
		identityBytes, err := os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		i, err = Import(identityBytes)
		if err != nil {
			return nil, err
		}
	}
	return i, nil
}

// PublicKey returns the public key of an identity
func (i *Identity) PublicKey() kem.PublicKey {
	return i.pk
}

// PrivateKey returns the private key of an identity
func (i *Identity) PrivateKey() kem.PrivateKey {
	return i.sk
}

// MarshalPublicKey returns a binary representation of the public key
func (i *Identity) MarshalPublicKey() []byte {
	pkM, err := i.pk.MarshalBinary()
	if err != nil {
		panic("code error: invalid pk: " + err.Error())
	}
	return pkM
}

// Export returns a JSON representation of the identity
func (i *Identity) Export() ([]byte, error) {
	pkM, err := i.pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	skM, err := i.sk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(IdentityStore{
		PublicKey: pkM,
		SecretKey: skM,
	})
}

// Import restores an identity from a JSON representation
func Import(identityJSONBytes []byte) (*Identity, error) {
	var identityStore *IdentityStore
	if err := json.Unmarshal(identityJSONBytes, &identityStore); err != nil {
		return nil, err
	}

	var i Identity
	var err error
	i.pk, err = kemScheme.UnmarshalBinaryPublicKey(identityStore.PublicKey)
	if err != nil {
		return nil, err
	}
	i.sk, err = kemScheme.UnmarshalBinaryPrivateKey(identityStore.SecretKey)
	if err != nil {
		return nil, err
	}

	return &i, nil
}
