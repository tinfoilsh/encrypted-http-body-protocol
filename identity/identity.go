package identity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/tinfoilsh/stransport/protocol"
	"golang.org/x/crypto/cryptobyte"
)

type Identity struct {
	pk    kem.PublicKey
	sk    kem.PrivateKey
	suite hpke.Suite
}

func (i *Identity) Suite() hpke.Suite {
	return i.suite
}

func (i *Identity) KEMScheme() kem.Scheme {
	kemID, _, _ := i.suite.Params()
	return kemID.Scheme()
}

// IdentityStore is a serializable representation of an Identity
type IdentityStore struct {
	PublicKey []byte
	SecretKey []byte

	// HPKE suite parameters
	KEM  hpke.KEM
	KDF  hpke.KDF
	AEAD hpke.AEAD
}

// NewIdentity generates a new key pair
func NewIdentity() (*Identity, error) {
	i := &Identity{
		suite: hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM),
	}

	kemID, _, _ := i.suite.Params()

	var err error
	i.pk, i.sk, err = kemID.Scheme().GenerateKeyPair()
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

// MarhsalConfig returns a binary representation of the identity compatible with RFC9458 application/ohttp-keys
func (i *Identity) MarshalConfig() ([]byte, error) {
	pkBytes, err := i.pk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %v", err)
	}

	kemID, kdfID, aeadID := i.suite.Params()

	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(0) // Key ID
	b.AddUint16(uint16(kemID))
	b.AddBytes(pkBytes)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(uint16(kdfID))
		b.AddUint16(uint16(aeadID))
	})

	return b.Bytes()
}

// ConfigHandler is a HTTP handler that returns the identity's configuration
func (i *Identity) ConfigHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", protocol.KeysMediaType)
	configs, err := i.MarshalConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(configs)
}

// UnmarshalPublicConfig unmarshals a keys config into an identity
//
// Per https://github.com/chris-wood/ohttp-go/blob/main/ohttp.go
func UnmarshalPublicConfig(data []byte) (*Identity, error) {
	s := cryptobyte.String(data)

	var id uint8
	var kemID uint16
	if !s.ReadUint8(&id) ||
		!s.ReadUint16(&kemID) {
		return nil, fmt.Errorf("invalid config")
	}

	kem := hpke.KEM(kemID)
	if !kem.IsValid() {
		return nil, fmt.Errorf("invalid KEM")
	}

	publicKeyBytes := make([]byte, kem.Scheme().PublicKeySize())
	if !s.ReadBytes(&publicKeyBytes, len(publicKeyBytes)) {
		return nil, fmt.Errorf("invalid config")
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return nil, fmt.Errorf("invalid config")
	}
	var suites []hpke.Suite
	for !cipherSuites.Empty() {
		var kdfID uint16
		var aeadID uint16
		if !cipherSuites.ReadUint16(&kdfID) ||
			!cipherSuites.ReadUint16(&aeadID) {
			return nil, fmt.Errorf("invalid config")
		}

		// Sanity check validity of the KDF and AEAD values
		kdf := hpke.KDF(kdfID)
		if !kdf.IsValid() {
			return nil, fmt.Errorf("invalid KDF")
		}
		aead := hpke.AEAD(aeadID)
		if !aead.IsValid() {
			return nil, fmt.Errorf("invalid AEAD")
		}

		suites = append(suites, hpke.NewSuite(kem, kdf, aead))
	}

	pk, err := kem.Scheme().UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public key: %v", err)
	}

	if len(suites) == 0 {
		return nil, fmt.Errorf("no cipher suites found in config")
	}

	return &Identity{
		suite: suites[0],
		pk:    pk,
		sk:    nil, // public key only
	}, nil
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

	kemID, kdfID, aeadID := i.suite.Params()

	return json.Marshal(IdentityStore{
		PublicKey: pkM,
		SecretKey: skM,
		KEM:       kemID,
		KDF:       kdfID,
		AEAD:      aeadID,
	})
}

// Import restores an identity from a JSON representation
func Import(identityJSONBytes []byte) (*Identity, error) {
	var identityStore *IdentityStore
	if err := json.Unmarshal(identityJSONBytes, &identityStore); err != nil {
		return nil, err
	}

	if identityStore.KEM == 0 || identityStore.KDF == 0 || identityStore.AEAD == 0 {
		return nil, fmt.Errorf("invalid identity HPKE configuration")
	}

	suite := hpke.NewSuite(identityStore.KEM, identityStore.KDF, identityStore.AEAD)

	var i Identity
	i.suite = suite
	var err error
	i.pk, err = i.KEMScheme().UnmarshalBinaryPublicKey(identityStore.PublicKey)
	if err != nil {
		return nil, err
	}
	i.sk, err = i.KEMScheme().UnmarshalBinaryPrivateKey(identityStore.SecretKey)
	if err != nil {
		return nil, err
	}

	return &i, nil
}
