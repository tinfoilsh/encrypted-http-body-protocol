package identity

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
	"golang.org/x/crypto/cryptobyte"
)

type Identity struct {
	pk   hpke.PublicKey
	sk   hpke.PrivateKey
	kem  hpke.KEM
	kdf  hpke.KDF
	aead hpke.AEAD
}

func (i *Identity) KEM() hpke.KEM {
	return i.kem
}

func (i *Identity) KDF() hpke.KDF {
	return i.kdf
}

func (i *Identity) AEAD() hpke.AEAD {
	return i.aead
}

// IdentityStore is a serializable representation of an Identity
type IdentityStore struct {
	PublicKey []byte
	SecretKey []byte

	// HPKE suite parameters (stored as RFC 9180 identifiers)
	KEM  uint16
	KDF  uint16
	AEAD uint16
}

// NewIdentity generates a new key pair
func NewIdentity() (*Identity, error) {
	kem := hpke.DHKEM(ecdh.X25519())
	kdf := hpke.HKDFSHA256()
	aead := hpke.AES256GCM()

	sk, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}

	return &Identity{
		pk:   sk.PublicKey(),
		sk:   sk,
		kem:  kem,
		kdf:  kdf,
		aead: aead,
	}, nil
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
func (i *Identity) PublicKey() hpke.PublicKey {
	return i.pk
}

// PrivateKey returns the private key of an identity
func (i *Identity) PrivateKey() hpke.PrivateKey {
	return i.sk
}

// MarshalPublicKey returns a binary representation of the public key
func (i *Identity) MarshalPublicKey() []byte {
	return i.pk.Bytes()
}

// MarshalPublicKeyHex returns a hex string representation of the public key
func (i *Identity) MarshalPublicKeyHex() string {
	return hex.EncodeToString(i.MarshalPublicKey())
}

// MarshalConfig returns a binary representation of the identity compatible with RFC9458 application/ohttp-keys
func (i *Identity) MarshalConfig() ([]byte, error) {
	pkBytes := i.pk.Bytes()

	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(0) // Key ID
	b.AddUint16(i.kem.ID())
	b.AddBytes(pkBytes)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(i.kdf.ID())
		b.AddUint16(i.aead.ID())
	})

	return b.Bytes()
}

// ConfigHandler is an HTTP handler that returns the identity's configuration
func (i *Identity) ConfigHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", protocol.KeysMediaType)
	configs, err := i.MarshalConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(configs)
}

// kemPublicKeySize returns the public key size for a given KEM ID per RFC 9180.
func kemPublicKeySize(kemID uint16) (int, error) {
	switch kemID {
	case 0x0010: // DHKEM(P-256, HKDF-SHA256)
		return 65, nil
	case 0x0011: // DHKEM(P-384, HKDF-SHA384)
		return 97, nil
	case 0x0012: // DHKEM(P-521, HKDF-SHA512)
		return 133, nil
	case 0x0020: // DHKEM(X25519, HKDF-SHA256)
		return 32, nil
	case 0x0021: // DHKEM(X448, HKDF-SHA512)
		return 56, nil
	default:
		return 0, fmt.Errorf("unknown KEM ID: 0x%04x", kemID)
	}
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

	kem, err := hpke.NewKEM(kemID)
	if err != nil {
		return nil, fmt.Errorf("invalid KEM")
	}

	pkSize, err := kemPublicKeySize(kemID)
	if err != nil {
		return nil, fmt.Errorf("invalid KEM")
	}

	publicKeyBytes := make([]byte, pkSize)
	if !s.ReadBytes(&publicKeyBytes, pkSize) {
		return nil, fmt.Errorf("invalid config")
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return nil, fmt.Errorf("invalid config")
	}

	type cipherSuite struct {
		kdf  hpke.KDF
		aead hpke.AEAD
	}
	var suites []cipherSuite
	for !cipherSuites.Empty() {
		var kdfID uint16
		var aeadID uint16
		if !cipherSuites.ReadUint16(&kdfID) ||
			!cipherSuites.ReadUint16(&aeadID) {
			return nil, fmt.Errorf("invalid config")
		}

		kdf, err := hpke.NewKDF(kdfID)
		if err != nil {
			return nil, fmt.Errorf("invalid KDF")
		}
		aead, err := hpke.NewAEAD(aeadID)
		if err != nil {
			return nil, fmt.Errorf("invalid AEAD")
		}

		suites = append(suites, cipherSuite{kdf: kdf, aead: aead})
	}

	pk, err := kem.NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public key: %v", err)
	}

	if len(suites) == 0 {
		return nil, fmt.Errorf("no cipher suites found in config")
	}

	return &Identity{
		kem:  kem,
		kdf:  suites[0].kdf,
		aead: suites[0].aead,
		pk:   pk,
		sk:   nil, // public key only
	}, nil
}

// Export returns a JSON representation of the identity
func (i *Identity) Export() ([]byte, error) {
	pkBytes := i.pk.Bytes()
	skBytes, err := i.sk.Bytes()
	if err != nil {
		return nil, err
	}

	return json.Marshal(IdentityStore{
		PublicKey: pkBytes,
		SecretKey: skBytes,
		KEM:       i.kem.ID(),
		KDF:       i.kdf.ID(),
		AEAD:      i.aead.ID(),
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

	kem, err := hpke.NewKEM(identityStore.KEM)
	if err != nil {
		return nil, fmt.Errorf("invalid KEM: %w", err)
	}
	kdf, err := hpke.NewKDF(identityStore.KDF)
	if err != nil {
		return nil, fmt.Errorf("invalid KDF: %w", err)
	}
	aead, err := hpke.NewAEAD(identityStore.AEAD)
	if err != nil {
		return nil, fmt.Errorf("invalid AEAD: %w", err)
	}

	var i Identity
	i.kem = kem
	i.kdf = kdf
	i.aead = aead

	i.pk, err = kem.NewPublicKey(identityStore.PublicKey)
	if err != nil {
		return nil, err
	}
	i.sk, err = kem.NewPrivateKey(identityStore.SecretKey)
	if err != nil {
		return nil, err
	}

	return &i, nil
}
