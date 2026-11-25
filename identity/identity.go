package identity

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"

	core "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/EHBP"
	_dafny "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/dafny"
	"github.com/tinfoilsh/encrypted-http-body-protocol/internal/eventresidue"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

type Identity struct {
	pk   hpke.PublicKey
	sk   hpke.PrivateKey
	kem  hpke.KEM
	kdf  hpke.KDF
	aead hpke.AEAD
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

	// The scalar comes from the residue's RandomBytes; crypto/hpke only
	// clamps it and derives the public key.
	sk, err := kem.NewPrivateKey(eventresidue.RandomBytes(32))
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
	r := core.Companion_Default___.MarshalConfig(eventresidue.Seq(i.pk.Bytes()))
	if err := resultErr(r); err != nil {
		return nil, err
	}
	return eventresidue.Bytes(r.Dtor_value().(_dafny.Sequence)), nil
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

// resultErr is a core Result as a Go error: nil for Ok.
func resultErr(r core.Result) error {
	if r.Is_Err() {
		return eventresidue.Error(r.Dtor_code(), eventresidue.String(r.Dtor_message()), nil)
	}
	return nil
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
		return nil, protocol.Errorf(protocol.InvalidKeyConfig, "invalid identity HPKE configuration")
	}

	kem, err := hpke.NewKEM(identityStore.KEM)
	if err != nil {
		return nil, protocol.Errorf(protocol.UnsupportedSuite, "invalid KEM: %w", err)
	}
	kdf, err := hpke.NewKDF(identityStore.KDF)
	if err != nil {
		return nil, protocol.Errorf(protocol.UnsupportedSuite, "invalid KDF: %w", err)
	}
	aead, err := hpke.NewAEAD(identityStore.AEAD)
	if err != nil {
		return nil, protocol.Errorf(protocol.UnsupportedSuite, "invalid AEAD: %w", err)
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
