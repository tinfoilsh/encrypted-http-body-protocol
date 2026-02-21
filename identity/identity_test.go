package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// requireIdentitiesEqual asserts that two identities have the same keys and HPKE parameters.
func requireIdentitiesEqual(t *testing.T, expected, actual *Identity) {
	t.Helper()
	assert.Equal(t, expected.pk.Bytes(), actual.pk.Bytes())
	expectedSK, err := expected.sk.Bytes()
	require.NoError(t, err)
	actualSK, err := actual.sk.Bytes()
	require.NoError(t, err)
	assert.Equal(t, expectedSK, actualSK)
	assert.Equal(t, expected.kem.ID(), actual.kem.ID())
	assert.Equal(t, expected.kdf.ID(), actual.kdf.ID())
	assert.Equal(t, expected.aead.ID(), actual.aead.ID())
}

func TestIdentityExportImport(t *testing.T) {
	// Create a new identity
	original, err := NewIdentity()
	assert.NoError(t, err)

	// Export the identity
	exported, err := original.Export()
	assert.NoError(t, err)

	// Import the identity
	imported, err := Import(exported)
	assert.NoError(t, err)

	// Compare
	requireIdentitiesEqual(t, original, imported)
}

func TestNewIdentity(t *testing.T) {
	identity, err := NewIdentity()
	require.NoError(t, err)
	require.NotNil(t, identity)

	// Verify the identity has valid components
	assert.NotNil(t, identity.pk)
	assert.NotNil(t, identity.sk)
	assert.NotNil(t, identity.kem)
	assert.NotNil(t, identity.kdf)
	assert.NotNil(t, identity.aead)

	// Verify suite parameters (DHKEM(X25519) = 0x0020, HKDF-SHA256 = 0x0001, AES-256-GCM = 0x0002)
	assert.Equal(t, uint16(0x0020), identity.kem.ID())
	assert.Equal(t, uint16(0x0001), identity.kdf.ID())
	assert.Equal(t, uint16(0x0002), identity.aead.ID())
}

func TestIdentityMethods(t *testing.T) {
	identity, err := NewIdentity()
	require.NoError(t, err)

	// Test PublicKey method
	pk := identity.PublicKey()
	assert.NotNil(t, pk)
	assert.Equal(t, identity.pk.Bytes(), pk.Bytes())

	// Test PrivateKey method
	sk := identity.PrivateKey()
	assert.NotNil(t, sk)

	// Test KEM/KDF/AEAD methods
	kem := identity.KEM()
	assert.NotNil(t, kem)
	kdf := identity.KDF()
	assert.NotNil(t, kdf)
	aead := identity.AEAD()
	assert.NotNil(t, aead)
}

func TestMarshalPublicKey(t *testing.T) {
	identity, err := NewIdentity()
	require.NoError(t, err)

	pkBytes := identity.MarshalPublicKey()
	assert.NotEmpty(t, pkBytes)
	assert.Equal(t, 32, len(pkBytes)) // X25519 public key size

	// Verify we can unmarshal it back
	pk, err := identity.KEM().NewPublicKey(pkBytes)
	assert.NoError(t, err)
	assert.Equal(t, identity.pk.Bytes(), pk.Bytes())
}

func TestMarshalConfig(t *testing.T) {
	identity, err := NewIdentity()
	require.NoError(t, err)

	config, err := identity.MarshalConfig()
	require.NoError(t, err)
	assert.NotEmpty(t, config)

	// Verify we can unmarshal the config
	parsedIdentity, err := UnmarshalPublicConfig(config)
	require.NoError(t, err)
	assert.NotNil(t, parsedIdentity)
	assert.Equal(t, identity.pk.Bytes(), parsedIdentity.pk.Bytes())
	assert.Equal(t, identity.kem.ID(), parsedIdentity.kem.ID())
	assert.Equal(t, identity.kdf.ID(), parsedIdentity.kdf.ID())
	assert.Equal(t, identity.aead.ID(), parsedIdentity.aead.ID())
	assert.Nil(t, parsedIdentity.sk) // public key only
}

func TestConfigHandler(t *testing.T) {
	identity, err := NewIdentity()
	require.NoError(t, err)

	// Create a test request
	req := httptest.NewRequest("GET", protocol.KeysPath, nil)
	w := httptest.NewRecorder()

	// Call the handler
	identity.ConfigHandler(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, protocol.KeysMediaType, w.Header().Get("Content-Type"))
	assert.NotEmpty(t, w.Body.Bytes())

	// Verify we can parse the response
	_, err = UnmarshalPublicConfig(w.Body.Bytes())
	assert.NoError(t, err)
}

func TestUnmarshalPublicConfig(t *testing.T) {
	identity, err := NewIdentity()
	require.NoError(t, err)

	config, err := identity.MarshalConfig()
	require.NoError(t, err)

	parsedIdentity, err := UnmarshalPublicConfig(config)
	require.NoError(t, err)

	// Verify parsed identity
	assert.Equal(t, identity.pk.Bytes(), parsedIdentity.pk.Bytes())
	assert.Equal(t, identity.kem.ID(), parsedIdentity.kem.ID())
	assert.Equal(t, identity.kdf.ID(), parsedIdentity.kdf.ID())
	assert.Equal(t, identity.aead.ID(), parsedIdentity.aead.ID())
	assert.Nil(t, parsedIdentity.sk) // should be nil for public key only
}

func TestExportImportErrorCases(t *testing.T) {
	// Test Import with invalid JSON
	_, err := Import([]byte("invalid json"))
	assert.Error(t, err)

	// Test Import with empty data
	_, err = Import([]byte(""))
	assert.Error(t, err)

	// Test Import with malformed identity data
	malformedData := IdentityStore{
		PublicKey: []byte("invalid"),
		SecretKey: []byte("invalid"),
		KEM:       0x0020, // DHKEM(X25519, HKDF-SHA256)
		KDF:       0x0001, // HKDF-SHA256
		AEAD:      0x0002, // AES-256-GCM
	}
	malformedJSON, err := json.Marshal(malformedData)
	require.NoError(t, err)
	_, err = Import(malformedJSON)
	assert.Error(t, err)
}

func TestFromFile(t *testing.T) {
	tempDir := t.TempDir()
	identityFile := filepath.Join(tempDir, "test_identity.json")

	// Test creating new identity when file doesn't exist
	identity1, err := FromFile(identityFile)
	require.NoError(t, err)
	assert.NotNil(t, identity1)

	// Verify file was created
	_, err = os.Stat(identityFile)
	assert.NoError(t, err)

	// Test loading existing identity from file
	identity2, err := FromFile(identityFile)
	require.NoError(t, err)
	assert.NotNil(t, identity2)

	// Verify identities are the same
	requireIdentitiesEqual(t, identity1, identity2)
}

func TestUnmarshalPublicConfigErrorCases(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"insufficient data", []byte{0x00}},
		{"invalid KEM", []byte{0x00, 0xFF, 0xFF}},          // invalid KEM ID
		{"truncated public key", []byte{0x00, 0x00, 0x20}}, // valid KEM but no public key
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnmarshalPublicConfig(tc.data)
			assert.Error(t, err)
		})
	}
}

func TestIdentityStoreStruct(t *testing.T) {
	// Test that IdentityStore can be marshaled/unmarshaled
	identity, err := NewIdentity()
	require.NoError(t, err)

	exported, err := identity.Export()
	require.NoError(t, err)

	var store IdentityStore
	err = json.Unmarshal(exported, &store)
	require.NoError(t, err)

	// Verify all fields are populated
	assert.NotEmpty(t, store.PublicKey)
	assert.NotEmpty(t, store.SecretKey)
	assert.Equal(t, uint16(0x0020), store.KEM)
	assert.Equal(t, uint16(0x0001), store.KDF)
	assert.Equal(t, uint16(0x0002), store.AEAD)
}
