package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

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
	assert.True(t, original.pk.Equal(imported.pk))
	assert.True(t, original.sk.Equal(imported.sk))
	assert.Equal(t, original.suite, imported.suite)
}

func TestNewIdentity(t *testing.T) {
	identity, err := NewIdentity()
	require.NoError(t, err)
	require.NotNil(t, identity)

	// Verify the identity has valid components
	assert.NotNil(t, identity.pk)
	assert.NotNil(t, identity.sk)
	assert.NotNil(t, identity.suite)

	// Verify suite parameters
	kemID, kdfID, aeadID := identity.suite.Params()
	assert.Equal(t, hpke.KEM_X25519_HKDF_SHA256, kemID)
	assert.Equal(t, hpke.KDF_HKDF_SHA256, kdfID)
	assert.Equal(t, hpke.AEAD_AES256GCM, aeadID)
}

func TestIdentityMethods(t *testing.T) {
	identity, err := NewIdentity()
	require.NoError(t, err)

	// Test PublicKey method
	pk := identity.PublicKey()
	assert.NotNil(t, pk)
	assert.True(t, identity.pk.Equal(pk))

	// Test PrivateKey method
	sk := identity.PrivateKey()
	assert.NotNil(t, sk)
	assert.True(t, identity.sk.Equal(sk))

	// Test Suite method
	suite := identity.Suite()
	assert.Equal(t, identity.suite, suite)

	// Test KEMScheme method
	kemScheme := identity.KEMScheme()
	assert.NotNil(t, kemScheme)
}

func TestMarshalPublicKey(t *testing.T) {
	identity, err := NewIdentity()
	require.NoError(t, err)

	pkBytes := identity.MarshalPublicKey()
	assert.NotEmpty(t, pkBytes)
	assert.Equal(t, 32, len(pkBytes)) // X25519 public key size

	// Verify we can unmarshal it back
	kemScheme := identity.KEMScheme()
	pk, err := kemScheme.UnmarshalBinaryPublicKey(pkBytes)
	assert.NoError(t, err)
	assert.True(t, identity.pk.Equal(pk))
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
	assert.True(t, identity.pk.Equal(parsedIdentity.pk))
	assert.Equal(t, identity.suite, parsedIdentity.suite)
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
	assert.True(t, identity.pk.Equal(parsedIdentity.pk))
	assert.Equal(t, identity.suite, parsedIdentity.suite)
	assert.Nil(t, parsedIdentity.sk) // should be nil for public key only

	// Test error cases
	_, err = UnmarshalPublicConfig([]byte{})
	assert.Error(t, err)

	_, err = UnmarshalPublicConfig([]byte("invalid"))
	assert.Error(t, err)
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
		KEM:       hpke.KEM_X25519_HKDF_SHA256,
		KDF:       hpke.KDF_HKDF_SHA256,
		AEAD:      hpke.AEAD_AES256GCM,
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
	assert.True(t, identity1.pk.Equal(identity2.pk))
	assert.True(t, identity1.sk.Equal(identity2.sk))
	assert.Equal(t, identity1.suite, identity2.suite)
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
	assert.Equal(t, hpke.KEM_X25519_HKDF_SHA256, store.KEM)
	assert.Equal(t, hpke.KDF_HKDF_SHA256, store.KDF)
	assert.Equal(t, hpke.AEAD_AES256GCM, store.AEAD)
}
