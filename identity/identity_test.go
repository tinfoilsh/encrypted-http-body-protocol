package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

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
	original, err := NewIdentity()
	require.NoError(t, err)
	exported, err := original.Export()
	require.NoError(t, err)
	imported, err := Import(exported)
	require.NoError(t, err)
	requireIdentitiesEqual(t, original, imported)

	for _, bad := range []string{"invalid json", ""} {
		_, err = Import([]byte(bad))
		assert.Error(t, err)
	}
	malformed, err := json.Marshal(IdentityStore{PublicKey: []byte("invalid"), SecretKey: []byte("invalid"), KEM: 0x0020, KDF: 0x0001, AEAD: 0x0002})
	require.NoError(t, err)
	_, err = Import(malformed)
	assert.Error(t, err)
}

func TestFromFile(t *testing.T) {
	identityFile := filepath.Join(t.TempDir(), "test_identity.json")
	created, err := FromFile(identityFile)
	require.NoError(t, err)
	loaded, err := FromFile(identityFile)
	require.NoError(t, err)
	requireIdentitiesEqual(t, created, loaded)
}

func TestConfigHandler(t *testing.T) {
	id, err := NewIdentity()
	require.NoError(t, err)
	w := httptest.NewRecorder()
	id.ConfigHandler(w, httptest.NewRequest("GET", protocol.KeysPath, nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, protocol.KeysMediaType, w.Header().Get("Content-Type"))
	cfg, err := id.MarshalConfig()
	require.NoError(t, err)
	assert.Equal(t, cfg, w.Body.Bytes())
}
