package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

	// Compare keys
	assert.True(t, original.pk.Equal(imported.pk))
	assert.True(t, original.sk.Equal(imported.sk))

	// Compare suite parameters
	originalKEM, originalKDF, originalAEAD := suite.Params()
	importedKEM, importedKDF, importedAEAD := suite.Params()
	assert.Equal(t, originalKEM, importedKEM)
	assert.Equal(t, originalKDF, importedKDF)
	assert.Equal(t, originalAEAD, importedAEAD)
}
