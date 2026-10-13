package reconstruct

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nsuiteio/nsuite-mpc-key-export/internal/testfixture"
	"github.com/nsuiteio/nsuite-mpc-key-export/utility/strutil"
)

func TestLoadFromZip(t *testing.T) {
	ctx := context.Background()

	prv, err := testfixture.RSAPrivateKey()
	require.NoError(t, err)

	ecdsaHexes, eddsaHexes, err := testfixture.ShareHexes()
	require.NoError(t, err)
	assert.Equal(t, len(ecdsaHexes), len(eddsaHexes))
	assert.Len(t, ecdsaHexes, 3)

	zipPath := filepath.Join(t.TempDir(), "keyshares.zip")
	require.NoError(t, testfixture.WriteKeyShareZip(zipPath))

	// Now load and decrypt using the private key and verify
	ecdsaShares, eddsaShares, err := LoadFromZip(ctx, prv, zipPath)
	require.NoError(t, err)

	// Integrity check: reconstruct with threshold 3
	// should match known expected keys
	if assert.Equal(t, len(ecdsaHexes), len(ecdsaShares)) {
		prvECDSA, err := ReconstructECDSA(ctx, 3, ecdsaShares)
		require.NoError(t, err)
		got := strutil.ToHex(prvECDSA.Serialize())
		assert.Equal(t, testfixture.SamplePrivateKeyECDSAHex, got)
	}
	if assert.Equal(t, len(eddsaHexes), len(eddsaShares)) {
		prvEdDSA, err := ReconstructEdDSA(ctx, 3, eddsaShares)
		require.NoError(t, err)
		got := strutil.ToHex(prvEdDSA.Serialize())
		assert.Equal(t, testfixture.SamplePrivateKeyEdDSAHex, got)
	}
}
