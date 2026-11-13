//go:build !windows

package requestsign

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadPrivateModeAndLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte("fixture"), 0600))
	data, err := ReadPrivate(path, 7)
	require.NoError(t, err)
	assert.Equal(t, "fixture", string(data))
	for _, mode := range []os.FileMode{0640, 0644} {
		require.NoError(t, os.Chmod(path, mode))
		_, err := ReadPrivate(path, 7)
		assert.ErrorIs(t, err, ErrPrivateMode)
	}
	require.NoError(t, os.Chmod(path, 0600))
	_, err = ReadPrivate(path, 6)
	assert.EqualError(t, err, "reading private signing file failed")
}
