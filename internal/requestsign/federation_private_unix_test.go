//go:build !windows

package requestsign

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPrivateFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte("fixture"), 0600))
	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	for _, tc := range []struct {
		mode os.FileMode
		want bool
	}{{0600, true}, {0640, false}, {0644, false}} {
		require.NoError(t, os.Chmod(path, tc.mode))
		assert.Equal(t, tc.want, IsPrivateFile(file))
	}
}
