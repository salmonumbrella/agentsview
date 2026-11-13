package db

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPulseAuthorityOriginalAndRejoin(t *testing.T) {
	home := t.TempDir()
	_, err := rejoinPulseAuthority(t.Context(), home, "archive-a", "missing")
	require.Error(t, err)
	_, err = os.Stat(filepath.Join(home, ".agentsview-pulse-authority"))
	require.ErrorIs(t, err, os.ErrNotExist)
	archive := filepath.Join(t.TempDir(), "sessions.db")
	require.NoError(t, os.WriteFile(archive, []byte("archive"), 0600))
	original, err := createPulseAuthority(t.Context(), home, "archive-a", archive)
	require.NoError(t, err)
	assert.NotEmpty(t, original.AuthorityID)
	assert.NotEmpty(t, original.Incarnation)
	assert.Equal(t, "archive-a", original.ArchiveID)
	rejoined, err := rejoinPulseAuthority(t.Context(), home, "archive-a", original.AuthorityID)
	require.NoError(t, err)
	assert.Equal(t, original, rejoined)
	_, err = createPulseAuthority(t.Context(), home, "archive-a", archive)
	require.Error(t, err)
	_, err = rejoinPulseAuthority(t.Context(), home, "archive-a", "wrong-authority")
	require.Error(t, err)
	_, err = rejoinPulseAuthority(t.Context(), home, "missing", original.AuthorityID)
	require.Error(t, err)
}

func TestPulseAuthorityCorruptStateIsNeverReinitialized(t *testing.T) {
	home := t.TempDir()
	archive := filepath.Join(t.TempDir(), "sessions.db")
	require.NoError(t, os.WriteFile(archive, []byte("archive"), 0600))
	original, err := createPulseAuthority(t.Context(), home, "archive-a", archive)
	require.NoError(t, err)
	path, err := pulseAuthorityPath(home, "archive-a")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("corrupt"), 0600))
	_, err = rejoinPulseAuthority(t.Context(), home, "archive-a", original.AuthorityID)
	require.Error(t, err)
	_, err = createPulseAuthority(t.Context(), home, "archive-a", archive)
	require.Error(t, err)
}
