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

func TestPulseAuthorityBindsArchiveMetadataAndRequiresRejoin(t *testing.T) {
	ctx := t.Context()
	home := t.TempDir()
	d := testDB(t)
	first, err := d.bindPulseAuthority(ctx, home, true)
	require.NoError(t, err)
	archiveID, err := d.GetArchiveID(ctx)
	require.NoError(t, err)
	assert.Equal(t, archiveID, first.ArchiveID)
	second, err := d.bindPulseAuthority(ctx, home, false)
	require.NoError(t, err)
	assert.Equal(t, first, second)
	_, err = d.bindPulseAuthority(ctx, t.TempDir(), true)
	require.Error(t, err, "a bound archive must not initialize a replacement authority")
	third, err := d.bindPulseAuthority(ctx, home, false)
	require.NoError(t, err)
	assert.Equal(t, first, third)
}

func TestPulseAuthorityArchiveOnlyCannotCreateOriginal(t *testing.T) {
	ctx := t.Context()
	home := t.TempDir()
	d := testDB(t)
	require.NoError(t, d.EnableArchiveOnly(ctx))
	_, err := d.bindPulseAuthority(ctx, home, true)
	require.Error(t, err)
	_, err = os.Stat(filepath.Join(home, ".agentsview-pulse-authority"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestPulseAuthorityResyncCopyCarriesReferenceAndRequiresRejoin(t *testing.T) {
	ctx := t.Context()
	home := t.TempDir()
	source := testDB(t)
	binding, err := source.bindPulseAuthority(ctx, home, true)
	require.NoError(t, err)
	target := testDB(t)
	require.NoError(t, target.CopyArchiveIdentityFrom(ctx, source.Path()))
	var raw, marker string
	require.NoError(t, target.Reader().QueryRow(ctx, `SELECT value FROM archive_metadata WHERE key=?`, pulseAuthorityMetadataKey).Scan(&raw))
	require.Contains(t, raw, binding.AuthorityID)
	require.NoError(t, target.Reader().QueryRow(ctx, `SELECT value FROM archive_metadata WHERE key='federation_pulse_requires_rejoin'`).Scan(&marker))
	assert.Equal(t, "1", marker)
	_, err = target.bindPulseAuthority(ctx, home, true)
	require.Error(t, err, "a staged copy cannot activate its inherited reference")
}
