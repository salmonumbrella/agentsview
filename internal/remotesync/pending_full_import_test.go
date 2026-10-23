package remotesync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPendingFullImportReasons(t *testing.T) {
	for _, tc := range []struct {
		name    string
		journal string
		want    bool
	}{
		{"explicit", `{"version":1,"full_import":true,"full_import_reason":"explicit-full"}`, true},
		{"overflow", `{"version":1,"full_import":true,"full_import_reason":"journal-overflow","invalidate_all":true,"force_full_parse_all":true}`, true},
		{"recovery", `{"version":1,"full_import":true,"full_import_reason":"journal-recovery","invalidate_all":true,"force_full_parse_all":true}`, true},
		{"incremental", `{"version":1}`, false},
		{"missing", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.journal != "" {
				path := MirrorDir(dir, "host") + ".changes.json"
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
				require.NoError(t, os.WriteFile(path, []byte(tc.journal), 0o600))
			}
			got, err := PendingFullImport(dir, "host")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
