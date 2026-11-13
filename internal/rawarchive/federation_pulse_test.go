package rawarchive

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/dbtest"
	"go.kenn.io/agentsview/internal/money"
)

// Both managed copy paths must preserve the original publication constraint.
func TestManagedCopiesKeepFederationPulseHistory(t *testing.T) {
	for _, method := range []string{"restore", "seed", "restore-old-seed"} {
		t.Run(method, func(t *testing.T) {
			ctx := t.Context()
			t.Setenv("HOME", t.TempDir())
			opts := captureFixture(t)
			opts.Roots[0].Provider = "files"
			dbtest.WriteTestFile(t, filepath.Join(opts.DataDir, "telemetry-install-id"), []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
			database, err := db.OpenIsolatedContext(ctx, filepath.Join(opts.DataDir, "sessions.db"))
			require.NoError(t, err)
			day := time.Now().UTC().AddDate(0, 0, -2)
			start := day.Format("2006-01-02") + "T09:00:00Z"
			older := day.AddDate(0, 0, -1).Format("2006-01-02") + "T09:00:00Z"
			for i, name := range []string{"a", "b", "c"} {
				enrollment, spoke, share := "e-"+name, "s-"+name, "h-"+name
				require.NoError(t, database.CreateFederationEnrollment(ctx, db.FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: name, CredentialSHA256: "digest-" + name}))
				_, err := database.PutFederationHubShare(ctx, spoke, db.FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active", Retention: "member-controlled"})
				require.NoError(t, err)
				cost := money.Money{Microdollars: int64((i + 1) * 100)}
				record := db.FederationHubRecord{UID: name, Hash: "initial", Remote: "example/repo", ProjectKey: "project", Write: db.SessionBatchWrite{Session: db.Session{ID: name, Project: "example/repo", Agent: "codex", StartedAt: &start}, Signals: db.SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []db.UsageEvent{{Source: "federation", Model: "model", InputTokens: (i + 1) * 10, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: start, DedupKey: "model"}}}}
				_, err = database.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch-1", []db.FederationHubRecord{record})
				require.NoError(t, err)
			}
			cost := money.Money{Microdollars: 70}
			record := db.FederationHubRecord{UID: "a-older", Hash: "initial", Remote: "example/repo", ProjectKey: "project", Write: db.SessionBatchWrite{Session: db.Session{ID: "a-older", Project: "example/repo", Agent: "codex", StartedAt: &older}, Signals: db.SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []db.UsageEvent{{Source: "federation", Model: "model", InputTokens: 7, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: older, DedupKey: "model"}}}}
			_, err = database.CommitFederationBatch(ctx, "e-a", "s-a", "h-a", "policy", 1, 2, "batch-2", []db.FederationHubRecord{record})
			require.NoError(t, err)
			var oldBackupPath, oldSnapshot string
			if method == "seed" || method == "restore-old-seed" {
				// Capture the source before any pulse publication. The later seed
				// must join the authority that the original creates afterward.
				require.NoError(t, database.Close())
				_, err = Capture(ctx, opts)
				require.NoError(t, err)
				if method == "restore-old-seed" {
					seed := filepath.Join(t.TempDir(), "seed")
					_, err = Seed(ctx, filepath.Join(opts.Destination, "capture.json"), seed, nil)
					require.NoError(t, err)
					seedDB, err := db.OpenIsolatedContext(ctx, filepath.Join(seed, "sessions.db"))
					require.NoError(t, err)
					archive, err := Open(ctx, seedDB, seed, nil)
					require.NoError(t, err)
					oldBackupPath = filepath.Join(t.TempDir(), "old-backup")
					backup, err := archive.Backup(ctx, oldBackupPath, opts.Settings, "test")
					require.NoError(t, err)
					oldSnapshot = backup.SnapshotID
					require.NoError(t, archive.Close())
					require.NoError(t, seedDB.Close())
				}
				database, err = db.OpenIsolatedContext(ctx, filepath.Join(opts.DataDir, "sessions.db"))
				require.NoError(t, err)
			}
			first, err := database.FederationPulse(ctx, day.Format("2006-01-02"), 3)
			require.NoError(t, err)
			require.NotNil(t, first.Totals["sessions"].Value)
			require.NotNil(t, first.Totals["tokens"].Value)
			require.NotNil(t, first.Totals["cost_microdollars"].Value)
			assert.EqualValues(t, 3, *first.Totals["sessions"].Value)
			assert.EqualValues(t, 60, *first.Totals["tokens"].Value)
			assert.EqualValues(t, 600, *first.Totals["cost_microdollars"].Value)

			target := filepath.Join(t.TempDir(), "copied")
			if method == "restore" {
				require.NoError(t, database.EnableArchiveOnly(ctx))
				archive, err := Open(ctx, database, opts.DataDir, nil)
				require.NoError(t, err)
				backupPath := filepath.Join(t.TempDir(), "backup")
				backup, err := archive.Backup(ctx, backupPath, opts.Settings, "test")
				require.NoError(t, err)
				require.NoError(t, archive.Close())
				require.NoError(t, database.Close())
				_, err = Restore(ctx, backupPath, backup.SnapshotID, target, nil)
				require.NoError(t, err)
			} else if method == "seed" {
				require.NoError(t, database.Close())
				_, err = Seed(ctx, filepath.Join(opts.Destination, "capture.json"), target, nil)
				require.NoError(t, err)
			} else {
				require.NoError(t, database.Close())
				_, err = Restore(ctx, oldBackupPath, oldSnapshot, target, nil)
				require.NoError(t, err)
			}
			copied, err := db.OpenIsolatedContext(ctx, filepath.Join(target, "sessions.db"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, copied.Close()) })
			later, err := copied.FederationPulse(ctx, day.AddDate(0, 0, -1).Format("2006-01-02"), 3)
			if err != nil {
				assert.Empty(t, later.Projects)
				assert.Nil(t, later.Totals)
				return
			}
			assert.True(t, later.Suppressed)
			assert.Empty(t, later.Projects)
			assert.Nil(t, later.Totals["tokens"].Value)
			assert.Nil(t, later.Totals["cost_microdollars"].Value)
		})
	}
}
