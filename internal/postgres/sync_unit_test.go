package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/dbtest"
	"go.kenn.io/agentsview/internal/storage"
)

func testDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(t.Context(), t.TempDir()+"/test.db")
	require.NoError(t, err, "opening test db")
	dbtest.SeedPricingMeta(t, d)
	t.Cleanup(func() { d.Close() })
	return d
}

func TestIsUndefinedTable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			"unrelated error",
			errors.New("connection refused"),
			false,
		},
		{
			"generic does not exist",
			errors.New(
				`column "foo" does not exist`,
			),
			false,
		},
		{
			"SQLSTATE 42P01",
			fmt.Errorf("query sessions: %w", &pgconn.PgError{Code: "42P01", Message: `relation "sessions" does not exist`}),
			true,
		},
		{
			"bare SQLSTATE",
			errors.New("42P01"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isUndefinedTable(tt.err))
		})
	}
}

func TestScopedSyncStateStoreMigratesLegacyState(t *testing.T) {
	local := testDB(t)

	require.NoError(t, local.SetSyncState(t.Context(),
		"last_push_at",
		"2026-03-11T12:34:56.123Z",
	))
	require.NoError(t, local.SetSyncState(t.Context(),
		lastPushBoundaryStateKey,
		`{"cutoff":"2026-03-11T12:34:56.123Z"}`,
	))
	require.NoError(t, local.SetSyncState(t.Context(),
		lastPushTargetFingerprintKey,
		"fingerprint-a",
	))
	require.NoError(t, local.SetSyncState(t.Context(),
		pushMarkerIDStateKey,
		"marker-a",
	))

	store := newScopedSyncStateStore(local, "work", true)

	lastPush, err := store.GetSyncState(t.Context(), "last_push_at")
	require.NoError(t, err)
	assert.Equal(t, "2026-03-11T12:34:56.123Z", lastPush)

	for _, key := range []string{
		"last_push_at",
		lastPushBoundaryStateKey,
		lastPushTargetFingerprintKey,
	} {
		legacyValue, err := local.GetSyncState(t.Context(), key)
		require.NoError(t, err)
		assert.Empty(t, legacyValue)

		scopedValue, err := local.GetSyncState(t.Context(), key+":work")
		require.NoError(t, err)
		assert.NotEmpty(t, scopedValue)
	}

	legacyMarker, err := local.GetSyncState(t.Context(), pushMarkerIDStateKey)
	require.NoError(t, err)
	assert.Equal(t, "marker-a", legacyMarker)

	scopedMarker, err := local.GetSyncState(t.Context(),
		pushMarkerIDStateKey+":work",
	)
	require.NoError(t, err)
	assert.Empty(t, scopedMarker)
}

func TestScopedSyncStateStoreNonDefaultTargetDoesNotMigrateLegacyState(t *testing.T) {
	local := testDB(t)

	require.NoError(t, local.SetSyncState(t.Context(),
		"last_push_at",
		"2026-03-11T12:34:56.123Z",
	))

	store := newScopedSyncStateStore(local, "archive", false)

	got, err := store.GetSyncState(t.Context(), "last_push_at")
	require.NoError(t, err)
	assert.Empty(t, got)

	legacyValue, err := local.GetSyncState(t.Context(), "last_push_at")
	require.NoError(t, err)
	assert.Equal(t, "2026-03-11T12:34:56.123Z", legacyValue)
}

func TestScopedSyncStateStoreLegacyModeUsesUnscopedKeys(t *testing.T) {
	local := testDB(t)
	store := newScopedSyncStateStore(local, "", false)

	require.NoError(t, store.SetSyncState(t.Context(),
		"last_push_at",
		"2026-03-11T12:34:56.123Z",
	))

	got, err := local.GetSyncState(t.Context(), "last_push_at")
	require.NoError(t, err)
	assert.Equal(t, "2026-03-11T12:34:56.123Z", got)
}

func TestPushSyncStateScopeIncludesProjectFilters(t *testing.T) {
	assert.Empty(t, pushSyncStateScope("", nil, nil, nil))
	assert.Equal(t, "work", pushSyncStateScope("work", nil, nil, nil))

	includeAB := pushSyncStateScope(
		"work",
		[]string{"beta", "alpha"},
		nil,
		nil)
	includeBA := pushSyncStateScope(
		"work",
		[]string{"alpha", "beta"},
		nil,
		nil)
	excludeAB := pushSyncStateScope(
		"work",
		nil,
		[]string{"alpha", "beta"},
		nil)
	includeAExcludeB := pushSyncStateScope(
		"work",
		[]string{"alpha"},
		[]string{"beta"},
		nil)
	defaultIncludeAB := pushSyncStateScope(
		"",
		[]string{"alpha", "beta"},
		nil,
		nil)

	assert.Equal(t, includeAB, includeBA)
	assert.NotEmpty(t, includeAB)
	assert.NotEqual(t, "work", includeAB)
	assert.NotEqual(t, includeAB, excludeAB)
	assert.NotEqual(t, pushSyncStateScope("work", []string{"alpha"}, nil, nil),
		includeAExcludeB)
	assert.NotEqual(t, includeAB, defaultIncludeAB)
}

func TestNewRejectsIncludeAndExcludeProjects(t *testing.T) {
	local := testDB(t)

	_, err := New(
		t.Context(), "postgres://127.0.0.1:1/db?sslmode=disable",
		"agentsview",
		local,
		"test-machine",
		true,
		storage.PusherOptions{
			Projects:        []string{"alpha"},
			ExcludeProjects: []string{"beta"},
		},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(),
		"projects and exclude_projects are mutually exclusive")
}

func TestNewRejectsInvalidProjectRemotes(t *testing.T) {
	local := testDB(t)
	for _, tc := range []struct {
		name    string
		options storage.PusherOptions
		wantErr string
	}{
		{name: "local path", options: storage.PusherOptions{ProjectRemotes: []string{"/tmp/repo"}}, wantErr: "invalid project remote"},
		{name: "raw URL", options: storage.PusherOptions{ProjectRemotes: []string{"https://example.com/org/repo"}}, wantErr: "invalid project remote"},
		{name: "mixed labels and remotes", options: storage.PusherOptions{Projects: []string{"label"}, ProjectRemotes: []string{"example.com/org/repo"}}, wantErr: "project_remotes and project labels are mutually exclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(t.Context(), "postgres://127.0.0.1:1/db?sslmode=disable", "agentsview", local, "test-machine", true, tc.options)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestReadLastPushAtUsesProjectFilterScope(t *testing.T) {
	local := testDB(t)

	require.NoError(t, local.SetSyncState(t.Context(),
		"last_push_at:work",
		"2026-03-11T12:00:00.000Z",
	))
	filterScope := pushSyncStateScope(
		"work",
		[]string{"alpha", "beta"},
		nil,
		nil)
	require.NoError(t, local.SetSyncState(t.Context(),
		"last_push_at:"+filterScope,
		"2026-03-11T13:00:00.000Z",
	))

	got, err := ReadLastPushAt(t.Context(),
		local,
		"work",
		[]string{"beta", "alpha"},
		nil,
		true,
		nil)
	require.NoError(t, err)
	assert.Equal(t, "2026-03-11T13:00:00.000Z", got)
}

func TestReadLastPushAtDoesNotMigrateLegacyStateForProjectFilter(t *testing.T) {
	local := testDB(t)

	require.NoError(t, local.SetSyncState(t.Context(),
		"last_push_at",
		"2026-03-11T12:00:00.000Z",
	))

	got, err := ReadLastPushAt(t.Context(),
		local,
		"",
		[]string{"alpha"},
		nil,
		true,
		nil)
	require.NoError(t, err)
	assert.Empty(t, got)

	legacyValue, err := local.GetSyncState(t.Context(), "last_push_at")
	require.NoError(t, err)
	assert.Equal(t, "2026-03-11T12:00:00.000Z", legacyValue)
}

func TestRemotePushScopeSeparatesCursors(t *testing.T) {
	plain := pushSyncStateScope("work", nil, nil, nil)
	label := pushSyncStateScope("work", []string{"alpha"}, nil, nil)
	assert.Equal(t, "work", plain)
	assert.Equal(t, "work:project-filter:29def59da1267056", label)
	remote := pushSyncStateScope("work", nil, nil, []string{"example.com/team/repo"})
	assert.NotEqual(t, plain, remote)
	assert.NotEqual(t, label, remote)
	assert.NotEqual(t, remote, pushSyncStateScope("work", nil, nil, []string{"example.com/team/other"}))
}
