package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/storage"
)

func TestBackendTargetsLegacyBlock(t *testing.T) {
	cfg := config.Config{PG: config.PGConfig{URL: "postgres://legacy"}}
	refs, err := Backend{}.Targets(cfg)
	require.NoError(t, err)
	assert.Equal(t, []storage.ReplicaTargetRef{{IsDefault: true}}, refs)

	target, err := Backend{}.ResolveTarget(cfg, refs[0])
	require.NoError(t, err)
	assert.Equal(t, "postgres://legacy", target.Target.URL)
	assert.True(t, target.Target.PushVectors, "unset push_vectors means enabled")
	assert.Empty(t, target.SyncStateTarget())
	assert.False(t, target.MigrateLegacySyncState())
}

func TestBackendTargetsNamedDefaultFirst(t *testing.T) {
	off := false
	cfg := config.Config{
		InstallationID: "machine-a",
		DefaultPG:      "work",
		PGTargets: map[string]config.PGConfig{
			"archive": {
				URL: "postgres://archive", PushVectors: &off,
				Projects: []string{"kit"},
			},
			"work": {
				URL: "postgres://work", Schema: "team",
				MachineName: "workbox", AllowInsecure: true,
			},
		},
	}
	refs, err := Backend{}.Targets(cfg)
	require.NoError(t, err)
	assert.Equal(t, []storage.ReplicaTargetRef{
		{Name: "work", IsDefault: true},
		{Name: "archive"},
	}, refs)

	work, err := Backend{}.ResolveTarget(cfg, refs[0])
	require.NoError(t, err)
	assert.Equal(t, storage.ReplicaTarget{
		URL: "postgres://work", Schema: "team", MachineName: "workbox",
		AllowInsecure: true, PushVectors: true,
	}, work.Target)
	assert.Equal(t, "work", work.SyncStateTarget())
	assert.True(t, work.MigrateLegacySyncState())

	archive, err := Backend{}.ResolveTarget(cfg, refs[1])
	require.NoError(t, err)
	assert.False(t, archive.Target.PushVectors)
	assert.Equal(t, "machine-a", archive.Target.MachineName,
		"machine name defaults to the installation id")
	assert.Equal(t, []string{"kit"}, archive.Projects)
	assert.False(t, archive.MigrateLegacySyncState())
}

func TestBackendNewPusherRejectsReservedMachine(t *testing.T) {
	_, err := Backend{}.NewPusher(
		t.Context(), storage.ReplicaTarget{URL: "postgres://x", MachineName: "local"},
		nil, storage.PusherOptions{},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `machine name "local" is reserved`)
}

func TestBackendNewPusherRejectsPushBatchSize(t *testing.T) {
	_, err := Backend{}.NewPusher(
		t.Context(), storage.ReplicaTarget{
			URL: "postgres://x", MachineName: "m", PushBatchSize: 250,
		},
		nil, storage.PusherOptions{},
	)
	require.EqualError(t, err,
		"push_batch_size is a ClickHouse setting; PostgreSQL push does not accept it (got 250)")
}

func TestBackendResolveTargetNormalizesProjectRemotes(t *testing.T) {
	cfg := config.Config{PG: config.PGConfig{URL: "postgres://localhost/db", ProjectRemotes: []string{"git@example.com:org/repo.git", "example.com/org/repo"}}}
	target, err := (Backend{}).ResolveTarget(cfg, storage.ReplicaTargetRef{})
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com/org/repo"}, target.ProjectRemotes)
}

func TestResolveTargetDefersProjectRemoteErrors(t *testing.T) {
	for _, tc := range []struct {
		name        string
		input, want []string
		wantErr     string
	}{
		{"absent", nil, nil, ""},
		{"valid", []string{"https://example.com:8443/org/repo"}, []string{"example.com:8443/org/repo"}, ""},
		{"empty", []string{}, nil, "project_remotes cannot be empty"},
		{"invalid", []string{"/local/path"}, nil, "invalid project remote"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, err := (Backend{}).ResolveTarget(config.Config{PG: config.PGConfig{URL: "postgres://localhost/db", ProjectRemotes: tc.input}}, storage.ReplicaTargetRef{})
			require.NoError(t, err)
			assert.Equal(t, tc.want, target.ProjectRemotes)
			if tc.wantErr != "" {
				require.ErrorContains(t, target.ProjectRemotesErr, tc.wantErr)
				_, err = (Backend{}).LastPushAt(t.Context(), nil, target, nil, nil)
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, target.ProjectRemotesErr)
			}
		})
	}
}
