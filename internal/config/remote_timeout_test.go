package config

import (
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hegel.dev/go/hegel"
)

func TestRemoteHostTimeoutDefaults(t *testing.T) {
	f := newConfigFixture(t)
	f.WriteConfigText(t, `[[remote_hosts]]
host = "first"
transport = "ssh"
[[remote_hosts]]
host = "second"
transport = "ssh"
sync_timeout = "0s"
full_sync_timeout = "12m"
`)
	cfg := f.LoadMinimal(t)
	require.Len(t, cfg.RemoteHosts, 2)
	assert.Equal(t, 10*time.Minute, cfg.RemoteHosts[0].SyncTimeout)
	assert.Zero(t, cfg.RemoteHosts[0].FullSyncTimeout)
	assert.Zero(t, cfg.RemoteHosts[1].SyncTimeout)
	assert.Equal(t, 12*time.Minute, cfg.RemoteHosts[1].FullSyncTimeout)
}

func TestRemoteHostTimeoutDurations(t *testing.T) {
	f := newConfigFixture(t)
	hegel.Test(t, func(ht *hegel.T) {
		incremental := time.Duration(hegel.Draw(ht, hegel.Integers[int64](0, math.MaxInt64)))
		full := time.Duration(hegel.Draw(ht, hegel.Integers[int64](0, math.MaxInt64)))
		require.NoError(ht, os.WriteFile(f.Path(configFileName), []byte(fmt.Sprintf("[[remote_hosts]]\nhost = 'host'\ntransport = 'ssh'\nsync_timeout = %q\nfull_sync_timeout = %q", incremental.String(), full.String())+fmt.Sprintf("\n[[remote_hosts]]\nhost = 'other'\ntransport = 'ssh'\nsync_timeout = %q\nfull_sync_timeout = %q", full.String(), incremental.String())), 0o600))
		cfg, err := LoadMinimal()
		require.NoError(ht, err)
		require.Len(ht, cfg.RemoteHosts, 2)
		assert.Equal(ht, incremental, cfg.RemoteHosts[0].SyncTimeout)
		assert.Equal(ht, full, cfg.RemoteHosts[0].FullSyncTimeout)
		assert.Equal(ht, full, cfg.RemoteHosts[1].SyncTimeout)
		assert.Equal(ht, incremental, cfg.RemoteHosts[1].FullSyncTimeout)
	}, hegel.WithTestCases(1000))
}

func TestRemoteHostTimeoutValidation(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		incremental := time.Duration(hegel.Draw(ht, hegel.Integers[int64](math.MinInt64, math.MaxInt64)))
		full := time.Duration(hegel.Draw(ht, hegel.Integers[int64](math.MinInt64, math.MaxInt64)))
		err := (Config{RemoteHosts: []RemoteHost{{Host: "host", Transport: RemoteTransportSSH, SyncTimeout: incremental, FullSyncTimeout: full}}}).ValidateRemoteHosts()
		if incremental < 0 || full < 0 {
			require.Error(ht, err)
		} else {
			require.NoError(ht, err)
		}
	}, hegel.WithTestCases(1000))
}

func TestRemoteHostMalformedTimeout(t *testing.T) {
	for _, key := range []string{"sync_timeout", "full_sync_timeout"} {
		t.Run(key, func(t *testing.T) {
			f := newConfigFixture(t)
			f.WriteConfigText(t, fmt.Sprintf("[[remote_hosts]]\nhost='host'\ntransport='ssh'\n%s='not-a-duration'", key))
			require.Error(t, f.LoadMinimalErr(t))
		})
	}
}
