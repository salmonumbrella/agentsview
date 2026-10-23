package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/archivepush"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/dbtest"
	"go.kenn.io/agentsview/internal/parser"
	"go.kenn.io/agentsview/internal/remotesync"
	"go.kenn.io/agentsview/internal/sshremote"
	"go.kenn.io/agentsview/internal/storage"
	syncpkg "go.kenn.io/agentsview/internal/sync"
	"go.kenn.io/agentsview/internal/testjsonl"
)

type immediateRemoteRunner struct{}

func (immediateRemoteRunner) RunExclusiveCtx(_ context.Context, f func() error) error { return f() }

func TestRemoteHostAttemptDeadline(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mirror      bool
		fullTimeout time.Duration
		want        time.Duration
		oldVersion  bool
		journal     bool
	}{
		{"incremental", true, 0, time.Minute, false, false},
		{"first pull", false, 0, 0, false, false},
		{"bounded first pull", false, time.Hour, time.Hour, false, false},
		{"data rebuild", true, time.Hour, time.Hour, true, false},
		{"resumed full", true, time.Hour, time.Hour, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := dbtest.OpenTestDB(t)
			dir := t.TempDir()
			version := db.CurrentDataVersion()
			if tc.oldVersion {
				version--
			}
			require.NoError(t, database.SetRemoteImportDataVersion(t.Context(), "host", version))
			if tc.mirror {
				require.NoError(t, os.MkdirAll(remotesync.MirrorDir(dir, "host"), 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(remotesync.MirrorDir(dir, "host"), "session"), []byte("session"), 0o600))
			}
			if tc.journal {
				require.NoError(t, os.WriteFile(remotesync.MirrorDir(dir, "host")+".changes.json", []byte(`{"version":1,"full_import":true,"full_import_reason":"explicit-full"}`), 0o600))
			}
			fn := remoteHostSyncFunc(t.Context(), config.Config{DataDir: dir}, database, immediateRemoteRunner{}, config.RemoteHost{Host: "host", SyncTimeout: time.Minute, FullSyncTimeout: tc.fullTimeout}, func(ctx context.Context, _ config.Config, _ *db.DB, _ config.RemoteHost, _ bool) (remotesync.SyncStats, error) {
				deadline, bounded := ctx.Deadline()
				assert.Equal(t, tc.want > 0, bounded)
				if bounded {
					assert.InDelta(t, tc.want.Seconds(), time.Until(deadline).Seconds(), 1)
				}
				return remotesync.SyncStats{}, nil
			})
			_, err := fn()
			require.NoError(t, err)
		})
	}
}

func TestRemoteHostDeadlineStopsStalledSSH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	database := dbtest.OpenTestDB(t)
	dir := t.TempDir()
	require.NoError(t, database.SetRemoteImportDataVersion(t.Context(), "host", db.CurrentDataVersion()))
	require.NoError(t, os.MkdirAll(remotesync.MirrorDir(dir, "host"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(remotesync.MirrorDir(dir, "host"), "session"), []byte("session"), 0o600))
	script := filepath.Join(t.TempDir(), "ssh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 60\n"), 0o700))
	fn := remoteHostSyncFunc(t.Context(), config.Config{DataDir: dir}, database, immediateRemoteRunner{}, config.RemoteHost{Host: "host", SyncTimeout: time.Second}, func(ctx context.Context, _ config.Config, _ *db.DB, _ config.RemoteHost, _ bool) (remotesync.SyncStats, error) {
		_, err := (sshremote.Runner{Destination: "host", SSHPath: script}).Output(ctx, "true", nil)
		assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
		return remotesync.SyncStats{}, err
	})
	_, err := fn()
	require.Error(t, err)
}

func TestRemoteHostPartialCommitNotifiesAndRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		emitter := &fakeEmitter{}
		attempts := 0
		done := make(chan struct{})
		go func() {
			defer close(done)
			runRemoteHostSyncLoop(ctx, "host", time.Minute, func() (int, error) {
				attempts++
				if attempts == 1 {
					return 2, errors.New("partial import")
				}
				return 1, nil
			}, emitter, nil, nil)
		}()
		synctest.Wait()
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		assert.EqualValues(t, 2, emitter.count.Load())
		cancel()
		<-done
	})
}

func TestReplicaWatchBoundsFullStartup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	for _, prepared := range []bool{false, true} {
		t.Run(fmt.Sprintf("prepared=%v", prepared), func(t *testing.T) {
			database := dbtest.OpenTestDB(t)
			dir := t.TempDir()
			script := filepath.Join(t.TempDir(), "ssh")
			command := "exec sleep 60"
			if prepared {
				command = "exit 0"
			}
			require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\n"+command+"\n"), 0o700))
			var attempts atomic.Int32
			old := prepareHTTPRebuildCLI
			t.Cleanup(func() { prepareHTTPRebuildCLI = old })
			prepareHTTPRebuildCLI = func(c context.Context, syncs []remotesync.RemoteSync) (preparedHTTPRebuildCLI, error) {
				attempts.Add(1)
				source := fixtureRemoteSource{targets: remotesync.TargetSet{Dirs: map[parser.AgentType][]string{parser.AgentClaude: {t.TempDir()}}}}
				syncs[0].Source = fixtureSSHSource{runner: sshremote.Runner{Destination: "host", SSHPath: script}, fixtureRemoteSource: source}
				p, err := remotesync.PrepareAvailableRemoteSyncs(c, syncs)
				if prepared {
					require.NoError(t, err)
					// The timer must survive successful preparation until import finishes.
					<-c.Done()
					return p, c.Err()
				}
				return p, err
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			backend := &localArchiveWriteBackend{database: database, appCfg: config.Config{DataDir: dir, DBPath: database.Path(), AgentDirs: map[parser.AgentType][]string{}, RemoteHosts: []config.RemoteHost{{Host: "host", Transport: config.RemoteTransportSSH, FullSyncTimeout: time.Second}}}}
			err := backend.ReplicaPushWatch(ctx, pgReplica{}, storage.ConfiguredReplica{}, ReplicaPushConfig{Full: true}, nil, nil, time.Millisecond, time.Hour)
			require.NoError(t, err)
			require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
			assert.GreaterOrEqual(t, attempts.Load(), int32(2), "bounded attempts must retry before the enclosing context expires")
		})
	}
}

func TestRemoteHostRetryGetsFreshDeadline(t *testing.T) {
	database := dbtest.OpenTestDB(t)
	cfg := config.Config{DataDir: t.TempDir()}
	host := config.RemoteHost{Host: "host", FullSyncTimeout: time.Millisecond}
	attempts := 0
	fn := remoteHostSyncFunc(t.Context(), cfg, database, immediateRemoteRunner{}, host, func(c context.Context, _ config.Config, _ *db.DB, _ config.RemoteHost, _ bool) (remotesync.SyncStats, error) {
		attempts++
		if attempts == 1 {
			<-c.Done()
			return remotesync.SyncStats{}, c.Err()
		}
		require.NoError(t, c.Err(), "expired prior attempts must not cancel retries")
		return remotesync.SyncStats{SessionsSynced: 1}, nil
	})
	_, err := fn()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	synced, err := fn()
	require.NoError(t, err)
	assert.Equal(t, 1, synced)
	assert.NoError(t, t.Context().Err())
}

func TestRemoteHostDeadlineIncludesLockWait(t *testing.T) {
	for _, registry := range []bool{false, true} {
		t.Run(fmt.Sprintf("registry=%v", registry), func(t *testing.T) {
			database := dbtest.OpenTestDB(t)
			engine := syncpkg.NewEngine(t.Context(), database, syncpkg.EngineConfig{AgentDirs: map[parser.AgentType][]string{}})
			defer engine.Close()
			original := httpRemoteCleanupRegistry
			httpRemoteCleanupRegistry = new(remotesync.CleanupRegistry)
			t.Cleanup(func() { httpRemoteCleanupRegistry = original })
			held, release, unlocked := make(chan struct{}), make(chan struct{}), make(chan struct{})
			finished := make(chan struct{})
			go func() {
				defer close(unlocked)
				work := func() error { close(held); <-release; return nil }
				if registry {
					_, _ = httpRemoteCleanupRegistry.Run(func() (remotesync.SyncStats, error) { return remotesync.SyncStats{}, work() })
				} else {
					_ = engine.RunExclusive(work)
				}
			}()
			<-held
			defer func() { close(release); <-unlocked; <-finished }()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fn := remoteHostSyncFunc(ctx, config.Config{DataDir: t.TempDir()}, database, engine, config.RemoteHost{Host: "host", FullSyncTimeout: 20 * time.Millisecond}, func(context.Context, config.Config, *db.DB, config.RemoteHost, bool) (remotesync.SyncStats, error) {
				assert.Fail(t, "expired attempt must not enter transport")
				return remotesync.SyncStats{}, nil
			})
			before := make([]byte, 1<<20)
			before = before[:runtime.Stack(before, true)]
			for range 10 {
				_, err := fn()
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
			after := make([]byte, 1<<20)
			after = after[:runtime.Stack(after, true)]
			assert.LessOrEqual(t, countLockWaiters(after), countLockWaiters(before)+1, "retries retain at most one queued mutex acquisition")
			done := make(chan error, 1)
			go func() { defer close(finished); _, err := fn(); done <- err }()
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.DeadlineExceeded)
			case <-time.After(2 * time.Second):
				cancel()
				assert.Fail(t, "remote attempt did not stop while lock remained held")
			}
		})
	}
}

func TestReplicaWatchRejectsInvalidRemoteBeforeSync(t *testing.T) {
	cfg := config.Config{RemoteHosts: []config.RemoteHost{{Host: "host", Transport: config.RemoteTransportSSH, SyncTimeout: -1}}}
	backend := &localArchiveWriteBackend{appCfg: cfg}
	require.ErrorContains(t, backend.ReplicaPushWatch(t.Context(), pgReplica{}, storage.ConfiguredReplica{}, ReplicaPushConfig{}, nil, nil, time.Hour, time.Hour), "invalid sync_timeout")
}

func TestCoordinatedStartupPreservesFullPush(t *testing.T) {
	database := dbtest.OpenTestDB(t)
	engine := syncpkg.NewEngine(t.Context(), database, syncpkg.EngineConfig{AgentDirs: map[parser.AgentType][]string{}})
	defer engine.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	pushed := false
	watch := archivePushWatch{
		database: database, engine: engine, label: "test", debounce: time.Second, interval: time.Hour,
		full: true, incrementalStartup: true,
		hooks: &archivePushWatchHooks{
			startWatcher: func(config.Config, *syncpkg.Engine, syncpkg.WatchCallback, syncpkg.WatcherOptions) (func(), func(), []string) {
				return func() {}, func() {}, nil
			},
			startupSync: func(_ context.Context, _ *syncpkg.Engine, full bool) (bool, error) {
				assert.False(t, full, "coordinated rebuild must not repeat")
				return false, nil
			},
		},
		push: func(_ context.Context, _ pushReason, full bool, _ *syncpkg.WatchBatch) error {
			assert.True(t, full, "coordinated startup must preserve the full destination push")
			pushed = true
			cancel()
			return nil
		},
	}
	require.NoError(t, watch.run(ctx))
	require.True(t, pushed)
}

func TestRemoteHostRetainedRebuildUsesFullDeadline(t *testing.T) {
	database := dbtest.OpenTestDB(t)
	dir := t.TempDir()
	require.NoError(t, database.SetRemoteImportDataVersion(t.Context(), "host", db.CurrentDataVersion()))
	mirror := remotesync.MirrorDir(dir, "host")
	require.NoError(t, os.MkdirAll(mirror, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(mirror, "session"), []byte("session"), 0o600))
	journal := fmt.Sprintf(`{"version":1,"full_import":true,"required_data_version":%d}`, db.CurrentDataVersion())
	require.NoError(t, os.WriteFile(mirror+".changes.json", []byte(journal), 0o600))
	fn := remoteHostSyncFunc(t.Context(), config.Config{DataDir: dir}, database, immediateRemoteRunner{}, config.RemoteHost{Host: "host", SyncTimeout: time.Minute, FullSyncTimeout: time.Hour}, func(ctx context.Context, _ config.Config, _ *db.DB, _ config.RemoteHost, _ bool) (remotesync.SyncStats, error) {
		deadline, bounded := ctx.Deadline()
		require.True(t, bounded)
		assert.InDelta(t, time.Hour.Seconds(), time.Until(deadline).Seconds(), 1)
		return remotesync.SyncStats{}, nil
	})
	_, err := fn()
	require.NoError(t, err)
}

type fixtureSSHSource struct {
	fixtureRemoteSource
	runner sshremote.Runner
}

func (s fixtureSSHSource) Targets(ctx context.Context) (remotesync.TargetSet, error) {
	_, err := s.runner.Output(ctx, "true", nil)
	return s.targets, err
}

func TestRemoteHostStartupFailureRemainsPending(t *testing.T) {
	database := dbtest.OpenTestDB(t)
	cfg := config.Config{DataDir: t.TempDir(), AgentDirs: map[parser.AgentType][]string{}}
	oldLocal, oldRemote := runLocalSyncWithRebuildCLI, runRemoteHostSync
	t.Cleanup(func() { runLocalSyncWithRebuildCLI, runRemoteHostSync = oldLocal, oldRemote })
	cause := &remotesync.HostError{Host: "host", Operation: "import", Err: context.DeadlineExceeded}
	runLocalSyncWithRebuildCLI = func(_ context.Context, _ config.Config, _ *db.DB, _ bool, _ syncpkg.ProgressFunc, _ func() (syncpkg.RebuildOptions, syncpkg.RebuildCleanup, error), after func(bool, bool) error) (bool, error) {
		return false, after(false, false)
	}
	runRemoteHostSync = func(ctx context.Context, _ config.Config, _ *db.DB, _ config.RemoteHost, _ bool) (remotesync.SyncStats, error) {
		if _, bounded := ctx.Deadline(); bounded {
			<-ctx.Done()
		}
		return remotesync.SyncStats{}, cause
	}
	hosts := []config.RemoteHost{{Host: "host", Transport: config.RemoteTransportSSH, FullSyncTimeout: 20 * time.Millisecond}}
	for _, bounded := range []bool{false, true} {
		t.Run(fmt.Sprintf("watcher=%v", bounded), func(t *testing.T) {
			_, failures, err := runConfiguredLocalAndRemotesCore(t.Context(), cfg, database, hosts, false, nil, bounded)
			if bounded {
				require.Len(t, failures, 1)
				require.ErrorIs(t, failures[0].Err, cause)
			} else {
				require.Empty(t, failures)
			}
			if bounded {
				require.ErrorIs(t, err, cause, "watcher must retry incremental remote startup")
			} else {
				require.NoError(t, err, "one-shot sync retains per-host warning behavior")
			}
		})
	}
}

func TestArchiveWatchStartsRemoteWorkersBeforeStartupPush(t *testing.T) {
	database := dbtest.OpenTestDB(t)
	engine := syncpkg.NewEngine(t.Context(), database, syncpkg.EngineConfig{AgentDirs: map[parser.AgentType][]string{}})
	defer engine.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started, stopped := false, false
	watch := archivePushWatch{
		database: database, engine: engine, label: "test", debounce: time.Second, interval: time.Hour,
		hooks: &archivePushWatchHooks{startWatcher: func(config.Config, *syncpkg.Engine, syncpkg.WatchCallback, syncpkg.WatcherOptions) (func(), func(), []string) {
			return func() {}, func() {}, nil
		}},
		startRemotes: func(context.Context, *pushLoop) func() { started = true; return func() { stopped = true } },
		push: func(context.Context, pushReason, bool, *syncpkg.WatchBatch) error {
			assert.True(t, started, "remote workers must run while startup push is blocked")
			cancel()
			return nil
		},
	}
	require.NoError(t, watch.run(ctx))
	assert.True(t, stopped, "startup cancellation joins remote workers")
}

func TestWatchCoordinatorKeepsFailedFullPreparationPending(t *testing.T) {
	cfg, database := newDirectSyncFixture(t)
	old := runLocalSyncWithRebuildCLI
	t.Cleanup(func() { runLocalSyncWithRebuildCLI = old })
	cause := errors.New("remote unavailable")
	runLocalSyncWithRebuildCLI = func(context.Context, config.Config, *db.DB, bool, syncpkg.ProgressFunc, func() (syncpkg.RebuildOptions, syncpkg.RebuildCleanup, error), func(bool, bool) error) (bool, error) {
		return true, &remotesync.HostError{Host: "host", Operation: "prepare", Err: cause}
	}
	_, _, err := runConfiguredLocalAndRemotesForWatch(t.Context(), cfg, database, []config.RemoteHost{{Host: "host", Transport: config.RemoteTransportHTTP}}, true, nil)
	require.ErrorIs(t, err, cause, "a failed full preparation must remain a startup failure")
}

func TestReplicaWatchRetriesTimedOutRemoteWithZeroInterval(t *testing.T) {
	database := dbtest.OpenTestDB(t)
	cfg := config.Config{DataDir: t.TempDir(), DBPath: database.Path(), AgentDirs: map[parser.AgentType][]string{}, RemoteHosts: []config.RemoteHost{{Host: "host", Transport: config.RemoteTransportSSH, FullSyncTimeout: 20 * time.Millisecond}}}
	oldLocal, oldRemote := runLocalSyncWithRebuildCLI, runRemoteHostSync
	t.Cleanup(func() { runLocalSyncWithRebuildCLI, runRemoteHostSync = oldLocal, oldRemote })
	runLocalSyncWithRebuildCLI = func(_ context.Context, _ config.Config, _ *db.DB, _ bool, _ syncpkg.ProgressFunc, _ func() (syncpkg.RebuildOptions, syncpkg.RebuildCleanup, error), after func(bool, bool) error) (bool, error) {
		return false, after(false, false)
	}
	var attempts atomic.Int32
	runRemoteHostSync = func(ctx context.Context, _ config.Config, _ *db.DB, _ config.RemoteHost, _ bool) (remotesync.SyncStats, error) {
		if attempts.Add(1) == 1 {
			<-ctx.Done()
			return remotesync.SyncStats{}, &remotesync.HostError{Host: "host", Operation: "import", Err: ctx.Err()}
		}
		return remotesync.SyncStats{}, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var pushed atomic.Bool
	backend := &localArchiveWriteBackend{appCfg: cfg, database: database, watchHooks: &archivePushWatchHooks{
		startWatcher: func(config.Config, *syncpkg.Engine, syncpkg.WatchCallback, syncpkg.WatcherOptions) (func(), func(), []string) {
			return func() {}, func() {}, nil
		},
		newReplicaPusher: func(*syncpkg.Engine) *replicaPusher {
			return &replicaPusher{session: archivepush.ReplicaSession{Connect: func(context.Context) (storage.Pusher, error) {
				return remoteWatchPusher{push: func(context.Context) {
					assert.GreaterOrEqual(t, attempts.Load(), int32(2), "push waits for the timed-out startup import to retry")
					if pushed.CompareAndSwap(false, true) {
						cancel()
					}
				}}, nil
			}}}
		},
	}}
	require.NoError(t, backend.ReplicaPushWatch(ctx, pgReplica{}, embedTarget(), ReplicaPushConfig{}, nil, nil, time.Millisecond, time.Hour))
	require.True(t, pushed.Load())
	require.ErrorIs(t, ctx.Err(), context.Canceled, "successful startup push ends the watcher")
	require.GreaterOrEqual(t, attempts.Load(), int32(2))
}

func TestReplicaWatchRetriesCoordinatedStartup(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprintf("full=%v", full), func(t *testing.T) {
			database := dbtest.OpenTestDB(t)
			dir := t.TempDir()
			cfg := config.Config{DataDir: dir, DBPath: database.Path(), AgentDirs: map[parser.AgentType][]string{}, RemoteHosts: []config.RemoteHost{{Host: "host", Transport: config.RemoteTransportSSH}}}
			old := runLocalSyncWithRebuildCLI
			t.Cleanup(func() { runLocalSyncWithRebuildCLI = old })
			var attempts atomic.Int32
			runLocalSyncWithRebuildCLI = func(_ context.Context, _ config.Config, _ *db.DB, requested bool, _ syncpkg.ProgressFunc, _ func() (syncpkg.RebuildOptions, syncpkg.RebuildCleanup, error), _ func(bool, bool) error) (bool, error) {
				assert.Equal(t, full, requested)
				if attempts.Add(1) == 1 {
					return false, errors.New("local sync processing incomplete")
				}
				return full, nil
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			var pushed atomic.Bool
			backend := &localArchiveWriteBackend{appCfg: cfg, database: database, watchHooks: &archivePushWatchHooks{
				startWatcher: func(config.Config, *syncpkg.Engine, syncpkg.WatchCallback, syncpkg.WatcherOptions) (func(), func(), []string) {
					return func() {}, func() {}, nil
				},
				newReplicaPusher: func(*syncpkg.Engine) *replicaPusher {
					return &replicaPusher{session: archivepush.ReplicaSession{Connect: func(context.Context) (storage.Pusher, error) {
						return remoteWatchPusher{push: func(context.Context) {
							assert.GreaterOrEqual(t, attempts.Load(), int32(2), "push waits for successful startup retry")
							if !pushed.CompareAndSwap(false, true) {
								return
							}
							require.NoError(t, ctx.Err(), "push must precede timeout or shutdown")
							cancel()
						}}, nil
					}}}
				},
			}}
			require.NoError(t, backend.ReplicaPushWatch(ctx, pgReplica{}, embedTarget(), ReplicaPushConfig{Full: full}, nil, nil, time.Millisecond, time.Hour))
			require.True(t, pushed.Load(), "startup must reach a push")
			require.ErrorIs(t, ctx.Err(), context.Canceled, "push must trigger shutdown")
			require.GreaterOrEqual(t, attempts.Load(), int32(2))
		})
	}
}

func TestArchiveLaneReadinessWaitsForRemoteWorkers(t *testing.T) {
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	lane := &archiveSyncLane{engine: &syncpkg.Engine{}, openDispatch: func() {}, onReady: func() { close(started); <-release }}
	go func() { defer close(done); lane.markReady() }()
	<-started
	assert.False(t, lane.canPush(), "a startup retry cannot publish readiness before remote workers start")
	close(release)
	<-done
	assert.True(t, lane.canPush())
}

func countLockWaiters(stack []byte) int {
	count := 0
	for goroutine := range bytes.SplitSeq(stack, []byte("\n\n")) {
		if bytes.Contains(goroutine, []byte("lockctx.Lock")) {
			count++
		}
	}
	return count
}

func TestReplicaWatchCoordinatesFullRemoteStartup(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(fmt.Sprintf("upgrade=%v", upgrade), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "sessions.db")
			database := dbtest.OpenTestDBAt(t, path)
			remoteRoot := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(remoteRoot, "project"), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(remoteRoot, "project", "session.jsonl"), []byte(testjsonl.ClaudeUserWithSessionIDJSON("remote startup", "2026-01-01T00:00:00Z", "session")+"\n"), 0o600))
			source := fixtureRemoteSource{targets: remotesync.TargetSet{Dirs: map[parser.AgentType][]string{parser.AgentClaude: {remoteRoot}}}}
			if upgrade {
				_, err := (remotesync.RemoteSync{Host: "host", Source: source, DataDir: dir, DB: database}).Run(t.Context())
				require.NoError(t, err)
				require.NoError(t, database.SetRemoteImportDataVersion(t.Context(), "host", db.CurrentDataVersion()-1))
				require.NoError(t, database.Close())
				raw, err := sql.Open("sqlite3", path)
				require.NoError(t, err)
				_, err = raw.ExecContext(t.Context(), "PRAGMA user_version = 0")
				require.NoError(t, err)
				require.NoError(t, raw.Close())
				database, err = db.Open(t.Context(), path)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, database.Close()) })
				require.True(t, database.NeedsResync())
			}
			old := prepareHTTPRebuildCLI
			t.Cleanup(func() { prepareHTTPRebuildCLI = old })
			preparedDone := false
			prepareHTTPRebuildCLI = func(c context.Context, syncs []remotesync.RemoteSync) (preparedHTTPRebuildCLI, error) {
				require.Len(t, syncs, 1)
				want := remotesync.FullImportExplicit
				if upgrade {
					want = remotesync.FullImportDataRebuild
				}
				assert.Equal(t, want, syncs[0].FullReason)
				syncs[0].Source = source
				p, err := remotesync.PrepareAvailableRemoteSyncs(c, syncs)
				preparedDone = true
				return p, err
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			var pushed atomic.Bool
			backend := &localArchiveWriteBackend{database: database, appCfg: config.Config{DataDir: dir, DBPath: path, AgentDirs: map[parser.AgentType][]string{}, RemoteHosts: []config.RemoteHost{{Host: "host", Transport: config.RemoteTransportSSH, SyncTimeout: time.Nanosecond}}}, watchHooks: &archivePushWatchHooks{
				startWatcher: func(config.Config, *syncpkg.Engine, syncpkg.WatchCallback, syncpkg.WatcherOptions) (func(), func(), []string) {
					assert.True(t, preparedDone)
					return func() {}, func() {}, nil
				},
				startupSync: func(c context.Context, e *syncpkg.Engine, full bool) (bool, error) {
					assert.False(t, full, "the lane must not repeat the coordinated full rebuild")
					return runPGWatchStartupSync(c, e, full)
				},
				newReplicaPusher: func(*syncpkg.Engine) *replicaPusher {
					return &replicaPusher{session: archivepush.ReplicaSession{Connect: func(context.Context) (storage.Pusher, error) {
						return remoteWatchPusher{push: func(c context.Context) {
							session, err := database.GetSession(c, "host~session")
							require.NoError(t, err)
							require.NotNil(t, session)
							assert.Equal(t, "host", session.Machine)
							if !pushed.CompareAndSwap(false, true) {
								return
							}
							require.NoError(t, ctx.Err(), "push must precede timeout or shutdown")
							cancel()
						}}, nil
					}}}
				},
			}}
			require.NoError(t, backend.ReplicaPushWatch(ctx, pgReplica{}, storage.ConfiguredReplica{}, ReplicaPushConfig{Full: !upgrade}, nil, nil, time.Hour, time.Hour))
			require.True(t, pushed.Load(), "startup must reach a push")
			require.ErrorIs(t, ctx.Err(), context.Canceled, "push must trigger shutdown")
			assert.True(t, preparedDone, "configured remote preparation must run before the lane")
		})
	}
}

// fixtureRemoteSource keeps the archive, mirror, and import pipeline local.
type fixtureRemoteSource struct {
	targets remotesync.TargetSet
}

func (s fixtureRemoteSource) Targets(context.Context) (remotesync.TargetSet, error) {
	return s.targets, nil
}

func (s fixtureRemoteSource) Manifest(c context.Context, targets remotesync.TargetSet) (remotesync.Manifest, bool, error) {
	m, err := remotesync.BuildManifest(c, targets)
	return m, true, err
}

func (s fixtureRemoteSource) Archive(c context.Context, r remotesync.ArchiveRequest) (*remotesync.ArchiveStream, error) {
	var data bytes.Buffer
	var err error
	if len(r.DeltaFiles) > 0 {
		err = remotesync.WriteArchiveFiles(c, &data, r.TargetSet, r.DeltaFiles)
	} else {
		err = remotesync.WriteArchive(c, &data, r.TargetSet)
	}
	return &remotesync.ArchiveStream{Body: io.NopCloser(bytes.NewReader(data.Bytes()))}, err
}
