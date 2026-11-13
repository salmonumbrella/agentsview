package federation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/export"
	"go.kenn.io/agentsview/internal/testutil"
)

func TestStopRetriesAfterHubEpochAhead(t *testing.T) {
	ctx := t.Context()
	archive, err := db.OpenIsolated(ctx, filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	consent, err := json.Marshal(SharePreview{DeliveryNotice: shareDeliveryNotice, Policy: policy})
	require.NoError(t, err)
	var epochs []int64
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(HandshakeResponse{HubArchiveID: "hub", SpokeArchiveID: "spoke", ProtocolVersions: []int{ProtocolVersion}, EnrollmentUID: "enr", Member: "member", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest})
			return
		}
		var manifest ShareManifest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&manifest))
		assert.Equal(t, "stop", manifest.Action)
		epochs = append(epochs, manifest.Epoch)
		view := ShareView{State: "accepted", Epoch: 5, Committed: 2, Retention: "org-retained"}
		if manifest.Epoch == 6 {
			view.State, view.Epoch, view.Committed = "stopped", 6, 0
		}
		_ = json.NewEncoder(w).Encode(view)
	}))
	t.Cleanup(hub.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0600))
	link := db.FederationLink{UID: "link", HubOrigin: hub.URL, HubArchiveID: "hub", EnrollmentUID: "enr", Member: "member", TokenFile: file, ProtocolVersion: ProtocolVersion, State: "active"}
	require.NoError(t, archive.PutFederationLink(ctx, link))
	require.NoError(t, archive.PutFederationShare(ctx, db.FederationShare{UID: "share", LinkUID: link.UID, NormalizedRemote: "github.com/example/repo", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: string(consent), PolicyDigest: digest}))
	require.NoError(t, archive.StopFederationShare(ctx, link.UID, "share", "remove"))
	svc := NewService("spoke", "spoke", policy, archive)
	_, err = svc.Push(ctx)
	require.NoError(t, err)
	assert.Equal(t, []int64{1, 6}, epochs)
	share, err := archive.GetFederationShare(ctx, link.UID, "share")
	require.NoError(t, err)
	assert.EqualValues(t, 6, share.Epoch)
	assert.Equal(t, "retained", share.StopReceipt)
}

func TestPushOldConsentDoesNotDeliver(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	calls := 0
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "/api/v1/federation/handshake", r.URL.Path)
		_ = json.NewEncoder(w).Encode(HandshakeResponse{HubArchiveID: "hub", ProtocolVersions: []int{ProtocolVersion}, EnrollmentUID: "enr", Member: "member", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest})
	}))
	t.Cleanup(hub.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0600))
	svc := NewService("spoke", "spoke", policy, archive)
	require.NoError(t, svc.Join(t.Context(), hub.URL, "hub", file))
	link, err := archive.GetFederationLink(t.Context())
	require.NoError(t, err)
	require.NoError(t, archive.PutFederationShare(t.Context(), db.FederationShare{UID: "share", LinkUID: link.UID, NormalizedRemote: "github.com/example/api", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: `{"delivery_notice":"This release records the share only; nothing is sent"}`, PolicyDigest: digest}))
	before := calls
	result, err := svc.Push(t.Context())
	require.NoError(t, err)
	assert.Equal(t, before+1, calls)
	assert.Equal(t, PushResult{}, result)
	ledger, err := archive.FederationLedger(t.Context(), "share")
	require.NoError(t, err)
	assert.Empty(t, ledger)
	// A newly changed policy pauses even a share carrying current delivery
	// consent before any manifest or batch is sent.
	currentConsent, err := json.Marshal(SharePreview{DeliveryNotice: shareDeliveryNotice})
	require.NoError(t, err)
	require.NoError(t, archive.Update(t.Context(), func(tx *sql.Tx) error {
		_, e := tx.ExecContext(t.Context(), `UPDATE federation_shares SET consent_json=? WHERE share_uid='share'`, string(currentConsent))
		return e
	}))
	policy.Retention = "org-retained"
	digest, err = export.DigestCanonical(policy)
	require.NoError(t, err)
	before = calls
	result, err = svc.Push(t.Context())
	require.NoError(t, err)
	assert.Equal(t, PushResult{}, result)
	assert.Equal(t, before+1, calls)
	paused, err := archive.GetFederationShare(t.Context(), link.UID, "share")
	require.NoError(t, err)
	assert.Equal(t, "policy_paused", paused.State)
}

func TestPushWithNoActiveShareAvoidsHub(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	require.NoError(t, archive.PutFederationLink(t.Context(), db.FederationLink{UID: "link", HubOrigin: "https://example.invalid", HubArchiveID: "hub", EnrollmentUID: "enr", Member: "member", TokenFile: "/missing", ProtocolVersion: ProtocolVersion, State: "active"}))
	svc := NewService("spoke", "spoke", config.FederationHubConfig{}, archive)
	result, err := svc.Push(t.Context())
	require.NoError(t, err)
	assert.Equal(t, PushResult{}, result)
}

func TestGrantChangesWaitForPush(t *testing.T) {
	for _, operation := range []string{"pause", "exclude"} {
		t.Run(operation, func(t *testing.T) {
			ctx := t.Context()
			archive, err := db.OpenIsolated(ctx, filepath.Join(t.TempDir(), "archive.db"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, archive.Close()) })
			policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
			digest, err := export.DigestCanonical(policy)
			require.NoError(t, err)
			entered, release := make(chan struct{}), make(chan struct{})
			batches := 0
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet:
					_ = json.NewEncoder(w).Encode(HandshakeResponse{HubArchiveID: "hub", ProtocolVersions: []int{ProtocolVersion}, EnrollmentUID: "enr", Member: "member", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest})
				case r.Method == http.MethodPut:
					var manifest ShareManifest
					require.NoError(t, json.NewDecoder(r.Body).Decode(&manifest))
					state := "accepted"
					if manifest.Action == "stop" {
						state = "stopped"
					}
					_ = json.NewEncoder(w).Encode(ShareView{State: state, Epoch: 1, Committed: int64(batches), Retention: policy.Retention})
				case strings.HasSuffix(r.URL.Path, "/reconcile"):
					var request ReconcileRequest
					require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
					_ = json.NewEncoder(w).Encode(db.FederationInventoryResult{Boundary: request.Through, Covered: request.Through, Complete: request.Final})
				default:
					batches++
					if batches == 1 {
						close(entered)
						<-release
					}
					_ = json.NewEncoder(w).Encode(BatchAck{Committed: int64(batches), Refused: map[string]string{}})
				}
			}))
			t.Cleanup(hub.Close)
			file := filepath.Join(testutil.PrivateTempDir(t), "credential")
			require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0600))
			svc := NewService("spoke", "spoke", policy, archive)
			require.NoError(t, svc.Join(ctx, hub.URL, "hub", file))
			remote := "github.com/example/api"
			key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
			require.NoError(t, archive.Update(ctx, func(tx *sql.Tx) error {
				for _, q := range []string{
					`INSERT INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','install')`,
					`INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count) VALUES('s','fixture','install','claude','s','2026-01-02T00:00:00Z',1)`,
					`INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES('s','install','claude','s')`,
				} {
					if _, e := tx.ExecContext(ctx, q); e != nil {
						return e
					}
				}
				_, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES('s','fixture','install','2026-01-01T00:00:00Z','resolved',1,?,'git_remote',?)`, remote, key)
				return e
			}))
			preview, err := svc.PreviewShare(ctx, ShareGrant{Project: remote, Level: "summary", Attribution: "pooled"})
			require.NoError(t, err)
			require.NoError(t, svc.AddShare(ctx, preview))
			link, err := archive.GetFederationLink(ctx)
			require.NoError(t, err)
			shares, err := archive.ListFederationShares(ctx, link.UID)
			require.NoError(t, err)
			require.Len(t, shares, 1)
			require.NoError(t, archive.Update(ctx, func(tx *sql.Tx) error {
				_, e := tx.ExecContext(ctx, `UPDATE federation_shares SET consent_json=? WHERE share_uid=?`, `{"delivery_notice":"old"}`, shares[0].UID)
				return e
			}))
			require.NoError(t, svc.AddShare(ctx, preview))
			same, err := archive.GetFederationShare(ctx, link.UID, shares[0].UID)
			require.NoError(t, err)
			assert.Contains(t, same.ConsentJSON, shareDeliveryNotice)
			done := make(chan error, 1)
			go func() { _, e := svc.Push(ctx); done <- e }()
			<-entered
			timed, cancel := context.WithTimeout(ctx, 20*time.Millisecond) //nolint:kennlint // deadlinetest: push holds the semaphore until the deadline
			defer cancel()
			mutate := func(c context.Context) error {
				if operation == "pause" {
					return svc.PauseShare(c, shares[0].UID)
				}
				return svc.Exclude(c, "s", "private")
			}
			require.ErrorIs(t, mutate(timed), context.DeadlineExceeded)
			current, err := archive.GetFederationShare(ctx, link.UID, shares[0].UID)
			require.NoError(t, err)
			assert.Equal(t, "active", current.State)
			close(release)
			require.NoError(t, <-done)
			require.NoError(t, mutate(ctx))
			_, err = svc.Push(ctx)
			require.NoError(t, err)
			if operation == "pause" {
				assert.Equal(t, 1, batches)
			} else {
				assert.Equal(t, 2, batches)
			}
		})
	}
}

func TestPushLargeAcknowledgmentAndBatchLimit(t *testing.T) {
	for _, tc := range []struct {
		name              string
		count, modelBytes int
		refused           bool
	}{
		{"large acknowledgment", 1000, 0, true},
		{"large records split", 2, 4 << 20, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			archive, err := db.OpenIsolated(ctx, filepath.Join(t.TempDir(), "archive.db"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, archive.Close()) })
			policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
			digest, err := export.DigestCanonical(policy)
			require.NoError(t, err)
			var sizes []int
			var committed int64
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet:
					_ = json.NewEncoder(w).Encode(HandshakeResponse{HubArchiveID: "hub", ProtocolVersions: []int{ProtocolVersion}, EnrollmentUID: "enr", Member: "member", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest})
				case r.Method == http.MethodPut:
					_ = json.NewEncoder(w).Encode(ShareView{State: "accepted", Epoch: 1, Committed: committed})
				case strings.HasSuffix(r.URL.Path, "/reconcile"):
					var request ReconcileRequest
					require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
					_ = json.NewEncoder(w).Encode(db.FederationInventoryResult{Boundary: request.Through, Covered: request.Through, Complete: request.Final})
				default:
					data, e := io.ReadAll(r.Body)
					require.NoError(t, e)
					sizes = append(sizes, len(data))
					var batch Batch
					require.NoError(t, json.Unmarshal(data, &batch))
					committed = batch.Sequence
					refused := map[string]string{}
					if tc.refused {
						for _, record := range batch.Records {
							refused[record.RecordUID] = db.FederationCollision
						}
					}
					_ = json.NewEncoder(w).Encode(BatchAck{Committed: committed, Refused: refused})
				}
			}))
			t.Cleanup(hub.Close)
			file := filepath.Join(testutil.PrivateTempDir(t), "credential")
			require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0600))
			svc := NewService("spoke", "spoke", policy, archive)
			require.NoError(t, svc.Join(ctx, hub.URL, "hub", file))
			link, err := archive.GetFederationLink(ctx)
			require.NoError(t, err)
			remote := "github.com/example/api"
			key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
			require.NoError(t, archive.Update(ctx, func(tx *sql.Tx) error {
				if _, e := tx.ExecContext(ctx, `INSERT INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','install')`); e != nil {
					return e
				}
				for i := 0; i < tc.count; i++ {
					id := fmt.Sprintf("%080d", i)
					if _, e := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count) VALUES(?,'fixture','install','claude',?,'2026-01-02T00:00:00Z',1)`, id, id); e != nil {
						return e
					}
					if _, e := tx.ExecContext(ctx, `INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES(?,'install','claude',?)`, id, id); e != nil {
						return e
					}
					if _, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES(?,'fixture','install','2026-01-01T00:00:00Z','resolved',1,?,'git_remote',?)`, id, remote, key); e != nil {
						return e
					}
					if tc.modelBytes > 0 {
						if _, e := tx.ExecContext(ctx, `INSERT INTO usage_events(session_id,source,model,input_tokens,occurred_at,dedup_key) VALUES(?,'fixture',?,1,'2026-01-02T00:00:00Z',?)`, id, strings.Repeat("m", tc.modelBytes), id); e != nil {
							return e
						}
					}
				}
				return nil
			}))
			consent, err := json.Marshal(SharePreview{DeliveryNotice: shareDeliveryNotice})
			require.NoError(t, err)
			require.NoError(t, archive.PutFederationShare(ctx, db.FederationShare{UID: "share", LinkUID: link.UID, NormalizedRemote: remote, Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: string(consent), PolicyDigest: digest}))
			result, err := svc.Push(ctx)
			require.NoError(t, err)
			if tc.refused {
				assert.Equal(t, 1000, result.Refused)
				ledger, e := archive.FederationLedger(ctx, "share")
				require.NoError(t, e)
				require.Len(t, ledger, 1000)
				for _, row := range ledger {
					assert.Equal(t, "refused", row.State)
				}
			} else {
				assert.Equal(t, 2, result.Sent)
				require.Len(t, sizes, 2)
				for _, size := range sizes {
					assert.LessOrEqual(t, size, 16<<20)
				}
			}
		})
	}
}

func TestFederationInventoryResponseRejectsUntrustedRanges(t *testing.T) {
	page := db.FederationInventoryPage{After: "a", Through: "z", Items: []db.FederationInventoryItem{{UID: "b", Hash: "hash"}}}
	for _, tc := range []struct {
		name   string
		result db.FederationInventoryResult
	}{
		{"unknown missing", db.FederationInventoryResult{Boundary: "a", Covered: "z", Missing: []string{"c"}}},
		{"duplicate extra", db.FederationInventoryResult{Boundary: "a", Covered: "z", Extra: []string{"c", "c"}}},
		{"extra outside coverage", db.FederationInventoryResult{Boundary: "a", Covered: "c", Extra: []string{"d"}}},
		{"premature complete", db.FederationInventoryResult{Complete: true}},
		{"advance while repairing", db.FederationInventoryResult{Boundary: "z", Covered: "z", Missing: []string{"b"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Error(t, validateFederationInventoryResponse(page, tc.result))
		})
	}
	assert.NoError(t, validateFederationInventoryResponse(page, db.FederationInventoryResult{Boundary: "a", Covered: "z", Missing: []string{"b"}}))
	assert.NoError(t, validateFederationInventoryResponse(page, db.FederationInventoryResult{Boundary: "z", Covered: "z"}))
}

func TestRetainedNarrowingDoesNotInferDeletionAfterArchiveReplacement(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	service := NewService("spoke", "spoke", config.FederationHubConfig{}, archive)
	share := db.FederationShare{UID: "share", State: "paused", StopReceipt: "retained", SourceGeneration: "replaced-generation"}
	_, err = archive.GetDatabaseID(t.Context())
	require.NoError(t, err)
	err = service.processRetainedNarrowing(t.Context(), db.FederationLink{TokenFile: "/missing"}, []db.FederationShare{share}, &PushResult{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "retained share archive generation changed")
}

func TestRetainedPendingTombstoneIsNotReplayedAfterRestore(t *testing.T) {
	ctx := t.Context()
	archive, err := db.OpenIsolated(ctx, filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	generation, err := archive.GetDatabaseID(ctx)
	require.NoError(t, err)
	remote := "github.com/example/api"
	key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
	require.NoError(t, archive.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','install')`,
			`INSERT INTO sessions(id,project,machine,agent,file_path) VALUES('restored','p','install','claude','fixture')`,
			`INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES('restored','install','claude','fixture')`,
		} {
			if _, e := tx.ExecContext(ctx, q); e != nil {
				return e
			}
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES('restored','p','install','2026-01-01T00:00:00Z','resolved',1,?,'git_remote',?)`, remote, key)
		return e
	}))
	policy := config.FederationHubConfig{Retention: "org-retained", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	batches := 0
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			batches++
			http.Error(w, "unexpected delivery", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(HandshakeResponse{HubArchiveID: "hub", ProtocolVersions: []int{ProtocolVersion}, EnrollmentUID: "enr", Member: "member", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest})
	}))
	t.Cleanup(hub.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0600))
	batch, err := json.Marshal(Batch{Protocol: ProtocolVersion, SpokeInstance: "spoke", ShareUID: "share", Epoch: 1, Sequence: 1, Records: []BatchRecord{{RecordUID: "restored", Kind: "tombstone"}}})
	require.NoError(t, err)
	share := db.FederationShare{UID: "share", State: "paused", NormalizedRemote: remote, StopReceipt: "retained", SourceGeneration: generation, Epoch: 1, PendingBatch: string(batch)}
	svc := NewService("spoke", "spoke", policy, archive)
	err = svc.processRetainedNarrowing(ctx, db.FederationLink{HubOrigin: hub.URL, HubArchiveID: "hub", TokenFile: file}, []db.FederationShare{share}, &PushResult{})
	require.ErrorContains(t, err, "unresolved deletion after restore")
	assert.Zero(t, batches)
}
