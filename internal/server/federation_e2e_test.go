package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/dbtest"
	"go.kenn.io/agentsview/internal/export"
	"go.kenn.io/agentsview/internal/federation"
	"go.kenn.io/agentsview/internal/service"
	"go.kenn.io/agentsview/internal/testutil"
)

func TestFederationRevokePublishesCommittedPartialCleanup(t *testing.T) {
	ctx := t.Context()
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "hub.db"))
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	oldPolicy := policy
	oldPolicy.MinGroupSize++
	oldDigest, err := export.DigestCanonical(oldPolicy)
	require.NoError(t, err)
	require.NoError(t, database.CreateFederationEnrollment(ctx, db.FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	for _, item := range []struct{ uid, retention, policy string }{{"known", "member-controlled", digest}, {"legacy", "", oldDigest}} {
		share := db.FederationHubShare{UID: item.uid, EnrollmentUID: "enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: item.policy, Epoch: 1, State: "active", Retention: item.retention}
		_, err := database.PutFederationHubShare(ctx, "spoke", share)
		require.NoError(t, err)
		record := db.FederationHubRecord{UID: item.uid, Hash: "hash", Remote: share.Remote, ProjectKey: share.ProjectKey, Write: db.SessionBatchWrite{Session: db.Session{ID: item.uid, Project: "fixture", Machine: "federated", Agent: "claude"}}}
		_, err = database.CommitFederationBatch(ctx, "enr", "spoke", item.uid, item.policy, 1, 1, "batch", []db.FederationHubRecord{record})
		require.NoError(t, err)
	}
	require.NoError(t, database.CreateFederationEnrollment(ctx, db.FederationEnrollment{UID: "other-enr", SpokeArchiveID: "other-spoke", Member: "other", CredentialSHA256: "other-digest"}))
	other := db.FederationHubShare{UID: "other-share", EnrollmentUID: "other-enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: digest, Epoch: 1, State: "active", Retention: "member-controlled"}
	_, err = database.PutFederationHubShare(ctx, "other-spoke", other)
	require.NoError(t, err)
	otherRecord := db.FederationHubRecord{UID: "other", Hash: "hash", Remote: other.Remote, ProjectKey: other.ProjectKey, Write: db.SessionBatchWrite{Session: db.Session{ID: "other", Project: "fixture", Machine: "federated", Agent: "claude"}}}
	_, err = database.CommitFederationBatch(ctx, "other-enr", "other-spoke", other.UID, digest, 1, 1, "other", []db.FederationHubRecord{otherRecord})
	require.NoError(t, err)
	require.NoError(t, database.Update(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent) VALUES('collision','fixture','host','claude')`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO messages(session_id,ordinal,role,content) VALUES('collision',0,'user','original')`)
		return err
	}))
	collision := db.FederationHubRecord{UID: "collision", Hash: "hash", Remote: other.Remote, ProjectKey: other.ProjectKey, Write: db.SessionBatchWrite{Session: db.Session{ID: "collision", Project: "fixture", Machine: "federated", Agent: "claude"}}}
	refusal, err := database.CommitFederationBatch(ctx, "enr", "spoke", "known", digest, 1, 2, "collision", []db.FederationHubRecord{collision})
	require.NoError(t, err)
	assert.Equal(t, db.FederationCollision, refusal.Refused["collision"])
	var callbacks atomic.Int32
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, database, nil, WithFederation(federation.NewService("hub", "hub", policy, database)), WithSessionMutationNotifier(func() {
		var known int
		err := database.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id='known'`).Scan(&known)
		assert.NoError(t, err)
		assert.Zero(t, known) // The callback observes the committed purge.
		callbacks.Add(1)
	}))
	srv.broadcaster = NewBroadcaster(0)
	events, unsubscribe := srv.broadcaster.Subscribe()
	defer unsubscribe()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/federation/enrollments/enr/revoke", nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	response := httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req)
	// Pending legacy cleanup still publishes the known share's committed purge.
	assert.Equal(t, http.StatusBadRequest, response.Code)
	assert.Contains(t, response.Body.String(), "cleanup pending")
	require.NotEmpty(t, events)
	assert.Equal(t, "sessions", (<-events).Scope)
	assert.EqualValues(t, 1, callbacks.Load())
	var known, legacy int
	require.NoError(t, database.Reader().QueryRow(ctx, `SELECT (SELECT count(*) FROM sessions WHERE id='known'),(SELECT count(*) FROM sessions WHERE id='legacy')`).Scan(&known, &legacy))
	assert.Zero(t, known)
	assert.Equal(t, 1, legacy)
	var otherCount, messages int
	require.NoError(t, database.Reader().QueryRow(ctx, `SELECT (SELECT count(*) FROM sessions WHERE id='other'),(SELECT count(*) FROM messages WHERE session_id='collision' AND content='original')`).Scan(&otherCount, &messages))
	assert.Equal(t, 1, otherCount)
	assert.Equal(t, 1, messages)
	_, err = database.LookupFederationCredential(ctx, "digest", "spoke")
	assert.ErrorIs(t, err, db.ErrFederationUnauthorized)
	response = httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req.Clone(ctx))
	assert.Empty(t, events)
	assert.EqualValues(t, 1, callbacks.Load())
	// Matching original policy proof resolves the legacy row and publishes it.
	srv.federation = federation.NewService("hub", "hub", oldPolicy, database)
	response = httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req.Clone(ctx))
	assert.Equal(t, http.StatusOK, response.Code)
	require.NotEmpty(t, events)
	assert.Equal(t, "sessions", (<-events).Scope)
	assert.EqualValues(t, 2, callbacks.Load())
	require.NoError(t, database.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id='legacy'`).Scan(&legacy))
	assert.Zero(t, legacy)
	response = httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req.Clone(ctx))
	assert.Empty(t, events)
	assert.EqualValues(t, 2, callbacks.Load())
}

func TestFederationSummaryDelivery(t *testing.T) {
	ctx := t.Context()
	hubDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "hub.db"))
	spokeDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "spoke.db"))
	cfg, err := config.Default()
	require.NoError(t, err)
	policy := cfg.Federation.Hub
	hub := federation.NewService("hub", "hub-a", policy, hubDB)
	_, token, err := hub.Enroll(ctx, "spoke-a", "member-a", "")
	require.NoError(t, err)
	var mutations atomic.Int32
	server := New(config.Config{Host: "127.0.0.1", Port: 8080}, hubDB, nil, WithFederation(hub), WithSessionMutationNotifier(func() { mutations.Add(1) }))
	server.broadcaster = NewBroadcaster(0)
	events, unsubscribe := server.broadcaster.Subscribe()
	defer unsubscribe()
	var captured bytes.Buffer
	dropFirst := true
	conflictNext, rejectNext := false, false
	offline := false
	changeContributorAfterBatch := false
	batches := 0
	var batchBodies []string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if offline {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		if r.Body != nil {
			data, e := io.ReadAll(r.Body)
			require.NoError(t, e)
			captured.Write(data)
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/batches") {
				batchBodies = append(batchBodies, string(data))
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/batches") {
			batches++
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/batches") && conflictNext {
			conflictNext = false
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"committed":2,"refused":{}}`))
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/batches") && rejectNext {
			rejectNext = false
			http.Error(w, "invalid federation batch", http.StatusBadRequest)
			return
		}
		if dropFirst && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/batches") {
			dropFirst = false
			buffered := httptest.NewRecorder()
			server.Handler().ServeHTTP(buffered, r)
			require.Equal(t, http.StatusOK, buffered.Code)
			conn, _, e := w.(http.Hijacker).Hijack()
			require.NoError(t, e)
			require.NoError(t, conn.Close())
			return
		}
		if changeContributorAfterBatch && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/batches") {
			changeContributorAfterBatch = false
			buffered := httptest.NewRecorder()
			server.Handler().ServeHTTP(buffered, r)
			require.Equal(t, http.StatusOK, buffered.Code)
			require.NoError(t, spokeDB.SoftDeleteSession(ctx, "a-snapshot-peer"))
			for key, values := range buffered.Header() {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(buffered.Code)
			_, _ = w.Write(buffered.Body.Bytes())
			return
		}
		server.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(peer.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte(token), 0600))
	spoke := federation.NewService("spoke", "spoke-a", policy, spokeDB)
	spokeServer := New(config.Config{Host: "127.0.0.1", Port: 8080}, spokeDB, nil, WithFederation(spoke))
	daemon := httptest.NewServer(spokeServer.Handler())
	t.Cleanup(daemon.Close)
	request := func(method, path string, body any, result any) int {
		var input io.Reader
		if body != nil {
			data, e := json.Marshal(body)
			require.NoError(t, e)
			input = bytes.NewReader(data)
		}
		req, e := http.NewRequestWithContext(ctx, method, daemon.URL+path, input)
		require.NoError(t, e)
		req.Host = "127.0.0.1:8080"
		req.Header.Set("Origin", "http://127.0.0.1:8080")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, e := http.DefaultClient.Do(req)
		require.NoError(t, e)
		defer resp.Body.Close()
		if result != nil && resp.StatusCode == http.StatusOK {
			require.NoError(t, json.NewDecoder(resp.Body).Decode(result))
		}
		return resp.StatusCode
	}
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/link", map[string]string{"hub": peer.URL, "hub_archive": "hub-a", "credential_file": file}, nil))
	remote := "github.com/example/api"
	key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','install-a')`,
			`INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count,user_message_count,cwd,git_branch,first_message,display_name,session_name,pr_links) VALUES('session-a','fixture','install-a','claude','CANARY-file','2026-01-02T00:00:00Z',2,1,'CANARY-path','CANARY-branch','CANARY-first','CANARY-title','CANARY-name','[{"url":"CANARY-pr"}]')`,
			`INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES('session-a','install-a','claude','CANARY-file')`,
			`INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count) VALUES('session-b','fixture','install-a','claude','session-b','2026-01-02T00:00:00Z',1)`,
			`INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES('session-b','install-a','claude','session-b')`,
			`INSERT INTO session_project_assignments(session_id,project,original_project) VALUES('session-a','CANARY-renamed-label','CANARY-personal-folder')`,
			`UPDATE sessions SET project='CANARY-personal-folder' WHERE id='session-a'`,
			`INSERT INTO messages(session_id,ordinal,role,content) VALUES('session-a',0,'user','CANARY-message')`,
			`INSERT INTO tool_calls(message_id,session_id,tool_name,category,input_json,result_content) SELECT id,session_id,'CANARY-tool','CANARY-category','CANARY-input','CANARY-result' FROM messages WHERE session_id='session-a'`,
			`INSERT INTO usage_events(session_id,source,model,input_tokens,output_tokens,cost_microdollars,cost_status,cost_source,occurred_at,dedup_key) VALUES('session-a','fixture','model-a',100,20,50,'exact','reported','2026-01-02T00:00:00Z','a')`,
		} {
			if _, e := tx.ExecContext(ctx, q); e != nil {
				return e
			}
		}
		if _, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES('session-a','fixture','install-a','2026-01-01T00:00:00Z','resolved',1,?,'git_remote',?)`, remote, key); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES('session-b','fixture','install-a','2026-01-01T00:00:00Z','resolved',1,?,'git_remote',?)`, remote, key); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, `UPDATE session_project_identity_snapshots SET root_path='CANARY-root', repository_path='CANARY-repository', worktree_name='CANARY-worktree', worktree_root_path='CANARY-worktree-root', git_branch='CANARY-identity-branch' WHERE session_id='session-a'`); e != nil {
			return e
		}

		for _, id := range []string{"unshared", "ambiguous", "repo-less", "imported", "child", "before"} {
			start, machine, candidate, source, candidateRemote := "2026-01-02T00:00:00Z", "install-a", 1, "git_remote", remote
			if id == "before" {
				start = "2026-01-01T23:59:59Z"
			}
			if id == "imported" {
				machine = "install-b"
			}
			if id == "unshared" || id == "child" {
				candidateRemote = "github.com/example/private"
			}
			if id == "ambiguous" {
				candidate = 2
			}
			if id == "repo-less" {
				source = "root_path"
			}
			if _, e := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count,cwd,git_branch,first_message,display_name,parent_session_id) VALUES(?,'fixture',?,'claude',?,?,2,'CANARY-cwd','CANARY-branch','CANARY-first','CANARY-title','session-a')`, id, machine, id, start); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, `INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES(?,?,'claude',?)`, id, machine, id); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES(?,'fixture',?,'2026-01-01T00:00:00Z','resolved',?,?,?,?)`, id, machine, candidate, candidateRemote, source, key); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, `INSERT INTO messages(session_id,ordinal,role,content,thinking_text) VALUES(?,0,'assistant','CANARY-message','CANARY-thinking')`, id); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, `INSERT INTO tool_calls(message_id,session_id,tool_name,category,input_json,result_content) SELECT id,session_id,'CANARY-tool','CANARY-category','CANARY-input','CANARY-result' FROM messages WHERE session_id=?`, id); e != nil {
				return e
			}

		}
		return nil
	}))
	var preview federation.SharePreview
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/shares/preview", federation.ShareGrant{Project: remote, Level: "summary", Attribution: "pooled", Since: "2026-01-02"}, &preview))
	assert.Equal(t, 2, preview.Selected)
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/shares", preview, nil))
	var dry federation.SummaryRecord
	require.Equal(t, http.StatusOK, request(http.MethodGet, "/api/v1/federation/dry-run", nil, &dry))
	assert.Equal(t, "session-a", dry.SessionID)
	dryJSON, err := json.Marshal(dry)
	require.NoError(t, err)
	assert.NotContains(t, string(dryJSON), "CANARY")
	assert.NotEqual(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, nil))
	assert.Equal(t, int32(1), mutations.Load())
	require.NotEmpty(t, events)
	assert.Equal(t, "sessions", (<-events).Scope)
	var committed int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id='session-a'`).Scan(&committed))
	assert.Equal(t, 1, committed)
	shares, err := spokeDB.ListFederationShares(ctx, func() string { link, e := spokeDB.GetFederationLink(ctx); require.NoError(t, e); return link.UID }())
	require.NoError(t, err)
	require.Len(t, shares, 1)
	ledger, err := spokeDB.FederationLedger(ctx, shares[0].UID)
	require.NoError(t, err)
	assert.Equal(t, "unconfirmed", ledger["session-a"].State)
	assert.NotEmpty(t, ledger["session-a"].AttemptHash)
	assert.Equal(t, "unconfirmed", ledger["session-b"].State)
	excludedAttempt := ledger["session-b"].AttemptHash
	require.NotEmpty(t, excludedAttempt)
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/exclusions", map[string]string{"session_id": "session-b"}, nil))
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `UPDATE sessions SET message_count=3 WHERE id='session-a'`)
		return e
	}))
	var first federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &first))
	// Exclusion makes the uncertain envelope unsafe to replay. The first
	// retry starts a new epoch; the next push delivers the current selection.
	assert.Zero(t, first.Sent)
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &first))
	assert.Equal(t, 1, first.Sent)
	assert.Equal(t, int32(2), mutations.Load())
	require.NotEmpty(t, events)
	assert.Equal(t, "sessions", (<-events).Scope)
	require.GreaterOrEqual(t, len(batchBodies), 2)
	assert.NotContains(t, captured.String(), "CANARY")
	var machine, project string
	var messages, tools, usage, input, output int
	var hasOutput bool
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT machine,project,(SELECT count(*) FROM messages WHERE session_id=s.id),(SELECT count(*) FROM tool_calls WHERE session_id=s.id),(SELECT count(*) FROM usage_events WHERE session_id=s.id),(SELECT COALESCE(sum(input_tokens),0) FROM usage_events WHERE session_id=s.id),total_output_tokens,has_total_output_tokens FROM sessions s WHERE id='session-a'`).Scan(&machine, &project, &messages, &tools, &usage, &input, &output, &hasOutput))
	assert.Equal(t, "federated", machine)
	assert.Equal(t, remote, project)
	assert.Zero(t, messages)
	assert.Zero(t, tools)
	assert.Equal(t, 1, usage)
	assert.Equal(t, 100, input)
	assert.Equal(t, 20, output)
	assert.True(t, hasOutput)
	var unchangedBatch federation.Batch
	require.NoError(t, json.Unmarshal([]byte(batchBodies[1]), &unchangedBatch))
	require.Len(t, unchangedBatch.Records, 2)
	assert.Equal(t, "session-a", unchangedBatch.Records[0].RecordUID)
	assert.Equal(t, "session-b", unchangedBatch.Records[1].RecordUID)
	assert.Equal(t, "tombstone", unchangedBatch.Records[1].Kind)
	assert.Nil(t, unchangedBatch.Records[1].Payload)
	unchangedAck, err := federation.PostBatch(ctx, peer.URL, token, "spoke-a", unchangedBatch)
	require.NoError(t, err)
	assert.Equal(t, unchangedBatch.Sequence, unchangedAck.Committed)
	assert.Equal(t, int32(2), mutations.Load())
	assert.Empty(t, events)
	failedBatch := unchangedBatch
	failedBatch.Sequence++
	failedBatch.Records = append([]federation.BatchRecord(nil), unchangedBatch.Records...)
	failedBatch.Records[0].Payload.MessageCount++
	failedBatch.Records[0].Hash, err = export.DigestCanonical(failedBatch.Records[0].Payload)
	require.NoError(t, err)
	// The maintenance barrier leaves peer authentication readable but makes
	// the validated batch fail at the persistence owner.
	require.NoError(t, hubDB.CloseWriter())
	t.Cleanup(func() {
		if hubDB.WriterClosed() {
			assert.NoError(t, hubDB.ReopenWriter())
		}
	})
	_, err = federation.PostBatch(ctx, peer.URL, token, "spoke-a", failedBatch)
	require.Error(t, err)
	assert.ErrorContains(t, err, "hub returned HTTP 503")
	require.NoError(t, hubDB.ReopenWriter())
	assert.Equal(t, int32(2), mutations.Load())
	assert.Empty(t, events)
	var afterFailedWrite int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT message_count FROM sessions WHERE id='session-a'`).Scan(&afterFailedWrite))
	assert.Equal(t, 3, afterFailedWrite)
	var afterFailedSequence int64
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT sequence FROM federation_hub_shares WHERE share_uid=?`, unchangedBatch.ShareUID).Scan(&afterFailedSequence))
	assert.Equal(t, unchangedBatch.Sequence, afterFailedSequence)
	invalidBatch := unchangedBatch
	invalidBatch.Sequence++
	invalidBatch.Records = append([]federation.BatchRecord(nil), unchangedBatch.Records...)
	invalidBatch.Records[0].Hash = "invalid"
	_, err = federation.PostBatch(ctx, peer.URL, token, "spoke-a", invalidBatch)
	require.Error(t, err)
	assert.Equal(t, int32(2), mutations.Load())
	assert.Empty(t, events)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "session-a")
	for _, id := range []string{"unshared", "ambiguous", "repo-less", "imported", "child", "before"} {
		assert.NotContains(t, rec.Body.String(), `"id":"`+id+`"`)
	}
	assert.NotContains(t, rec.Body.String(), "CANARY")
	for _, endpoint := range []string{"/api/v1/usage/summary", "/api/v1/analytics/tools"} {
		req = httptest.NewRequest(http.MethodGet, endpoint+"?from=2026-01-02&to=2026-01-02&timezone=UTC", nil)
		rec = httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.NotContains(t, rec.Body.String(), "CANARY")
		if strings.Contains(endpoint, "usage") {
			var result service.UsageSummaryResult
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
			assert.Equal(t, 100, result.Totals.InputTokens)
			assert.Equal(t, 20, result.Totals.OutputTokens)
			assert.EqualValues(t, 50, result.Totals.TotalCost.Microdollars)
		} else {
			var result db.ToolsAnalyticsResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
			assert.Zero(t, result.TotalCalls)
		}
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/analytics/summary?from=2026-01-02&to=2026-01-02&timezone=UTC&include_one_shot=true", nil)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var summary db.AnalyticsSummary
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &summary))
	assert.Equal(t, 1, summary.TotalSessions)
	assert.Equal(t, 3, summary.TotalMessages)
	assert.NotContains(t, rec.Body.String(), "CANARY")
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO usage_events(session_id,source,model,output_tokens,cost_microdollars,cost_status,cost_source,occurred_at,dedup_key) VALUES('session-a','fixture','model-b',7,25,'exact','reported','2026-01-02T00:00:00Z','b')`)
		return err
	}))
	var modelGrowth federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &modelGrowth))
	assert.Equal(t, 1, modelGrowth.Sent)
	assert.Equal(t, int32(3), mutations.Load())
	require.NotEmpty(t, events)
	assert.Equal(t, "sessions", (<-events).Scope)
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT total_output_tokens,has_total_output_tokens FROM sessions WHERE id='session-a'`).Scan(&output, &hasOutput))
	assert.Equal(t, 27, output)
	assert.True(t, hasOutput)
	var removedCount int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id='session-b'`).Scan(&removedCount))
	assert.Zero(t, removedCount)
	for _, tc := range []struct {
		model                            string
		sessions, messages, output, cost int
	}{
		{"model-a", 1, 3, 20, 50}, {"model-b", 1, 3, 7, 25}, {"absent", 0, 0, 0, 0},
	} {
		req = httptest.NewRequest(http.MethodGet, "/api/v1/analytics/summary?from=2026-01-02&to=2026-01-02&timezone=UTC&include_one_shot=true&model="+tc.model, nil)
		rec = httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		var scoped db.AnalyticsSummary
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &scoped))
		assert.Equal(t, tc.sessions, scoped.TotalSessions)
		assert.Equal(t, tc.messages, scoped.TotalMessages)
		assert.Equal(t, tc.output, scoped.TotalOutputTokens)
		req = httptest.NewRequest(http.MethodGet, "/api/v1/usage/summary?from=2026-01-02&to=2026-01-02&timezone=UTC&model="+tc.model, nil)
		rec = httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		var filteredUsage service.UsageSummaryResult
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &filteredUsage))
		assert.EqualValues(t, tc.cost, filteredUsage.Totals.TotalCost.Microdollars)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/analytics/activity?from=2026-01-02&to=2026-01-02&timezone=UTC&include_one_shot=true&model=model-a", nil)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var activity db.ActivityResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &activity))
	require.Len(t, activity.Series, 1)
	assert.Equal(t, 1, activity.Series[0].Sessions)
	assert.Equal(t, 3, activity.Series[0].Messages)
	assert.Zero(t, activity.Series[0].ToolCalls)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/analytics/activity?from=2026-01-02&to=2026-01-02&timezone=UTC&include_one_shot=true", nil)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &activity))
	require.Len(t, activity.Series, 1)
	assert.Equal(t, 1, activity.Series[0].Sessions)
	assert.Equal(t, 3, activity.Series[0].Messages)
	assert.Zero(t, activity.Series[0].ToolCalls)
	var again federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &again))
	assert.Zero(t, again.Sent)
	assert.Equal(t, int32(3), mutations.Load())
	assert.Empty(t, events)
	assert.Equal(t, 1, again.Unchanged)
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `UPDATE sessions SET message_count=4 WHERE id='session-a'`)
		return e
	}))
	conflictNext = true
	assert.NotEqual(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, nil))
	rejectNext = true
	assert.NotEqual(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, nil))
	assert.Equal(t, int32(3), mutations.Load())
	assert.Empty(t, events)
	quarantines, err := spokeDB.FederationQuarantines(ctx)
	require.NoError(t, err)
	require.Len(t, quarantines, 1)
	assert.Equal(t, "hub rejected batch", quarantines[0].Error)
	var changed federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &changed))
	assert.Equal(t, 1, changed.Sent)
	assert.Equal(t, int32(4), mutations.Load())
	require.NotEmpty(t, events)
	assert.Equal(t, "sessions", (<-events).Scope)
	quarantines, err = spokeDB.FederationQuarantines(ctx)
	require.NoError(t, err)
	assert.Empty(t, quarantines)
	var count, storedMessages int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*),max(message_count) FROM sessions WHERE id='session-a'`).Scan(&count, &storedMessages))
	assert.Equal(t, 1, count)
	assert.Equal(t, 4, storedMessages)
	assert.False(t, strings.Contains(captured.String(), "CANARY"))

	// A local hub row with the incoming ID is never overwritten and the
	// acknowledged refusal is retained rather than retried on the next pass.
	require.NoError(t, hubDB.Update(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent,message_count) VALUES('collision','hub-local','hub-host','claude',9)`); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO messages(session_id,ordinal,role,content) VALUES('collision',0,'user','local message')`)
		return e
	}))
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count) VALUES('collision','fixture','install-a','claude','collision','2026-01-02T00:00:00Z',4)`,
			`INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES('collision','install-a','claude','collision')`,
		} {
			if _, e := tx.ExecContext(ctx, q); e != nil {
				return e
			}
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES('collision','fixture','install-a','2026-01-01T00:00:00Z','resolved',1,?,'git_remote',?)`, remote, key)
		return e
	}))
	var refused federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &refused))
	assert.Equal(t, 1, refused.Refused)
	assert.Equal(t, 1, refused.Quarantined)
	assert.Equal(t, int32(4), mutations.Load())
	assert.Empty(t, events)
	var existingProject, existingMachine string
	var existingCount int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT project,machine,message_count FROM sessions WHERE id='collision'`).Scan(&existingProject, &existingMachine, &existingCount))
	assert.Equal(t, "hub-local", existingProject)
	assert.Equal(t, "hub-host", existingMachine)
	assert.Equal(t, 9, existingCount)
	ledger, err = spokeDB.FederationLedger(ctx, shares[0].UID)
	require.NoError(t, err)
	assert.Equal(t, "refused", ledger["collision"].State)
	quarantines, err = spokeDB.FederationQuarantines(ctx)
	require.NoError(t, err)
	require.Len(t, quarantines, 1)
	assert.Equal(t, db.FederationCollision, quarantines[0].Error)
	firstCollisionSequence := quarantines[0].Sequence
	previousBatches := batches
	var retry federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &retry))
	assert.Equal(t, previousBatches, batches)
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `UPDATE sessions SET message_count=5 WHERE id='session-a'`)
		return e
	}))
	beforeAttempt, err := spokeDB.FederationLedger(ctx, shares[0].UID)
	require.NoError(t, err)
	dropFirst = true
	assert.NotEqual(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, nil))
	afterAttempt, err := spokeDB.FederationLedger(ctx, shares[0].UID)
	require.NoError(t, err)
	assert.Equal(t, "sent", afterAttempt["session-a"].State)
	assert.Equal(t, beforeAttempt["session-a"].Hash, afterAttempt["session-a"].Hash)
	assert.NotEmpty(t, afterAttempt["session-a"].AttemptHash)
	var pending federation.ShareDetails
	require.Equal(t, http.StatusOK, request(http.MethodGet, "/api/v1/federation/shares/"+shares[0].UID, nil, &pending))
	assert.Equal(t, 1, pending.Delivery.Sent)
	assert.Equal(t, 2, pending.Delivery.Unconfirmed)
	assert.Equal(t, excludedAttempt, afterAttempt["session-b"].AttemptHash)
	var delivered federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &delivered))
	assert.Equal(t, 1, delivered.Sent)
	quarantines, err = spokeDB.FederationQuarantines(ctx)
	require.NoError(t, err)
	require.Len(t, quarantines, 1)
	assert.Equal(t, db.FederationCollision, quarantines[0].Error)
	assert.Equal(t, firstCollisionSequence, quarantines[0].Sequence)
	var status federation.Status
	require.Equal(t, http.StatusOK, request(http.MethodGet, "/api/v1/federation/link", nil, &status))
	var details federation.ShareDetails
	require.Equal(t, http.StatusOK, request(http.MethodGet, "/api/v1/federation/shares/"+shares[0].UID, nil, &details))
	assert.Equal(t, 1, details.Delivery.Unconfirmed)
	assert.Equal(t, "tombstoned", afterAttempt["session-b"].State)
	// Copilot shutdown reports can contain a cost without model token metrics.
	// Exercise the real grant and delivery path for both zero and nonzero cost.
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		for _, tc := range []struct {
			id   string
			cost int
		}{{"cost-only", 30000}, {"cost-zero", 0}} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count) VALUES(?,'fixture','install-a','copilot',?,'2026-06-02T00:00:00Z',1)`, tc.id, tc.id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES(?,'install-a','copilot',?)`, tc.id, tc.id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES(?,'fixture','install-a','2026-06-02T00:00:00Z','resolved',1,?,'git_remote',?)`, tc.id, remote, key); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO usage_events(session_id,source,model,cost_microdollars,cost_status,cost_source,occurred_at,dedup_key) VALUES(?,'shutdown','copilot',?,'exact','copilot-reported','2026-06-02T00:00:00Z','total')`, tc.id, tc.cost); err != nil {
				return err
			}
		}
		return nil
	}))
	var costs federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &costs))
	assert.Equal(t, 2, costs.Sent)
	for _, tc := range []struct {
		id   string
		cost int
	}{{"cost-only", 30000}, {"cost-zero", 0}} {
		var count, cost, output int
		var model string
		require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*),sum(cost_microdollars),sum(output_tokens),min(model) FROM usage_events WHERE session_id=?`, tc.id).Scan(&count, &cost, &output, &model))
		assert.Equal(t, 1, count)
		assert.Equal(t, tc.cost, cost)
		assert.Zero(t, output)
		assert.Equal(t, "<unknown>", model)
		var hasOutput bool
		require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT has_total_output_tokens FROM sessions WHERE id=?`, tc.id).Scan(&hasOutput))
		assert.False(t, hasOutput)
	}
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE usage_events SET cost_microdollars=45000 WHERE session_id='cost-only'`)
		return err
	}))
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &costs))
	assert.Equal(t, 1, costs.Sent)
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &costs))
	assert.Zero(t, costs.Sent)
	var finalCost, costRows int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*),sum(cost_microdollars) FROM usage_events WHERE session_id='cost-only'`).Scan(&costRows, &finalCost))
	assert.Equal(t, 1, costRows)
	assert.Equal(t, 45000, finalCost)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/usage/summary?from=2026-06-02&to=2026-06-02&timezone=UTC", nil)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var costSummary service.UsageSummaryResult
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &costSummary))
	assert.EqualValues(t, 45000, costSummary.Totals.TotalCost.Microdollars)
	assert.Zero(t, costSummary.Totals.OutputTokens)
	exported, err := hubDB.ExportSessionSummaries(ctx, db.SessionExportOptions{Filter: db.SessionFilter{Project: remote}, Limit: 100, Format: "json"})
	require.NoError(t, err)
	foundCost := false
	for _, row := range exported.Rows {
		if row.ID == "cost-only" {
			foundCost = true
			require.NotNil(t, row.ModelUsage)
			assert.True(t, row.ModelUsage.HasCost)
			assert.EqualValues(t, 45000, row.ModelUsage.Cost.Microdollars)
		}
	}
	assert.True(t, foundCost)
	// Change the contributor set after the first real hub batch commits and
	// before the second is assembled. The later parent must be refreshed.
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		for i := -1; i <= 1000; i++ {
			id := fmt.Sprintf("m-batch-%04d", i)
			if i == -1 {
				id = "a-snapshot-peer"
			}
			if i == 1000 {
				id = "z-snapshot-parent"
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count) VALUES(?,'fixture','install-a','claude',?,'2026-01-02T00:00:00Z',1)`, id, id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES(?,'install-a','claude',?)`, id, id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES(?,'fixture','install-a','2026-01-01T00:00:00Z','resolved',1,?,'git_remote',?)`, id, remote, key); err != nil {
				return err
			}
			if i == -1 || i == 1000 {
				usage := `{"input_tokens":1000,"output_tokens":100}`
				if i == 1000 {
					usage = `{"input_tokens":100,"output_tokens":5}`
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO messages(session_id,ordinal,role,model,claude_message_id,claude_request_id,token_usage) VALUES(?,0,'assistant','model-a','shared','request',?)`, id, usage); err != nil {
					return err
				}
			}
		}
		return nil
	}))
	// Preview and dry run use the same grant-bounded projection as delivery.
	// Excluding the larger snapshot peer leaves only the parent's own usage.
	require.NoError(t, spokeDB.PutFederationExclusion(ctx, "a-snapshot-peer", "fixture"))
	var boundedPreview federation.SharePreview
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/shares/preview", federation.ShareGrant{Project: remote, Level: "summary", Attribution: "pooled", Since: "2026-01-02"}, &boundedPreview))
	boundedDry, err := spoke.DryRun(ctx)
	require.NoError(t, err)
	var boundedParent *federation.SummaryRecord
	for i := range boundedDry {
		if boundedDry[i].SessionID == "z-snapshot-parent" {
			boundedParent = &boundedDry[i]
		}
	}
	require.NotNil(t, boundedParent)
	assert.Equal(t, 100, boundedParent.ByModel["model-a"].InputTokens)
	assert.Equal(t, 5, boundedParent.ByModel["model-a"].OutputTokens)
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM federation_exclusions WHERE session_id='a-snapshot-peer'`)
		return err
	}))
	var fullPreview federation.SharePreview
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/shares/preview", federation.ShareGrant{Project: remote, Level: "summary", Attribution: "pooled", Since: "2026-01-02"}, &fullPreview))
	assert.Equal(t, 900, fullPreview.Usage.InputTokens-boundedPreview.Usage.InputTokens)
	assert.Equal(t, 95, fullPreview.Usage.OutputTokens-boundedPreview.Usage.OutputTokens)
	changeContributorAfterBatch = true
	var batchesBeforeChange = batches
	var chunked federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &chunked))
	assert.GreaterOrEqual(t, batches-batchesBeforeChange, 2)
	var parentInput, parentOutput int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT COALESCE(sum(input_tokens),0),COALESCE(sum(output_tokens),0) FROM usage_events WHERE session_id='z-snapshot-parent'`).Scan(&parentInput, &parentOutput))
	assert.Equal(t, 100, parentInput)
	assert.Equal(t, 5, parentOutput)
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sessions SET message_count=6 WHERE id='session-a'`)
		return err
	}))
	beforeExclusion, err := spokeDB.FederationLedger(ctx, shares[0].UID)
	require.NoError(t, err)
	dropFirst = true
	assert.NotEqual(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, nil))
	uncertain, err := spokeDB.FederationLedger(ctx, shares[0].UID)
	require.NoError(t, err)
	assert.Equal(t, beforeExclusion["session-a"].Hash, uncertain["session-a"].Hash)
	assert.NotEmpty(t, uncertain["session-a"].AttemptHash)
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/exclusions", map[string]string{"session_id": "session-a"}, nil))
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/shares/"+shares[0].UID+"/pause", nil, nil))
	offline = true
	assert.NotEqual(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, nil))
	stopped, err := spokeDB.GetFederationShare(ctx, shares[0].LinkUID, shares[0].UID)
	require.NoError(t, err)
	assert.Equal(t, "pending", stopped.StopReceipt)
	stopEvents, unsubscribeStop := server.broadcaster.Subscribe()
	defer unsubscribeStop()
	beforeStopMutations := mutations.Load()
	offline = false
	var paused federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &paused))
	assert.Zero(t, paused.Sent)
	assert.Equal(t, beforeStopMutations+1, mutations.Load())
	require.NotEmpty(t, stopEvents)
	assert.Equal(t, "sessions", (<-stopEvents).Scope)
	var spokeCount, hubCount, hubUsage int
	require.NoError(t, spokeDB.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id='session-a'`).Scan(&spokeCount))
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT (SELECT count(*) FROM sessions WHERE id='session-a'), (SELECT count(*) FROM usage_events WHERE session_id='session-a')`).Scan(&hubCount, &hubUsage))
	assert.Equal(t, 1, spokeCount, "exclusion must preserve the local session")
	assert.Zero(t, hubCount, "exclusion must remove the delivered session")
	assert.Zero(t, hubUsage, "exclusion must remove delivered usage")
	require.Equal(t, http.StatusOK, request(http.MethodDelete, "/api/v1/federation/shares/"+shares[0].UID, nil, nil))
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, nil))
	var owned, collisionMessages int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT (SELECT count(*) FROM federation_records WHERE share_uid=?), (SELECT count(*) FROM messages WHERE session_id='collision' AND content='local message')`, shares[0].UID).Scan(&owned, &collisionMessages))
	assert.Zero(t, owned, "withdrawal must remove hub record receipts")
	assert.Equal(t, 1, collisionMessages, "a refused local session must retain its messages")
	ledger, err = spokeDB.FederationLedger(ctx, shares[0].UID)
	require.NoError(t, err)
	assert.NotEmpty(t, ledger, "withdrawal must preserve local delivery accounting")
	require.Equal(t, http.StatusOK, request(http.MethodDelete, "/api/v1/federation/link", nil, nil))
	var offlineStatus federation.Status
	require.Equal(t, http.StatusOK, request(http.MethodGet, "/api/v1/federation/link", nil, &offlineStatus))
	require.Len(t, offlineStatus.History, 1)
	assert.Equal(t, peer.URL, offlineStatus.History[0].HubOrigin)
	assert.Equal(t, "hub-a", offlineStatus.History[0].HubArchiveID)
	assert.Equal(t, remote, offlineStatus.History[0].NormalizedRemote)
	var history federation.ShareDetails
	require.Equal(t, http.StatusOK, request(http.MethodGet, "/api/v1/federation/shares/"+shares[0].UID, nil, &history))
	assert.True(t, history.Historical)
	assert.Greater(t, history.Delivery.Sent, 0)
	assert.Equal(t, 2, history.Delivery.Unconfirmed)
	assert.Equal(t, "session-a", history.Records["session-a"].SessionID)
	assert.Equal(t, excludedAttempt, history.Records["session-b"].AttemptHash)
	assert.Equal(t, beforeExclusion["session-a"].Hash, history.Records["session-a"].Hash)
	assert.Equal(t, uncertain["session-a"].AttemptHash, history.Records["session-a"].AttemptHash)
	otherDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "other-hub.db"))
	otherHub := federation.NewService("hub", "hub-b", policy, otherDB)
	_, otherToken, err := otherHub.Enroll(ctx, "spoke-a", "member-a", "")
	require.NoError(t, err)
	otherServer := New(config.Config{Host: "127.0.0.1", Port: 8080}, otherDB, nil, WithFederation(otherHub))
	otherPeer := httptest.NewServer(otherServer.Handler())
	t.Cleanup(otherPeer.Close)
	otherFile := filepath.Join(testutil.PrivateTempDir(t), "other-credential")
	require.NoError(t, os.WriteFile(otherFile, []byte(otherToken), 0600))
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/link", map[string]string{"hub": otherPeer.URL, "hub_archive": "hub-b", "credential_file": otherFile}, nil))
	require.Equal(t, http.StatusOK, request(http.MethodGet, "/api/v1/federation/link", nil, &offlineStatus))
	require.Len(t, offlineStatus.History, 1)
	assert.False(t, offlineStatus.History[0].Current)
	assert.Equal(t, peer.URL, offlineStatus.History[0].HubOrigin)
	assert.Equal(t, "hub-a", offlineStatus.History[0].HubArchiveID)
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/shares/preview", federation.ShareGrant{Project: remote, Level: "summary", Attribution: "pooled", Since: "2026-01-02"}, &preview))
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/shares", preview, nil))
	newLink, err := spokeDB.GetFederationLink(ctx)
	require.NoError(t, err)
	newShares, err := spokeDB.ListFederationShares(ctx, newLink.UID)
	require.NoError(t, err)
	require.Len(t, newShares, 1)
	assert.NotEqual(t, shares[0].UID, newShares[0].UID)
	require.Equal(t, http.StatusOK, request(http.MethodGet, "/api/v1/federation/shares/"+shares[0].UID, nil, &history))
	assert.Equal(t, uncertain["session-a"].AttemptHash, history.Records["session-a"].AttemptHash)
	assert.Equal(t, peer.URL, history.Records["session-a"].HubOrigin)
	assertArchiveHasNoCanary(t, hubDB)
}

// Scan every text value, including metadata and auxiliary tables,
// so a new persistence path cannot silently retain a fixture secret.
func assertArchiveHasNoCanary(t *testing.T, archive *db.DB) {
	t.Helper()
	ctx := t.Context()
	rows, err := archive.Reader().Query(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	require.NoError(t, err)
	var tables []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		tables = append(tables, name)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	quote := func(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
	for _, table := range tables {
		columns, err := archive.Reader().Query(ctx, `SELECT name FROM pragma_table_info(?)`, table)
		require.NoError(t, err)
		var names []string
		for columns.Next() {
			var name string
			require.NoError(t, columns.Scan(&name))
			names = append(names, name)
		}
		require.NoError(t, columns.Err())
		require.NoError(t, columns.Close())
		for _, column := range names {
			var count int
			query := fmt.Sprintf(`SELECT count(*) FROM %s WHERE typeof(%s) = 'text' AND instr(%s, ?) > 0`, quote(table), quote(column), quote(column))
			require.NoError(t, archive.Reader().QueryRow(ctx, query, "CANARY").Scan(&count), "%s.%s", table, column)
			assert.Zero(t, count, "%s.%s", table, column)
		}
	}
}

// A source session can be trashed while a push waits for the first response.
func TestFederationExclusionBetweenBatches(t *testing.T) {
	ctx := t.Context()
	hubDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "hub.db"))
	spokeDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "spoke.db"))
	cfg, err := config.Default()
	require.NoError(t, err)
	hub := federation.NewService("hub", "hub-a", cfg.Federation.Hub, hubDB)
	_, token, err := hub.Enroll(ctx, "spoke-a", "member", "")
	require.NoError(t, err)
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, hubDB, nil, WithFederation(hub))
	spoke := federation.NewService("spoke", "spoke-a", cfg.Federation.Hub, spokeDB)
	var batches int
	var exclusionErr error
	var childPayload string
	var parentAfterTrash bool
	var excludedBeforeRepair bool
	var wire bytes.Buffer
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			data, e := io.ReadAll(r.Body)
			require.NoError(t, e)
			wire.Write(data)
			r.Body = io.NopCloser(bytes.NewReader(data))
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/batches") {
			batches++
			body, e := io.ReadAll(r.Body)
			require.NoError(t, e)
			childPayload += string(body)
			var batch federation.Batch
			require.NoError(t, json.Unmarshal(body, &batch))
			for _, record := range batch.Records {
				if record.RecordUID == "s1001" && record.Payload != nil && record.Payload.ParentID != nil {
					parentAfterTrash = true
				}
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			buffered := httptest.NewRecorder()
			srv.Handler().ServeHTTP(buffered, r)
			if batches == 1 && buffered.Code == http.StatusOK {
				exclusionErr = spokeDB.SoftDeleteSession(r.Context(), "s1000")
			}
			for key, values := range buffered.Header() {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(buffered.Code)
			_, _ = w.Write(buffered.Body.Bytes())
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/reconcile") && !excludedBeforeRepair {
			buffered := httptest.NewRecorder()
			srv.Handler().ServeHTTP(buffered, r)
			var response db.FederationInventoryResult
			if buffered.Code == http.StatusOK {
				require.NoError(t, json.Unmarshal(buffered.Body.Bytes(), &response))
				if response.Complete {
					require.NoError(t, spokeDB.PutFederationExclusion(r.Context(), "s0999", "private"))
					excludedBeforeRepair = true
				}
			}
			for key, values := range buffered.Header() {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(buffered.Code)
			_, _ = w.Write(buffered.Body.Bytes())
			return
		}
		srv.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(peer.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte(token), 0600))
	require.NoError(t, spoke.Join(ctx, peer.URL, "hub-a", file))
	remote := "github.com/example/api"
	key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, `INSERT INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','install-a')`); e != nil {
			return e
		}
		for i := 0; i < 1002; i++ {
			id := fmt.Sprintf("s%04d", i)
			if _, e := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count) VALUES(?,'fixture','install-a','claude',?,'2026-01-02T00:00:00Z',1)`, id, id); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, `INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES(?,'install-a','claude',?)`, id, id); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES(?,'fixture','install-a','2026-01-01T00:00:00Z','resolved',1,?,'git_remote',?)`, id, remote, key); e != nil {
				return e
			}
		}
		if _, e := tx.ExecContext(ctx, `UPDATE sessions SET parent_session_id='s1000', relationship_type='subagent', cwd='CANARY-path',git_branch='CANARY-branch',first_message='CANARY-first',display_name='CANARY-title',session_name='CANARY-name',pr_links='CANARY-links' WHERE id='s1001'`); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, `INSERT INTO usage_events(session_id,source,model,input_tokens,output_tokens,cost_status,occurred_at,dedup_key) VALUES('s0000','fixture','model-a',100,20,'unknown','2026-01-02T00:00:00Z','page-child')`); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, `UPDATE sessions SET parent_session_id='s0999', relationship_type='subagent' WHERE id='s0001'`); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, `UPDATE sessions SET parent_session_id='s1001', relationship_type='subagent' WHERE id='s0000'`)
		return e
	}))
	preview, err := spoke.PreviewShare(ctx, federation.ShareGrant{Project: remote, Level: "summary", Attribution: "pooled"})
	require.NoError(t, err)
	require.Len(t, preview.Records, 1002)
	require.NoError(t, spoke.AddShare(ctx, preview))
	result, err := spoke.Push(ctx)
	require.NoError(t, err)
	require.NoError(t, exclusionErr)
	assert.Equal(t, 1002, result.Sent)
	assert.Equal(t, 4, batches)
	assert.Contains(t, childPayload, "s1001")
	assert.False(t, parentAfterTrash)
	assert.True(t, excludedBeforeRepair)
	assert.NotContains(t, wire.String(), "CANARY")
	var count, excluded int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*),coalesce(sum(id='s1000'),0) FROM sessions`).Scan(&count, &excluded))
	assert.Equal(t, 1001, count)
	assert.Zero(t, excluded)
	var parent, relationship string
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT coalesce(parent_session_id,''),relationship_type FROM sessions WHERE id='s0000'`).Scan(&parent, &relationship))
	assert.Equal(t, "s1001", parent)
	assert.Equal(t, "subagent", relationship)
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT coalesce(parent_session_id,''),relationship_type FROM sessions WHERE id='s0001'`).Scan(&parent, &relationship))
	assert.Empty(t, parent)
	assert.Empty(t, relationship)
	var usageRows, inputTokens int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*),coalesce(sum(input_tokens),0) FROM usage_events WHERE session_id='s0000'`).Scan(&usageRows, &inputTokens))
	assert.Equal(t, 1, usageRows)
	assert.Equal(t, 100, inputTokens)
	_, err = spoke.Push(ctx)
	require.NoError(t, err)
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&count))
	assert.Equal(t, 1000, count)
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*),coalesce(sum(input_tokens),0) FROM usage_events WHERE session_id='s0000'`).Scan(&usageRows, &inputTokens))
	assert.Equal(t, 1, usageRows)
	assert.Equal(t, 100, inputTokens)
	assertArchiveHasNoCanary(t, hubDB)
}

func TestFederationLostReplyKeepsExcludedAttempt(t *testing.T) {
	ctx := t.Context()
	hubDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "hub.db"))
	spokeDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "spoke.db"))
	cfg, err := config.Default()
	require.NoError(t, err)
	hub := federation.NewService("hub", "hub-a", cfg.Federation.Hub, hubDB)
	_, token, err := hub.Enroll(ctx, "spoke-a", "member", "")
	require.NoError(t, err)
	server := New(config.Config{Host: "127.0.0.1", Port: 8080}, hubDB, nil, WithFederation(hub))
	dropped := false
	var batches []string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/batches") {
			data, e := io.ReadAll(r.Body)
			require.NoError(t, e)
			batches = append(batches, string(data))
			r.Body = io.NopCloser(bytes.NewReader(data))
			if !dropped {
				dropped = true
				buffered := httptest.NewRecorder()
				server.Handler().ServeHTTP(buffered, r)
				require.Equal(t, http.StatusOK, buffered.Code)
				conn, _, e := w.(http.Hijacker).Hijack()
				require.NoError(t, e)
				require.NoError(t, conn.Close())
				return
			}
		}
		server.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(peer.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte(token), 0600))
	spoke := federation.NewService("spoke", "spoke-a", cfg.Federation.Hub, spokeDB)
	require.NoError(t, spoke.Join(ctx, peer.URL, "hub-a", file))
	remote := "github.com/example/api"
	key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, `INSERT INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','install-a')`); e != nil {
			return e
		}
		for _, id := range []string{"excluded", "selected"} {
			if _, e := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count) VALUES(?,'fixture','install-a','claude',?,'2026-01-02T00:00:00Z',1)`, id, id); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, `INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES(?,'install-a','claude',?)`, id, id); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES(?,'fixture','install-a','2026-01-01T00:00:00Z','resolved',1,?,'git_remote',?)`, id, remote, key); e != nil {
				return e
			}
		}
		return nil
	}))
	preview, err := spoke.PreviewShare(ctx, federation.ShareGrant{Project: remote, Level: "summary", Attribution: "pooled"})
	require.NoError(t, err)
	require.NoError(t, spoke.AddShare(ctx, preview))
	link, err := spokeDB.GetFederationLink(ctx)
	require.NoError(t, err)
	shares, err := spokeDB.ListFederationShares(ctx, link.UID)
	require.NoError(t, err)
	require.Len(t, shares, 1)
	_, err = spoke.Push(ctx)
	require.Error(t, err)
	var committedCount int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id IN ('excluded','selected')`).Scan(&committedCount))
	assert.Equal(t, 2, committedCount)
	ledger, err := spokeDB.FederationLedger(ctx, shares[0].UID)
	require.NoError(t, err)
	attempted := ledger["excluded"].AttemptHash
	require.NotEmpty(t, attempted)
	require.NoError(t, spoke.Exclude(ctx, "excluded", "private"))
	result, err := spoke.Push(ctx)
	require.NoError(t, err)
	assert.Zero(t, result.Sent)
	result, err = spoke.Push(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Sent)
	require.Len(t, batches, 2)
	assert.NotContains(t, batches[1], "excluded")
	ledger, err = spokeDB.FederationLedger(ctx, shares[0].UID)
	require.NoError(t, err)
	assert.Equal(t, "unconfirmed", ledger["excluded"].State)
	assert.Empty(t, ledger["excluded"].Hash)
	assert.Equal(t, attempted, ledger["excluded"].AttemptHash)
	assert.Equal(t, "sent", ledger["selected"].State)
	assert.Empty(t, ledger["selected"].AttemptHash)
	details, err := spoke.Share(ctx, shares[0].UID)
	require.NoError(t, err)
	assert.Equal(t, 1, details.Delivery.Unconfirmed)
}

// Individual deletion paths must converge while the share remains active.
func TestFederationIndividualWithdrawalKeepsOtherSession(t *testing.T) {
	for _, operation := range []string{"exclude", "archive deletion"} {
		t.Run(operation, func(t *testing.T) {
			ctx := t.Context()
			hubDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "hub.db"))
			spokeDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "spoke.db"))
			cfg, err := config.Default()
			require.NoError(t, err)
			hub := federation.NewService("hub", "hub-a", cfg.Federation.Hub, hubDB)
			_, token, err := hub.Enroll(ctx, "spoke-a", "member", "")
			require.NoError(t, err)
			hubServer := httptest.NewServer(New(config.Config{Host: "127.0.0.1", Port: 8080}, hubDB, nil, WithFederation(hub)).Handler())
			t.Cleanup(hubServer.Close)
			file := filepath.Join(testutil.PrivateTempDir(t), "credential")
			require.NoError(t, os.WriteFile(file, []byte(token), 0600))
			spoke := federation.NewService("spoke", "spoke-a", cfg.Federation.Hub, spokeDB)
			spokeServer := httptest.NewServer(New(config.Config{Host: "127.0.0.1", Port: 8080}, spokeDB, nil, WithFederation(spoke)).Handler())
			t.Cleanup(spokeServer.Close)
			request := func(method, endpoint string, payload any) {
				var body io.Reader
				if payload != nil {
					data, e := json.Marshal(payload)
					require.NoError(t, e)
					body = bytes.NewReader(data)
				}
				req, e := http.NewRequestWithContext(ctx, method, spokeServer.URL+endpoint, body)
				require.NoError(t, e)
				if payload != nil {
					req.Header.Set("Content-Type", "application/json")
				}
				resp, e := http.DefaultClient.Do(req)
				require.NoError(t, e)
				resp.Body.Close()
				require.Equal(t, http.StatusOK, resp.StatusCode)
			}
			require.NoError(t, spoke.Join(ctx, hubServer.URL, "hub-a", file))
			remote := "github.com/example/repo"
			key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
			sourceDir := t.TempDir()
			require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
				if _, e := tx.ExecContext(ctx, `INSERT INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','install')`); e != nil {
					return e
				}
				for _, id := range []string{"a", "b"} {
					path := filepath.Join(sourceDir, id)
					if _, e := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count) VALUES(?,'fixture','install','claude',?,'2026-01-02T00:00:00Z',1)`, id, path); e != nil {
						return e
					}
					if _, e := tx.ExecContext(ctx, `INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES(?,'install','claude',?)`, id, path); e != nil {
						return e
					}
					if _, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES(?,'fixture','install','2026-01-01','resolved',1,?,'git_remote',?)`, id, remote, key); e != nil {
						return e
					}
				}
				return nil
			}))
			for _, id := range []string{"a", "b"} {
				require.NoError(t, spokeDB.ReplaceSessionUsageEvents(ctx, id, []db.UsageEvent{{SessionID: id, Source: "fixture", Model: "model", InputTokens: 42, OccurredAt: "2026-01-02T00:00:00Z", DedupKey: id}}))
			}
			preview, err := spoke.PreviewShare(ctx, federation.ShareGrant{Project: remote, Level: "summary", Attribution: "pooled"})
			require.NoError(t, err)
			require.NoError(t, spoke.AddShare(ctx, preview))
			request(http.MethodPost, "/api/v1/federation/push", nil)
			var a, b, usage, owned int
			require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT (SELECT count(*) FROM sessions WHERE id='a'),(SELECT count(*) FROM sessions WHERE id='b'),(SELECT count(*) FROM usage_events WHERE session_id='a'),(SELECT count(*) FROM federation_records WHERE session_id='a')`).Scan(&a, &b, &usage, &owned))
			require.Equal(t, 1, a)
			require.Equal(t, 1, b)
			require.Greater(t, usage, 0)
			require.Equal(t, 1, owned)
			shares, err := spoke.Shares(ctx)
			require.NoError(t, err)
			require.Len(t, shares.Shares, 1)
			before, err := spoke.Share(ctx, shares.Shares[0].UID)
			require.NoError(t, err)
			require.NotEmpty(t, before.Records["a"].Hash)
			_, err = os.Stat(filepath.Join(sourceDir, "a"))
			require.ErrorIs(t, err, os.ErrNotExist)
			request(http.MethodPost, "/api/v1/federation/push", nil)
			require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id='a'`).Scan(&a))
			assert.Equal(t, 1, a)
			if operation == "exclude" {
				request(http.MethodPost, "/api/v1/federation/exclusions", map[string]string{"session_id": "a", "reason": "private"})
			} else {
				for _, endpoint := range []string{"/api/v1/sessions/a", "/api/v1/sessions/a/permanent"} {
					req, e := http.NewRequestWithContext(ctx, http.MethodDelete, spokeServer.URL+endpoint, nil)
					require.NoError(t, e)
					resp, e := http.DefaultClient.Do(req)
					require.NoError(t, e)
					resp.Body.Close()
					require.Equal(t, http.StatusNoContent, resp.StatusCode)
				}
			}
			for i := 0; i < 2; i++ {
				request(http.MethodPost, "/api/v1/federation/push", nil)
				require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT (SELECT count(*) FROM sessions WHERE id='a'),(SELECT count(*) FROM sessions WHERE id='b'),(SELECT count(*) FROM usage_events WHERE session_id='a'),(SELECT count(*) FROM federation_records WHERE session_id='a')`).Scan(&a, &b, &usage, &owned))
				assert.Zero(t, a)
				assert.Equal(t, 1, b)
				assert.Zero(t, usage)
				assert.Zero(t, owned)
			}
			page, err := hubDB.ListSessions(ctx, db.SessionFilter{IDs: []string{"a", "b"}, IncludeChildren: true})
			require.NoError(t, err)
			require.Len(t, page.Sessions, 1)
			assert.Equal(t, "b", page.Sessions[0].ID)
			after, err := spoke.Share(ctx, shares.Shares[0].UID)
			require.NoError(t, err)
			assert.Equal(t, "tombstoned", after.Records["a"].State)
			assert.Equal(t, before.Records["a"].Hash, after.Records["a"].Hash)
			var localA int
			require.NoError(t, spokeDB.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id='a'`).Scan(&localA))
			if operation == "exclude" {
				assert.Equal(t, 1, localA)
			} else {
				assert.Zero(t, localA)
			}
			shares, err = spoke.Shares(ctx)
			require.NoError(t, err)
			require.Len(t, shares.Shares, 1)
			assert.Equal(t, "active", shares.Shares[0].State)
		})
	}
}

func TestFederationRestoreReconcilesAndContinuesDeletion(t *testing.T) {
	for _, mode := range []string{"copied generation", "same identity snapshot"} {
		t.Run(mode, func(t *testing.T) {
			ctx := t.Context()
			hubDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "hub.db"))
			cfg, err := config.Default()
			require.NoError(t, err)
			hub := federation.NewService("hub", "hub-a", cfg.Federation.Hub, hubDB)
			_, token, err := hub.Enroll(ctx, "spoke-a", "member", "")
			require.NoError(t, err)
			peer := httptest.NewServer(New(config.Config{Host: "127.0.0.1", Port: 8080}, hubDB, nil, WithFederation(hub)).Handler())
			t.Cleanup(peer.Close)
			file := filepath.Join(testutil.PrivateTempDir(t), "credential")
			require.NoError(t, os.WriteFile(file, []byte(token), 0600))
			old, err := db.OpenIsolated(ctx, filepath.Join(t.TempDir(), "old.db"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, old.Close()) })
			remote := "github.com/example/repo"
			key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
			seed := func(archive *db.DB, ids ...string) {
				t.Helper()
				require.NoError(t, archive.Update(ctx, func(tx *sql.Tx) error {
					if _, e := tx.ExecContext(ctx, `INSERT OR IGNORE INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','install')`); e != nil {
						return e
					}
					for _, id := range ids {
						if _, e := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count) VALUES(?,'fixture','install','claude',?,'2026-01-02T00:00:00Z',1)`, id, id); e != nil {
							return e
						}
						if _, e := tx.ExecContext(ctx, `INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES(?,'install','claude',?)`, id, id); e != nil {
							return e
						}
						if _, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES(?,'fixture','install','2026-01-01','resolved',1,?,'git_remote',?)`, id, remote, key); e != nil {
							return e
						}
					}
					return nil
				}))
			}
			seed(old, "a")
			require.NoError(t, old.ReplaceSessionUsageEvents(ctx, "a", []db.UsageEvent{{SessionID: "a", Source: "fixture", Model: "model", InputTokens: 42, OccurredAt: "2026-01-02T00:00:00Z", DedupKey: "a-usage"}}))
			// Preserve an earlier same-identity archive before federation state is
			// copied back from the newer archive after its journals advance.
			snapshot := filepath.Join(t.TempDir(), "snapshot.db")
			require.NoError(t, old.SnapshotTo(ctx, snapshot))
			seed(old, "c")
			spoke := federation.NewService("spoke", "spoke-a", cfg.Federation.Hub, old)
			require.NoError(t, spoke.Join(ctx, peer.URL, "hub-a", file))
			preview, err := spoke.PreviewShare(ctx, federation.ShareGrant{Project: remote, Level: "summary", Attribution: "pooled"})
			require.NoError(t, err)
			require.NoError(t, spoke.AddShare(ctx, preview))
			_, err = spoke.Push(ctx)
			require.NoError(t, err)
			seed(old, "b")
			_, err = spoke.Push(ctx)
			require.NoError(t, err)
			require.NoError(t, old.DeleteSession(ctx, "c"))
			_, err = spoke.Push(ctx)
			require.NoError(t, err)
			var beforeA, beforeB int
			require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT (SELECT count(*) FROM sessions WHERE id='a'),(SELECT count(*) FROM sessions WHERE id='b')`).Scan(&beforeA, &beforeB))
			require.Equal(t, 1, beforeA)
			require.Equal(t, 1, beforeB)
			var restored *db.DB
			if mode == "copied generation" {
				restored, err = db.OpenIsolated(ctx, filepath.Join(t.TempDir(), "replacement.db"))
				require.NoError(t, err)
				seed(restored, "a")
				require.NoError(t, restored.CopyFederationStateFrom(ctx, old.Path()))
			} else {
				restored, err = db.OpenIsolated(ctx, snapshot)
				require.NoError(t, err)
				require.NoError(t, restored.CopyFederationStateFrom(ctx, old.Path()))
			}
			t.Cleanup(func() { require.NoError(t, restored.Close()) })
			recovered := federation.NewService("spoke", "spoke-a", cfg.Federation.Hub, restored)
			for i := 0; i < 3; i++ {
				_, err = recovered.Push(ctx)
				require.NoError(t, err)
			}
			var countA, countB, complete int
			require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT (SELECT count(*) FROM sessions WHERE id='a'),(SELECT count(*) FROM sessions WHERE id='b'),(SELECT count(*) FROM federation_hub_shares WHERE completed_epoch=epoch AND epoch>1)`).Scan(&countA, &countB, &complete))
			assert.Equal(t, 1, countA)
			assert.Zero(t, countB)
			assert.Equal(t, 1, complete)
			require.NoError(t, restored.DeleteSession(ctx, "a"))
			_, err = recovered.Push(ctx)
			require.NoError(t, err)
			require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id='a'`).Scan(&countA))
			assert.Zero(t, countA)
		})
	}
}

func TestRetainedSnapshotRecoversHubSequenceWithoutSendingContent(t *testing.T) {
	ctx := t.Context()
	hubDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "hub.db"))
	spokeDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "spoke.db"))
	cfg, err := config.Default()
	require.NoError(t, err)
	cfg.Federation.Hub.Retention = "org-retained"
	hub := federation.NewService("hub", "hub-a", cfg.Federation.Hub, hubDB)
	_, token, err := hub.Enroll(ctx, "spoke-a", "member", "")
	require.NoError(t, err)
	peer := httptest.NewServer(New(config.Config{Host: "127.0.0.1", Port: 8080}, hubDB, nil, WithFederation(hub)).Handler())
	t.Cleanup(peer.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte(token), 0600))
	spoke := federation.NewService("spoke", "spoke-a", cfg.Federation.Hub, spokeDB)
	require.NoError(t, spoke.Join(ctx, peer.URL, "hub-a", file))
	remote := "github.com/example/repo"
	key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','install')`); err != nil {
			return err
		}
		for _, id := range []string{"a", "b", "c"} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count) VALUES(?,'fixture','install','claude',?,'2026-01-02T00:00:00Z',1)`, id, id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES(?,'install','claude',?)`, id, id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES(?,'fixture','install','2026-01-01','resolved',1,?,'git_remote',?)`, id, remote, key); err != nil {
				return err
			}
		}
		return nil
	}))
	preview, err := spoke.PreviewShare(ctx, federation.ShareGrant{Project: remote, Level: "summary", Attribution: "pooled"})
	require.NoError(t, err)
	require.NoError(t, spoke.AddShare(ctx, preview))
	_, err = spoke.Push(ctx)
	require.NoError(t, err)
	shares, err := spoke.Shares(ctx)
	require.NoError(t, err)
	require.Len(t, shares.Shares, 1)
	uid := shares.Shares[0].UID
	require.NoError(t, spoke.RemoveShare(ctx, uid))
	_, err = spoke.Push(ctx)
	require.NoError(t, err)
	snapshot := filepath.Join(t.TempDir(), "snapshot.db")
	require.NoError(t, spokeDB.SnapshotTo(ctx, snapshot))
	require.NoError(t, spoke.Exclude(ctx, "a", "private"))
	_, err = spoke.Push(ctx)
	require.NoError(t, err)
	restored, err := db.OpenIsolated(ctx, snapshot)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restored.Close()) })
	recovered := federation.NewService("spoke", "spoke-a", cfg.Federation.Hub, restored)
	require.NoError(t, recovered.Exclude(ctx, "b", "private"))
	// A restored sequence must not loop on the hub's different sequence-two
	// digest or reopen the stopped share to deliver content.
	for i := 0; i < 3; i++ {
		_, err = recovered.Push(ctx)
		require.NoError(t, err)
	}
	var a, b, c int
	var state string
	var sequence int64
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT (SELECT count(*) FROM sessions WHERE id='a'),(SELECT count(*) FROM sessions WHERE id='b'),(SELECT count(*) FROM sessions WHERE id='c'),state,sequence FROM federation_hub_shares WHERE share_uid=?`, uid).Scan(&a, &b, &c, &state, &sequence))
	assert.Zero(t, a)
	assert.Zero(t, b)
	assert.Equal(t, 1, c)
	assert.Equal(t, "stopped", state)
	assert.GreaterOrEqual(t, sequence, int64(3))
}

func TestFederationOfflineStopBeforeNewEpochRegistration(t *testing.T) {
	for _, tc := range []struct{ retention, scenario string }{
		{"member-controlled", "local ahead"}, {"org-retained", "local ahead"},
		{"member-controlled", "hub ahead"}, {"org-retained", "hub ahead"},
		{"member-controlled", "resume pending"}, {"org-retained", "resume pending"},
	} {
		t.Run(tc.retention+" "+tc.scenario, func(t *testing.T) {
			retention := tc.retention
			ctx := t.Context()
			hubDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "hub.db"))
			spokeDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "spoke.db"))
			cfg, err := config.Default()
			require.NoError(t, err)
			cfg.Federation.Hub.Retention = retention
			hub := federation.NewService("hub", "hub-a", cfg.Federation.Hub, hubDB)
			_, token, err := hub.Enroll(ctx, "spoke-a", "member", "")
			require.NoError(t, err)
			handler := New(config.Config{Host: "127.0.0.1", Port: 8080}, hubDB, nil, WithFederation(hub)).Handler()
			var offline atomic.Bool
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if offline.Load() {
					http.Error(w, "offline", http.StatusServiceUnavailable)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			t.Cleanup(peer.Close)
			file := filepath.Join(testutil.PrivateTempDir(t), "credential")
			require.NoError(t, os.WriteFile(file, []byte(token), 0600))
			spoke := federation.NewService("spoke", "spoke-a", cfg.Federation.Hub, spokeDB)
			require.NoError(t, spoke.Join(ctx, peer.URL, "hub-a", file))
			remote := "github.com/example/repo"
			key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
			seed := func(id string) {
				t.Helper()
				require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
					if _, e := tx.ExecContext(ctx, `INSERT OR IGNORE INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','install')`); e != nil {
						return e
					}
					if _, e := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count) VALUES(?,'fixture','install','claude',?,'2026-01-02T00:00:00Z',1)`, id, id); e != nil {
						return e
					}
					if _, e := tx.ExecContext(ctx, `INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES(?,'install','claude',?)`, id, id); e != nil {
						return e
					}
					_, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES(?,'fixture','install','2026-01-01','resolved',1,?,'git_remote',?)`, id, remote, key)
					return e
				}))
			}
			seed("a")
			require.NoError(t, spokeDB.ReplaceSessionUsageEvents(ctx, "a", []db.UsageEvent{{SessionID: "a", Source: "fixture", Model: "model", InputTokens: 42, OccurredAt: "2026-01-02T00:00:00Z", DedupKey: "a-usage"}}))
			grant := federation.ShareGrant{Project: remote, Level: "summary", Attribution: "pooled"}
			preview, err := spoke.PreviewShare(ctx, grant)
			require.NoError(t, err)
			require.NoError(t, spoke.AddShare(ctx, preview))
			_, err = spoke.Push(ctx)
			require.NoError(t, err)
			shares, err := spoke.Shares(ctx)
			require.NoError(t, err)
			require.Len(t, shares.Shares, 1)
			uid := shares.Shares[0].UID
			var localEpoch, hubEpoch int64
			link, err := spokeDB.GetFederationLink(ctx)
			require.NoError(t, err)
			if tc.scenario == "local ahead" {
				grant.Since = "2026-01-01"
				preview, err = spoke.PreviewShare(ctx, grant)
				require.NoError(t, err)
				require.NoError(t, spoke.AddShare(ctx, preview))
			} else if tc.scenario == "resume pending" {
				require.NoError(t, spoke.PauseShare(ctx, uid))
				_, err = spoke.Push(ctx)
				require.NoError(t, err)
				require.NoError(t, spoke.ResumeShare(ctx, uid))
			} else {
				// A restored spoke can lag a rebuild that the hub has accepted.
				_, err = hubDB.PutFederationHubShare(ctx, "spoke-a", db.FederationHubShare{UID: uid, EnrollmentUID: link.EnrollmentUID, Remote: remote, ProjectKey: key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: preview.PolicyDigest, Epoch: 2, State: "active", Retention: retention, Rebuild: true})
				require.NoError(t, err)
			}
			localShare, err := spokeDB.GetFederationShare(ctx, link.UID, uid)
			require.NoError(t, err)
			localEpoch = localShare.Epoch
			require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT epoch FROM federation_hub_shares WHERE share_uid=?`, uid).Scan(&hubEpoch))
			if tc.scenario != "hub ahead" {
				assert.EqualValues(t, 2, localEpoch)
				assert.EqualValues(t, 1, hubEpoch)
			} else {
				assert.EqualValues(t, 1, localEpoch)
				assert.EqualValues(t, 2, hubEpoch)
			}
			offline.Store(true)
			require.NoError(t, spoke.RemoveShare(ctx, uid))
			_, err = spoke.Push(ctx)
			require.Error(t, err)
			details, err := spoke.Share(ctx, uid)
			require.NoError(t, err)
			assert.Equal(t, "pending", details.Share.StopReceipt)
			offline.Store(false)
			_, err = spoke.Push(ctx)
			require.NoError(t, err)
			details, err = spoke.Share(ctx, uid)
			require.NoError(t, err)
			if tc.scenario == "hub ahead" {
				assert.EqualValues(t, 3, details.Share.Epoch)
			}
			var a, usage, receipts int
			require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT (SELECT count(*) FROM sessions WHERE id='a'),(SELECT count(*) FROM usage_events WHERE session_id='a'),(SELECT count(*) FROM federation_records WHERE session_id='a')`).Scan(&a, &usage, &receipts))
			if retention == "member-controlled" {
				assert.Equal(t, "purged", details.Share.StopReceipt)
				assert.Zero(t, a)
				assert.Zero(t, usage)
				assert.Zero(t, receipts)
			} else {
				assert.Equal(t, "retained", details.Share.StopReceipt)
				assert.Equal(t, 1, a)
				assert.Greater(t, usage, 0)
				assert.Equal(t, 1, receipts)
				require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
					_, e := tx.ExecContext(ctx, `UPDATE sessions SET message_count=9 WHERE id='a'`)
					return e
				}))
				seed("b")
				_, err = spoke.Push(ctx)
				require.NoError(t, err)
				var count, b int
				require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT (SELECT message_count FROM sessions WHERE id='a'),(SELECT count(*) FROM sessions WHERE id='b')`).Scan(&count, &b))
				assert.Equal(t, 1, count)
				assert.Zero(t, b)
				require.NoError(t, spoke.Exclude(ctx, "a", "private"))
				_, err = spoke.Push(ctx)
				require.NoError(t, err)
				require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id='a'`).Scan(&a))
				assert.Zero(t, a)
			}
		})
	}
}
