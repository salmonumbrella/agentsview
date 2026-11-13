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
	server := New(config.Config{Host: "127.0.0.1", Port: 8080}, hubDB, nil, WithFederation(hub))
	var captured bytes.Buffer
	dropFirst := true
	conflictNext, rejectNext := false, false
	offline := false
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
	require.GreaterOrEqual(t, len(batchBodies), 2)
	assert.NotContains(t, batchBodies[1], "session-b")
	assert.NotContains(t, captured.String(), "CANARY")
	var machine, project string
	var messages, tools, usage, input int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT machine,project,(SELECT count(*) FROM messages WHERE session_id=s.id),(SELECT count(*) FROM tool_calls WHERE session_id=s.id),(SELECT count(*) FROM usage_events WHERE session_id=s.id),(SELECT COALESCE(sum(input_tokens),0) FROM usage_events WHERE session_id=s.id) FROM sessions s WHERE id='session-a'`).Scan(&machine, &project, &messages, &tools, &usage, &input))
	assert.Equal(t, "federated", machine)
	assert.Equal(t, remote, project)
	assert.Zero(t, messages)
	assert.Zero(t, tools)
	assert.Equal(t, 1, usage)
	assert.Equal(t, 100, input)
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
	assert.Equal(t, 2, summary.TotalSessions)
	assert.Equal(t, 4, summary.TotalMessages)
	assert.NotContains(t, rec.Body.String(), "CANARY")
	var again federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &again))
	assert.Zero(t, again.Sent)
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `UPDATE sessions SET message_count=4 WHERE id='session-a'`)
		return e
	}))
	conflictNext = true
	assert.NotEqual(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, nil))
	rejectNext = true
	assert.NotEqual(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, nil))
	quarantines, err := spokeDB.FederationQuarantines(ctx)
	require.NoError(t, err)
	require.Len(t, quarantines, 1)
	assert.Equal(t, "hub rejected batch", quarantines[0].Error)
	var changed federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &changed))
	assert.Equal(t, 1, changed.Sent)
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
	assert.Equal(t, "unconfirmed", afterAttempt["session-b"].State)
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/exclusions", map[string]string{"session_id": "session-a"}, nil))
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/shares/"+shares[0].UID+"/pause", nil, nil))
	offline = true
	assert.NotEqual(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, nil))
	stopped, err := spokeDB.GetFederationShare(ctx, shares[0].LinkUID, shares[0].UID)
	require.NoError(t, err)
	assert.Equal(t, "pending", stopped.StopReceipt)
	offline = false
	var paused federation.PushResult
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/api/v1/federation/push", nil, &paused))
	assert.Zero(t, paused.Sent)
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

// The first response lets a member exclude a session before the next chunk.
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
			r.Body = io.NopCloser(bytes.NewReader(body))
			buffered := httptest.NewRecorder()
			srv.Handler().ServeHTTP(buffered, r)
			if batches == 1 && buffered.Code == http.StatusOK {
				exclusionErr = spokeDB.PutFederationExclusion(r.Context(), "s1000", "member excluded")
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
		_, e := tx.ExecContext(ctx, `UPDATE sessions SET parent_session_id='s1000', relationship_type='subagent', cwd='CANARY-path',git_branch='CANARY-branch',first_message='CANARY-first',display_name='CANARY-title',session_name='CANARY-name',pr_links='CANARY-links' WHERE id='s1001'`)
		return e
	}))
	preview, err := spoke.PreviewShare(ctx, federation.ShareGrant{Project: remote, Level: "summary", Attribution: "pooled"})
	require.NoError(t, err)
	require.Len(t, preview.Records, 1002)
	require.NoError(t, spoke.AddShare(ctx, preview))
	result, err := spoke.Push(ctx)
	require.NoError(t, err)
	require.NoError(t, exclusionErr)
	assert.Equal(t, 1001, result.Sent)
	assert.Equal(t, 3, batches)
	assert.Contains(t, childPayload, "s1001")
	assert.NotContains(t, childPayload, "parent_session_id")
	assert.NotContains(t, wire.String(), "CANARY")
	var count, excluded int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*),coalesce(sum(id='s1000'),0) FROM sessions`).Scan(&count, &excluded))
	assert.Equal(t, 1001, count)
	assert.Zero(t, excluded)
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
	confirmedHash := ledger["selected"].Hash
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `UPDATE sessions SET message_count=2 WHERE id='selected'`)
		return e
	}))
	dropped = false
	_, err = spoke.Push(ctx)
	require.Error(t, err)
	ledger, err = spokeDB.FederationLedger(ctx, shares[0].UID)
	require.NoError(t, err)
	assert.Equal(t, "sent", ledger["selected"].State)
	assert.Equal(t, confirmedHash, ledger["selected"].Hash)
	assert.NotEmpty(t, ledger["selected"].AttemptHash)
	details, err = spoke.Share(ctx, shares[0].UID)
	require.NoError(t, err)
	assert.Equal(t, 1, details.Delivery.Sent)
	assert.Equal(t, 2, details.Delivery.Unconfirmed)
}
