package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
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
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			data, e := io.ReadAll(r.Body)
			require.NoError(t, e)
			captured.Write(data)
			r.Body = io.NopCloser(bytes.NewReader(data))
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
	require.NoError(t, spoke.Join(ctx, peer.URL, "hub-a", file))
	remote := "github.com/example/api"
	key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','install-a')`,
			`INSERT INTO sessions(id,project,machine,agent,file_path,started_at,message_count,user_message_count,cwd,first_message) VALUES('session-a','fixture','install-a','claude','fixture','2026-01-02T00:00:00Z',2,1,'CANARY-path','CANARY-first')`,
			`INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES('session-a','install-a','claude','fixture')`,
			`INSERT INTO messages(session_id,ordinal,role,content) VALUES('session-a',0,'user','CANARY-message')`,
			`INSERT INTO usage_events(session_id,source,model,input_tokens,output_tokens,cost_microdollars,cost_status,cost_source,occurred_at,dedup_key) VALUES('session-a','fixture','model-a',100,20,50,'exact','reported','2026-01-02T00:00:00Z','a')`,
		} {
			if _, e := tx.ExecContext(ctx, q); e != nil {
				return e
			}
		}
		if _, e := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots(session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES('session-a','fixture','install-a','2026-01-01T00:00:00Z','resolved',1,?,'git_remote',?)`, remote, key); e != nil {
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
		}
		return nil
	}))
	preview, err := spoke.PreviewShare(ctx, federation.ShareGrant{Project: remote, Level: "summary", Attribution: "pooled", Since: "2026-01-02"})
	require.NoError(t, err)
	require.Len(t, preview.Records, 1)
	require.NoError(t, spoke.AddShare(ctx, preview))
	dry, err := spoke.DryRun(ctx)
	require.NoError(t, err)
	require.Len(t, dry, 1)
	_, err = spoke.Push(ctx)
	require.Error(t, err)
	shares, err := spokeDB.ListFederationShares(ctx, func() string { link, e := spokeDB.GetFederationLink(ctx); require.NoError(t, e); return link.UID }())
	require.NoError(t, err)
	require.Len(t, shares, 1)
	ledger, err := spokeDB.FederationLedger(ctx, shares[0].UID)
	require.NoError(t, err)
	assert.Empty(t, ledger)
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `UPDATE sessions SET message_count=3 WHERE id='session-a'`)
		return e
	}))
	first, err := spoke.Push(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, first.Sent)
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
		assert.NotContains(t, rec.Body.String(), id)
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
		} else {
			var result db.ToolsAnalyticsResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
			assert.Zero(t, result.TotalCalls)
		}
	}
	again, err := spoke.Push(ctx)
	require.NoError(t, err)
	assert.Zero(t, again.Sent)
	assert.Equal(t, 1, again.Unchanged)
	require.NoError(t, spokeDB.Update(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `UPDATE sessions SET message_count=4 WHERE id='session-a'`)
		return e
	}))
	changed, err := spoke.Push(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, changed.Sent)
	var count, storedMessages int
	require.NoError(t, hubDB.Reader().QueryRow(ctx, `SELECT count(*),max(message_count) FROM sessions WHERE id='session-a'`).Scan(&count, &storedMessages))
	assert.Equal(t, 1, count)
	assert.Equal(t, 4, storedMessages)
	assert.False(t, strings.Contains(captured.String(), "CANARY"))
}
