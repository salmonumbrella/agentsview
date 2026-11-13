package db

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetainedDeletionEvidenceDistinguishesAbsenceAndReinsertion(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.PutFederationLink(ctx, FederationLink{UID: "link", HubOrigin: "https://hub.example", HubArchiveID: "hub", EnrollmentUID: "enr", Member: "member", TokenFile: "/fixture/token", ProtocolVersion: 2, State: "active"}))
	require.NoError(t, d.PutFederationShare(ctx, FederationShare{UID: "share", LinkUID: "link", NormalizedRemote: "example.org/repo", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: "{}", PolicyDigest: "policy"}))
	saveSummaryFixture(t, d, "share", "claude", []string{"absent", "deleted", "excluded", "restored"}, true)
	for _, id := range []string{"deleted", "excluded", "restored"} {
		require.NoError(t, d.UpsertSession(ctx, Session{ID: id, Project: "fixture", Machine: "fixture", Agent: "claude"}))
	}
	require.NoError(t, d.DeleteSession(ctx, "deleted"))
	require.NoError(t, d.DeleteSession(ctx, "restored"))
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent) VALUES('restored','fixture','fixture','claude')`)
		return err
	}))
	require.NoError(t, d.PutFederationExclusion(ctx, "excluded", "private"))
	// Only the explicit exclusion and the current hard deletion may be sent;
	// replacement absence and a reinserted row remain unproven.
	ids, err := d.FederationRetainedRemovals(ctx, "share", "", 400)
	require.NoError(t, err)
	assert.Equal(t, []string{"deleted", "excluded"}, ids)
	evidence, err := d.FederationRetainedProven(ctx, "share", []string{"absent", "deleted", "excluded", "restored"})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"deleted": true, "excluded": true}, evidence)
	missing, err := d.FederationRetainedMissing(ctx, "share")
	require.NoError(t, err)
	assert.True(t, missing)
}

func TestFederationSelectionRequiresOwnSnapshotAndLocalProof(t *testing.T) {
	database := testDB(t)
	ctx := t.Context()
	require.NoError(t, database.Update(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO pg_sync_state (key,value) VALUES ('artifact_local_installation_id','install-a')`); err != nil {
			return err
		}
		for _, id := range []string{"selected", "imported", "other", "ambiguous", "excluded", "before", "boundary", "child", "no-snapshot", "attached", "artifact", "trashed", "root-only", "renamed", "local-sentinel"} {
			machine := "install-a"
			if id == "other" {
				machine = "other"
			}
			if id == "local-sentinel" {
				machine = "local"
			}
			start := "2026-01-02T00:00:00Z"
			if id == "before" {
				start = "2026-01-01T23:59:59Z"
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (id,project,machine,agent,file_path,started_at,source_session_id) VALUES (?, 'fixture', ?, 'claude', ?, ?, 'native-lineage')`, id, machine, id, start); err != nil {
				return err
			}
			if id != "imported" {
				if _, err := tx.ExecContext(ctx, `INSERT INTO local_session_source_baselines (session_id,machine,agent,file_path) VALUES (?,?,'claude',?)`, id, machine, id); err != nil {
					return err
				}
			}
			if id == "no-snapshot" {
				continue
			}
			remote := "github.com/example/api"
			if id == "child" || id == "renamed" {
				remote = "github.com/example/private"
			}
			count := 1
			if id == "ambiguous" {
				count = 2
			}
			keySource := "git_remote"
			if id == "root-only" {
				keySource = "root_path"
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO session_project_identity_snapshots (session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES (?,'fixture',?,'2026-01-01T00:00:00Z','resolved',?,?,?,'key')`, id, machine, count, remote, keySource); err != nil {
				return err
			}
		}
		for _, q := range []string{
			`INSERT INTO archive_source_bindings (archive_id,device_id,root_id,source_key,manifest_id) VALUES ('archive','device','root','source','manifest')`,
			`INSERT INTO archive_session_provenance (session_id,archive_id,device_id,root_id,source_key,manifest_id,native_session_id) VALUES ('attached','archive','device','root','source','manifest','native')`,
			`INSERT INTO artifact_imported_sessions (origin,gid,manifest_hash,imported_session_id) VALUES ('origin','gid','hash','artifact')`,
			`UPDATE sessions SET deleted_at='2026-01-03' WHERE id='trashed'`,
			`INSERT INTO messages (id,session_id,ordinal,role,content) VALUES (100,'selected',0,'assistant','fixture-content')`,
			`INSERT INTO tool_calls (message_id,session_id,tool_name,category,input_json) VALUES (100,'selected','fixture','fixture-category','fixture-input')`,
			`UPDATE sessions SET parent_session_id='selected',relationship_type='subagent' WHERE id='child'`,
			`UPDATE sessions SET parent_session_id='selected',relationship_type='subagent' WHERE id='boundary'`,
			`UPDATE sessions SET parent_session_id='excluded',relationship_type='subagent' WHERE id='selected'`,
			`UPDATE sessions SET project='personal', cwd='/fixture/private/work' WHERE id='renamed'`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}))
	_, err := database.CreateWorktreeProjectMapping(ctx, WorktreeProjectMapping{Machine: "install-a", PathPrefix: "/fixture/private", Project: "fixture", Enabled: true})
	require.NoError(t, err)
	mapping, err := database.ApplyWorktreeProjectMappings(ctx, "install-a")
	require.NoError(t, err)
	assert.Equal(t, 1, mapping.MatchedSessions)
	require.NoError(t, database.PutFederationExclusion(ctx, "excluded", "private"))
	result, err := database.SelectFederationSessions(ctx, "github.com/example/api", "2026-01-02")
	require.NoError(t, err)
	assert.Equal(t, []string{"boundary", "selected"}, result.IDs)
	assert.Equal(t, 5, result.NotLocal)
	assert.Equal(t, 1, result.Excluded)
	assert.Equal(t, 3, result.NotIdentifiable)
	idsOnly, err := database.SelectFederationSessionIDs(ctx, "github.com/example/api", "2026-01-02")
	require.NoError(t, err)
	assert.Equal(t, result.IDs, idsOnly.IDs)
	assert.Equal(t, result.NotLocal, idsOnly.NotLocal)
	assert.Equal(t, result.Excluded, idsOnly.Excluded)
	assert.Equal(t, 2, idsOnly.NotIdentifiable)
	assert.Equal(t, 1, result.ToolCounts["selected"])
	first, err := database.SelectFederationPage(ctx, "github.com/example/api", "2026-01-02", "", 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"boundary"}, first.IDs)
	assert.True(t, first.EligibleParents["selected"])
	second, err := database.SelectFederationPage(ctx, "github.com/example/api", "2026-01-02", first.IDs[0], 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"selected"}, second.IDs)
	assert.False(t, second.EligibleParents["excluded"])
	candidates, err := database.SelectFederationCandidates(ctx, "github.com/example/api", "2026-01-02", []string{"boundary", "selected", "excluded", "attached", "ambiguous", "before", "no-snapshot", "trashed"})
	require.NoError(t, err)
	assert.Equal(t, []string{"boundary", "selected"}, candidates.IDs)
	assert.True(t, candidates.EligibleParents["selected"])
	assert.False(t, candidates.EligibleParents["excluded"])
	last, err := database.SelectFederationPage(ctx, "github.com/example/api", "2026-01-02", second.IDs[0], 1)
	require.NoError(t, err)
	assert.Empty(t, last.IDs)
}

func TestFederationSelectionAttachesUsageAcrossChunks(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO pg_sync_state (key,value) VALUES ('artifact_local_installation_id','install-a')`); err != nil {
			return err
		}
		for i := 0; i < 1000; i++ {
			id := fmt.Sprintf("session-%04d", i)
			for _, q := range []string{
				`INSERT INTO sessions (id,project,machine,agent,file_path,started_at) VALUES (?,'fixture','install-a','claude',?,'2026-01-02T00:00:00Z')`,
				`INSERT INTO local_session_source_baselines (session_id,machine,agent,file_path) VALUES (?,'install-a','claude',?)`,
				`INSERT INTO session_project_identity_snapshots (session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES (?,'fixture','install-a','2026-01-01','resolved',1,'github.com/example/api','git_remote',?)`,
			} {
				if _, err := tx.ExecContext(ctx, q, id, id); err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO messages (session_id,ordinal,role,content,model,token_usage,has_context_tokens,has_output_tokens) VALUES (?,0,'assistant','','model-computed','{"input_tokens":1000,"output_tokens":500}',1,1)`, id); err != nil {
				return err
			}
		}
		return nil
	}))
	result, err := d.SelectFederationSessions(ctx, "github.com/example/api", "")
	require.NoError(t, err)
	require.Len(t, result.IDs, 1000)
	require.Len(t, result.Rows, 1000)
	for _, row := range result.Rows {
		assert.Equal(t, 1000, row.ModelUsage.InputTokens)
		assert.Equal(t, 500, row.ModelUsage.OutputTokens)
	}
	candidates, err := d.SelectFederationCandidates(ctx, "github.com/example/api", "", []string{"session-0000", "session-0999", "absent"})
	require.NoError(t, err)
	assert.Equal(t, []string{"session-0000", "session-0999"}, candidates.IDs)
	require.Len(t, candidates.Rows, 2)
	assert.Equal(t, "session-0000", candidates.Rows[0].ID)
	assert.Equal(t, "session-0999", candidates.Rows[1].ID)
	assert.Equal(t, 1000, candidates.Rows[0].ModelUsage.InputTokens)
}

func TestFederationChangedCandidatesPageSessionsAndDeletions(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO sessions(id,project,machine,agent,sync_marker) VALUES('changed','p','host','claude','2030-01-01T00:00:00Z')`,
			`UPDATE sessions SET sync_marker='2030-01-01T00:00:00Z' WHERE id='changed'`,
			`INSERT INTO federation_deliveries(share_uid,record_uid,session_id,hash,state) VALUES('share','gone','gone','old','sent')`,
			`INSERT INTO session_deletion_changes(session_id,project,revision,deleted) VALUES('gone','p',1,1)`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}))
	ids, err := d.FederationChangedCandidates(ctx, "share", "2029-01-01T00:00:00Z", 0, 0, 0, 1, "", 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"changed"}, ids)
	ids, err = d.FederationChangedCandidates(ctx, "share", "2029-01-01T00:00:00Z", 0, 0, 0, 1, "changed", 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"gone"}, ids)
}
