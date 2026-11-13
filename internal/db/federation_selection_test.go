package db

import (
	"database/sql"
	"encoding/json/jsontext"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederationSelectionRequiresOwnSnapshotAndLocalProof(t *testing.T) {
	database := testDB(t)
	ctx := t.Context()
	require.NoError(t, database.Update(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO pg_sync_state (key,value) VALUES ('artifact_local_installation_id','install-a')`); err != nil {
			return err
		}
		for _, id := range []string{"selected", "imported", "other", "ambiguous", "excluded", "before", "boundary", "child", "no-snapshot", "attached", "artifact", "trashed", "other-repo", "root-only", "renamed"} {
			machine := "install-a"
			if id == "other" {
				machine = "other"
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
			if id == "child" || id == "other-repo" || id == "renamed" {
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
			`INSERT INTO messages (id,session_id,ordinal,role,content) VALUES (100,'selected',0,'assistant','CANARY-content')`,
			`INSERT INTO tool_calls (message_id,session_id,tool_name,category,input_json) VALUES (100,'selected','fixture','CANARY-category','CANARY-input')`,
			`UPDATE sessions SET parent_session_id='selected',relationship_type='subagent' WHERE id='child'`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}))
	seedSessionExportPricing(t, database)
	insertMessages(t, database, Message{SessionID: "selected", Ordinal: 1, Role: "assistant", Model: "model-computed", TokenUsage: jsontext.Value(`{"input_tokens":1000,"output_tokens":500}`), HasContextTokens: true, HasOutputTokens: true})
	require.NoError(t, database.PutFederationExclusion(ctx, "excluded", "share-a", "private"))
	result, err := database.SelectFederationSessions(ctx, "github.com/example/api", "2026-01-02")
	require.NoError(t, err)
	assert.Equal(t, []string{"boundary", "selected"}, result.IDs)
	assert.Equal(t, 4, result.NotLocal)
	assert.Equal(t, 1, result.Excluded)
	assert.Equal(t, 1, result.NotIdentifiable)
	assert.Equal(t, 1, result.ToolCounts["selected"])
	for _, row := range result.Rows {
		if row.ID == "selected" {
			assert.Equal(t, 1000, row.ModelUsage.InputTokens)
			assert.Equal(t, 500, row.ModelUsage.OutputTokens)
			assert.True(t, row.ModelUsage.HasCost)
			assert.Equal(t, int64(20000), row.ModelUsage.Cost.Microdollars)
		}
	}
}
