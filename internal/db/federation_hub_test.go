package db

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederationBatchOwnershipAndRevocation(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "m", CredentialSHA256: "digest"}))
	share := FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"}
	_, err := d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	write := SessionBatchWrite{Session: Session{ID: "session", Project: "example.org/repo", Machine: "federated", Agent: "claude", MessageCount: 2}, DataVersion: CurrentDataVersion()}
	record := FederationHubRecord{UID: "session", Hash: "first", Remote: "example.org/repo", ProjectKey: "key", Write: write}
	ack, err := d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "batch1", []FederationHubRecord{record})
	require.NoError(t, err)
	assert.Equal(t, int64(1), ack.Committed)
	assert.Empty(t, ack.Refused)
	var modified string
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT local_modified_at FROM sessions WHERE id='session'`).Scan(&modified))
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 2, "unchanged", []FederationHubRecord{record})
	require.NoError(t, err)
	var after string
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT local_modified_at FROM sessions WHERE id='session'`).Scan(&after))
	assert.Equal(t, modified, after)
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "unknown", "policy", 1, 1, "unknown", []FederationHubRecord{record})
	require.ErrorIs(t, err, sql.ErrNoRows)
	_, err = d.CommitFederationBatch(ctx, "foreign", "spoke", "share", "policy", 1, 1, "foreign", []FederationHubRecord{record})
	require.ErrorIs(t, err, sql.ErrNoRows)
	var messages, tools int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT (SELECT count(*) FROM messages WHERE session_id='session'), (SELECT count(*) FROM tool_calls WHERE session_id='session')`).Scan(&messages, &tools))
	assert.Zero(t, messages)
	assert.Zero(t, tools)
	ack, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 2, "different", []FederationHubRecord{record})
	require.ErrorIs(t, err, ErrFederationSequence)
	assert.Equal(t, int64(2), ack.Committed)
	require.NoError(t, d.RevokeFederationEnrollment(ctx, "enr"))
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 3, "batch2", []FederationHubRecord{record})
	require.ErrorIs(t, err, sql.ErrNoRows)
}

func TestFederationCollisionsHaveOneRefusalAndReplayKeepsIt(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	share := FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"}
	_, err := d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{`INSERT INTO sessions(id,project,machine,agent,message_count) VALUES('host','local','host','claude',7)`, `INSERT INTO sessions(id,project,machine,agent,deleted_at) VALUES('trash','local','host','claude','2026-01-01')`, `INSERT INTO excluded_sessions(id) VALUES('excluded')`, `INSERT INTO sessions(id,project,machine,agent) VALUES('foreign','local','federated','claude')`, `INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('other','foreign','foreign','same')`} {
			if _, e := tx.ExecContext(ctx, q); e != nil {
				return e
			}
		}
		return nil
	}))
	records := []FederationHubRecord{}
	for _, id := range []string{"host", "trash", "excluded", "foreign"} {
		records = append(records, FederationHubRecord{UID: id, Hash: "same", Remote: "example.org/repo", ProjectKey: "key", Write: SessionBatchWrite{Session: Session{ID: id, Project: "remote", Machine: "federated", Agent: "claude"}}})
	}
	ack, err := d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "batch", records)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"host": FederationCollision, "trash": FederationCollision, "excluded": FederationCollision, "foreign": FederationCollision}, ack.Refused)
	replay, err := d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "batch", records)
	require.NoError(t, err)
	assert.Equal(t, ack, replay)
	var project string
	var count int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT project,message_count FROM sessions WHERE id='host'`).Scan(&project, &count))
	assert.Equal(t, "local", project)
	assert.Equal(t, 7, count)
}

func TestFederationUpdateKeepsSingleSessionAndDropsForeignParent(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	_, err := d.PutFederationHubShare(ctx, "spoke", FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "remote", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
	require.NoError(t, err)
	record := FederationHubRecord{UID: "child", Hash: "one", Remote: "remote", ProjectKey: "key", Write: SessionBatchWrite{Session: Session{ID: "child", Project: "remote", Machine: "federated", Agent: "claude", MessageCount: 1, ParentSessionID: Ptr("outside"), RelationshipType: "subagent", IsAutomated: true}}}
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "first", []FederationHubRecord{record})
	require.NoError(t, err)
	record.Hash = "two"
	record.Write.Session.MessageCount = 3
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 2, "second", []FederationHubRecord{record})
	require.NoError(t, err)
	var count, messages int
	var parent sql.NullString
	var automated bool
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT count(*),max(message_count),max(parent_session_id),max(is_automated) FROM sessions WHERE id='child'`).Scan(&count, &messages, &parent, &automated))
	assert.Equal(t, 1, count)
	assert.Equal(t, 3, messages)
	assert.False(t, parent.Valid)
	assert.True(t, automated)
}

func TestFederationSessionOriginsDistinguishesOwners(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{`INSERT INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','host')`, `INSERT INTO sessions(id,project,machine,agent,file_path) VALUES('local','p','host','claude','file')`, `INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES('local','host','claude','file')`, `INSERT INTO sessions(id,project,machine,agent) VALUES('old','p','other','claude')`, `INSERT INTO sessions(id,project,machine,agent) VALUES('shared','p','federated','claude')`, `INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('share','shared','shared','hash')`} {
			if _, e := tx.ExecContext(ctx, q); e != nil {
				return e
			}
		}
		return nil
	}))
	got, err := d.FederationSessionOrigins(ctx)
	require.NoError(t, err)
	assert.Equal(t, FederationOrigins{Federated: 1, HubHost: 1, Other: 1}, got)
}
