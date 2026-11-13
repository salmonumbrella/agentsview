package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/money"
)

func TestFederationSignalsSurviveStoragePoliciesAndTrashCopy(t *testing.T) {
	for _, policy := range []config.ArchiveContent{config.ArchiveContentFull, config.ArchiveContentTranscripts, config.ArchiveContentUsage} {
		t.Run(string(policy), func(t *testing.T) {
			ctx := t.Context()
			source, target := testDB(t), testDB(t)
			source.SetArchiveContent(policy)
			target.SetArchiveContent(policy)
			require.NoError(t, source.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
			_, err := source.PutFederationHubShare(ctx, "spoke", FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "remote", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
			require.NoError(t, err)
			r := FederationHubRecord{UID: "shared", Hash: "one", Remote: "remote", ProjectKey: "key", Write: SessionBatchWrite{Session: Session{ID: "shared", Project: "remote", Machine: "federated", Agent: "claude", MessageCount: 3}, Signals: SessionSignalUpdate{Outcome: "completed", HealthGrade: Ptr("A")}}}
			_, err = source.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "first", []FederationHubRecord{r})
			require.NoError(t, err)
			r.Hash, r.Write.Signals.Outcome, r.Write.Signals.HealthGrade = "two", "errored", Ptr("D")
			_, err = source.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 2, "second", []FederationHubRecord{r})
			require.NoError(t, err)
			_, err = source.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 2, "second", []FederationHubRecord{r})
			require.NoError(t, err)
			require.NoError(t, source.UpdateSessionSignals(ctx, "shared", SessionSignalUpdate{}))
			if policy.UsageOnly() {
				require.NoError(t, source.SettleUsageOnlySignals(ctx, "shared"))
			}
			_, err = source.SoftDeleteSessions(ctx, []string{"shared"})
			require.NoError(t, err)
			_, err = target.CopyTrashedDataFrom(ctx, source.Path())
			require.NoError(t, err)
			require.NoError(t, target.CopyFederationStateFrom(ctx, source.Path()))
			var outcome, health string
			var messages, tools, findings int
			require.NoError(t, target.rawReader().QueryRowContext(ctx, `SELECT outcome,health_grade,(SELECT count(*) FROM messages WHERE session_id=s.id),(SELECT count(*) FROM tool_calls WHERE session_id=s.id),(SELECT count(*) FROM secret_findings WHERE session_id=s.id) FROM sessions s WHERE id='shared'`).Scan(&outcome, &health, &messages, &tools, &findings))
			assert.Equal(t, "errored", outcome)
			assert.Equal(t, "D", health)
			assert.Zero(t, messages)
			assert.Zero(t, tools)
			assert.Zero(t, findings)
		})
	}
}

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
	ack, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 2, "unchanged", []FederationHubRecord{record})
	require.NoError(t, err)
	assert.False(t, ack.Changed)
	assert.Equal(t, int64(2), ack.Committed)
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
	require.NoError(t, revokeFederationEnrollment(d, ctx, "enr"))
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
		session := Session{ID: id, Project: "local", Machine: "host", Agent: "claude"}
		if id == "host" {
			session.MessageCount = 7
		}
		if id == "foreign" {
			session.Machine = "federated"
		}
		records = append(records, FederationHubRecord{UID: id, Hash: "same", Remote: "example.org/repo", ProjectKey: "key", Write: SessionBatchWrite{Session: session}})
	}
	snapshot := func(query string) string {
		rows, err := d.rawReader().QueryContext(ctx, query)
		require.NoError(t, err)
		defer rows.Close()
		columns, err := rows.Columns()
		require.NoError(t, err)
		var result [][]any
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			require.NoError(t, rows.Scan(pointers...))
			result = append(result, values)
		}
		require.NoError(t, rows.Err())
		encoded, err := json.Marshal(result)
		require.NoError(t, err)
		return string(encoded)
	}
	sessionSnapshot := snapshot(`SELECT * FROM sessions ORDER BY id`)
	exclusionSnapshot := snapshot(`SELECT * FROM excluded_sessions ORDER BY id`)
	ownershipSnapshot := snapshot(`SELECT * FROM federation_records ORDER BY session_id`)
	ack, err := d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "batch", records)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"host": FederationCollision, "trash": FederationCollision, "excluded": FederationCollision, "foreign": FederationCollision}, ack.Refused)
	replay, err := d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "batch", records)
	require.NoError(t, err)
	assert.Equal(t, ack, replay)
	assert.Equal(t, sessionSnapshot, snapshot(`SELECT * FROM sessions ORDER BY id`))
	assert.Equal(t, exclusionSnapshot, snapshot(`SELECT * FROM excluded_sessions ORDER BY id`))
	assert.Equal(t, ownershipSnapshot, snapshot(`SELECT * FROM federation_records ORDER BY session_id`))
	for i := range records {
		records[i].Hash = "different"
		records[i].Write.Session.MessageCount = 999
	}
	changed, err := d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 2, "changed", records)
	require.NoError(t, err)
	assert.Equal(t, ack.Refused, changed.Refused)
	assert.Equal(t, sessionSnapshot, snapshot(`SELECT * FROM sessions ORDER BY id`))
	assert.Equal(t, exclusionSnapshot, snapshot(`SELECT * FROM excluded_sessions ORDER BY id`))
	assert.Equal(t, ownershipSnapshot, snapshot(`SELECT * FROM federation_records ORDER BY session_id`))
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
		for _, q := range []string{`INSERT INTO pg_sync_state(key,value) VALUES('artifact_local_installation_id','host')`, `INSERT INTO sessions(id,project,machine,agent,file_path) VALUES('local','p','host','claude','file')`, `INSERT INTO local_session_source_baselines(session_id,machine,agent,file_path) VALUES('local','host','claude','file')`, `INSERT INTO sessions(id,project,machine,agent) VALUES('old','p','federated','claude')`, `INSERT INTO sessions(id,project,machine,agent) VALUES('shared','p','federated','claude')`, `INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('share','shared','shared','hash')`} {
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

func TestFederatedSessionAndUsageSurviveRebuildCopy(t *testing.T) {
	source, target := testDB(t), testDB(t)
	ctx := t.Context()
	require.NoError(t, source.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	_, err := source.PutFederationHubShare(ctx, "spoke", FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
	require.NoError(t, err)
	cost := money.Money{Microdollars: 125}
	largeInput := MaxPlausibleTokens + 17
	start := "2026-01-02T00:00:00Z"
	record := FederationHubRecord{UID: "shared", Hash: "hash", Remote: "example.org/repo", ProjectKey: "key", AssistantCount: 2, Write: SessionBatchWrite{Session: Session{ID: "shared", Project: "example.org/repo", Machine: "federated", Agent: "codex", MessageCount: 4, StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "completed", HealthGrade: Ptr("A")}, UsageEvents: []UsageEvent{{SessionID: "shared", Source: "federation", Model: "model", InputTokens: largeInput, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: start, DedupKey: "model"}}}}
	_, err = source.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "batch", []FederationHubRecord{record})
	require.NoError(t, err)
	require.NoError(t, source.UpdateSessionSignals(ctx, "shared", SessionSignalUpdate{}))
	var outcome string
	var health sql.NullString
	require.NoError(t, source.rawReader().QueryRowContext(ctx, `SELECT outcome,health_grade FROM sessions WHERE id='shared'`).Scan(&outcome, &health))
	assert.Equal(t, "completed", outcome)
	assert.Equal(t, "A", health.String)
	require.NoError(t, target.CopyFederationStateFrom(ctx, source.Path()))
	copied, err := target.CopyOrphanedDataFrom(ctx, source.Path())
	require.NoError(t, err)
	assert.Equal(t, 1, copied)
	var machine, model string
	var messages, input, storedCost, assistants int
	require.NoError(t, target.rawReader().QueryRowContext(ctx, `SELECT s.machine,s.message_count,u.model,u.input_tokens,u.cost_microdollars,r.assistant_count FROM sessions s JOIN usage_events u ON u.session_id=s.id JOIN federation_records r ON r.session_id=s.id WHERE s.id='shared'`).Scan(&machine, &messages, &model, &input, &storedCost, &assistants))
	assert.Equal(t, "federated", machine)
	assert.Equal(t, 4, messages)
	assert.Equal(t, "model", model)
	assert.Equal(t, largeInput, input)
	assert.Equal(t, 125, storedCost)
	assert.Equal(t, 2, assistants)
	require.NoError(t, target.rawReader().QueryRowContext(ctx, `SELECT outcome,health_grade FROM sessions WHERE id='shared'`).Scan(&outcome, &health))
	assert.Equal(t, "completed", outcome)
	assert.Equal(t, "A", health.String)
	daily, err := target.GetDailyUsage(ctx, UsageFilter{From: "2026-01-02", To: "2026-01-02", Timezone: "UTC"})
	require.NoError(t, err)
	assert.Equal(t, largeInput, daily.Totals.InputTokens)
	assert.EqualValues(t, 125, daily.Totals.TotalCost.Microdollars)
}

func TestLocalRelinkingDoesNotTakeFederatedParent(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	_, err := d.PutFederationHubShare(ctx, "spoke", FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "remote", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
	require.NoError(t, err)
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO sessions(id,project,machine,agent) VALUES('host','local','host','claude')`,
			`INSERT INTO messages(id,session_id,ordinal,role,content) VALUES(100,'host',0,'assistant','spawn')`,
			`INSERT INTO tool_calls(message_id,session_id,tool_name,category,subagent_session_id) VALUES(100,'host','tool','other','child')`,
		} {
			if _, e := tx.ExecContext(ctx, q); e != nil {
				return e
			}
		}
		return nil
	}))
	parent := FederationHubRecord{UID: "parent", Hash: "p", Remote: "remote", ProjectKey: "key", Write: SessionBatchWrite{Session: Session{ID: "parent", Project: "remote", Machine: "federated", Agent: "claude"}}}
	child := FederationHubRecord{UID: "child", Hash: "c", Remote: "remote", ProjectKey: "key", Write: SessionBatchWrite{Session: Session{ID: "child", Project: "remote", Machine: "federated", Agent: "claude", ParentSessionID: Ptr("parent"), RelationshipType: "subagent"}}}
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "batch", []FederationHubRecord{parent, child})
	require.NoError(t, err)
	_, err = d.LinkSubagentSessionsForSessions(ctx, []string{"host"})
	require.NoError(t, err)
	_, err = d.LinkSubagentSessionsContext(ctx)
	require.NoError(t, err)
	var got string
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT parent_session_id FROM sessions WHERE id='child'`).Scan(&got))
	assert.Equal(t, "parent", got)
}

func TestFederationPurgeOnlyOwnedRecords(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO sessions(id,project,machine,agent) VALUES('owned','p','federated','claude'),('other','p','federated','claude'),('local','p','host','claude')`,
			`INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('share','owned','owned','a'),('other-share','other','other','b')`,
			`INSERT INTO messages(session_id,ordinal,role,content) VALUES('owned',0,'user','shared'),('other',0,'user','other'),('local',0,'user','local')`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		_, err := purgeFederationRecordsTx(ctx, tx, "share", []string{"owned", "other", "local", "unknown"}, &recallEvidenceRevocationEvents{})
		return err
	}))
	var owned, other, local, messages, deleted int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM sessions WHERE id='owned'),
		(SELECT count(*) FROM sessions WHERE id='other'),
		(SELECT count(*) FROM sessions WHERE id='local'),
		(SELECT count(*) FROM messages WHERE session_id IN ('other','local')),
		(SELECT count(*) FROM session_deletion_changes WHERE session_id='owned' AND deleted=1)`).Scan(&owned, &other, &local, &messages, &deleted))
	assert.Zero(t, owned)
	assert.Equal(t, 1, other)
	assert.Equal(t, 1, local)
	assert.Equal(t, 2, messages)
	assert.Equal(t, 1, deleted)
}

func TestFederationStopPurgesOnlyOwnedAndCannotBeReactivatedByStaleManifest(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	share := FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active", Retention: "member-controlled"}
	_, err := d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	record := FederationHubRecord{UID: "owned", Hash: "hash", Remote: share.Remote, ProjectKey: share.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: "owned", Project: share.Remote, Machine: "federated", Agent: "claude"}}}
	started := "2026-01-02T00:00:00Z"
	record.Write.Session.StartedAt = &started
	record.Write.UsageEvents = []UsageEvent{{SessionID: "owned", Source: "federation", Model: "model", InputTokens: 42, OccurredAt: started, DedupKey: "model"}}
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "batch", []FederationHubRecord{record})
	require.NoError(t, err)
	other := share
	other.UID = "other"
	_, err = d.PutFederationHubShare(ctx, "spoke", other)
	require.NoError(t, err)
	otherRecord := FederationHubRecord{UID: "other-owned", Hash: "other-hash", Remote: other.Remote, ProjectKey: other.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: "other-owned", Project: other.Remote, Machine: "federated", Agent: "claude"}}}
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "other", "policy", 1, 1, "other-batch", []FederationHubRecord{otherRecord})
	require.NoError(t, err)
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent) VALUES('collision','local','host','claude')`); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO messages(session_id,ordinal,role,content) VALUES('collision',0,'user','local message')`)
		return e
	}))
	collision := FederationHubRecord{UID: "collision", Hash: "collision-hash", Remote: share.Remote, ProjectKey: share.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: "collision", Project: share.Remote, Machine: "federated", Agent: "claude"}}}
	refused, err := d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 2, "collision-batch", []FederationHubRecord{collision})
	require.NoError(t, err)
	assert.Equal(t, FederationCollision, refused.Refused["collision"])
	filter := UsageFilter{From: "2026-01-02", To: "2026-01-02", Timezone: "UTC"}
	warm, err := d.GetDailyUsage(ctx, filter)
	require.NoError(t, err)
	assert.Equal(t, 42, warm.Totals.InputTokens)
	// The spoke can advance its grant while offline and stop it before the
	// new active manifest reaches this hub.
	share.State, share.Epoch = "stopped", 2
	stopped, err := d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	assert.Equal(t, "stopped", stopped.State)
	assert.EqualValues(t, 2, stopped.Epoch)
	var sessions, records int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT (SELECT count(*) FROM sessions WHERE id='owned'), (SELECT count(*) FROM federation_records WHERE share_uid='share')`).Scan(&sessions, &records))
	assert.Zero(t, sessions)
	assert.Zero(t, records)
	var otherCount, collisionCount, messages int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT (SELECT count(*) FROM federation_records WHERE share_uid='other' AND session_id='other-owned'), (SELECT count(*) FROM sessions WHERE id='collision' AND machine='host'), (SELECT count(*) FROM messages WHERE session_id='collision' AND content='local message')`).Scan(&otherCount, &collisionCount, &messages))
	assert.Equal(t, 1, otherCount)
	assert.Equal(t, 1, collisionCount)
	assert.Equal(t, 1, messages)
	after, err := d.GetDailyUsage(ctx, filter)
	require.NoError(t, err)
	assert.Zero(t, after.Totals.InputTokens)
	share.State, share.Epoch = "active", 1
	stale, err := d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	assert.Equal(t, "stopped", stale.State)
	share.Epoch, share.Resume = 3, true
	resumed, err := d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	assert.Equal(t, "active", resumed.State)
	share.State, share.Epoch, share.Resume = "stopped", 2, false
	stale, err = d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	assert.Equal(t, "active", stale.State)
	assert.EqualValues(t, 3, stale.Epoch)
	share.State, share.Epoch = "active", 1
	stale, err = d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	assert.Equal(t, "active", stale.State)
	assert.EqualValues(t, 3, stale.Epoch)
}

func TestFederationReconcileIsShareScopedAndRejectsOutOfOrderPages(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	for _, id := range []string{"share", "other"} {
		_, err := d.PutFederationHubShare(ctx, "spoke", FederationHubShare{UID: id, EnrollmentUID: "enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
	}
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('share','owned','owned','a'),('other','private','private','b')`)
		return err
	}))
	page := FederationInventoryPage{Round: "round", Epoch: 1, Sequence: 0, Items: []FederationInventoryItem{{UID: "missing", Hash: "x"}}, Final: true}
	result, err := d.ReconcileFederationPage(ctx, "enr", "spoke", "share", "policy", page)
	require.NoError(t, err)
	assert.Equal(t, []string{"missing"}, result.Missing)
	assert.Equal(t, []string{"owned"}, result.Extra)
	assert.NotContains(t, result.Extra, "private")
	page.After = "wrong"
	_, err = d.ReconcileFederationPage(ctx, "enr", "spoke", "share", "policy", page)
	require.ErrorIs(t, err, ErrFederationSequence)
	_, err = d.ReconcileFederationPage(ctx, "enr", "spoke", "unknown", "policy", page)
	require.ErrorIs(t, err, sql.ErrNoRows)
	_, err = d.ReconcileFederationPage(ctx, "foreign", "spoke", "share", "policy", page)
	require.ErrorIs(t, err, sql.ErrNoRows)
}

func TestFederationRevokeUsesShareRetention(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	for _, tc := range []struct{ uid, retention string }{{"purge", "member-controlled"}, {"retain", "org-retained"}} {
		_, err := d.PutFederationHubShare(ctx, "spoke", FederationHubShare{UID: tc.uid, EnrollmentUID: "enr", Remote: "example.org/" + tc.uid, ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active", Retention: tc.retention})
		require.NoError(t, err)
		record := FederationHubRecord{UID: tc.uid, Hash: "hash", Remote: "example.org/" + tc.uid, ProjectKey: "key", Write: SessionBatchWrite{Session: Session{ID: tc.uid, Project: "p", Machine: "federated", Agent: "claude"}}}
		_, err = d.CommitFederationBatch(ctx, "enr", "spoke", tc.uid, "policy", 1, 1, "batch", []FederationHubRecord{record})
		require.NoError(t, err)
	}
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "foreign-enr", SpokeArchiveID: "foreign-spoke", Member: "other", CredentialSHA256: "foreign-digest"}))
	foreign := FederationHubShare{UID: "foreign-share", EnrollmentUID: "foreign-enr", Remote: "example.org/foreign", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active", Retention: "member-controlled"}
	_, err := d.PutFederationHubShare(ctx, "foreign-spoke", foreign)
	require.NoError(t, err)
	foreignRecord := FederationHubRecord{UID: "foreign", Hash: "hash", Remote: foreign.Remote, ProjectKey: foreign.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: "foreign", Project: "p", Machine: "federated", Agent: "claude"}}}
	_, err = d.CommitFederationBatch(ctx, "foreign-enr", "foreign-spoke", "foreign-share", "policy", 1, 1, "batch", []FederationHubRecord{foreignRecord})
	require.NoError(t, err)
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent) VALUES('collision','local','host','claude')`); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO messages(session_id,ordinal,role,content) VALUES('collision',0,'user','local message')`)
		return e
	}))
	collision := FederationHubRecord{UID: "collision", Hash: "hash", Remote: "example.org/purge", ProjectKey: "key", Write: SessionBatchWrite{Session: Session{ID: "collision", Project: "p", Machine: "federated", Agent: "claude"}}}
	result, err := d.CommitFederationBatch(ctx, "enr", "spoke", "purge", "policy", 1, 2, "collision", []FederationHubRecord{collision})
	require.NoError(t, err)
	assert.Equal(t, FederationCollision, result.Refused["collision"])
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	changed, err := d.RevokeFederationEnrollment(canceled, "enr")
	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, changed)
	var before int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id='purge'`).Scan(&before))
	assert.Equal(t, 1, before)
	require.NoError(t, revokeFederationEnrollment(d, ctx, "enr"))
	var purged, retained int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT (SELECT count(*) FROM sessions WHERE id='purge'),(SELECT count(*) FROM sessions WHERE id='retain')`).Scan(&purged, &retained))
	assert.Zero(t, purged)
	assert.Equal(t, 1, retained)
	var foreignCount, collisionCount, messages int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT (SELECT count(*) FROM federation_records WHERE share_uid='foreign-share' AND session_id='foreign'),(SELECT count(*) FROM sessions WHERE id='collision' AND machine='host'),(SELECT count(*) FROM messages WHERE session_id='collision' AND content='local message')`).Scan(&foreignCount, &collisionCount, &messages))
	assert.Equal(t, 1, foreignCount)
	assert.Equal(t, 1, collisionCount)
	assert.Equal(t, 1, messages)
}

func TestRetainedStoppedShareAllowsOnlyTombstoneNarrowing(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	share := FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active", Retention: "org-retained"}
	_, err := d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	record := FederationHubRecord{UID: "owned", Hash: "hash", Remote: share.Remote, ProjectKey: share.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: "owned", Project: "p", Machine: "federated", Agent: "claude"}}}
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "batch", []FederationHubRecord{record})
	require.NoError(t, err)
	share.State = "stopped"
	_, err = d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	// A policy change grants no new content under the old retained stop.
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "changed-policy", 1, 2, "mixed", []FederationHubRecord{{UID: "owned", Tombstone: true}, record})
	require.ErrorIs(t, err, ErrFederationInvalidBatch)
	var count int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id='owned'`).Scan(&count))
	assert.Equal(t, 1, count)
	// The accepted retained stop still permits an identified tombstone.
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "changed-policy", 1, 2, "delete", []FederationHubRecord{{UID: "owned", Tombstone: true}})
	require.NoError(t, err)
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id='owned'`).Scan(&count))
	assert.Zero(t, count)
}

func TestStopKeepsHubAcceptedRetentionWhenNewConsentWasNotRegistered(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	share := FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "accepted", Epoch: 1, State: "active", Retention: "org-retained"}
	_, err := d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	record := FederationHubRecord{UID: "owned", Hash: "hash", Remote: share.Remote, ProjectKey: share.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: "owned", Project: "p", Machine: "federated", Agent: "claude"}}}
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "accepted", 1, 1, "batch", []FederationHubRecord{record})
	require.NoError(t, err)
	share.State, share.Epoch, share.PolicyDigest, share.Retention = "stopped", 2, "new-policy", "member-controlled"
	stopped, err := d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	assert.Equal(t, "org-retained", stopped.Retention)
	var count int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id='owned'`).Scan(&count))
	assert.Equal(t, 1, count)
}

func TestFederationRebuildKeepsOldRowsUntilAllRangesRepaired(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	share := FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active", Retention: "member-controlled"}
	_, err := d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	record := func(id, hash string) FederationHubRecord {
		return FederationHubRecord{UID: id, Hash: hash, Remote: share.Remote, ProjectKey: share.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: id, Project: share.Remote, Machine: "federated", Agent: "claude"}}}
	}
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "first", []FederationHubRecord{record("a", "same"), record("z", "old")})
	require.NoError(t, err)
	share.Epoch, share.Rebuild = 2, true
	_, err = d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	first := FederationInventoryPage{Round: "round", Epoch: 2, Through: "a", Items: []FederationInventoryItem{{UID: "a", Hash: "same"}}}
	result, err := d.ReconcileFederationPage(ctx, "enr", "spoke", "share", "policy", first)
	require.NoError(t, err)
	assert.Equal(t, "a", result.Boundary)
	// A changed hub policy must reveal no inventory and must not complete the
	// epoch or purge the older row, including for an empty final page.
	stale := FederationInventoryPage{Round: "round", Epoch: 2, After: "a", Final: true}
	refused, err := d.ReconcileFederationPage(ctx, "enr", "spoke", "share", "changed-policy", stale)
	require.ErrorIs(t, err, sql.ErrNoRows)
	assert.Empty(t, refused.Missing)
	assert.Empty(t, refused.Extra)
	var boundary string
	var completed int64
	var retained int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT reconcile_boundary,completed_epoch,(SELECT count(*) FROM sessions WHERE id='z') FROM federation_hub_shares WHERE share_uid='share'`).Scan(&boundary, &completed, &retained))
	assert.Equal(t, "a", boundary)
	assert.Less(t, completed, int64(2))
	assert.Equal(t, 1, retained)
	last := FederationInventoryPage{Round: "round", Epoch: 2, After: "a", Final: true, Items: []FederationInventoryItem{{UID: "b", Hash: "new"}}}
	result, err = d.ReconcileFederationPage(ctx, "enr", "spoke", "share", "policy", last)
	require.NoError(t, err)
	assert.Equal(t, []string{"b"}, result.Missing)
	var old int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id='z'`).Scan(&old))
	assert.Equal(t, 1, old)
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 2, 1, "repair", []FederationHubRecord{record("b", "new")})
	require.NoError(t, err)
	last.Sequence = 1
	result, err = d.ReconcileFederationPage(ctx, "enr", "spoke", "share", "policy", last)
	require.NoError(t, err)
	assert.False(t, result.Complete)
	result, err = d.ReconcileFederationPage(ctx, "enr", "spoke", "share", "policy", last)
	require.NoError(t, err)
	assert.True(t, result.Complete)
	var same, repaired int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT (SELECT count(*) FROM sessions WHERE id='a'), (SELECT count(*) FROM sessions WHERE id='b'), (SELECT count(*) FROM sessions WHERE id='z')`).Scan(&same, &repaired, &old))
	assert.Equal(t, 1, same)
	assert.Equal(t, 1, repaired)
	assert.Zero(t, old)
}

func TestFederationPurgeRevokesSurvivingRecallEvidence(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO sessions(id,project,machine,agent) VALUES('shared','p','federated','claude'),('local','p','host','claude')`,
			`INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('share','shared','shared','hash')`,
			`INSERT INTO recall_entries(id,type,scope,title,body,source_session_id,provenance_ok) VALUES('fact','fact','project','title','body','local',1)`,
			`INSERT INTO recall_evidence(entry_id,session_id,message_start_ordinal,message_end_ordinal) VALUES('fact','shared',0,0)`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		_, err := purgeFederationRecordsTx(ctx, tx, "share", []string{"shared"}, &recallEvidenceRevocationEvents{})
		return err
	}))
	var trusted, evidence int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT provenance_ok,(SELECT count(*) FROM recall_evidence WHERE entry_id='fact') FROM recall_entries WHERE id='fact'`).Scan(&trusted, &evidence))
	assert.Zero(t, trusted)
	assert.Zero(t, evidence)
}

func TestFederationInventoryRejectsOversizedAndCompletesEmpty(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	_, err := d.PutFederationHubShare(ctx, "spoke", FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
	require.NoError(t, err)
	page := FederationInventoryPage{Round: "round", Epoch: 1, Final: true, Items: make([]FederationInventoryItem, 1001)}
	for i := range page.Items {
		page.Items[i] = FederationInventoryItem{UID: fmt.Sprintf("item-%04d", i), Hash: "hash"}
	}
	_, err = d.ReconcileFederationPage(ctx, "enr", "spoke", "share", "policy", page)
	require.ErrorIs(t, err, ErrFederationInvalidBatch)
	page.Items = nil
	result, err := d.ReconcileFederationPage(ctx, "enr", "spoke", "share", "policy", page)
	require.NoError(t, err)
	assert.True(t, result.Complete)
	assert.Empty(t, result.Missing)
	assert.Empty(t, result.Extra)
}

func TestFederationPurgeInvalidatesWarmSearchAndExtraction(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.UpsertSession(ctx, Session{ID: "shared", Project: "p", Machine: "federated", Agent: "claude"}))
	require.NoError(t, d.InsertMessages(ctx, []Message{{SessionID: "shared", Ordinal: 0, Role: "user", Content: "uniquewithdrawalterm"}}))
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('share','shared','shared','hash')`,
			`INSERT INTO recall_entries(id,type,scope,title,body,source_session_id,provenance_ok) VALUES('fact','fact','project','title','body','shared',1)`,
			`INSERT INTO recall_extract_generations(fingerprint,model,segmenter) VALUES('generation','model','segmenter')`,
			`INSERT INTO recall_extract_progress(session_id,generation_fingerprint) VALUES('shared','generation')`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}))
	warm, err := d.Search(ctx, SearchFilter{Query: "uniquewithdrawalterm"})
	require.NoError(t, err)
	require.Len(t, warm.Results, 1)
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		_, err := purgeFederationRecordsTx(ctx, tx, "share", []string{"shared"}, &recallEvidenceRevocationEvents{})
		return err
	}))
	cold, err := d.Search(ctx, SearchFilter{Query: "uniquewithdrawalterm"})
	require.NoError(t, err)
	assert.Empty(t, cold.Results)
	var progress, vectorDeletion int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT (SELECT count(*) FROM recall_extract_progress WHERE session_id='shared'),(SELECT count(*) FROM recall_embedding_deletions WHERE entry_id='fact')`).Scan(&progress, &vectorDeletion))
	assert.Zero(t, progress)
	assert.Equal(t, 1, vectorDeletion)
}

func TestFederationSameHashAttachesLaterOwnedParent(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	share := FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active", Retention: "member-controlled"}
	_, err := d.PutFederationHubShare(ctx, "spoke", share)
	require.NoError(t, err)
	parent := "z-parent"
	child := FederationHubRecord{UID: "a-child", Hash: "child-hash", Remote: share.Remote, ProjectKey: share.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: "a-child", Project: "p", Machine: "federated", Agent: "claude", ParentSessionID: &parent, RelationshipType: "subagent"}}}
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 1, "child", []FederationHubRecord{child})
	require.NoError(t, err)
	parentRecord := FederationHubRecord{UID: parent, Hash: "parent-hash", Remote: share.Remote, ProjectKey: share.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: parent, Project: "p", Machine: "federated", Agent: "claude"}}}
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 2, "parent", []FederationHubRecord{parentRecord})
	require.NoError(t, err)
	// A later relationship repair must republish the surviving child to mirrors.
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sessions SET sync_marker='2001-01-01T00:00:00.000Z' WHERE id='a-child'`)
		return err
	}))
	result, err := d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 3, "repair", []FederationHubRecord{child})
	require.NoError(t, err)
	assert.True(t, result.Changed)
	candidates, err := d.ListSessionsForMirrorWindow(ctx, "2002-01-01T00:00:00Z", nil, nil)
	require.NoError(t, err)
	var candidateIDs []string
	for _, candidate := range candidates {
		candidateIDs = append(candidateIDs, candidate.ID)
	}
	assert.Contains(t, candidateIDs, "a-child")
	var gotParent, relationship string
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT coalesce(parent_session_id,''),relationship_type FROM sessions WHERE id='a-child'`).Scan(&gotParent, &relationship))
	assert.Equal(t, "z-parent", gotParent)
	assert.Equal(t, "subagent", relationship)
	var beforeRepeat, afterRepeat string
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT sync_marker FROM sessions WHERE id='a-child'`).Scan(&beforeRepeat))
	result, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 4, "repeat", []FederationHubRecord{child})
	require.NoError(t, err)
	assert.False(t, result.Changed)
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT sync_marker FROM sessions WHERE id='a-child'`).Scan(&afterRepeat))
	assert.Equal(t, beforeRepeat, afterRepeat)
	childID := "a-child"
	parentRecord.Write.Session.ParentSessionID = &childID
	parentRecord.Write.Session.RelationshipType = "subagent"
	parentRecord.Hash = "parent-cycle"
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 5, "cycle", []FederationHubRecord{parentRecord})
	require.NoError(t, err)
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT coalesce(parent_session_id,''),relationship_type FROM sessions WHERE id='z-parent'`).Scan(&gotParent, &relationship))
	assert.Empty(t, gotParent)
	assert.Empty(t, relationship)
	foreign := share
	foreign.UID = "foreign-share"
	_, err = d.PutFederationHubShare(ctx, "spoke", foreign)
	require.NoError(t, err)
	foreignParent := FederationHubRecord{UID: "foreign-parent", Hash: "foreign", Remote: share.Remote, ProjectKey: share.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: "foreign-parent", Project: "p", Machine: "federated", Agent: "claude"}}}
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", foreign.UID, "policy", 1, 1, "foreign", []FederationHubRecord{foreignParent})
	require.NoError(t, err)
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent) VALUES('local-parent','local','host','claude')`); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO messages(session_id,ordinal,role,content) VALUES('local-parent',0,'user','original')`)
		return e
	}))
	localParent := FederationHubRecord{UID: "local-parent", Hash: "local", Remote: share.Remote, ProjectKey: share.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: "local-parent", Project: "p", Machine: "federated", Agent: "claude"}}}
	result, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 6, "refusal", []FederationHubRecord{localParent})
	require.NoError(t, err)
	assert.Equal(t, FederationCollision, result.Refused["local-parent"])
	for i, parentID := range []string{"foreign-parent", "local-parent"} {
		childID := "child-" + parentID
		candidate := FederationHubRecord{UID: childID, Hash: "child", Remote: share.Remote, ProjectKey: share.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: childID, Project: "p", Machine: "federated", Agent: "claude", ParentSessionID: &parentID, RelationshipType: "subagent"}}}
		_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, int64(7+i), childID, []FederationHubRecord{candidate})
		require.NoError(t, err)
		require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT coalesce(parent_session_id,''),relationship_type FROM sessions WHERE id=?`, childID).Scan(&gotParent, &relationship))
		assert.Empty(t, gotParent)
		assert.Empty(t, relationship)
	}
	var messages int
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT count(*) FROM messages WHERE session_id='local-parent' AND content='original'`).Scan(&messages))
	assert.Equal(t, 1, messages)
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sessions SET sync_marker='2001-01-01T00:00:00.000Z' WHERE id='a-child'`)
		return err
	}))
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 9, "remove-parent", []FederationHubRecord{{UID: "z-parent", Tombstone: true}})
	require.NoError(t, err)
	// Removing the parent must publish the still-present child's detachment.
	candidates, err = d.ListSessionsForMirrorWindow(ctx, "2002-01-01T00:00:00Z", nil, nil)
	require.NoError(t, err)
	candidateIDs = nil
	for _, candidate := range candidates {
		candidateIDs = append(candidateIDs, candidate.ID)
	}
	assert.Contains(t, candidateIDs, "a-child")
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT coalesce(parent_session_id,''),relationship_type FROM sessions WHERE id='a-child'`).Scan(&gotParent, &relationship))
	assert.Empty(t, gotParent)
	assert.Empty(t, relationship)
	parentRecord.Write.Session.ParentSessionID = nil
	parentRecord.Write.Session.RelationshipType = ""
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 10, "return-parent", []FederationHubRecord{parentRecord})
	require.NoError(t, err)
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sessions SET sync_marker='2999-01-01T00:00:00.000Z' WHERE id='a-child'`)
		return err
	}))
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 11, "repair-future-marker", []FederationHubRecord{child})
	require.NoError(t, err)
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT sync_marker FROM sessions WHERE id='a-child'`).Scan(&afterRepeat))
	assert.Equal(t, "2999-01-01T00:00:00.000Z", afterRepeat)
	_, err = d.CommitFederationBatch(ctx, "enr", "spoke", "share", "policy", 1, 12, "remove-parent-again", []FederationHubRecord{{UID: "z-parent", Tombstone: true}})
	require.NoError(t, err)
	require.NoError(t, d.rawReader().QueryRowContext(ctx, `SELECT sync_marker FROM sessions WHERE id='a-child'`).Scan(&afterRepeat))
	assert.Equal(t, "2999-01-01T00:00:00.000Z", afterRepeat)
}
