package db

import (
	"database/sql"
	"encoding/json"
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
