package db

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederationPulseScopeUsesOwnedLiveRecords(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		statements := []string{
			`INSERT INTO federation_enrollments(enrollment_uid,spoke_archive_id,member,credential_sha256) VALUES('active','spoke-a','alice','digest-a'),('retained','spoke-b','alice','digest-b'),('missing','spoke-c','','digest-c')`,
			`UPDATE federation_enrollments SET revoked_at='2026-01-01' WHERE enrollment_uid='retained'`,
			`INSERT INTO federation_hub_shares(share_uid,enrollment_uid,normalized_remote,project_key,level,attribution,audience,policy_digest,epoch,state,retention) VALUES('a','active','example/a','project-a','summary','pooled','operators','policy',1,'active',''),('b','retained','example/b','project-b','summary','pooled','operators','policy',1,'stopped','org-retained'),('c','missing','example/c','project-c','summary','pooled','operators','policy',1,'active',''),('d','active','example/d','project-d','summary','pooled','operators','policy',1,'stopped','member-controlled')`,
			`INSERT INTO sessions(id,project,machine,agent) VALUES('owned','example/a','federated','claude'),('retained','example/b','federated','claude'),('missing-member','example/c','federated','claude'),('purged','example/d','federated','claude'),('local','example/a','federated','claude'),('deleted','example/a','federated','claude'),('excluded','example/a','federated','claude')`,
			`UPDATE sessions SET deleted_at='2026-01-01' WHERE id='deleted'`,
			`INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('a','owned','owned','h'),('b','retained','retained','h'),('c','missing-member','missing-member','h'),('d','purged','purged','h'),('a','deleted','deleted','h'),('orphan','orphan','local','h'),('a','excluded','excluded','h')`,
			`INSERT INTO federation_exclusions(session_id,reason) VALUES('excluded','fixture')`,
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		return nil
	}))
	tx, err := d.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	got, err := federationPulseScope(ctx, tx)
	require.NoError(t, err)
	assert.Equal(t, map[string]federationPulseOwner{
		"owned":    {member: "alice", project: "project-a"},
		"retained": {member: "alice", project: "project-b"},
	}, got)
}

func TestFederationPulseSinceValidation(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		input   string
		want    *time.Time
		invalid bool
	}{
		{input: "", want: nil},
		{input: "2026-07-28", want: Ptr(time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC))},
		{input: "2026-08-01", want: Ptr(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))},
		{input: "2026-08-02", invalid: true},
		{input: "2026-7-28", invalid: true},
		{input: "2026-02-30", invalid: true},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseFederationPulseSince(tc.input, now)
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFederationPulseSnapshotScopesAndVisitsDays(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		for _, statement := range []string{
			`INSERT INTO federation_enrollments(enrollment_uid,spoke_archive_id,member,credential_sha256) VALUES('e','spoke','alice','digest')`,
			`INSERT INTO federation_hub_shares(share_uid,enrollment_uid,normalized_remote,project_key,level,attribution,audience,policy_digest,epoch,state) VALUES('share','e','example/a','project','summary','pooled','operators','policy',1,'active')`,
		} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		return nil
	}))
	for _, item := range []struct{ id, started string }{{"owned", "2026-07-28T10:00:00Z"}, {"local", "2026-07-27T10:00:00Z"}} {
		insertSession(t, d, item.id, "fixture", func(s *Session) { s.StartedAt = &item.started })
		seedMessage(t, d, item.id, 1, "user", item.started, "")
	}
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('share','r','owned','hash')`)
		return err
	}))
	var dates []string
	rng, err := d.readFederationPulseSnapshot(ctx, "", time.Date(2026, 7, 29, 12, 30, 0, 0, time.UTC), func(tx *sql.Tx, date, end time.Time, owners map[string]federationPulseOwner, source reportingDaySource) error {
		dates = append(dates, date.Format(time.DateOnly))
		assert.Equal(t, "alice", owners["owned"].member)
		assert.NotContains(t, owners, "local")
		assert.Empty(t, source.standaloneUsage)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"2026-07-28", "2026-07-29"}, dates)
	assert.Equal(t, Ptr("2026-07-28"), rng.EarliestDate)
	assert.Equal(t, "2026-07-29T12:00:00Z", rng.ClosedThrough)
}

func TestFederationPulseSuppressionProtectsSupportAtoms(t *testing.T) {
	owners := map[string]federationPulseOwner{
		"a": {member: "alice"}, "b": {member: "bob"}, "c": {member: "carol"},
		"d": {member: "dave"}, "e": {member: "erin"}, "f": {member: "frank"},
		"a2": {member: "alice"},
	}
	support := map[string]map[string]map[string]struct{}{
		"safe": {"sessions": {"d": {}, "e": {}, "f": {}}, "model": {"d": {}, "e": {}, "f": {}}},
		// Both marginals have three members, but their differences isolate two.
		"unsafe": {"sessions": {"a": {}, "b": {}, "c": {}, "d": {}}, "model": {"a": {}, "b": {}, "c": {}}},
		// A second enrollment for Alice must not raise support to three.
		"duplicate": {"sessions": {"a": {}, "a2": {}, "b": {}}},
	}
	hidden, global := federationPulseSuppression(support, owners, 3)
	assert.Equal(t, map[string]bool{"unsafe": true, "duplicate": true}, hidden)
	assert.True(t, global)
	clear, global := federationPulseSuppression(map[string]map[string]map[string]struct{}{"safe": support["safe"]}, owners, 3)
	assert.Empty(t, clear)
	assert.False(t, global)
}

func TestFederationPulseReadsStoredSignalsForSelectedSessions(t *testing.T) {
	d := testDB(t)
	insertSession(t, d, "selected", "fixture", func(s *Session) {})
	insertSession(t, d, "missing", "fixture", func(s *Session) {})
	insertSession(t, d, "other", "fixture", func(s *Session) {})
	updateSignals(t, d, "missing", SessionSignalUpdate{Outcome: ""})
	updateSignals(t, d, "selected", SessionSignalUpdate{Outcome: "unknown", HealthGrade: Ptr("D")})
	updateSignals(t, d, "other", SessionSignalUpdate{Outcome: "completed", HealthGrade: Ptr("A")})
	tx, err := d.getReader().BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	got, err := federationPulseSignals(t.Context(), tx, []string{"selected", "missing"})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "unknown", got["selected"].Outcome)
	assert.Equal(t, Ptr("D"), got["selected"].HealthGrade)
	assert.Empty(t, got["missing"].Outcome)
	assert.Nil(t, got["missing"].HealthGrade)
	assert.NotContains(t, got, "other")
}
