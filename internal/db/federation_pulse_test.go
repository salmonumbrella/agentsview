package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/json/jsontext"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/export"
	"go.kenn.io/agentsview/internal/money"
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
	rng, err := d.readFederationPulseSnapshot(ctx, "", time.Date(2026, 7, 29, 12, 30, 0, 0, time.UTC), nil, func(tx *sql.Tx, date, end time.Time, owners map[string]federationPulseOwner, source reportingDaySource) error {
		dates = append(dates, date.Format(time.DateOnly))
		assert.Equal(t, "alice", owners["owned"].member)
		assert.NotContains(t, owners, "local")
		assert.Empty(t, source.standaloneUsage)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"2026-07-28"}, dates)
	assert.Equal(t, Ptr("2026-07-28"), rng.EarliestDate)
	assert.Equal(t, "2026-07-29T12:00:00Z", rng.ClosedThrough)
	for _, tc := range []struct {
		since string
		want  []string
	}{
		{"0001-01-01", []string{"2026-07-28"}},
		{"2026-07-29", nil},
	} {
		var visited []string
		_, err := d.readFederationPulseSnapshot(ctx, tc.since, time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC), nil, func(_ *sql.Tx, date, _ time.Time, _ map[string]federationPulseOwner, _ reportingDaySource) error {
			visited = append(visited, date.Format(time.DateOnly))
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, tc.want, visited)
	}
	empty := testDB(t)
	visits := 0
	_, err = empty.readFederationPulseSnapshot(ctx, "0001-01-01", time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC), nil, func(_ *sql.Tx, _, _ time.Time, _ map[string]federationPulseOwner, _ reportingDaySource) error {
		visits++
		return nil
	})
	require.NoError(t, err)
	assert.Zero(t, visits)
	require.NoError(t, empty.Update(ctx, func(tx *sql.Tx) error {
		for _, statement := range []string{
			`INSERT INTO federation_enrollments(enrollment_uid,spoke_archive_id,member,credential_sha256) VALUES('e','s','a','digest')`,
			`INSERT INTO federation_hub_shares(share_uid,enrollment_uid,normalized_remote,project_key,level,attribution,audience,policy_digest,epoch,state) VALUES('h','e','example/a','project','summary','pooled','operators','policy',1,'active')`,
			`INSERT INTO sessions(id,project,machine,agent,started_at) VALUES('future','example/a','federated','codex','2026-07-30T00:30:00Z')`,
			`INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('h','future','future','hash')`,
			`INSERT INTO sessions(id,project,machine,agent,started_at) VALUES('cutoff','example/a','federated','codex','2026-07-30T00:00:00Z')`,
			`INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('h','cutoff','cutoff','hash')`,
		} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		return nil
	}))
	_, err = empty.readFederationPulseSnapshot(ctx, "0001-01-01", time.Date(2026, 7, 30, 0, 45, 0, 0, time.UTC), nil, func(_ *sql.Tx, _, _ time.Time, _ map[string]federationPulseOwner, _ reportingDaySource) error {
		visits++
		return nil
	})
	require.NoError(t, err)
	assert.Zero(t, visits)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = d.readFederationPulseSnapshot(canceled, "0001-01-01", time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC), nil, func(_ *sql.Tx, _, _ time.Time, _ map[string]federationPulseOwner, _ reportingDaySource) error {
		return nil
	})
	assert.ErrorIs(t, err, context.Canceled)
	pulse, err := d.readFederationPulse(ctx, "0001-01-01", 1, time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, Ptr("0001-01-01"), pulse.Since)
	assert.Equal(t, Ptr(int64(1)), pulse.Totals["sessions"].Value)
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

func TestFederationPulseReleaseWithholdsUnsafeProjectsAndTotals(t *testing.T) {
	owners := map[string]federationPulseOwner{
		"session-a": {member: "alice", project: "safe"},
		"session-b": {member: "bob", project: "safe"},
		"session-c": {member: "carol", project: "safe"},
		"session-d": {member: "dave", project: "private-key"},
	}
	a := newFederationPulseAccumulator(owners)
	for _, item := range []struct {
		id     string
		tokens int64
	}{{"session-a", 10}, {"session-b", 20}, {"session-c", 30}, {"session-d", 9}} {
		a.add(item.id, "total", "", "tokens", item.tokens)
		a.add(item.id, "model", "model-x", "tokens", item.tokens)
	}
	got := a.release(3)
	require.True(t, got.Suppressed)
	require.Len(t, got.Projects, 1)
	assert.Equal(t, "safe", got.Projects[0].Key)
	assert.Equal(t, Ptr(int64(60)), got.Projects[0].Totals["tokens"].Value)
	assert.Equal(t, "suppressed", got.Totals["tokens"].State)
	assert.Nil(t, got.Totals["tokens"].Value)
	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	for _, secret := range []string{"private-key", "session-a", "session-d", "alice", "dave"} {
		assert.NotContains(t, string(encoded), secret)
	}
}

func TestFederationPulseReleaseDistinguishesUnavailableAndCostSupport(t *testing.T) {
	owners := map[string]federationPulseOwner{
		"a": {member: "one", project: "p"}, "b": {member: "two", project: "p"},
		"c": {member: "three", project: "p"},
	}
	a := newFederationPulseAccumulator(owners)
	for _, id := range []string{"a", "b", "c"} {
		a.add(id, "total", "", "tokens", 10)
	}
	a.add("a", "total", "", "cost_microdollars", 7)
	a.add("b", "total", "", "cost_microdollars", 8)
	got := a.release(3)
	assert.True(t, got.Suppressed)
	assert.Empty(t, got.Projects)
	assert.Equal(t, "suppressed", got.Totals["tokens"].State)
	empty := newFederationPulseAccumulator(nil).release(3)
	assert.Equal(t, "unavailable", empty.Totals["tokens"].State)
	assert.Nil(t, empty.Totals["tokens"].Value)
}

func TestFederationPulseWithholdsIntersectingSafeMarginals(t *testing.T) {
	owners := map[string]federationPulseOwner{
		"a": {member: "a", project: "private-project"}, "b": {member: "b", project: "private-project"},
		"c": {member: "c", project: "private-project"}, "d": {member: "d", project: "private-project"},
		"e": {member: "e", project: "private-project"}, "f": {member: "f", project: "private-project"},
		"g": {member: "g", project: "safe"}, "h": {member: "h", project: "safe"}, "i": {member: "i", project: "safe"},
	}
	a := newFederationPulseAccumulator(owners)
	for _, item := range []struct{ id, model, outcome string }{
		{"a", "private-model-a", "private-outcome-x"}, {"b", "private-model-a", "private-outcome-x"},
		{"c", "private-model-a", "private-outcome-y"}, {"d", "private-model-b", "private-outcome-x"},
		{"e", "private-model-b", "private-outcome-y"}, {"f", "private-model-b", "private-outcome-y"},
	} {
		a.add(item.id, "total", "", "sessions", 1)
		a.add(item.id, "model", item.model, "sessions", 1)
		a.add(item.id, "outcome", item.outcome, "sessions", 1)
	}
	for _, id := range []string{"g", "h", "i"} {
		a.add(id, "total", "", "sessions", 1)
		a.add(id, "total", "", "tokens", 10)
	}
	got := a.release(3)
	require.True(t, got.Suppressed)
	require.Len(t, got.Projects, 1)
	assert.Equal(t, "safe", got.Projects[0].Key)
	assert.Equal(t, Ptr(int64(30)), got.Projects[0].Totals["tokens"].Value)
	assert.Nil(t, got.Totals["sessions"].Value)
	assert.Equal(t, "suppressed", got.Totals["sessions"].State)
	assert.Equal(t, "suppressed", got.Ratios["automation_share"].State)
	data, err := json.Marshal(got)
	require.NoError(t, err)
	for _, secret := range []string{"private-project", "private-model", "private-outcome"} {
		assert.NotContains(t, string(data), secret)
	}
}

func TestFederationPulseWithholdsModelComplementOfEightAndOne(t *testing.T) {
	owners := map[string]federationPulseOwner{}
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
		owners[id] = federationPulseOwner{member: id, project: "project"}
	}
	a := newFederationPulseAccumulator(owners)
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
		a.add(id, "total", "", "sessions", 1)
		model := "common"
		if id == "i" {
			model = "private-model"
		}
		a.add(id, "model", model, "sessions", 1)
	}
	got := a.release(3)
	assert.True(t, got.Suppressed)
	assert.Empty(t, got.Projects)
	assert.Nil(t, got.Totals["sessions"].Value)
	assert.Equal(t, "suppressed", got.Totals["sessions"].State)
	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "private-model")
	assert.NotContains(t, string(encoded), "common")
}

func TestFederationPulseUsesDistinctDatedSessionsAndReportingUsage(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	for _, item := range []struct {
		id, member, occurred string
		tokens               int
	}{{"one", "alice", "2026-07-28T09:05:00Z", 10}, {"two", "bob", "2026-07-28T10:05:00Z", 20}, {"three", "carol", "2026-07-28T11:05:00Z", 30}} {
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-" + item.id, SpokeArchiveID: "spoke-" + item.id, Member: item.member, CredentialSHA256: "digest-" + item.id}))
		attribution := "pooled"
		if item.id == "three" {
			attribution = "member"
		}
		_, err := d.PutFederationHubShare(ctx, "spoke-"+item.id, FederationHubShare{UID: "share-" + item.id, EnrollmentUID: "enr-" + item.id, Remote: "example/repo", ProjectKey: "project-key", Level: "summary", Attribution: attribution, Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		started := "2026-07-28T09:00:00Z"
		record := FederationHubRecord{UID: item.id, Hash: "hash", Remote: "example/repo", ProjectKey: "project-key", Write: SessionBatchWrite{Session: Session{ID: item.id, Project: "example/repo", Machine: "federated", Agent: "codex", StartedAt: &started}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: item.tokens, OccurredAt: item.occurred, DedupKey: item.id}}}}
		_, err = d.CommitFederationBatch(ctx, "enr-"+item.id, "spoke-"+item.id, "share-"+item.id, "policy", 1, 1, "batch", []FederationHubRecord{record})
		require.NoError(t, err)
	}
	got, err := d.readFederationPulse(ctx, "2026-07-28", 3, time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.False(t, got.Suppressed)
	assert.Equal(t, Ptr(int64(3)), got.Totals["sessions"].Value)
	assert.Equal(t, Ptr(int64(60)), got.Totals["tokens"].Value)
	assert.Equal(t, "unavailable", got.Totals["health_observed_sessions"].State)
	ancient, err := d.readFederationPulse(ctx, "0001-01-01", 3, time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, Ptr("0001-01-01"), ancient.Since)
	assert.Equal(t, Ptr(int64(3)), ancient.Totals["sessions"].Value)
	assert.Equal(t, Ptr(int64(60)), ancient.Totals["tokens"].Value)
	assert.Equal(t, got.Totals["sessions"], ancient.Totals["sessions"])
	assert.Equal(t, got.Totals["tokens"], ancient.Totals["tokens"])
	require.Len(t, got.Projects, 1)
	assert.Equal(t, "project-key", got.Projects[0].Key)
	assert.Equal(t, Ptr(int64(60)), got.Projects[0].Totals["tokens"].Value)
	require.Len(t, got.Projects[0].Models, 1)
	assert.Equal(t, Ptr(int64(3)), got.Projects[0].Models[0].Metrics["sessions"].Value)

	// Compare with the ordinary export owner over the identical lawful scope;
	// the literal 60 above remains the independent accounting oracle.
	date := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	tx, err := d.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	scope := map[string]struct{}{"one": {}, "two": {}, "three": {}}
	source, err := d.loadReportingExportSourceScoped(ctx, tx, date, date.Add(24*time.Hour), export.ReportingJointSchemaVersion, scope)
	require.NoError(t, err)
	hours, err := reportingHoursFromSource(ctx, source.forDate(date, date.Add(24*time.Hour)), date, 24, export.ReportingJointSchemaVersion, nil, time.Hour)
	require.NoError(t, err)
	var exported int64
	for _, hour := range hours {
		exported += hour.Usage.Totals.InputTokens
	}
	assert.EqualValues(t, 10, hours[9].Usage.Totals.InputTokens)
	assert.EqualValues(t, 20, hours[10].Usage.Totals.InputTokens)
	assert.EqualValues(t, 30, hours[11].Usage.Totals.InputTokens)
	assert.EqualValues(t, 60, exported)
	assert.Equal(t, exported, *got.Totals["tokens"].Value)
}

// These regressions describe the accepted cross-release privacy requirement.
// The publication policy is still open; no admission bypass is used here.
func TestFederationPulseProtectsRepeatedWindowsAndUpdates(t *testing.T) {
	for _, scenario := range []string{"window", "reverse-window", "update", "copy-before-publication", "cancel-before-admission", "concurrent", "purge-regrant", "untraced-write", "reopen", "second-handle"} {
		t.Run(scenario, func(t *testing.T) {
			d := testDB(t)
			ctx := t.Context()
			start := "2026-07-29T09:00:00Z"
			for i, name := range []string{"a", "b", "c"} {
				enrollment, spoke, share := "e-"+name, "s-"+name, "h-"+name
				require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: name, CredentialSHA256: "digest-" + name}))
				_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active", Retention: "member-controlled"})
				require.NoError(t, err)
				cost := money.Money{Microdollars: int64((i + 1) * 100)}
				record := FederationHubRecord{UID: name, Hash: "initial", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: name, Project: "example/repo", Agent: "codex", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: (i + 1) * 10, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: start, DedupKey: name}}}}
				_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch-1", []FederationHubRecord{record})
				require.NoError(t, err)
			}
			now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
			if scenario == "window" || scenario == "reverse-window" || scenario == "copy-before-publication" || scenario == "cancel-before-admission" || scenario == "concurrent" || scenario == "purge-regrant" || scenario == "reopen" || scenario == "second-handle" {
				older := "2026-07-28T09:00:00Z"
				cost := money.Money{Microdollars: 70}
				record := FederationHubRecord{UID: "a-older", Hash: "initial", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: "a-older", Project: "example/repo", Agent: "codex", StartedAt: &older}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: 7, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: older, DedupKey: "a-older"}}}}
				_, err := d.CommitFederationBatch(ctx, "e-a", "s-a", "h-a", "policy", 1, 2, "batch-2", []FederationHubRecord{record})
				require.NoError(t, err)
			}
			var copied *DB
			if scenario == "copy-before-publication" {
				copied = testDB(t)
				// The copy is made before the live archive publishes its first result.
				require.NoError(t, copied.CopyArchiveIdentityFrom(ctx, d.Path()))
				require.NoError(t, copied.CopyFederationStateFrom(ctx, d.Path()))
				count, err := copied.CopyOrphanedDataFrom(ctx, d.Path())
				require.NoError(t, err)
				assert.Equal(t, 4, count)
			}
			if scenario == "concurrent" {
				type response struct {
					pulse FederationPulse
					err   error
				}
				ready := make(chan struct{})
				results := make(chan response, 2)
				for _, since := range []string{"2026-07-28", "2026-07-29"} {
					go func() {
						<-ready
						pulse, err := d.readFederationPulse(ctx, since, 3, now)
						results <- response{pulse: pulse, err: err}
					}()
				}
				close(ready)
				a, b := <-results, <-results
				require.NoError(t, a.err)
				require.NoError(t, b.err)
				assert.NotEqual(t, a.pulse.Suppressed, b.pulse.Suppressed)
				for _, result := range []FederationPulse{a.pulse, b.pulse} {
					if result.Suppressed {
						assert.Nil(t, result.Totals["tokens"].Value)
						assert.Nil(t, result.Totals["cost_microdollars"].Value)
						continue
					}
					require.NotNil(t, result.Since)
					if *result.Since == "2026-07-28" {
						assert.Equal(t, Ptr(int64(67)), result.Totals["tokens"].Value)
						assert.Equal(t, Ptr(int64(670)), result.Totals["cost_microdollars"].Value)
					} else {
						assert.Equal(t, Ptr(int64(60)), result.Totals["tokens"].Value)
						assert.Equal(t, Ptr(int64(600)), result.Totals["cost_microdollars"].Value)
					}
				}
				return
			}
			if scenario == "cancel-before-admission" {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				result, err := d.readFederationPulse(canceled, "2026-07-28", 3, now)
				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, result.Projects)
				assert.Nil(t, result.Totals)
			}
			firstSince := "2026-07-29"
			if scenario == "reverse-window" {
				firstSince = "2026-07-28"
			}
			first, err := d.readFederationPulse(ctx, firstSince, 3, now)
			require.NoError(t, err)
			if scenario == "reverse-window" {
				assert.Equal(t, Ptr(int64(4)), first.Totals["sessions"].Value)
				assert.Equal(t, Ptr(int64(67)), first.Totals["tokens"].Value)
				assert.Equal(t, Ptr(int64(670)), first.Totals["cost_microdollars"].Value)
			} else {
				assert.Equal(t, Ptr(int64(3)), first.Totals["sessions"].Value)
				assert.Equal(t, Ptr(int64(60)), first.Totals["tokens"].Value)
				assert.Equal(t, Ptr(int64(600)), first.Totals["cost_microdollars"].Value)
			}
			if scenario == "purge-regrant" {
				share := FederationHubShare{UID: "h-a", EnrollmentUID: "e-a", Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 2, State: "stopped", Retention: "member-controlled"}
				_, err = d.PutFederationHubShare(ctx, "s-a", share)
				require.NoError(t, err)
				share.Epoch, share.State, share.Resume = 3, "active", true
				_, err = d.PutFederationHubShare(ctx, "s-a", share)
				require.NoError(t, err)
				oldDate := "2026-07-28T09:00:00Z"
				records := make([]FederationHubRecord, 0, 2)
				for _, item := range []struct {
					id, at string
					tokens int
					cost   int64
				}{{"a", start, 10, 100}, {"a-older", oldDate, 7, 70}} {
					cost := money.Money{Microdollars: item.cost}
					records = append(records, FederationHubRecord{UID: item.id, Hash: "regrant", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: item.id, Project: "example/repo", Agent: "codex", StartedAt: &item.at}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: item.tokens, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: item.at, DedupKey: item.id}}}})
				}
				ack, err := d.CommitFederationBatch(ctx, "e-a", "s-a", "h-a", "policy", 3, 1, "regrant", records)
				require.NoError(t, err)
				assert.Empty(t, ack.Refused)
				ambiguous, err := d.readFederationPulse(ctx, "2026-07-28", 3, now)
				require.NoError(t, err)
				assert.True(t, ambiguous.Suppressed)
				assert.Empty(t, ambiguous.Projects)
				assert.Nil(t, ambiguous.Totals["tokens"].Value)
				freshDate := "2026-07-31T09:00:00Z"
				for _, item := range []struct {
					name            string
					epoch, sequence int64
					tokens          int
					cost            int64
				}{{"a", 3, 2, 17, 170}, {"b", 1, 2, 25, 250}, {"c", 1, 2, 35, 350}} {
					id := item.name + "-fresh"
					cost := money.Money{Microdollars: item.cost}
					record := FederationHubRecord{UID: id, Hash: "fresh", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: id, Project: "example/repo", Agent: "codex", StartedAt: &freshDate}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: item.tokens, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: freshDate, DedupKey: id}}}}
					ack, err := d.CommitFederationBatch(ctx, "e-"+item.name, "s-"+item.name, "h-"+item.name, "policy", item.epoch, item.sequence, "fresh", []FederationHubRecord{record})
					require.NoError(t, err)
					assert.Empty(t, ack.Refused)
				}
				fresh, err := d.readFederationPulse(ctx, "2026-07-31", 3, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
				require.NoError(t, err)
				assert.Equal(t, Ptr(int64(3)), fresh.Totals["sessions"].Value)
				assert.Equal(t, Ptr(int64(77)), fresh.Totals["tokens"].Value)
				assert.Equal(t, Ptr(int64(770)), fresh.Totals["cost_microdollars"].Value)
				return
			}
			if scenario == "copy-before-publication" {
				later, err := copied.readFederationPulse(ctx, "2026-07-28", 3, now)
				if err != nil {
					assert.Empty(t, later.Projects)
					assert.Nil(t, later.Totals)
					return
				}
				assert.True(t, later.Suppressed)
				assert.Empty(t, later.Projects)
				assert.Nil(t, later.Totals["tokens"].Value)
				assert.Nil(t, later.Totals["cost_microdollars"].Value)
				return
			}
			if scenario == "second-handle" {
				other, err := OpenIsolated(ctx, d.Path())
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, other.Close()) })
				later, err := other.readFederationPulse(ctx, "2026-07-28", 3, now)
				require.NoError(t, err)
				assert.True(t, later.Suppressed)
				assert.Empty(t, later.Projects)
				assert.Nil(t, later.Totals["tokens"].Value)
				assert.Nil(t, later.Totals["cost_microdollars"].Value)
				return
			}
			if scenario == "reopen" {
				require.NoError(t, d.Reopen())
			}
			if scenario == "untraced-write" {
				// This bypasses DB.Update's traced owner and exercises the source-DML fence.
				result, err := d.getWriter().ExecContext(ctx, `UPDATE usage_events SET input_tokens=17,cost_microdollars=170 WHERE session_id='a'`)
				require.NoError(t, err)
				changed, err := result.RowsAffected()
				require.NoError(t, err)
				require.EqualValues(t, 1, changed)
				later, err := d.readFederationPulse(ctx, "2026-07-29", 3, now)
				if err != nil {
					assert.Empty(t, later.Projects)
					assert.Nil(t, later.Totals)
					return
				}
				assert.True(t, later.Suppressed)
				assert.Empty(t, later.Projects)
				assert.Nil(t, later.Totals["tokens"].Value)
				assert.Nil(t, later.Totals["cost_microdollars"].Value)
				return
			}
			if scenario == "update" {
				cost := money.Money{Microdollars: 170}
				record := FederationHubRecord{UID: "a", Hash: "changed", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: "a", Project: "example/repo", Agent: "codex", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: 17, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: start, DedupKey: "a"}}}}
				_, err = d.CommitFederationBatch(ctx, "e-a", "s-a", "h-a", "policy", 1, 2, "batch-2", []FederationHubRecord{record})
				require.NoError(t, err)
			}
			date := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
			if scenario == "window" || scenario == "cancel-before-admission" || scenario == "reopen" {
				date = date.AddDate(0, 0, -1)
			}
			day, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: date, Now: now, SchemaVersion: export.ReportingJointSchemaVersion})
			require.NoError(t, err)
			if scenario == "window" || scenario == "cancel-before-admission" || scenario == "reopen" {
				assert.EqualValues(t, 7, day.Hours[9].Usage.Totals.InputTokens)
				assert.EqualValues(t, 70, day.Hours[9].Usage.Totals.Cost.Microdollars)
			} else if scenario == "reverse-window" {
				assert.EqualValues(t, 60, day.Hours[9].Usage.Totals.InputTokens)
				assert.EqualValues(t, 600, day.Hours[9].Usage.Totals.Cost.Microdollars)
			} else {
				assert.EqualValues(t, 67, day.Hours[9].Usage.Totals.InputTokens)
				assert.EqualValues(t, 670, day.Hours[9].Usage.Totals.Cost.Microdollars)
			}
			since := "2026-07-29"
			if scenario == "window" || scenario == "cancel-before-admission" || scenario == "reopen" {
				since = "2026-07-28"
			}
			later, err := d.readFederationPulse(ctx, since, 3, now)
			require.NoError(t, err)
			assert.True(t, later.Suppressed)
			assert.Empty(t, later.Projects)
			assert.Equal(t, "suppressed", later.Totals["tokens"].State)
			assert.Nil(t, later.Totals["tokens"].Value)
			assert.Nil(t, later.Totals["cost_microdollars"].Value)
			assert.Equal(t, Ptr(since), later.Since)
		})
	}
}

func TestFederationPulseVisitsSparseEvidenceDays(t *testing.T) {
	for _, tc := range []struct {
		name, since string
		newer       bool
		dates       []string
		sessions    int64
		tokens      int64
		cost        int64
	}{
		{"old default", "", false, []string{"2016-07-28"}, 3, 60, 600},
		{"both default", "", true, []string{"2016-07-28", "2026-07-28"}, 6, 66, 660},
		{"recent", "2026-07-28", true, []string{"2026-07-28"}, 3, 6, 60},
		{"ancient", "0001-01-01", true, []string{"2016-07-28", "2026-07-28"}, 6, 66, 660},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			ctx := t.Context()
			for i, name := range []string{"a", "b", "c"} {
				enrollment, spoke, share := "e-"+name, "s-"+name, "h-"+name
				require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: name, CredentialSHA256: "digest-" + name}))
				_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
				require.NoError(t, err)
				var records []FederationHubRecord
				for _, item := range []struct {
					id, start  string
					multiplier int
				}{{name + "-old", "2016-07-28T09:00:00Z", 10}, {name + "-new", "2026-07-28T09:00:00Z", 1}} {
					if !tc.newer && item.multiplier == 1 {
						continue
					}
					cost := money.Money{Microdollars: int64((i + 1) * item.multiplier * 10)}
					records = append(records, FederationHubRecord{UID: item.id, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: item.id, Project: "example/repo", Agent: "codex", StartedAt: &item.start}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: (i + 1) * item.multiplier, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: item.start, DedupKey: item.id}}}})
				}
				_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", records)
				require.NoError(t, err)
			}
			now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
			var dates []string
			_, err := d.readFederationPulseSnapshot(ctx, tc.since, now, nil, func(_ *sql.Tx, date, _ time.Time, _ map[string]federationPulseOwner, _ reportingDaySource) error {
				dates = append(dates, date.Format(time.DateOnly))
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, tc.dates, dates)
			pulse, err := d.readFederationPulse(ctx, tc.since, 3, now)
			require.NoError(t, err)
			assert.False(t, pulse.Suppressed)
			assert.Equal(t, Ptr(tc.sessions), pulse.Totals["sessions"].Value)
			assert.Equal(t, Ptr(int64(1)), pulse.Totals["active_projects"].Value)
			assert.Equal(t, Ptr(tc.tokens), pulse.Totals["tokens"].Value)
			assert.Equal(t, Ptr(tc.cost), pulse.Totals["cost_microdollars"].Value)
			assert.Equal(t, "available", pulse.Totals["cost_microdollars"].State)
			assert.Equal(t, "unavailable", pulse.Totals["health_observed_sessions"].State)
			require.Len(t, pulse.Outcomes, 1)
			assert.Equal(t, "unknown", pulse.Outcomes[0].Key)
			assert.Equal(t, Ptr(tc.sessions), pulse.Outcomes[0].Metrics["sessions"].Value)
			assert.Equal(t, "2026-07-30T00:00:00Z", pulse.ClosedThrough)
			if tc.since == "" {
				assert.Nil(t, pulse.Since)
			} else {
				assert.Equal(t, Ptr(tc.since), pulse.Since)
			}
		})
	}
}

func TestFederationPulseCrossProjectScopedExportParity(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	start := "2026-07-28T09:00:00Z"
	fixtures := []struct {
		id, project string
		tokens      int
		cost        int64
	}{
		{"a", "alpha", 10, 1}, {"b", "alpha", 20, 2}, {"c", "alpha", 30, 3},
		{"d", "beta", 40, 4}, {"e", "beta", 50, 5}, {"f", "beta", 60, 6},
	}
	scope := make(map[string]struct{}, len(fixtures))
	for _, f := range fixtures {
		scope[f.id] = struct{}{}
		enrollment, share, spoke := "enr-"+f.id, "share-"+f.id, "spoke-"+f.id
		remote, key := "example/"+f.project, "key-"+f.project
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: f.id, CredentialSHA256: "digest-" + f.id}))
		_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: remote, ProjectKey: key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		cost := money.Money{Microdollars: f.cost}
		record := FederationHubRecord{UID: f.id, Hash: "hash", Remote: remote, ProjectKey: key, Write: SessionBatchWrite{
			Session: Session{ID: f.id, Project: remote, Agent: "codex", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "unknown"},
			UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: f.tokens, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: start, DedupKey: f.id}},
		}}
		_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
		require.NoError(t, err)
	}
	pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	require.False(t, pulse.Suppressed)
	require.Len(t, pulse.Projects, 2)
	assert.Equal(t, "key-alpha", pulse.Projects[0].Key)
	assert.Equal(t, Ptr(int64(60)), pulse.Projects[0].Totals["tokens"].Value)
	assert.Equal(t, Ptr(int64(6)), pulse.Projects[0].Totals["cost_microdollars"].Value)
	assert.Equal(t, "key-beta", pulse.Projects[1].Key)
	assert.Equal(t, Ptr(int64(150)), pulse.Projects[1].Totals["tokens"].Value)
	assert.Equal(t, Ptr(int64(15)), pulse.Projects[1].Totals["cost_microdollars"].Value)
	assert.Equal(t, Ptr(int64(210)), pulse.Totals["tokens"].Value)
	assert.Equal(t, Ptr(int64(21)), pulse.Totals["cost_microdollars"].Value)
	date := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	tx, err := d.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	source, err := d.loadReportingExportSourceScoped(ctx, tx, date, date.Add(24*time.Hour), export.ReportingJointSchemaVersion, scope)
	require.NoError(t, err)
	hours, err := reportingHoursFromSource(ctx, source.forDate(date, date.Add(24*time.Hour)), date, 24, export.ReportingJointSchemaVersion, nil, time.Hour)
	require.NoError(t, err)
	assert.EqualValues(t, 210, hours[9].Usage.Totals.InputTokens)
	assert.EqualValues(t, 21, hours[9].Usage.Totals.Cost.Microdollars)
	assert.Equal(t, *pulse.Totals["tokens"].Value, hours[9].Usage.Totals.InputTokens)
	assert.Equal(t, *pulse.Totals["cost_microdollars"].Value, hours[9].Usage.Totals.Cost.Microdollars)
	projectUsage := map[string]int64{}
	projectCost := map[string]int64{}
	for _, project := range hours[9].Usage.ByProject {
		projectUsage[project.Project] += project.InputTokens
		projectCost[project.Project] += project.Cost.Microdollars
	}
	assert.Equal(t, map[string]int64{"example/alpha": 60, "example/beta": 150}, projectUsage)
	assert.Equal(t, map[string]int64{"example/alpha": 6, "example/beta": 15}, projectCost)
}

func TestFederationPulseCrossProjectAllocatedCostMatchesScopedExport(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.UpsertModelPricing([]ModelPricing{
		{ModelPattern: "copilot-model-a", InputPerMTok: money.MustParseDollars("10")},
		{ModelPattern: "copilot-model-b", InputPerMTok: money.MustParseDollars("20")},
	}))
	scope := map[string]struct{}{}
	for _, project := range []string{"alpha", "beta"} {
		for _, member := range []string{"a", "b", "c"} {
			id := project + "-" + member
			scope[id] = struct{}{}
			enrollment, spoke, share := "enr-"+id, "spoke-"+id, "share-"+id
			remote, key := "example/"+project, "key-"+project
			require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: member, CredentialSHA256: "digest-" + id}))
			_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: remote, ProjectKey: key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
			require.NoError(t, err)
			started, ended := "2026-07-28T10:00:00Z", "2026-07-28T11:10:00Z"
			cost := money.MustParseDollars("0.03")
			record := FederationHubRecord{UID: id, Hash: "hash", Remote: remote, ProjectKey: key, Write: SessionBatchWrite{
				Session: Session{ID: id, Project: remote, Agent: "copilot", StartedAt: &started, EndedAt: &ended}, Signals: SessionSignalUpdate{Outcome: "unknown"},
				UsageEvents: []UsageEvent{
					{Source: "shutdown", Model: "copilot-model-a", InputTokens: 1_000_000, OccurredAt: "2026-07-28T10:05:00Z", DedupKey: id + "-first"},
					{Source: "shutdown", Model: "copilot-model-b", InputTokens: 1_000_000, Cost: &cost, CostStatus: "exact", CostSource: CopilotReportedCostSource, OccurredAt: "2026-07-28T11:10:00Z", DedupKey: id + "-final"},
				},
			}}
			_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
			require.NoError(t, err)
		}
	}
	date := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	tx, err := d.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	require.NoError(t, err)
	source, err := d.loadReportingExportSourceScoped(ctx, tx, date, date.Add(24*time.Hour), export.ReportingJointSchemaVersion, scope)
	require.NoError(t, err)
	hours, err := reportingHoursFromSource(ctx, source.forDate(date, date.Add(24*time.Hour)), date, 24, export.ReportingJointSchemaVersion, nil, time.Hour)
	require.NoError(t, err)
	assert.EqualValues(t, 6_000_000, hours[10].Usage.Totals.InputTokens)
	assert.EqualValues(t, 60_000, hours[10].Usage.Totals.Cost.Microdollars)
	assert.EqualValues(t, 6_000_000, hours[11].Usage.Totals.InputTokens)
	assert.EqualValues(t, 120_000, hours[11].Usage.Totals.Cost.Microdollars)
	for hour, expectedCost := range map[int]int64{10: 30_000, 11: 60_000} {
		costs := map[string]int64{}
		for _, project := range hours[hour].Usage.ByProject {
			costs[project.Project] += project.Cost.Microdollars
		}
		assert.Equal(t, map[string]int64{"example/alpha": expectedCost, "example/beta": expectedCost}, costs)
	}
	require.NoError(t, tx.Rollback())
	pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, date.Add(24*time.Hour))
	require.NoError(t, err)
	require.False(t, pulse.Suppressed)
	assert.Equal(t, Ptr(int64(12_000_000)), pulse.Totals["tokens"].Value)
	assert.Equal(t, Ptr(int64(180_000)), pulse.Totals["cost_microdollars"].Value)
	require.Len(t, pulse.Projects, 2)
	for _, project := range pulse.Projects {
		assert.Equal(t, Ptr(int64(6_000_000)), project.Totals["tokens"].Value)
		assert.Equal(t, Ptr(int64(90_000)), project.Totals["cost_microdollars"].Value)
	}
	// Separate unpriced sessions retain the authoritative allocation above;
	// a session-level authoritative total would price every row in that session.
	for _, project := range []string{"alpha", "beta"} {
		for _, member := range []string{"a", "b", "c"} {
			id := project + "-" + member
			share := "unpriced-" + id
			remote, key := "example/"+project, "key-"+project
			_, err := d.PutFederationHubShare(ctx, "spoke-"+id, FederationHubShare{UID: share, EnrollmentUID: "enr-" + id, Remote: remote, ProjectKey: key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
			require.NoError(t, err)
			start := "2026-07-28T11:20:00Z"
			record := FederationHubRecord{UID: share, Hash: "hash", Remote: remote, ProjectKey: key, Write: SessionBatchWrite{Session: Session{ID: share, Project: remote, Agent: "copilot", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{{Source: "fixture", Model: "synthetic-unpriced-model", InputTokens: 10, OccurredAt: start, DedupKey: share}}}}
			_, err = d.CommitFederationBatch(ctx, "enr-"+id, "spoke-"+id, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
			require.NoError(t, err)
		}
	}
	day, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: date, Now: date.Add(24 * time.Hour), SchemaVersion: export.ReportingJointSchemaVersion})
	require.NoError(t, err)
	assert.EqualValues(t, 120_000, day.Hours[11].Usage.Totals.Cost.Microdollars)
	var unpriced, allocated int64
	for _, cell := range day.Hours[11].Joint.Cells {
		unpriced += cell.Pricing.UnpricedRows
		allocated += cell.Pricing.AllocatedCost.Microdollars
	}
	assert.EqualValues(t, 6, unpriced)
	assert.EqualValues(t, 120_000, allocated)
	pulse, err = d.readFederationPulse(ctx, "2026-07-28", 3, date.Add(24*time.Hour))
	require.NoError(t, err)
	assert.False(t, pulse.Suppressed)
	assert.Equal(t, Ptr(int64(12_000_060)), pulse.Totals["tokens"].Value)
	assert.Equal(t, "partial", pulse.Totals["cost_microdollars"].State)
	assert.Equal(t, Ptr(int64(180_000)), pulse.Totals["cost_microdollars"].Value)
	require.Len(t, pulse.Projects, 2)
	for _, project := range pulse.Projects {
		assert.Equal(t, "partial", project.Totals["cost_microdollars"].State)
		assert.Equal(t, Ptr(int64(90_000)), project.Totals["cost_microdollars"].Value)
	}
}

func TestFederationPulseSurvivorUsesAttributedSessionForModelCoverage(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	scope := map[string]struct{}{}
	for _, id := range []string{"a", "b", "c"} {
		enrollment, spoke := "enr-"+id, "spoke-"+id
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: id, CredentialSHA256: "digest-" + id}))
		started, parent, child := "2026-07-28T09:00:00Z", "parent-"+id, "child-"+id
		scope[parent], scope[child] = struct{}{}, struct{}{}
		messageID := "snapshot-" + id
		makeRecord := func(sessionID, remote, timestamp, model, usage string) FederationHubRecord {
			return FederationHubRecord{UID: sessionID, Hash: "hash", Remote: remote, ProjectKey: "project", Write: SessionBatchWrite{
				Session: Session{ID: sessionID, Project: remote, Agent: "claude", StartedAt: &started, MessageCount: 1}, Signals: SessionSignalUpdate{Outcome: "unknown"},
				Messages: []Message{{SessionID: sessionID, Ordinal: 0, Role: "assistant", Timestamp: timestamp, Model: model, TokenUsage: jsontext.Value(usage), ClaudeMessageID: messageID, ClaudeRequestID: "request"}}, ReplaceMessages: true,
			}}
		}
		first := makeRecord(parent, "example/repo", "2026-07-28T09:05:00Z", "partial-model", `{"input_tokens":10,"output_tokens":5}`)
		winner := makeRecord(child, "example/repo", "2026-07-28T09:06:00Z", "complete-model", `{"input_tokens":1000,"output_tokens":631}`)
		for _, record := range []FederationHubRecord{first, winner} {
			share := "share-" + record.UID
			_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: record.Remote, ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
			require.NoError(t, err)
			_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
			require.NoError(t, err)
		}
	}
	date := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	tx, err := d.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	require.NoError(t, err)
	source, err := d.loadReportingExportSourceScoped(ctx, tx, date, date.Add(24*time.Hour), export.ReportingJointSchemaVersion, scope)
	require.NoError(t, err)
	hours, err := reportingHoursFromSource(ctx, source.forDate(date, date.Add(24*time.Hour)), date, 24, export.ReportingJointSchemaVersion, nil, time.Hour)
	require.NoError(t, err)
	assert.EqualValues(t, 3000, hours[9].Usage.Totals.InputTokens)
	assert.EqualValues(t, 1893, hours[9].Usage.Totals.OutputTokens)
	assert.NoError(t, tx.Rollback())
	pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	require.False(t, pulse.Suppressed)
	assert.Equal(t, Ptr(int64(6)), pulse.Totals["sessions"].Value)
	assert.Equal(t, Ptr(int64(4893)), pulse.Totals["tokens"].Value)
	assert.Equal(t, Ptr(int64(3)), pulse.Totals["usage_observed_sessions"].Value)
	require.Len(t, pulse.Models, 2)
	assert.Equal(t, "complete-model", pulse.Models[0].Key)
	assert.Equal(t, Ptr(int64(6)), pulse.Models[0].Metrics["sessions"].Value)
	assert.Equal(t, "partial-model", pulse.Models[1].Key)
	assert.Equal(t, Ptr(int64(3)), pulse.Models[1].Metrics["sessions"].Value)
}

func TestFederationPulseCrossProjectSurvivorWithholdsConflictingAuthority(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	scope := map[string]struct{}{}
	for _, member := range []string{"a", "b", "c"} {
		for _, f := range []struct{ role, project, timestamp, model, usage string }{
			{"parent", "private-parent", "2026-07-28T09:05:00Z", "partial-model", `{"input_tokens":10,"output_tokens":5}`},
			{"child", "private-child", "2026-07-28T09:06:00Z", "complete-model", `{"input_tokens":1000,"output_tokens":631}`},
			{"safe", "safe-project", "2026-07-28T09:07:00Z", "safe-model", `{"input_tokens":10}`},
		} {
			id := f.role + "-" + member
			scope[id] = struct{}{}
			enrollment, spoke, share := "enr-"+id, "spoke-"+id, "share-"+id
			remote := "example/" + f.project
			require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: member, CredentialSHA256: "digest-" + id}))
			_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: remote, ProjectKey: f.project, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
			require.NoError(t, err)
			started := "2026-07-28T09:00:00Z"
			message := Message{SessionID: id, Ordinal: 0, Role: "assistant", Timestamp: f.timestamp, Model: f.model, TokenUsage: jsontext.Value(f.usage)}
			if f.role != "safe" {
				message.ClaudeMessageID, message.ClaudeRequestID = "snapshot-"+member, "request"
			}
			record := FederationHubRecord{UID: id, Hash: "hash", Remote: remote, ProjectKey: f.project, Write: SessionBatchWrite{Session: Session{ID: id, Project: remote, Agent: "claude", StartedAt: &started, MessageCount: 1}, Signals: SessionSignalUpdate{Outcome: "unknown"}, Messages: []Message{message}, ReplaceMessages: true}}
			_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
			require.NoError(t, err)
		}
	}
	date := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	tx, err := d.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	require.NoError(t, err)
	source, err := d.loadReportingExportSourceScoped(ctx, tx, date, date.Add(24*time.Hour), export.ReportingJointSchemaVersion, scope)
	require.NoError(t, err)
	hours, err := reportingHoursFromSource(ctx, source.forDate(date, date.Add(24*time.Hour)), date, 24, export.ReportingJointSchemaVersion, nil, time.Hour)
	require.NoError(t, err)
	assert.EqualValues(t, 3030, hours[9].Usage.Totals.InputTokens)
	assert.EqualValues(t, 1893, hours[9].Usage.Totals.OutputTokens)
	assert.NoError(t, tx.Rollback())
	pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, date.Add(24*time.Hour))
	require.NoError(t, err)
	assert.True(t, pulse.Suppressed)
	assert.Nil(t, pulse.Totals["tokens"].Value)
	require.Len(t, pulse.Projects, 1)
	assert.Equal(t, "safe-project", pulse.Projects[0].Key)
	assert.Equal(t, Ptr(int64(30)), pulse.Projects[0].Totals["tokens"].Value)
	encoded, err := json.Marshal(pulse)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "private-parent")
	assert.NotContains(t, string(encoded), "private-child")
}

func TestFederationPulseUnionsSessionsAcrossDaysAndClipsCutoff(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	for _, id := range []string{"a", "b", "c"} {
		enrollment, spoke, share := "enr-"+id, "spoke-"+id, "share-"+id
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: id, CredentialSHA256: "digest-" + id}))
		_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		started := "2026-07-27T08:00:00Z"
		record := FederationHubRecord{UID: id, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{
			Session: Session{ID: id, Project: "example/repo", Agent: "codex", StartedAt: &started}, Signals: SessionSignalUpdate{Outcome: "unknown"},
			UsageEvents: []UsageEvent{
				{Source: "fixture", Model: "model", InputTokens: 10, OccurredAt: "2026-07-28T09:00:00Z", DedupKey: id + "-first"},
				{Source: "fixture", Model: "model", InputTokens: 20, OccurredAt: "2026-07-29T11:59:00Z", DedupKey: id + "-second"},
				{Source: "fixture", Model: "model", InputTokens: 1000, OccurredAt: "2026-07-29T12:00:00Z", DedupKey: id + "-cutoff"},
			},
		}}
		_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
		require.NoError(t, err)
	}
	pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, time.Date(2026, 7, 29, 12, 25, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.False(t, pulse.Suppressed)
	assert.Equal(t, "2026-07-29T12:00:00Z", pulse.ClosedThrough)
	assert.Equal(t, Ptr(int64(3)), pulse.Totals["sessions"].Value)
	assert.Equal(t, Ptr(int64(1)), pulse.Totals["active_projects"].Value)
	assert.Equal(t, Ptr(int64(90)), pulse.Totals["tokens"].Value)
}

func TestFederationPulseKeepsRetainedAndOmitsPurgedContributions(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	for _, f := range []struct {
		id, retention string
		tokens        int
	}{
		{"a", "org-retained", 10}, {"b", "org-retained", 20}, {"c", "org-retained", 30}, {"d", "member-controlled", 1000},
	} {
		enrollment, spoke, share := "enr-"+f.id, "spoke-"+f.id, "share-"+f.id
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: f.id, CredentialSHA256: "digest-" + f.id}))
		_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active", Retention: f.retention})
		require.NoError(t, err)
		started := "2026-07-28T09:00:00Z"
		record := FederationHubRecord{UID: f.id, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{
			Session: Session{ID: f.id, Project: "example/repo", Agent: "codex", StartedAt: &started}, Signals: SessionSignalUpdate{Outcome: "unknown"},
			UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: f.tokens, OccurredAt: started, DedupKey: f.id}},
		}}
		_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
		require.NoError(t, err)
		_, err = d.RevokeFederationEnrollment(ctx, enrollment)
		require.NoError(t, err)
	}
	pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.False(t, pulse.Suppressed)
	assert.Equal(t, Ptr(int64(3)), pulse.Totals["sessions"].Value)
	assert.Equal(t, Ptr(int64(60)), pulse.Totals["tokens"].Value)
	for _, link := range pulse.Links {
		assert.Equal(t, "revoked", link.State)
	}
}

func TestFederationPulseSubagentTakesPrecedenceOverAutomation(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	for _, id := range []string{"a", "b", "c"} {
		enrollment, spoke, share := "enr-"+id, "spoke-"+id, "share-"+id
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: id, CredentialSHA256: "digest-" + id}))
		_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		started, parent := "2026-07-28T09:00:00Z", "parent-"+id
		parentRecord := FederationHubRecord{UID: parent, Hash: "parent-hash", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: parent, Project: "example/repo", Agent: "codex", StartedAt: &started}, Signals: SessionSignalUpdate{Outcome: "unknown"}}}
		child := "child-" + id
		childRecord := FederationHubRecord{UID: child, Hash: "child-hash", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: child, Project: "example/repo", Agent: "codex", StartedAt: &started, IsAutomated: true, ParentSessionID: &parent, RelationshipType: "subagent"}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: 10, OccurredAt: started, DedupKey: child}}}}
		_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{parentRecord, childRecord})
		require.NoError(t, err)
	}
	pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	require.False(t, pulse.Suppressed)
	assert.Equal(t, Ptr(int64(6)), pulse.Totals["sessions"].Value)
	assert.Equal(t, Ptr(int64(0)), pulse.Totals["automated_sessions"].Value)
	assert.Equal(t, Ptr(float64(0)), pulse.Ratios["automation_share"].Value)
	require.Len(t, pulse.Categories, 2)
	assert.Equal(t, "interactive", pulse.Categories[0].Key)
	assert.Equal(t, Ptr(int64(3)), pulse.Categories[0].Metrics["sessions"].Value)
	assert.Equal(t, "subagent", pulse.Categories[1].Key)
	assert.Equal(t, Ptr(int64(3)), pulse.Categories[1].Metrics["sessions"].Value)
}

func TestFederationPulseCountsHandlesRatherThanEnrollments(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	for _, f := range []struct {
		id, member string
		tokens     int
	}{{"a", "member-one", 10}, {"b", "member-one", 20}, {"c", "member-two", 30}} {
		enrollment, spoke, share := "enr-"+f.id, "spoke-"+f.id, "share-"+f.id
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: f.member, CredentialSHA256: "digest-" + f.id}))
		_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "private-project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		started := "2026-07-28T09:00:00Z"
		record := FederationHubRecord{UID: f.id, Hash: "hash", Remote: "example/repo", ProjectKey: "private-project", Write: SessionBatchWrite{
			Session: Session{ID: f.id, Project: "example/repo", Agent: "codex", StartedAt: &started}, Signals: SessionSignalUpdate{Outcome: "unknown"},
			UsageEvents: []UsageEvent{{Source: "fixture", Model: "private-model", InputTokens: f.tokens, OccurredAt: started, DedupKey: f.id}},
		}}
		_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
		require.NoError(t, err)
	}
	pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.True(t, pulse.Suppressed)
	assert.Empty(t, pulse.Projects)
	assert.Nil(t, pulse.Totals["tokens"].Value)
	assert.Equal(t, "suppressed", pulse.Totals["tokens"].State)
	encoded, err := json.Marshal(pulse)
	require.NoError(t, err)
	for _, secret := range []string{"member-one", "member-two", "private-project", "private-model"} {
		assert.NotContains(t, string(encoded), secret)
	}
}

func TestFederationPulseIncludesDatedMessageLessSignals(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	for _, name := range []string{"one", "two", "three"} {
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "e-" + name, SpokeArchiveID: "s-" + name, Member: name, CredentialSHA256: "d-" + name}))
		_, err := d.PutFederationHubShare(ctx, "s-"+name, FederationHubShare{UID: "h-" + name, EnrollmentUID: "e-" + name, Remote: "example/repo", ProjectKey: "project-key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		start := "2026-07-28T09:00:00Z"
		record := FederationHubRecord{UID: name, Hash: "hash", Remote: "example/repo", ProjectKey: "project-key", Write: SessionBatchWrite{Session: Session{ID: name, Project: "example/repo", Agent: "codex", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "completed", HealthGrade: Ptr("A")}}}
		_, err = d.CommitFederationBatch(ctx, "e-"+name, "s-"+name, "h-"+name, "policy", 1, 1, "batch", []FederationHubRecord{record})
		require.NoError(t, err)
	}
	got, err := d.readFederationPulse(ctx, "", 3, time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Nil(t, got.Since)
	assert.Equal(t, Ptr(int64(3)), got.Totals["sessions"].Value)
	assert.Equal(t, "unavailable", got.Totals["tokens"].State)
	require.Len(t, got.Projects, 1)
	assert.Equal(t, Ptr(int64(3)), got.Projects[0].Outcomes[0].Metrics["sessions"].Value)
	assert.Equal(t, Ptr(int64(3)), got.Projects[0].Grades[0].Metrics["sessions"].Value)
}

func TestFederationPulseDoesNotReleaseInferredStart(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	empty, err := d.readFederationPulse(ctx, "", 3, now)
	require.NoError(t, err)
	assert.Nil(t, empty.Since)
	for i, name := range []string{"one", "two", "three"} {
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "e-" + name, SpokeArchiveID: "s-" + name, Member: name, CredentialSHA256: "digest-" + name}))
		_, err := d.PutFederationHubShare(ctx, "s-"+name, FederationHubShare{UID: "h-" + name, EnrollmentUID: "e-" + name, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		start := "2026-07-28T09:00:00Z"
		record := FederationHubRecord{UID: name, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: name, Project: "example/repo", Agent: "codex", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "unknown"}}}
		_, err = d.CommitFederationBatch(ctx, "e-"+name, "s-"+name, "h-"+name, "policy", 1, 1, "batch", []FederationHubRecord{record})
		require.NoError(t, err)
		if i == 1 {
			continue
		}
		pulse, err := d.readFederationPulse(ctx, "", 3, now)
		require.NoError(t, err)
		assert.Nil(t, pulse.Since)
		assert.Equal(t, i == 0, pulse.Suppressed)
		if i == 0 {
			assert.Nil(t, pulse.Totals["sessions"].Value)
		}
		encoded, err := json.Marshal(pulse)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"since":null`)
		assert.NotContains(t, string(encoded), "2026-07-28")
	}
	explicit, err := d.readFederationPulse(ctx, "2026-07-27", 4, now)
	require.NoError(t, err)
	assert.True(t, explicit.Suppressed)
	assert.Equal(t, Ptr("2026-07-27"), explicit.Since)
}

func TestFederationPulseReleaseRatiosAndGlobalDistributions(t *testing.T) {
	owners := map[string]federationPulseOwner{"a": {member: "one", project: "p"}, "b": {member: "two", project: "p"}, "c": {member: "three", project: "p"}}
	a := newFederationPulseAccumulator(owners)
	for _, id := range []string{"a", "b", "c"} {
		a.add(id, "total", "", "sessions", 1)
		a.add(id, "total", "", "automated_sessions", 1)
		a.add(id, "outcome", "unknown", "sessions", 1)
	}
	got := a.release(3)
	require.False(t, got.Suppressed)
	assert.Equal(t, Ptr(float64(1)), got.Ratios["automation_share"].Value)
	assert.Equal(t, "unavailable", got.Ratios["health_coverage"].State)
	require.Len(t, got.Outcomes, 1)
	assert.Equal(t, "unknown", got.Outcomes[0].Key)
	assert.Equal(t, Ptr(int64(3)), got.Outcomes[0].Metrics["sessions"].Value)
}

func TestFederationPulseLinkFactsDoNotExposeRefusalDetails(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enrollment-private", SpokeArchiveID: "archive-private", Member: "member-private", SpokeName: "fixture-spoke", CredentialSHA256: "digest"}))
	_, err := d.PutFederationHubShare(ctx, "archive-private", FederationHubShare{UID: "share-private", EnrollmentUID: "enrollment-private", Remote: "example/private", ProjectKey: "private-project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
	require.NoError(t, err)
	_, err = d.PutFederationHubShare(ctx, "archive-private", FederationHubShare{UID: "share-second", EnrollmentUID: "enrollment-private", Remote: "example/second", ProjectKey: "second-project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
	require.NoError(t, err)
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE federation_enrollments SET last_handshake_at='2026-07-28T10:00:00Z', last_delivery_at='2026-07-28T09:00:00Z'`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE federation_hub_shares SET last_refused='{"record-private":"session ID unavailable","other-private":"unrecognized detail"}'`)
		return err
	}))
	got, err := d.readFederationPulse(ctx, "", 3, time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	require.Len(t, got.Links, 1)
	link := got.Links[0]
	assert.Equal(t, "fixture-spoke", link.SpokeName)
	assert.Equal(t, "contacted", link.State)
	assert.Equal(t, Ptr("2026-07-28T10:00:00Z"), link.LastContactAt)
	assert.Equal(t, Ptr("2026-07-28T09:00:00Z"), link.LastDeliveryAt)
	assert.Nil(t, link.BacklogLagSeconds.Value)
	assert.Equal(t, "unavailable", link.BacklogLagSeconds.State)
	assert.Equal(t, []string{"collision", "other"}, link.StoredShareBatchRefusals)
	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	for _, secret := range []string{"enrollment-private", "archive-private", "member-private", "share-private", "private-project", "record-private", "unrecognized detail"} {
		assert.NotContains(t, string(encoded), secret)
	}
}

func TestFederationPulseAndPublicExportShareMessageLessExistence(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	for _, name := range []string{"a", "b", "c"} {
		enrollment, spoke, share := "e-"+name, "s-"+name, "h-"+name
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: name, CredentialSHA256: "digest-" + name}))
		_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		start := "2026-07-28T09:00:00Z"
		record := FederationHubRecord{UID: name, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: name, Project: "example/repo", Agent: "codex", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "unknown"}}}
		_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
		require.NoError(t, err)
	}
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	day, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: now.AddDate(0, 0, -1), Now: now, SchemaVersion: export.ReportingJointSchemaVersion})
	require.NoError(t, err)
	require.Len(t, day.Hours, 24)
	hour := day.Hours[9]
	assert.Equal(t, 3, hour.Activity.Totals.NewSessions)
	assert.Equal(t, 1, hour.Activity.Totals.NewProjects)
	assert.Equal(t, 3, hour.Activity.Totals.NewUntimedSessions)
	var daySessions, dayProjects, dayUntimed int
	for _, item := range day.Hours {
		daySessions += item.Activity.Totals.NewSessions
		dayProjects += item.Activity.Totals.NewProjects
		dayUntimed += item.Activity.Totals.NewUntimedSessions
	}
	assert.Equal(t, 3, daySessions)
	assert.Equal(t, 1, dayProjects)
	assert.Equal(t, 3, dayUntimed)
	assert.Zero(t, hour.Activity.Totals.AgentMinutes)
	assert.Empty(t, hour.Joint.Cells)
	rng, err := d.ExportReportingRange(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, Ptr("2026-07-28"), rng.EarliestDate)
	pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, now)
	require.NoError(t, err)
	assert.Equal(t, Ptr(int64(3)), pulse.Totals["sessions"].Value)
	assert.Equal(t, Ptr(int64(1)), pulse.Totals["active_projects"].Value)
	assert.Equal(t, "unavailable", pulse.Totals["tokens"].State)
	assert.Equal(t, "unavailable", pulse.Totals["health_observed_sessions"].State)
	require.Len(t, pulse.Outcomes, 1)
	assert.Equal(t, "unknown", pulse.Outcomes[0].Key)
	assert.Equal(t, Ptr(int64(3)), pulse.Outcomes[0].Metrics["sessions"].Value)
	assert.Equal(t, int64(hour.Activity.Totals.NewSessions), *pulse.Totals["sessions"].Value)
	insertSession(t, d, "ordinary", "example/repo", func(s *Session) {
		s.Machine = "federated"
		s.StartedAt = Ptr("2026-07-28T09:00:00Z")
	})
	require.NoError(t, d.ReplaceSessionUsageEvents(ctx, "ordinary", []UsageEvent{{Source: "fixture", Model: "synthetic-model", InputTokens: 1, OccurredAt: "2026-07-28T09:01:00Z", DedupKey: "ordinary"}}))
	day, err = d.ExportReportingDay(ctx, ReportingExportOptions{Date: now.AddDate(0, 0, -1), Now: now, SchemaVersion: export.ReportingJointSchemaVersion})
	require.NoError(t, err)
	assert.Equal(t, 4, day.Hours[9].Activity.Totals.NewSessions)
	pulse, err = d.readFederationPulse(ctx, "2026-07-28", 3, now)
	require.NoError(t, err)
	assert.Equal(t, Ptr(int64(3)), pulse.Totals["sessions"].Value)
	assert.Equal(t, "unavailable", pulse.Totals["tokens"].State)
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO federation_exclusions(session_id,reason) VALUES('a','fixture')`)
		return err
	}))
	pulse, err = d.readFederationPulse(ctx, "2026-07-28", 3, now)
	require.NoError(t, err)
	assert.True(t, pulse.Suppressed)
	assert.Nil(t, pulse.Totals["sessions"].Value)
}

func TestFederationPulsePartialCostRespectsCompletenessSupport(t *testing.T) {
	for _, tc := range []struct {
		name       string
		unpriced   int
		wantState  string
		wantValue  *int64
		suppressed bool
	}{
		{"all members", 3, "partial", Ptr(int64(600)), false},
		{"one member", 1, "suppressed", nil, true},
		{"fully priced", 0, "available", Ptr(int64(600)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			ctx := t.Context()
			start := "2026-07-28T09:00:00Z"
			for i, name := range []string{"a", "b", "c"} {
				enrollment, spoke, share := "e-"+name, "s-"+name, "h-"+name
				require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: name, CredentialSHA256: "digest-" + name}))
				_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
				require.NoError(t, err)
				cost := money.Money{Microdollars: int64((i + 1) * 100)}
				rows := []UsageEvent{{Source: "fixture", Model: "synthetic-unpriced-model", InputTokens: 10, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: start, DedupKey: name + "-known"}}
				if i < tc.unpriced {
					rows = append(rows, UsageEvent{Source: "fixture", Model: "synthetic-unpriced-model", InputTokens: 20, OccurredAt: start, DedupKey: name + "-unknown"})
				}
				record := FederationHubRecord{UID: name, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: name, Project: "example/repo", Agent: "codex", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: rows}}
				_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
				require.NoError(t, err)
			}
			now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
			day, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: now.AddDate(0, 0, -1), Now: now, SchemaVersion: export.ReportingJointSchemaVersion})
			require.NoError(t, err)
			var unpriced int64
			for _, cell := range day.Hours[9].Joint.Cells {
				unpriced += cell.Pricing.UnpricedRows
			}
			assert.Equal(t, int64(tc.unpriced), unpriced)
			assert.EqualValues(t, 600, day.Hours[9].Usage.Totals.Cost.Microdollars)
			pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, now)
			require.NoError(t, err)
			assert.Equal(t, tc.suppressed, pulse.Suppressed)
			assert.Equal(t, tc.wantState, pulse.Totals["cost_microdollars"].State)
			assert.Equal(t, tc.wantValue, pulse.Totals["cost_microdollars"].Value)
			if !tc.suppressed {
				require.Len(t, pulse.Projects, 1)
				assert.Equal(t, tc.wantState, pulse.Projects[0].Totals["cost_microdollars"].State)
				require.Len(t, pulse.Agents, 1)
				require.Len(t, pulse.Models, 1)
				assert.Equal(t, "synthetic-unpriced-model", pulse.Models[0].Key)
				assert.Equal(t, tc.wantState, pulse.Agents[0].Metrics["cost_microdollars"].State)
				assert.Equal(t, tc.wantValue, pulse.Agents[0].Metrics["cost_microdollars"].Value)
				assert.Equal(t, tc.wantState, pulse.Models[0].Metrics["cost_microdollars"].State)
				assert.Equal(t, tc.wantValue, pulse.Models[0].Metrics["cost_microdollars"].Value)
			}
		})
	}
}

func TestFederationPulseCostMissingAndPricedZero(t *testing.T) {
	for _, tc := range []struct {
		name   string
		priced bool
		state  string
		value  *int64
	}{
		{"all unpriced", false, "unavailable", nil},
		{"priced zero", true, "available", Ptr(int64(0))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			ctx := t.Context()
			start := "2026-07-28T09:00:00Z"
			for _, name := range []string{"a", "b", "c"} {
				enrollment, spoke, share := "e-"+name, "s-"+name, "h-"+name
				require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: name, CredentialSHA256: "digest-" + name}))
				_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
				require.NoError(t, err)
				row := UsageEvent{Source: "fixture", Model: "synthetic-unpriced-model", InputTokens: 10, OccurredAt: start, DedupKey: name}
				if tc.priced {
					row.Cost = &money.Money{}
					row.CostStatus = "exact"
					row.CostSource = "reported"
				}
				record := FederationHubRecord{UID: name, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: name, Project: "example/repo", Agent: "codex", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{row}}}
				_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
				require.NoError(t, err)
			}
			pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC))
			require.NoError(t, err)
			assert.False(t, pulse.Suppressed)
			assert.Equal(t, tc.state, pulse.Totals["cost_microdollars"].State)
			assert.Equal(t, tc.value, pulse.Totals["cost_microdollars"].Value)
			assert.Equal(t, Ptr(int64(30)), pulse.Totals["tokens"].Value)
			require.Len(t, pulse.Models, 1)
			assert.Equal(t, tc.state, pulse.Models[0].Metrics["cost_microdollars"].State)
			assert.Equal(t, tc.value, pulse.Models[0].Metrics["cost_microdollars"].Value)
		})
	}
}

func TestFederationPulsePartialCostAcrossProjects(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	start := "2026-07-28T09:00:00Z"
	for _, project := range []string{"alpha", "beta"} {
		for i, member := range []string{"a", "b", "c"} {
			id := project + "-" + member
			enrollment, spoke, share := "e-"+id, "s-"+id, "h-"+id
			remote := "example/" + project
			require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: member, CredentialSHA256: "digest-" + id}))
			_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: remote, ProjectKey: project, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
			require.NoError(t, err)
			cost := money.Money{Microdollars: int64((i + 1) * 100)}
			rows := []UsageEvent{{Source: "fixture", Model: "known", InputTokens: 10, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: start, DedupKey: id + "-known"}}
			if project == "alpha" {
				rows = append(rows, UsageEvent{Source: "fixture", Model: "synthetic-unpriced-model", InputTokens: 20, OccurredAt: start, DedupKey: id + "-unknown"})
			}
			record := FederationHubRecord{UID: id, Hash: "hash", Remote: remote, ProjectKey: project, Write: SessionBatchWrite{Session: Session{ID: id, Project: remote, Agent: "codex", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: rows}}
			_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
			require.NoError(t, err)
		}
	}
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	day, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: now.AddDate(0, 0, -1), Now: now, SchemaVersion: export.ReportingJointSchemaVersion})
	require.NoError(t, err)
	assert.EqualValues(t, 1200, day.Hours[9].Usage.Totals.Cost.Microdollars)
	var unpriced int64
	for _, cell := range day.Hours[9].Joint.Cells {
		unpriced += cell.Pricing.UnpricedRows
	}
	assert.EqualValues(t, 3, unpriced)
	pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, now)
	require.NoError(t, err)
	assert.False(t, pulse.Suppressed)
	assert.Equal(t, "partial", pulse.Totals["cost_microdollars"].State)
	assert.Equal(t, Ptr(int64(1200)), pulse.Totals["cost_microdollars"].Value)
	require.Len(t, pulse.Projects, 2)
	assert.Equal(t, "alpha", pulse.Projects[0].Key)
	assert.Equal(t, "partial", pulse.Projects[0].Totals["cost_microdollars"].State)
	assert.Equal(t, Ptr(int64(600)), pulse.Projects[0].Totals["cost_microdollars"].Value)
	assert.Equal(t, "beta", pulse.Projects[1].Key)
	assert.Equal(t, "available", pulse.Projects[1].Totals["cost_microdollars"].State)
	assert.Equal(t, Ptr(int64(600)), pulse.Projects[1].Totals["cost_microdollars"].Value)
}

func TestFederationPulseUnpricedRowsPreserveKnownFees(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	start := "2026-07-28T09:00:00Z"
	for _, name := range []string{"a", "b", "c"} {
		enrollment, spoke, share := "e-"+name, "s-"+name, "h-"+name
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: name, CredentialSHA256: "digest-" + name}))
		_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		record := FederationHubRecord{UID: name, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{
			Session: Session{ID: name, Project: "example/repo", Agent: "claude", StartedAt: &start, MessageCount: 1}, Signals: SessionSignalUpdate{Outcome: "unknown"},
			Messages: []Message{{SessionID: name, Ordinal: 0, Role: "assistant", Timestamp: start, Model: "synthetic-unpriced-model", TokenUsage: jsontext.Value(`{"input_tokens":100,"server_tool_use":{"web_search_requests":2}}`)}}, ReplaceMessages: true,
		}}
		_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
		require.NoError(t, err)
	}
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	day, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: now.AddDate(0, 0, -1), Now: now, SchemaVersion: export.ReportingJointSchemaVersion})
	require.NoError(t, err)
	require.Len(t, day.Hours[9].Joint.Cells, 1)
	assert.EqualValues(t, 3, day.Hours[9].Joint.Cells[0].Pricing.UnpricedRows)
	assert.EqualValues(t, 60_000, day.Hours[9].Usage.Totals.Cost.Microdollars)
	pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, now)
	require.NoError(t, err)
	assert.False(t, pulse.Suppressed)
	assert.Equal(t, "partial", pulse.Totals["cost_microdollars"].State)
	assert.Equal(t, Ptr(int64(60_000)), pulse.Totals["cost_microdollars"].Value)
	assert.Equal(t, Ptr(int64(300)), pulse.Totals["tokens"].Value)
}

func TestFederationPulseRejectedDuplicateDoesNotChangeCostCompleteness(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.UpsertModelPricing([]ModelPricing{{ModelPattern: "fixture-priced", InputPerMTok: money.MustParseDollars("1")}}))
	start := "2026-07-28T09:00:00Z"
	for _, member := range []string{"a", "b", "c"} {
		enrollment, spoke := "e-"+member, "s-"+member
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: member, CredentialSHA256: "digest-" + member}))
		for _, candidate := range []struct{ suffix, model, timestamp, usage string }{
			{"old", "synthetic-unpriced-model", "2026-07-28T09:01:00Z", `{"input_tokens":10}`},
			{"new", "fixture-priced", "2026-07-28T09:02:00Z", `{"input_tokens":1000}`},
		} {
			id, share := member+"-"+candidate.suffix, "h-"+member+"-"+candidate.suffix
			_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
			require.NoError(t, err)
			record := FederationHubRecord{UID: id, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: id, Project: "example/repo", Agent: "claude", StartedAt: &start, MessageCount: 1}, Signals: SessionSignalUpdate{Outcome: "unknown"}, Messages: []Message{{SessionID: id, Ordinal: 0, Role: "assistant", Timestamp: candidate.timestamp, Model: candidate.model, TokenUsage: jsontext.Value(candidate.usage), ClaudeMessageID: "message-" + member, ClaudeRequestID: "request"}}, ReplaceMessages: true}}
			_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
			require.NoError(t, err)
		}
	}
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	day, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: now.AddDate(0, 0, -1), Now: now, SchemaVersion: export.ReportingJointSchemaVersion})
	require.NoError(t, err)
	assert.EqualValues(t, 3000, day.Hours[9].Usage.Totals.InputTokens)
	assert.EqualValues(t, 3000, day.Hours[9].Usage.Totals.Cost.Microdollars)
	for _, cell := range day.Hours[9].Joint.Cells {
		assert.Zero(t, cell.Pricing.UnpricedRows)
	}
	// A larger, newer ordinary copy must not participate in the owned scope's
	// survivor selection.
	insertSession(t, d, "unowned", "example/repo", func(s *Session) { s.Agent = "claude"; s.StartedAt = &start; s.MessageCount = 1 })
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO messages(session_id,ordinal,role,content,timestamp,model,token_usage,claude_message_id,claude_request_id) VALUES('unowned',0,'assistant','','2026-07-28T09:03:00Z','fixture-priced','{"input_tokens":1000000}','message-a','request')`)
		return err
	}))
	pulse, err := d.readFederationPulse(ctx, "2026-07-28", 3, now)
	require.NoError(t, err)
	assert.False(t, pulse.Suppressed)
	assert.Equal(t, Ptr(int64(3000)), pulse.Totals["tokens"].Value)
	assert.Equal(t, "available", pulse.Totals["cost_microdollars"].State)
	assert.Equal(t, Ptr(int64(3000)), pulse.Totals["cost_microdollars"].Value)
}

func TestFederationPulseDatedEvidenceAndPublicReporting(t *testing.T) {
	for _, tc := range []struct {
		name, start, evidence string
		messageCount          int
	}{
		{"existence", "2026-07-28T10:00:00Z", "", 0},
		{"creation fallback", "2026-07-27T10:00:00Z", `UPDATE sessions SET created_at='2026-07-28T10:00:00Z', ended_at='2026-07-29T10:00:00Z' WHERE id='session'`, 0},
		{"usage", "2026-07-27T10:00:00Z", `INSERT INTO usage_events(session_id,source,model,occurred_at,input_tokens) VALUES('session','fixture','model','2026-07-28T10:00:00Z',7)`, 0},
		{"message", "2026-07-27T10:00:00Z", `INSERT INTO messages(session_id,ordinal,role,content,timestamp) VALUES('session',0,'user','fixture','2026-07-28T12:00:00+02:00')`, 1},
		{"terminal", "2026-07-27T10:00:00Z", `INSERT INTO tool_result_events(session_id,tool_call_message_ordinal,source,status,content,timestamp) VALUES('session',0,'tool_execution','completed','','2026-07-28T10:00:00Z')`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			ctx := t.Context()
			require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
				for _, q := range []string{
					`INSERT INTO federation_enrollments(enrollment_uid,spoke_archive_id,member,credential_sha256) VALUES('e','s','a','digest')`,
					`INSERT INTO federation_hub_shares(share_uid,enrollment_uid,normalized_remote,project_key,level,attribution,audience,policy_digest,epoch,state) VALUES('h','e','example/a','project','summary','pooled','operators','policy',1,'active')`,
				} {
					if _, err := tx.ExecContext(ctx, q); err != nil {
						return err
					}
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id,project,machine,agent,started_at,message_count) VALUES('session','example/a','federated','codex',?,?)`, tc.start, tc.messageCount); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('h','r','session','hash')`); err != nil {
					return err
				}
				if tc.evidence != "" {
					_, err := tx.ExecContext(ctx, tc.evidence)
					return err
				}
				return nil
			}))
			date := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
			now := date.Add(48 * time.Hour)
			var dates []string
			_, err := d.readFederationPulseSnapshot(ctx, "2026-07-28", now, nil, func(_ *sql.Tx, at, _ time.Time, _ map[string]federationPulseOwner, _ reportingDaySource) error {
				dates = append(dates, at.Format(time.DateOnly))
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, []string{"2026-07-28"}, dates)
			pulse, err := d.readFederationPulse(ctx, "2026-07-28", 1, now)
			require.NoError(t, err)
			if tc.name == "terminal" {
				assert.Equal(t, "unavailable", pulse.Totals["sessions"].State)
				assert.Nil(t, pulse.Totals["sessions"].Value)
			} else {
				assert.Equal(t, Ptr(int64(1)), pulse.Totals["sessions"].Value)
			}
			day, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: date, Now: now})
			require.NoError(t, err)
			assert.Equal(t, tc.name != "terminal", day.HasData)
			digest, err := d.ExportReportingDigest(ctx, ReportingDigestExportOptions{From: date, To: date, Now: now})
			require.NoError(t, err)
			require.Len(t, digest.Days, 1)
			assert.Equal(t, "2026-07-28", digest.Days[0].Date)
			assert.Equal(t, tc.name != "terminal", digest.Days[0].HasData)
			assert.Equal(t, day.Digest, digest.Days[0].DayDigest)
		})
	}
}

func TestFederationPulseMidnightEvidenceCountsSessionOnce(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO federation_enrollments(enrollment_uid,spoke_archive_id,member,credential_sha256) VALUES('e','s','a','digest')`,
			`INSERT INTO federation_hub_shares(share_uid,enrollment_uid,normalized_remote,project_key,level,attribution,audience,policy_digest,epoch,state) VALUES('h','e','example/a','project','summary','pooled','operators','policy',1,'active')`,
			`INSERT INTO sessions(id,project,machine,agent,started_at,message_count) VALUES('session','example/a','federated','codex','2026-07-28T23:59:00Z',2)`,
			`INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('h','r','session','hash')`,
			`INSERT INTO messages(session_id,ordinal,role,content,timestamp) VALUES('session',0,'user','fixture','2026-07-28T23:59:00Z'),('session',1,'assistant','fixture','2026-07-29T00:01:00Z')`,
			`INSERT INTO usage_events(session_id,source,model,occurred_at,input_tokens) VALUES('session','fixture','model','2026-07-29T00:01:00Z',7)`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}))
	now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		since string
		dates []string
	}{
		{"2026-07-28", []string{"2026-07-28", "2026-07-29"}},
		{"2026-07-29", []string{"2026-07-29"}},
	} {
		var dates []string
		_, err := d.readFederationPulseSnapshot(ctx, tc.since, now, nil, func(_ *sql.Tx, at, _ time.Time, _ map[string]federationPulseOwner, _ reportingDaySource) error {
			dates = append(dates, at.Format(time.DateOnly))
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, tc.dates, dates)
		pulse, err := d.readFederationPulse(ctx, tc.since, 1, now)
		require.NoError(t, err)
		assert.Equal(t, Ptr(int64(1)), pulse.Totals["sessions"].Value)
		assert.Equal(t, Ptr(int64(7)), pulse.Totals["tokens"].Value)
	}
	first := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	second := first.AddDate(0, 0, 1)
	day1, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: first, Now: now})
	require.NoError(t, err)
	day2, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: second, Now: now})
	require.NoError(t, err)
	assert.InDelta(t, 1, day1.Hours[23].Activity.Totals.AgentMinutes, 0.0001)
	assert.InDelta(t, 1, day2.Hours[0].Activity.Totals.AgentMinutes, 0.0001)
	assert.EqualValues(t, 7, day2.Hours[0].Usage.Totals.InputTokens)
	digest, err := d.ExportReportingDigest(ctx, ReportingDigestExportOptions{From: first, To: second, Now: now})
	require.NoError(t, err)
	require.Len(t, digest.Days, 2)
	assert.Equal(t, []string{"2026-07-28", "2026-07-29"}, []string{digest.Days[0].Date, digest.Days[1].Date})
	assert.True(t, digest.Days[0].HasData)
	assert.True(t, digest.Days[1].HasData)
	assert.Equal(t, []string{day1.Digest, day2.Digest}, []string{digest.Days[0].DayDigest, digest.Days[1].DayDigest})
}

func TestFederationPulseStoredRefusalsUnionAcrossShares(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "e", SpokeArchiveID: "spoke", Member: "member", SpokeName: "spoke", CredentialSHA256: "digest"}))
	read := func() FederationPulseLink {
		pulse, err := d.readFederationPulse(ctx, "", 1, time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC))
		require.NoError(t, err)
		require.Len(t, pulse.Links, 1)
		return pulse.Links[0]
	}
	assert.Empty(t, read().StoredShareBatchRefusals)
	for _, share := range []string{"a", "b"} {
		_, err := d.PutFederationHubShare(ctx, "spoke", FederationHubShare{UID: share, EnrollmentUID: "e", Remote: "example/" + share, ProjectKey: share, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
	}
	assert.Empty(t, read().StoredShareBatchRefusals)
	require.NoError(t, d.UpsertSession(ctx, Session{ID: "local", Project: "local", Machine: "host", Agent: "codex"}))
	collision := FederationHubRecord{UID: "secret-record", Hash: "hash", Remote: "example/a", ProjectKey: "a", Write: SessionBatchWrite{Session: Session{ID: "local", Project: "example/a", Agent: "codex"}}}
	refused, err := d.CommitFederationBatch(ctx, "e", "spoke", "a", "policy", 1, 1, "batch-a", []FederationHubRecord{collision})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"secret-record": FederationCollision}, refused.Refused)
	assert.Nil(t, read().LastDeliveryAt)
	start := "2026-07-28T09:00:00Z"
	accepted := FederationHubRecord{UID: "b-record", Hash: "hash", Remote: "example/b", ProjectKey: "b", Write: SessionBatchWrite{Session: Session{ID: "remote", Project: "example/b", Agent: "codex", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "unknown"}}}
	_, err = d.CommitFederationBatch(ctx, "e", "spoke", "b", "policy", 1, 1, "batch-b", []FederationHubRecord{accepted})
	require.NoError(t, err)
	link := read()
	assert.Equal(t, []string{"collision"}, link.StoredShareBatchRefusals)
	assert.NotNil(t, link.LastDeliveryAt)
	assert.Equal(t, "unavailable", link.BacklogLagSeconds.State)
	encoded, err := json.Marshal(link)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"stored_share_batch_refusals":["collision"]`)
	for _, secret := range []string{"secret-record", "example/a", "member", "session ID unavailable"} {
		assert.NotContains(t, string(encoded), secret)
	}
	clean := FederationHubRecord{UID: "a-record", Hash: "hash", Remote: "example/a", ProjectKey: "a", Write: SessionBatchWrite{Session: Session{ID: "clean", Project: "example/a", Agent: "codex", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "unknown"}}}
	_, err = d.CommitFederationBatch(ctx, "e", "spoke", "a", "policy", 1, 2, "batch-a-clean", []FederationHubRecord{clean})
	require.NoError(t, err)
	assert.Empty(t, read().StoredShareBatchRefusals)
}

func TestFederationPulseRejectsCrossContributorCostOverflow(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "e", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "digest"}))
	_, err := d.PutFederationHubShare(ctx, "spoke", FederationHubShare{UID: "h", EnrollmentUID: "e", Remote: "example/a", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
	require.NoError(t, err)
	start := "2026-07-28T09:00:00Z"
	var records []FederationHubRecord
	for _, item := range []struct {
		id   string
		cost int64
	}{{"a", math.MaxInt64}, {"b", 1}} {
		cost := money.Money{Microdollars: item.cost}
		records = append(records, FederationHubRecord{UID: item.id, Hash: "hash", Remote: "example/a", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: item.id, Project: "example/a", Agent: "codex", StartedAt: &start}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: 1, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: start, DedupKey: item.id}}}})
	}
	_, err = d.CommitFederationBatch(ctx, "e", "spoke", "h", "policy", 1, 1, "batch", records)
	require.NoError(t, err)
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	_, err = d.readFederationPulse(ctx, "2026-07-28", 1, now)
	require.ErrorIs(t, err, money.ErrOverflow)
	_, err = d.ExportReportingDay(ctx, ReportingExportOptions{Date: now.AddDate(0, 0, -1), Now: now, SchemaVersion: export.ReportingJointSchemaVersion})
	require.ErrorIs(t, err, money.ErrOverflow)
}

func TestFederationPulseVisitsDayWithOnlyIntervalSpill(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO federation_enrollments(enrollment_uid,spoke_archive_id,member,credential_sha256) VALUES('e','s','a','digest')`,
			`INSERT INTO federation_hub_shares(share_uid,enrollment_uid,normalized_remote,project_key,level,attribution,audience,policy_digest,epoch,state) VALUES('h','e','example/a','project','summary','pooled','operators','policy',1,'active')`,
			`INSERT INTO sessions(id,project,machine,agent,started_at,message_count) VALUES('session','example/a','federated','codex','2026-07-28T23:59:00Z',2)`,
			`INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('h','r','session','hash')`,
			`INSERT INTO messages(session_id,ordinal,role,content,timestamp) VALUES('session',0,'user','fixture','2026-07-28T23:59:00Z'),('session',1,'assistant','fixture','2026-07-30T00:01:00Z')`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}))
	now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	var dates []string
	_, err := d.readFederationPulseSnapshot(ctx, "2026-07-29", now, nil, func(_ *sql.Tx, at, _ time.Time, _ map[string]federationPulseOwner, _ reportingDaySource) error {
		dates = append(dates, at.Format(time.DateOnly))
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"2026-07-29"}, dates)
	pulse, err := d.readFederationPulse(ctx, "2026-07-29", 1, now)
	require.NoError(t, err)
	assert.Equal(t, Ptr(int64(1)), pulse.Totals["sessions"].Value)
	day, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: now.AddDate(0, 0, -1), Now: now})
	require.NoError(t, err)
	assert.InDelta(t, 4, day.Hours[0].Activity.Totals.AgentMinutes, 0.0001)
}

// A valid tombstone changes the current export, but cannot erase an already
// published four-member contribution from the comparison history.
func TestFederationPulsePreservesWithdrawalAndRetentionHistory(t *testing.T) {
	for _, scenario := range []string{"tombstone", "revoke", "retained-stop"} {
		t.Run(scenario, func(t *testing.T) {
			d := testDB(t)
			ctx := t.Context()
			started := "2026-07-29T09:00:00Z"
			retention := "member-controlled"
			if scenario == "retained-stop" {
				retention = "org-retained"
			}
			for i, name := range []string{"a", "b", "c", "d"} {
				enrollment, spoke, share := "e-"+name, "s-"+name, "h-"+name
				require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: name, CredentialSHA256: "digest-" + name}))
				_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active", Retention: retention})
				require.NoError(t, err)
				cost := money.Money{Microdollars: int64((i + 1) * 100)}
				record := FederationHubRecord{UID: name, Hash: "initial", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: name, Project: "example/repo", Agent: "codex", StartedAt: &started}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: (i + 1) * 10, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: started, DedupKey: name}}}}
				_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "initial", []FederationHubRecord{record})
				require.NoError(t, err)
			}
			now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
			first, err := d.readFederationPulse(ctx, "2026-07-29", 3, now)
			require.NoError(t, err)
			assert.Equal(t, Ptr(int64(4)), first.Totals["sessions"].Value)
			assert.Equal(t, Ptr(int64(100)), first.Totals["tokens"].Value)
			assert.Equal(t, Ptr(int64(1000)), first.Totals["cost_microdollars"].Value)
			if scenario == "retained-stop" {
				_, err = d.PutFederationHubShare(ctx, "s-a", FederationHubShare{UID: "h-a", EnrollmentUID: "e-a", Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "stopped", Retention: "org-retained"})
				require.NoError(t, err)
				repeated, err := d.readFederationPulse(ctx, "2026-07-29", 3, now)
				require.NoError(t, err)
				assert.Equal(t, Ptr(int64(4)), repeated.Totals["sessions"].Value)
				assert.Equal(t, Ptr(int64(100)), repeated.Totals["tokens"].Value)
				assert.Equal(t, Ptr(int64(1000)), repeated.Totals["cost_microdollars"].Value)
				return
			}
			if scenario == "revoke" {
				_, err = d.RevokeFederationEnrollment(ctx, "e-a")
			} else {
				_, err = d.CommitFederationBatch(ctx, "e-a", "s-a", "h-a", "policy", 1, 2, "tombstone", []FederationHubRecord{{UID: "a", Tombstone: true}})
			}
			require.NoError(t, err)
			day, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC), Now: now, SchemaVersion: export.ReportingJointSchemaVersion})
			require.NoError(t, err)
			assert.EqualValues(t, 90, day.Hours[9].Usage.Totals.InputTokens)
			assert.EqualValues(t, 900, day.Hours[9].Usage.Totals.Cost.Microdollars)
			later, err := d.readFederationPulse(ctx, "2026-07-29", 3, now)
			require.NoError(t, err)
			assert.True(t, later.Suppressed)
			assert.Empty(t, later.Projects)
			assert.Equal(t, "suppressed", later.Totals["sessions"].State)
			assert.Nil(t, later.Totals["sessions"].Value)
			assert.Nil(t, later.Totals["tokens"].Value)
			assert.Nil(t, later.Totals["cost_microdollars"].Value)
		})
	}
}

// Search fees are native message accounting, not federation summary ingress.
func TestFederationSharedSearchFeeKeeper(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.UpsertModelPricingContext(ctx, []ModelPricing{{ModelPattern: "fee-model", InputPerMTok: money.Money{Microdollars: 1000000}}}))
	started := "2026-07-28T09:00:00Z"
	for _, item := range []struct{ name, usage string }{
		{"a", `{"input_tokens":10,"server_tool_use":{"web_search_requests":1}}`},
		{"b", `{"input_tokens":20,"server_tool_use":{"web_search_requests":1}}`},
		{"c", `{"input_tokens":30,"server_tool_use":{"web_search_requests":1}}`},
	} {
		enrollment, spoke, share := "e-"+item.name, "s-"+item.name, "h-"+item.name
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: item.name, CredentialSHA256: "digest-" + item.name}))
		_, err := d.PutFederationHubShare(ctx, spoke, FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		record := FederationHubRecord{UID: item.name, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: SessionBatchWrite{Session: Session{ID: item.name, Project: "example/repo", Agent: "claude", StartedAt: &started, MessageCount: 1}, Signals: SessionSignalUpdate{Outcome: "unknown"}, Messages: []Message{{SessionID: item.name, Ordinal: 0, Role: "assistant", Timestamp: started, Model: "fee-model", TokenUsage: jsontext.Value(item.usage)}}, ReplaceMessages: true}}
		_, err = d.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []FederationHubRecord{record})
		require.NoError(t, err)
	}
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	day, err := d.ExportReportingDay(ctx, ReportingExportOptions{Date: now.AddDate(0, 0, -1), Now: now, SchemaVersion: export.ReportingJointSchemaVersion})
	require.NoError(t, err)
	assert.EqualValues(t, 60, day.Hours[9].Usage.Totals.InputTokens)
	assert.EqualValues(t, 30060, day.Hours[9].Usage.Totals.Cost.Microdollars)
	tx, err := d.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	date := now.AddDate(0, 0, -1)
	for _, item := range []struct {
		id   string
		cost int64
	}{{"a", 10010}, {"b", 10020}, {"c", 10030}} {
		source, err := d.loadReportingExportSourceScoped(ctx, tx, date, now, export.ReportingJointSchemaVersion, map[string]struct{}{item.id: {}})
		require.NoError(t, err)
		hours, err := reportingHoursFromSource(ctx, source.forDate(date, now), date, 24, export.ReportingJointSchemaVersion, nil, time.Hour)
		require.NoError(t, err)
		assert.EqualValues(t, item.cost, hours[9].Usage.Totals.Cost.Microdollars)
	}
}
