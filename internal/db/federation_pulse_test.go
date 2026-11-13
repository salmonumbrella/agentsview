package db

import (
	"database/sql"
	"encoding/json"
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

func TestFederationPulseUsesDistinctDatedSessionsAndReportingUsage(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	for _, item := range []struct {
		id, member string
		tokens     int
	}{{"one", "alice", 10}, {"two", "bob", 20}, {"three", "carol", 30}} {
		require.NoError(t, d.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-" + item.id, SpokeArchiveID: "spoke-" + item.id, Member: item.member, CredentialSHA256: "digest-" + item.id}))
		_, err := d.PutFederationHubShare(ctx, "spoke-"+item.id, FederationHubShare{UID: "share-" + item.id, EnrollmentUID: "enr-" + item.id, Remote: "example/repo", ProjectKey: "project-key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		started := "2026-07-28T09:00:00Z"
		record := FederationHubRecord{UID: item.id, Hash: "hash", Remote: "example/repo", ProjectKey: "project-key", Write: SessionBatchWrite{Session: Session{ID: item.id, Project: "example/repo", Machine: "federated", Agent: "codex", StartedAt: &started}, Signals: SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []UsageEvent{{Source: "fixture", Model: "model", InputTokens: item.tokens, OccurredAt: "2026-07-28T09:05:00Z", DedupKey: item.id}}}}
		_, err = d.CommitFederationBatch(ctx, "enr-"+item.id, "spoke-"+item.id, "share-"+item.id, "policy", 1, 1, "batch", []FederationHubRecord{record})
		require.NoError(t, err)
	}
	got, err := d.readFederationPulse(ctx, "2026-07-28", 3, time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.False(t, got.Suppressed)
	assert.Equal(t, Ptr(int64(3)), got.Totals["sessions"].Value)
	assert.Equal(t, Ptr(int64(60)), got.Totals["tokens"].Value)
	assert.Equal(t, "unavailable", got.Totals["health_observed_sessions"].State)
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
	assert.EqualValues(t, 60, exported)
	assert.Equal(t, exported, *got.Totals["tokens"].Value)
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
	assert.Equal(t, Ptr("2026-07-28"), got.Since)
	assert.Equal(t, Ptr(int64(3)), got.Totals["sessions"].Value)
	assert.Equal(t, "unavailable", got.Totals["tokens"].State)
	require.Len(t, got.Projects, 1)
	assert.Equal(t, Ptr(int64(3)), got.Projects[0].Outcomes[0].Metrics["sessions"].Value)
	assert.Equal(t, Ptr(int64(3)), got.Projects[0].Grades[0].Metrics["sessions"].Value)
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
	assert.Equal(t, []string{"collision", "other"}, link.LatestBatchRefusals)
	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	for _, secret := range []string{"enrollment-private", "archive-private", "member-private", "share-private", "private-project", "record-private", "unrecognized detail"} {
		assert.NotContains(t, string(encoded), secret)
	}
}
