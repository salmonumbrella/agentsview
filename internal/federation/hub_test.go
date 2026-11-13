package federation

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/export"
	"go.kenn.io/agentsview/internal/money"
)

func TestHubRejectsWholeBatchForKindOrHash(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "hub.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	cfg, err := config.Default()
	require.NoError(t, err)
	cfg.Federation.Hub.SuggestedProjects = []string{}
	hub := NewService("hub", "hub", cfg.Federation.Hub, archive)
	enrollment, _, err := hub.Enroll(t.Context(), "spoke", "member", "")
	require.NoError(t, err)
	policyDigest, err := export.DigestCanonical(cfg.Federation.Hub)
	require.NoError(t, err)
	remote := "github.com/example/api"
	key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
	_, err = hub.RegisterShare(t.Context(), enrollment.UID, "spoke", "share", ShareManifest{Protocol: ProtocolVersion, SpokeInstance: "spoke", ShareUID: "share", Epoch: 1, Remote: remote, ProjectKey: key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: policyDigest})
	require.NoError(t, err)
	payload := SummaryRecord{SessionID: "session", Remote: remote, ProjectKey: key, Agent: "claude"}
	hash, err := export.DigestCanonical(payload)
	require.NoError(t, err)
	prefix := payload
	prefix.SessionID = "valid-prefix"
	prefixHash, err := export.DigestCanonical(prefix)
	require.NoError(t, err)
	for _, r := range []BatchRecord{{RecordUID: "session", Kind: "unknown", Hash: hash, Payload: &payload}, {RecordUID: "session", Kind: "session_summary", Hash: "wrong", Payload: &payload}} {
		_, err = hub.ApplyBatch(t.Context(), enrollment.UID, "spoke", "share", Batch{Protocol: ProtocolVersion, SpokeInstance: "spoke", ShareUID: "share", Epoch: 1, Sequence: 1, Records: []BatchRecord{{RecordUID: "valid-prefix", Kind: "session_summary", Hash: prefixHash, Payload: &prefix}, r}})
		require.ErrorContains(t, err, "invalid federation batch")
		var count int
		require.NoError(t, archive.Reader().QueryRow(t.Context(), `SELECT count(*) FROM sessions`).Scan(&count))
		assert.Zero(t, count)
	}
}

func TestHubRejectsTombstoneWithPayloadOrHash(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "hub.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	cfg, err := config.Default()
	require.NoError(t, err)
	cfg.Federation.Hub.SuggestedProjects = []string{}
	hub := NewService("hub", "hub", cfg.Federation.Hub, archive)
	enrollment, _, err := hub.Enroll(t.Context(), "spoke", "member", "")
	require.NoError(t, err)
	digest, err := export.DigestCanonical(cfg.Federation.Hub)
	require.NoError(t, err)
	remote := "github.com/example/api"
	key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
	_, err = hub.RegisterShare(t.Context(), enrollment.UID, "spoke", "share", ShareManifest{Protocol: ProtocolVersion, SpokeInstance: "spoke", ShareUID: "share", Epoch: 1, Remote: remote, ProjectKey: key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: digest})
	require.NoError(t, err)
	for _, record := range []BatchRecord{
		{RecordUID: "session", Kind: "tombstone", Hash: "unexpected"},
		{RecordUID: "session", Kind: "tombstone", Payload: &SummaryRecord{SessionID: "session"}},
	} {
		_, err = hub.ApplyBatch(t.Context(), enrollment.UID, "spoke", "share", Batch{Protocol: ProtocolVersion, SpokeInstance: "spoke", ShareUID: "share", Epoch: 1, Sequence: 1, Records: []BatchRecord{record}})
		require.ErrorContains(t, err, "invalid federation batch")
	}
}

func TestStopManifestUsesConsentedRetentionAndStaleRegisterStaysStopped(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "hub.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	cfg, err := config.Default()
	require.NoError(t, err)
	cfg.Federation.Hub.SuggestedProjects = []string{}
	hub := NewService("hub", "hub", cfg.Federation.Hub, archive)
	enrollment, _, err := hub.Enroll(t.Context(), "spoke", "member", "")
	require.NoError(t, err)
	digest, err := export.DigestCanonical(cfg.Federation.Hub)
	require.NoError(t, err)
	remote := "github.com/example/api"
	manifest := ShareManifest{Protocol: ProtocolVersion, SpokeInstance: "spoke", ShareUID: "share", Epoch: 1, Remote: remote, ProjectKey: export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: digest}
	_, err = hub.RegisterShare(t.Context(), enrollment.UID, "spoke", "share", manifest)
	require.NoError(t, err)
	manifest.Action = "stop"
	manifest.Policy = &cfg.Federation.Hub
	view, err := hub.RegisterShare(t.Context(), enrollment.UID, "spoke", "share", manifest)
	require.NoError(t, err)
	assert.Equal(t, "stopped", view.State)
	manifest.Action, manifest.Policy = "", nil
	view, err = hub.RegisterShare(t.Context(), enrollment.UID, "spoke", "share", manifest)
	require.NoError(t, err)
	assert.Equal(t, "stopped", view.State)
}

// A change to any published membership or availability dimension must not
// become a second view of a single member while another project stays useful.
func TestHubPulseProtectsWholeSummaryAfterOneMemberChanges(t *testing.T) {
	for _, dimension := range []string{"agent", "model", "key-vanishes", "outcome", "outcome-unknown", "health", "health-absent", "automation", "usage-absent", "cost-availability", "zero-to-unknown", "partial-to-known"} {
		t.Run(dimension, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			ctx := t.Context()
			archive, err := db.OpenIsolated(ctx, filepath.Join(t.TempDir(), "hub.db"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, archive.Close()) })
			cfg, err := config.Default()
			require.NoError(t, err)
			cfg.Federation.Hub.SuggestedProjects = []string{}
			hub := NewService("hub", "hub", cfg.Federation.Hub, archive)
			digest, err := export.DigestCanonical(cfg.Federation.Hub)
			require.NoError(t, err)
			started := "2020-07-29T09:00:00Z"
			type member struct {
				name, spoke, share, enrollment string
				payload                        SummaryRecord
			}
			members := make([]member, 0, 6)
			for i, name := range []string{"a", "b", "c", "d", "e", "f"} {
				remote := "github.com/example/p"
				if i >= 3 {
					remote = "github.com/example/q"
				}
				key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
				m := member{name: name, spoke: "spoke-" + name, share: "share-" + name}
				m.payload = SummaryRecord{SessionID: name, Remote: remote, ProjectKey: key, Agent: "codex", StartedAt: &started, Outcome: "unknown", ByModel: map[string]db.SessionModelUsageBreakdown{"model": {InputTokens: (i + 1) * 10, HasCost: true, Cost: money.Money{Microdollars: int64((i + 1) * 100)}}}}
				if dimension == "outcome-unknown" {
					m.payload.Outcome = "completed"
				}
				if dimension == "health-absent" {
					grade := "A"
					m.payload.Health = &grade
				}
				if dimension == "zero-to-unknown" {
					m.payload.ByModel = map[string]db.SessionModelUsageBreakdown{"model": {InputTokens: (i + 1) * 10, HasCost: true, Cost: money.Money{}}}
				} else if dimension == "partial-to-known" {
					m.payload.ByModel["unpriced"] = db.SessionModelUsageBreakdown{InputTokens: 1}
				}
				enrollment, _, err := hub.Enroll(ctx, m.spoke, name, "")
				require.NoError(t, err)
				m.enrollment = enrollment.UID
				_, err = hub.RegisterShare(ctx, m.enrollment, m.spoke, m.share, ShareManifest{Protocol: ProtocolVersion, SpokeInstance: m.spoke, ShareUID: m.share, Epoch: 1, Remote: remote, ProjectKey: key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: digest})
				require.NoError(t, err)
				members = append(members, m)
			}
			apply := func(m member, sequence int64) {
				t.Helper()
				hash, err := export.DigestCanonical(m.payload)
				require.NoError(t, err)
				ack, err := hub.ApplyBatch(ctx, m.enrollment, m.spoke, m.share, Batch{Protocol: ProtocolVersion, SpokeInstance: m.spoke, ShareUID: m.share, Epoch: 1, Sequence: sequence, Records: []BatchRecord{{RecordUID: m.name, Kind: "session_summary", Hash: hash, Payload: &m.payload}}})
				require.NoError(t, err)
				assert.Empty(t, ack.Refused)
				assert.Equal(t, sequence, ack.Committed)
			}
			for _, m := range members {
				apply(m, 1)
			}
			first, err := hub.Pulse(ctx, "2020-07-29")
			require.NoError(t, err)
			require.Len(t, first.Projects, 2)
			require.NotNil(t, first.Totals["tokens"].Value)
			if dimension == "partial-to-known" {
				assert.EqualValues(t, 216, *first.Totals["tokens"].Value)
			} else {
				assert.EqualValues(t, 210, *first.Totals["tokens"].Value)
			}
			require.NotNil(t, first.Totals["cost_microdollars"].Value)
			if dimension == "zero-to-unknown" {
				assert.EqualValues(t, 0, *first.Totals["cost_microdollars"].Value)
				assert.Equal(t, "available", first.Totals["cost_microdollars"].State)
			} else {
				assert.EqualValues(t, 2100, *first.Totals["cost_microdollars"].Value)
				if dimension == "partial-to-known" {
					assert.Equal(t, "partial", first.Totals["cost_microdollars"].State)
				}
			}
			if dimension == "key-vanishes" {
				for i := range members {
					p := &members[i].payload
					p.ByModel = map[string]db.SessionModelUsageBreakdown{"other": p.ByModel["model"]}
					apply(members[i], 2)
				}
				later, err := hub.Pulse(ctx, "2020-07-29")
				require.NoError(t, err)
				assert.False(t, later.Suppressed)
				require.Len(t, later.Projects, 2)
				require.NotNil(t, later.Totals["tokens"].Value)
				assert.EqualValues(t, 210, *later.Totals["tokens"].Value)
				require.NotNil(t, later.Totals["cost_microdollars"].Value)
				assert.EqualValues(t, 2100, *later.Totals["cost_microdollars"].Value)
				require.Len(t, later.Models, 1)
				assert.Equal(t, "other", later.Models[0].Key)
				for _, project := range later.Projects {
					require.Len(t, project.Models, 1)
					assert.Equal(t, "other", project.Models[0].Key)
				}
				return
			}
			p := &members[0].payload
			switch dimension {
			case "agent":
				p.Agent = "claude"
			case "model":
				p.ByModel = map[string]db.SessionModelUsageBreakdown{"other": p.ByModel["model"]}
			case "outcome":
				p.Outcome = "completed"
			case "outcome-unknown":
				p.Outcome = "unknown"
			case "health":
				grade := "A"
				p.Health = &grade
			case "health-absent":
				p.Health = nil
			case "automation":
				p.Automated = true
			case "usage-absent":
				p.ByModel = map[string]db.SessionModelUsageBreakdown{}
			case "cost-availability", "zero-to-unknown":
				p.ByModel = map[string]db.SessionModelUsageBreakdown{"model": {InputTokens: 10}}
			case "partial-to-known":
				p.ByModel["unpriced"] = db.SessionModelUsageBreakdown{InputTokens: 1, HasCost: true, Cost: money.Money{Microdollars: 1}}
			}
			apply(members[0], 2)
			later, err := hub.Pulse(ctx, "2020-07-29")
			require.NoError(t, err)
			assert.True(t, later.Suppressed)
			for _, metric := range []string{"sessions", "active_projects", "tokens", "cost_microdollars", "automated_sessions", "usage_observed_sessions", "health_observed_sessions", "outcome_observed_sessions"} {
				assert.Equal(t, "suppressed", later.Totals[metric].State, metric)
				assert.Nil(t, later.Totals[metric].Value, metric)
			}
			for _, ratio := range []string{"automation_share", "usage_coverage", "health_coverage", "outcome_coverage"} {
				assert.Equal(t, "suppressed", later.Ratios[ratio].State, ratio)
				assert.Nil(t, later.Ratios[ratio].Value, ratio)
			}
			assert.Empty(t, later.Agents)
			assert.Empty(t, later.Models)
			assert.Empty(t, later.Outcomes)
			assert.Empty(t, later.Grades)
			assert.Empty(t, later.Categories)
			require.Len(t, later.Projects, 1)
			assert.Equal(t, members[3].payload.ProjectKey, later.Projects[0].Key)
			require.NotNil(t, later.Projects[0].Ratios["usage_coverage"].Value)
			assert.Equal(t, float64(1), *later.Projects[0].Ratios["usage_coverage"].Value)
			if dimension == "health-absent" {
				require.NotNil(t, later.Projects[0].Ratios["health_coverage"].Value)
				assert.Equal(t, float64(1), *later.Projects[0].Ratios["health_coverage"].Value)
			}
			require.NotNil(t, later.Projects[0].Totals["sessions"].Value)
			assert.EqualValues(t, 3, *later.Projects[0].Totals["sessions"].Value)
			require.NotNil(t, later.Projects[0].Totals["tokens"].Value)
			if dimension == "partial-to-known" {
				assert.EqualValues(t, 153, *later.Projects[0].Totals["tokens"].Value)
			} else {
				assert.EqualValues(t, 150, *later.Projects[0].Totals["tokens"].Value)
			}
			require.NotNil(t, later.Projects[0].Totals["cost_microdollars"].Value)
			if dimension == "zero-to-unknown" {
				assert.EqualValues(t, 0, *later.Projects[0].Totals["cost_microdollars"].Value)
				assert.Equal(t, "available", later.Projects[0].Totals["cost_microdollars"].State)
			} else {
				assert.EqualValues(t, 1500, *later.Projects[0].Totals["cost_microdollars"].Value)
				if dimension == "partial-to-known" {
					assert.Equal(t, "partial", later.Projects[0].Totals["cost_microdollars"].State)
				}
			}
		})
	}
}

// A real summary batch must participate in the same publication history as
// other pulse callers; a separate project remains useful after P is withheld.
func TestHubPulseProtectsSummaryUpdatesAndKeepsIndependentProject(t *testing.T) {
	ctx := t.Context()
	archive, err := db.OpenIsolated(ctx, filepath.Join(t.TempDir(), "hub.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	cfg, err := config.Default()
	require.NoError(t, err)
	cfg.Federation.Hub.SuggestedProjects = []string{}
	hub := NewService("hub", "hub", cfg.Federation.Hub, archive)
	digest, err := export.DigestCanonical(cfg.Federation.Hub)
	require.NoError(t, err)
	started := "2020-07-29T09:00:00Z"
	type peer struct {
		name, remote, key, enrollment string
		tokens, tools                 int
		cost                          int64
	}
	peers := []peer{
		{name: "a", remote: "github.com/example/p", tokens: 10, cost: 100},
		{name: "b", remote: "github.com/example/p", tokens: 20, cost: 200},
		{name: "c", remote: "github.com/example/p", tokens: 30, cost: 300},
		{name: "d", remote: "github.com/example/q", tokens: 40, cost: 400},
		{name: "e", remote: "github.com/example/q", tokens: 50, cost: 500},
		{name: "f", remote: "github.com/example/q", tokens: 60, cost: 600},
	}
	apply := func(p peer, seq int64) {
		t.Helper()
		payload := SummaryRecord{SessionID: p.name, Remote: p.remote, ProjectKey: p.key, Agent: "codex", StartedAt: &started, Outcome: "unknown", ToolCount: p.tools, ByModel: map[string]db.SessionModelUsageBreakdown{"model": {InputTokens: p.tokens, HasCost: true, Cost: money.Money{Microdollars: p.cost}}}}
		hash, err := export.DigestCanonical(payload)
		require.NoError(t, err)
		ack, err := hub.ApplyBatch(ctx, p.enrollment, "spoke-"+p.name, "share-"+p.name, Batch{Protocol: ProtocolVersion, SpokeInstance: "spoke-" + p.name, ShareUID: "share-" + p.name, Epoch: 1, Sequence: seq, Records: []BatchRecord{{RecordUID: p.name, Kind: "session_summary", Hash: hash, Payload: &payload}}})
		require.NoError(t, err)
		assert.Empty(t, ack.Refused)
		assert.Equal(t, seq, ack.Committed)
	}
	for i := range peers {
		p := &peers[i]
		p.key = export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: p.remote}).Key
		enrollment, _, err := hub.Enroll(ctx, "spoke-"+p.name, p.name, "")
		require.NoError(t, err)
		p.enrollment = enrollment.UID
		_, err = hub.RegisterShare(ctx, p.enrollment, "spoke-"+p.name, "share-"+p.name, ShareManifest{Protocol: ProtocolVersion, SpokeInstance: "spoke-" + p.name, ShareUID: "share-" + p.name, Epoch: 1, Remote: p.remote, ProjectKey: p.key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: digest})
		require.NoError(t, err)
		apply(*p, 1)
	}
	first, err := hub.Pulse(ctx, "2020-07-29")
	require.NoError(t, err)
	require.NotNil(t, first.Totals["sessions"].Value)
	assert.EqualValues(t, 6, *first.Totals["sessions"].Value)
	require.NotNil(t, first.Totals["tokens"].Value)
	assert.EqualValues(t, 210, *first.Totals["tokens"].Value)
	require.NotNil(t, first.Totals["cost_microdollars"].Value)
	assert.EqualValues(t, 2100, *first.Totals["cost_microdollars"].Value)
	peers[0].tokens, peers[0].cost = 17, 170
	apply(peers[0], 2)
	// The summary hashes of b and c change, but their consumed usage does not.
	peers[1].tools, peers[2].tools = 3, 3
	apply(peers[1], 2)
	apply(peers[2], 2)
	day, err := archive.ExportReportingDay(ctx, db.ReportingExportOptions{Date: time.Date(2020, 7, 29, 0, 0, 0, 0, time.UTC), Now: time.Date(2020, 7, 30, 0, 0, 0, 0, time.UTC), SchemaVersion: export.ReportingJointSchemaVersion})
	require.NoError(t, err)
	assert.EqualValues(t, 217, day.Hours[9].Usage.Totals.InputTokens)
	assert.EqualValues(t, 2170, day.Hours[9].Usage.Totals.Cost.Microdollars)
	later, err := hub.Pulse(ctx, "2020-07-29")
	require.NoError(t, err)
	assert.True(t, later.Suppressed)
	assert.Equal(t, "suppressed", later.Totals["tokens"].State)
	assert.Nil(t, later.Totals["tokens"].Value)
	assert.Nil(t, later.Totals["cost_microdollars"].Value)
	require.Len(t, later.Projects, 1)
	assert.Equal(t, peers[3].key, later.Projects[0].Key)
	require.NotNil(t, later.Projects[0].Totals["sessions"].Value)
	assert.EqualValues(t, 3, *later.Projects[0].Totals["sessions"].Value)
	require.NotNil(t, later.Projects[0].Totals["tokens"].Value)
	assert.EqualValues(t, 150, *later.Projects[0].Totals["tokens"].Value)
	require.NotNil(t, later.Projects[0].Totals["cost_microdollars"].Value)
	assert.EqualValues(t, 1500, *later.Projects[0].Totals["cost_microdollars"].Value)
	for _, metric := range []string{"sessions", "active_projects", "tokens", "cost_microdollars", "automated_sessions", "usage_observed_sessions", "health_observed_sessions", "outcome_observed_sessions"} {
		assert.Equal(t, "suppressed", later.Totals[metric].State, metric)
		assert.Nil(t, later.Totals[metric].Value, metric)
	}
	for _, ratio := range []string{"automation_share", "usage_coverage", "health_coverage", "outcome_coverage"} {
		assert.Equal(t, "suppressed", later.Ratios[ratio].State, ratio)
		assert.Nil(t, later.Ratios[ratio].Value, ratio)
	}
	assert.Empty(t, later.Agents)
	assert.Empty(t, later.Models)
	assert.Empty(t, later.Outcomes)
	assert.Empty(t, later.Grades)
	assert.Empty(t, later.Categories)
	q := later.Projects[0]
	require.NotNil(t, q.Totals["active_projects"].Value)
	assert.EqualValues(t, 1, *q.Totals["active_projects"].Value)
	require.NotNil(t, q.Ratios["usage_coverage"].Value)
	assert.Equal(t, float64(1), *q.Ratios["usage_coverage"].Value)
	require.NotNil(t, q.Ratios["automation_share"].Value)
	assert.Equal(t, float64(0), *q.Ratios["automation_share"].Value)
	assert.Equal(t, "unavailable", q.Ratios["health_coverage"].State)
	assert.Nil(t, q.Ratios["health_coverage"].Value)
	require.Len(t, q.Agents, 1)
	assert.Equal(t, "codex", q.Agents[0].Key)
	require.Len(t, q.Models, 1)
	assert.Equal(t, "model", q.Models[0].Key)
	require.Len(t, q.Outcomes, 1)
	assert.Equal(t, "unknown", q.Outcomes[0].Key)
	assert.Empty(t, q.Grades)
	require.Len(t, q.Categories, 1)
	assert.Equal(t, "interactive", q.Categories[0].Key)

	peers[1].tokens, peers[1].cost = 25, 250
	peers[2].tokens, peers[2].cost = 35, 350
	apply(peers[1], 3)
	apply(peers[2], 3)
	matched, err := hub.Pulse(ctx, "2020-07-29")
	require.NoError(t, err)
	var pTotals map[string]db.FederationPulseMetric
	for _, project := range matched.Projects {
		if project.Key == peers[0].key {
			pTotals = project.Totals
		}
	}
	require.NotNil(t, pTotals)
	require.NotNil(t, pTotals["sessions"].Value)
	assert.EqualValues(t, 3, *pTotals["sessions"].Value)
	require.NotNil(t, pTotals["tokens"].Value)
	assert.EqualValues(t, 77, *pTotals["tokens"].Value)
	require.NotNil(t, pTotals["cost_microdollars"].Value)
	assert.EqualValues(t, 770, *pTotals["cost_microdollars"].Value)
}

// The three selections overlap in individual stable origins even though no two
// complete selected bags are equal. Their combined values reveal one member's
// difference, so at least one later selection must be withheld.
func TestHubPulseProtectsPartiallyOverlappingSummaryViews(t *testing.T) {
	ctx := t.Context()
	archive, err := db.OpenIsolated(ctx, filepath.Join(t.TempDir(), "hub.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	cfg, err := config.Default()
	require.NoError(t, err)
	cfg.Federation.Hub.SuggestedProjects = []string{}
	hub := NewService("hub", "hub", cfg.Federation.Hub, archive)
	digest, err := export.DigestCanonical(cfg.Federation.Hub)
	require.NoError(t, err)
	remote := "github.com/example/overlap"
	key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
	enrollments := make([]string, 3)
	for i, name := range []string{"a", "b", "c"} {
		spoke, share := "spoke-"+name, "share-"+name
		enrollment, _, err := hub.Enroll(ctx, spoke, name, "")
		require.NoError(t, err)
		enrollments[i] = enrollment.UID
		_, err = hub.RegisterShare(ctx, enrollment.UID, spoke, share, ShareManifest{Protocol: ProtocolVersion, SpokeInstance: spoke, ShareUID: share, Epoch: 1, Remote: remote, ProjectKey: key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: digest})
		require.NoError(t, err)
	}
	inside, outside := "2020-07-29T09:00:00Z", "2020-07-28T09:00:00Z"
	ids := [][]string{{"a1", "a2", "a3"}, {"b1", "b2", "b3"}, {"c1", "c2", "c3"}}
	amounts := [][]int{{10, 20, 30}, {40, 50, 60}, {70, 80, 90}}
	apply := func(sequence int64, selected map[string]bool) {
		t.Helper()
		for i, name := range []string{"a", "b", "c"} {
			spoke, share := "spoke-"+name, "share-"+name
			var records []BatchRecord
			for j, id := range ids[i] {
				started := &outside
				if selected[id] {
					started = &inside
				}
				payload := SummaryRecord{SessionID: id, Remote: remote, ProjectKey: key, Agent: "codex", StartedAt: started, Outcome: "unknown", ByModel: map[string]db.SessionModelUsageBreakdown{"model": {InputTokens: amounts[i][j], HasCost: true, Cost: money.Money{Microdollars: int64(amounts[i][j] * 10)}}}}
				hash, err := export.DigestCanonical(payload)
				require.NoError(t, err)
				records = append(records, BatchRecord{RecordUID: id, Kind: "session_summary", Hash: hash, Payload: &payload})
			}
			ack, err := hub.ApplyBatch(ctx, enrollments[i], spoke, share, Batch{Protocol: ProtocolVersion, SpokeInstance: spoke, ShareUID: share, Epoch: 1, Sequence: sequence, Records: records})
			require.NoError(t, err)
			assert.Empty(t, ack.Refused)
			assert.Equal(t, sequence, ack.Committed)
		}
	}
	apply(1, map[string]bool{"a1": true, "b1": true, "c1": true})
	first, err := hub.Pulse(ctx, "2020-07-29")
	require.NoError(t, err)
	require.NotNil(t, first.Totals["sessions"].Value)
	assert.EqualValues(t, 3, *first.Totals["sessions"].Value)
	require.NotNil(t, first.Totals["tokens"].Value)
	assert.EqualValues(t, 120, *first.Totals["tokens"].Value)
	require.NotNil(t, first.Totals["cost_microdollars"].Value)
	assert.EqualValues(t, 1200, *first.Totals["cost_microdollars"].Value)
	apply(2, map[string]bool{"a2": true, "b2": true, "c2": true})
	second, err := hub.Pulse(ctx, "2020-07-29")
	require.NoError(t, err)
	if !second.Suppressed {
		require.NotNil(t, second.Totals["tokens"].Value)
		assert.EqualValues(t, 150, *second.Totals["tokens"].Value)
		require.NotNil(t, second.Totals["cost_microdollars"].Value)
		assert.EqualValues(t, 1500, *second.Totals["cost_microdollars"].Value)
	}
	apply(3, map[string]bool{"a1": true, "a3": true, "b1": true, "b2": true, "c1": true, "c2": true})
	third, err := hub.Pulse(ctx, "2020-07-29")
	require.NoError(t, err)
	if !third.Suppressed {
		require.NotNil(t, third.Totals["sessions"].Value)
		assert.EqualValues(t, 6, *third.Totals["sessions"].Value)
		require.NotNil(t, third.Totals["tokens"].Value)
		assert.EqualValues(t, 280, *third.Totals["tokens"].Value)
		require.NotNil(t, third.Totals["cost_microdollars"].Value)
		assert.EqualValues(t, 2800, *third.Totals["cost_microdollars"].Value)
	}
	assert.True(t, second.Suppressed || third.Suppressed, "all three views expose one member's difference")
}

// All windows are ordinary summary replacements. A separate correspondence per
// result would permit collecting a system that identifies one member.
func TestHubPulseProtectsJointSevenMemberHistory(t *testing.T) {
	ctx := t.Context()
	archive, err := db.OpenIsolated(ctx, filepath.Join(t.TempDir(), "hub.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	cfg, err := config.Default()
	require.NoError(t, err)
	cfg.Federation.Hub.SuggestedProjects = []string{}
	hub := NewService("hub", "hub", cfg.Federation.Hub, archive)
	digest, err := export.DigestCanonical(cfg.Federation.Hub)
	require.NoError(t, err)
	remote := "github.com/example/joint"
	key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
	names := []string{"a", "b", "c", "d", "e", "f", "g"}
	enrollments := make([]string, len(names))
	for i, name := range names {
		spoke, share := "spoke-"+name, "share-"+name
		enrollment, _, err := hub.Enroll(ctx, spoke, name, "")
		require.NoError(t, err)
		enrollments[i] = enrollment.UID
		_, err = hub.RegisterShare(ctx, enrollment.UID, spoke, share, ShareManifest{Protocol: ProtocolVersion, SpokeInstance: spoke, ShareUID: share, Epoch: 1, Remote: remote, ProjectKey: key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: digest})
		require.NoError(t, err)
	}
	inside, outside := "2020-07-29T09:00:00Z", "2020-07-28T09:00:00Z"
	apply := func(sequence int64, selected string) {
		t.Helper()
		for i, name := range names {
			spoke, share := "spoke-"+name, "share-"+name
			started := &outside
			if strings.Contains(selected, name) {
				started = &inside
			}
			payload := SummaryRecord{SessionID: name, Remote: remote, ProjectKey: key, Agent: "codex", StartedAt: started, Outcome: "unknown", ByModel: map[string]db.SessionModelUsageBreakdown{"model": {InputTokens: i + 1, HasCost: true, Cost: money.Money{Microdollars: int64((i + 1) * 10)}}}}
			hash, err := export.DigestCanonical(payload)
			require.NoError(t, err)
			ack, err := hub.ApplyBatch(ctx, enrollments[i], spoke, share, Batch{Protocol: ProtocolVersion, SpokeInstance: spoke, ShareUID: share, Epoch: 1, Sequence: sequence, Records: []BatchRecord{{RecordUID: name, Kind: "session_summary", Hash: hash, Payload: &payload}}})
			require.NoError(t, err)
			assert.Empty(t, ack.Refused)
			assert.Equal(t, sequence, ack.Committed)
		}
	}
	apply(1, "abcdefg")
	all, err := hub.Pulse(ctx, "2020-07-29")
	require.NoError(t, err)
	require.NotNil(t, all.Totals["tokens"].Value)
	assert.EqualValues(t, 28, *all.Totals["tokens"].Value)
	windows := []struct {
		members string
		tokens  int64
	}{{"abc", 6}, {"ade", 10}, {"afg", 14}, {"bdf", 12}, {"beg", 14}, {"cdg", 14}, {"cef", 14}}
	firstThreeWithheld := false
	for i, window := range windows {
		apply(int64(i+2), window.members)
		got, err := hub.Pulse(ctx, "2020-07-29")
		require.NoError(t, err)
		if got.Suppressed {
			if i < 3 {
				firstThreeWithheld = true
			}
			continue
		}
		require.NotNil(t, got.Totals["sessions"].Value)
		assert.EqualValues(t, 3, *got.Totals["sessions"].Value)
		require.NotNil(t, got.Totals["tokens"].Value)
		assert.Equal(t, window.tokens, *got.Totals["tokens"].Value)
	}
	assert.True(t, firstThreeWithheld, "28 plus 6, 10 and 14 exposes the first member")
}

// Computed cost shares the same token observations, including per-row rounding.
func TestHubPulseProtectsComputedSummaryCost(t *testing.T) {
	ctx := t.Context()
	archive, err := db.OpenIsolated(ctx, filepath.Join(t.TempDir(), "hub.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	require.NoError(t, archive.UpsertModelPricingContext(ctx, []db.ModelPricing{{ModelPattern: "synthetic-half", InputPerMTok: money.Money{Microdollars: 500000}}}))
	cfg, err := config.Default()
	require.NoError(t, err)
	cfg.Federation.Hub.SuggestedProjects = []string{}
	hub := NewService("hub", "hub", cfg.Federation.Hub, archive)
	digest, err := export.DigestCanonical(cfg.Federation.Hub)
	require.NoError(t, err)
	remote := "github.com/example/computed"
	key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
	started := "2020-07-29T09:00:00Z"
	enrollments := make([]string, 3)
	apply := func(i, tokens int, sequence int64) {
		t.Helper()
		name := []string{"a", "b", "c"}[i]
		spoke, share := "spoke-"+name, "share-"+name
		payload := SummaryRecord{SessionID: name, Remote: remote, ProjectKey: key, Agent: "codex", StartedAt: &started, Outcome: "unknown", ByModel: map[string]db.SessionModelUsageBreakdown{"synthetic-half": {InputTokens: tokens}}}
		hash, err := export.DigestCanonical(payload)
		require.NoError(t, err)
		ack, err := hub.ApplyBatch(ctx, enrollments[i], spoke, share, Batch{Protocol: ProtocolVersion, SpokeInstance: spoke, ShareUID: share, Epoch: 1, Sequence: sequence, Records: []BatchRecord{{RecordUID: name, Kind: "session_summary", Hash: hash, Payload: &payload}}})
		require.NoError(t, err)
		assert.Empty(t, ack.Refused)
	}
	for i, name := range []string{"a", "b", "c"} {
		spoke, share := "spoke-"+name, "share-"+name
		enrollment, _, err := hub.Enroll(ctx, spoke, name, "")
		require.NoError(t, err)
		enrollments[i] = enrollment.UID
		_, err = hub.RegisterShare(ctx, enrollment.UID, spoke, share, ShareManifest{Protocol: ProtocolVersion, SpokeInstance: spoke, ShareUID: share, Epoch: 1, Remote: remote, ProjectKey: key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: digest})
		require.NoError(t, err)
		apply(i, []int{3, 5, 7}[i], 1)
	}
	first, err := hub.Pulse(ctx, "2020-07-29")
	require.NoError(t, err)
	require.NotNil(t, first.Totals["sessions"].Value)
	assert.EqualValues(t, 3, *first.Totals["sessions"].Value)
	require.NotNil(t, first.Totals["tokens"].Value)
	assert.EqualValues(t, 15, *first.Totals["tokens"].Value)
	require.NotNil(t, first.Totals["cost_microdollars"].Value)
	assert.EqualValues(t, 9, *first.Totals["cost_microdollars"].Value)
	apply(0, 5, 2)
	day, err := archive.ExportReportingDay(ctx, db.ReportingExportOptions{Date: time.Date(2020, 7, 29, 0, 0, 0, 0, time.UTC), Now: time.Date(2020, 7, 30, 0, 0, 0, 0, time.UTC), SchemaVersion: export.ReportingJointSchemaVersion})
	require.NoError(t, err)
	assert.EqualValues(t, 17, day.Hours[9].Usage.Totals.InputTokens)
	assert.EqualValues(t, 10, day.Hours[9].Usage.Totals.Cost.Microdollars)
	later, err := hub.Pulse(ctx, "2020-07-29")
	require.NoError(t, err)
	assert.True(t, later.Suppressed)
	assert.Empty(t, later.Projects)
	assert.Nil(t, later.Totals["tokens"].Value)
	assert.Nil(t, later.Totals["cost_microdollars"].Value)
}

func TestHubPulsePreservesSummaryModelSplitImages(t *testing.T) {
	for _, scenario := range []string{"all", "two"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			archive, err := db.OpenIsolated(ctx, filepath.Join(t.TempDir(), "hub.db"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, archive.Close()) })
			cfg, err := config.Default()
			require.NoError(t, err)
			cfg.Federation.Hub.SuggestedProjects = []string{}
			hub := NewService("hub", "hub", cfg.Federation.Hub, archive)
			digest, err := export.DigestCanonical(cfg.Federation.Hub)
			require.NoError(t, err)
			remote := "github.com/example/split"
			key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: remote}).Key
			started := "2020-07-29T09:00:00Z"
			names := []string{"a", "b", "c"}
			enrollments := make([]string, 3)
			apply := func(i int, sequence int64, split bool) {
				t.Helper()
				name := names[i]
				spoke, share := "spoke-"+name, "share-"+name
				x := []int{3, 5, 7}[i]
				models := map[string]db.SessionModelUsageBreakdown{"x": {InputTokens: x, HasCost: true, Cost: money.Money{Microdollars: int64(x * 10)}}}
				if split {
					x, y := i+1, i+2
					models = map[string]db.SessionModelUsageBreakdown{"x": {InputTokens: x, HasCost: true, Cost: money.Money{Microdollars: int64(x * 10)}}, "y": {InputTokens: y, HasCost: true, Cost: money.Money{Microdollars: int64(y * 10)}}}
				}
				payload := SummaryRecord{SessionID: name, Remote: remote, ProjectKey: key, Agent: "codex", StartedAt: &started, Outcome: "unknown", ByModel: models}
				hash, err := export.DigestCanonical(payload)
				require.NoError(t, err)
				ack, err := hub.ApplyBatch(ctx, enrollments[i], spoke, share, Batch{Protocol: ProtocolVersion, SpokeInstance: spoke, ShareUID: share, Epoch: 1, Sequence: sequence, Records: []BatchRecord{{RecordUID: name, Kind: "session_summary", Hash: hash, Payload: &payload}}})
				require.NoError(t, err)
				assert.Empty(t, ack.Refused)
			}
			for i, name := range names {
				spoke, share := "spoke-"+name, "share-"+name
				enrollment, _, err := hub.Enroll(ctx, spoke, name, "")
				require.NoError(t, err)
				enrollments[i] = enrollment.UID
				_, err = hub.RegisterShare(ctx, enrollment.UID, spoke, share, ShareManifest{Protocol: ProtocolVersion, SpokeInstance: spoke, ShareUID: share, Epoch: 1, Remote: remote, ProjectKey: key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: digest})
				require.NoError(t, err)
				apply(i, 1, false)
			}
			first, err := hub.Pulse(ctx, "2020-07-29")
			require.NoError(t, err)
			require.NotNil(t, first.Totals["tokens"].Value)
			assert.EqualValues(t, 15, *first.Totals["tokens"].Value)
			require.NotNil(t, first.Totals["cost_microdollars"].Value)
			assert.EqualValues(t, 150, *first.Totals["cost_microdollars"].Value)
			for i := range names {
				if scenario == "all" || i > 0 {
					apply(i, 2, true)
				}
			}
			later, err := hub.Pulse(ctx, "2020-07-29")
			require.NoError(t, err)
			if scenario == "two" {
				assert.True(t, later.Suppressed)
				assert.Empty(t, later.Projects)
				assert.Nil(t, later.Totals["tokens"].Value)
				return
			}
			assert.False(t, later.Suppressed)
			require.Len(t, later.Projects, 1)
			project := later.Projects[0]
			require.NotNil(t, project.Totals["tokens"].Value)
			assert.EqualValues(t, 15, *project.Totals["tokens"].Value)
			require.NotNil(t, project.Totals["cost_microdollars"].Value)
			assert.EqualValues(t, 150, *project.Totals["cost_microdollars"].Value)
			require.Len(t, project.Models, 2)
			for _, model := range project.Models {
				require.NotNil(t, model.Metrics["sessions"].Value)
				assert.EqualValues(t, 3, *model.Metrics["sessions"].Value)
				require.NotNil(t, model.Metrics["tokens"].Value)
				require.NotNil(t, model.Metrics["cost_microdollars"].Value)
				switch model.Key {
				case "x":
					assert.EqualValues(t, 6, *model.Metrics["tokens"].Value)
					assert.EqualValues(t, 60, *model.Metrics["cost_microdollars"].Value)
				case "y":
					assert.EqualValues(t, 9, *model.Metrics["tokens"].Value)
					assert.EqualValues(t, 90, *model.Metrics["cost_microdollars"].Value)
				default:
					t.Errorf("unexpected model %q", model.Key)
				}
			}
		})
	}
}
