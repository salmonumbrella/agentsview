package federation

import (
	"path/filepath"
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
		tokens                        int
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
		payload := SummaryRecord{SessionID: p.name, Remote: p.remote, ProjectKey: p.key, Agent: "codex", StartedAt: &started, Outcome: "unknown", ByModel: map[string]db.SessionModelUsageBreakdown{"model": {InputTokens: p.tokens, HasCost: true, Cost: money.Money{Microdollars: p.cost}}}}
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

	peers[1].tokens, peers[1].cost = 25, 250
	peers[2].tokens, peers[2].cost = 35, 350
	apply(peers[1], 2)
	apply(peers[2], 2)
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
