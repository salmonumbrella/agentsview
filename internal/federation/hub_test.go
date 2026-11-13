package federation

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/export"
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
	_, err = hub.RegisterShare(t.Context(), enrollment.UID, "spoke", "share", ShareManifest{Protocol: 1, SpokeInstance: "spoke", ShareUID: "share", Epoch: 1, Remote: remote, ProjectKey: key, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: policyDigest})
	require.NoError(t, err)
	payload := SummaryRecord{SessionID: "session", Remote: remote, ProjectKey: key, Agent: "claude"}
	hash, err := export.DigestCanonical(payload)
	require.NoError(t, err)
	prefix := payload
	prefix.SessionID = "valid-prefix"
	prefixHash, err := export.DigestCanonical(prefix)
	require.NoError(t, err)
	for _, r := range []BatchRecord{{RecordUID: "session", Kind: "unknown", Hash: hash, Payload: payload}, {RecordUID: "session", Kind: "session_summary", Hash: "wrong", Payload: payload}} {
		_, err = hub.ApplyBatch(t.Context(), enrollment.UID, "spoke", "share", Batch{Protocol: 1, SpokeInstance: "spoke", ShareUID: "share", Epoch: 1, Sequence: 1, Records: []BatchRecord{{RecordUID: "valid-prefix", Kind: "session_summary", Hash: prefixHash, Payload: prefix}, r}})
		require.ErrorContains(t, err, "invalid federation batch")
		var count int
		require.NoError(t, archive.Reader().QueryRow(t.Context(), `SELECT count(*) FROM sessions`).Scan(&count))
		assert.Zero(t, count)
	}
}
