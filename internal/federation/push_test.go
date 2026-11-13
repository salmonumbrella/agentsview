package federation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/export"
	"go.kenn.io/agentsview/internal/testutil"
)

func TestPushOldConsentDoesNotDeliver(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	calls := 0
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "/api/v1/federation/handshake", r.URL.Path)
		_ = json.NewEncoder(w).Encode(HandshakeResponse{HubArchiveID: "hub", ProtocolVersions: []int{1}, EnrollmentUID: "enr", Member: "member", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest})
	}))
	t.Cleanup(hub.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0600))
	svc := NewService("spoke", "spoke", policy, archive)
	require.NoError(t, svc.Join(t.Context(), hub.URL, "hub", file))
	link, err := archive.GetFederationLink(t.Context())
	require.NoError(t, err)
	require.NoError(t, archive.PutFederationShare(t.Context(), db.FederationShare{UID: "share", LinkUID: link.UID, NormalizedRemote: "github.com/example/api", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: `{"delivery_notice":"This release records the share only; nothing is sent"}`, PolicyDigest: digest}))
	before := calls
	result, err := svc.Push(t.Context())
	require.NoError(t, err)
	assert.Equal(t, before+1, calls)
	assert.Equal(t, PushResult{}, result)
	ledger, err := archive.FederationLedger(t.Context(), "share")
	require.NoError(t, err)
	assert.Empty(t, ledger)
}

func TestPushWithNoActiveShareAvoidsHub(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	require.NoError(t, archive.PutFederationLink(t.Context(), db.FederationLink{UID: "link", HubOrigin: "https://example.invalid", HubArchiveID: "hub", EnrollmentUID: "enr", Member: "member", TokenFile: "/missing", ProtocolVersion: 1, State: "active"}))
	svc := NewService("spoke", "spoke", config.FederationHubConfig{}, archive)
	result, err := svc.Push(t.Context())
	require.NoError(t, err)
	assert.Equal(t, PushResult{}, result)
}
