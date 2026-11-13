//go:build !windows

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
)

func TestJoinRefusesReadableCredentialBeforeNetwork(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	calls := 0
	hub := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	t.Cleanup(hub.Close)
	file := filepath.Join(t.TempDir(), "credential")
	require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0644))
	require.NoError(t, os.Chmod(file, 0644))
	svc := NewService("spoke", "spoke-a", config.FederationHubConfig{}, archive)
	require.Error(t, svc.Join(t.Context(), hub.URL, "hub-a", file))
	assert.Zero(t, calls)
}

func TestStatusRechecksCredentialPermissions(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	calls := 0
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(HandshakeResponse{HubArchiveID: "hub-a", ProtocolVersions: []int{1}, EnrollmentUID: "enr-a", Member: "member-a", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest})
	}))
	t.Cleanup(hub.Close)
	file := filepath.Join(t.TempDir(), "credential")
	require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0600))
	svc := NewService("spoke", "spoke-a", policy, archive)
	require.NoError(t, svc.Join(t.Context(), hub.URL, "hub-a", file))
	require.NoError(t, os.Chmod(file, 0644))
	status, err := svc.Status(t.Context())
	require.NoError(t, err)
	assert.Equal(t, HubError, status.Hub.State)
	assert.Equal(t, "credential file must be a regular file readable only by its owner (mode 0600)", status.Hub.Message)
	assert.Nil(t, status.Hub.Policy)
	assert.Equal(t, 1, calls)
}
