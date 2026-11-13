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

func TestJoinPinsHubAndBlocksChangedIdentity(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	identity := "hub-a"
	calls := 0
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "/av/api/v1/federation/handshake", r.URL.Path)
		assert.Equal(t, "Bearer avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(HandshakeResponse{HubArchiveID: identity, ProtocolVersions: []int{1}, EnrollmentUID: "enr-a", Member: "member-a", Policy: policy, PolicyDigest: digest})
	}))
	t.Cleanup(hub.Close)
	token := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(token, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"), 0600))
	svc := NewService("spoke", "spoke-a", policy, archive)
	require.Error(t, svc.Join(t.Context(), hub.URL+"/av", "wrong-hub", token))
	_, err = archive.GetFederationLink(t.Context())
	require.Error(t, err)
	require.NoError(t, svc.Join(t.Context(), hub.URL+"/av", "hub-a", token))
	policy.Processing = "aggregated"
	digest, err = export.DigestCanonical(policy)
	require.NoError(t, err)
	status, err := svc.Status(t.Context())
	require.NoError(t, err)
	require.NotNil(t, status.Link)
	assert.Equal(t, digest, status.Link.PolicyDigest)
	assert.Contains(t, status.Link.PolicyJSON, "aggregated")
	identity = "hub-b"
	_, err = svc.Status(t.Context())
	require.NoError(t, err)
	before := calls
	_, err = svc.Status(t.Context())
	require.NoError(t, err)
	assert.Equal(t, before, calls)
	link, err := archive.GetFederationLink(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "blocked", link.State)
	require.NoError(t, svc.Leave(t.Context()))
	_, err = os.Stat(token)
	require.NoError(t, err)
}

func TestJoinRejectsUnsupportedProtocolAndBadDigest(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	response := HandshakeResponse{HubArchiveID: "hub-a", ProtocolVersions: []int{2}, EnrollmentUID: "enr-a", Member: "member-a", Policy: policy, PolicyDigest: digest}
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(response) }))
	t.Cleanup(hub.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0600))
	svc := NewService("spoke", "spoke-a", policy, archive)
	require.Error(t, svc.Join(t.Context(), hub.URL, "hub-a", file))
	_, err = archive.GetFederationLink(t.Context())
	require.Error(t, err)
	response.ProtocolVersions = []int{1}
	response.PolicyDigest = "wrong"
	require.Error(t, svc.Join(t.Context(), hub.URL, "hub-a", file))
	_, err = archive.GetFederationLink(t.Context())
	require.Error(t, err)
}

func TestEnrollmentStoresOnlyDigestAndRevocationStopsHandshake(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	svc := NewService("hub", "hub-a", config.FederationHubConfig{}, archive)
	enrollment, credential, err := svc.Enroll(t.Context(), "spoke-a", "member-a", "laptop")
	require.NoError(t, err)
	assert.Regexp(t, `^avfc_[A-Za-z0-9_-]{43}$`, credential)
	var stored string
	require.NoError(t, archive.Reader().QueryRow(t.Context(), `SELECT credential_sha256 FROM federation_enrollments WHERE enrollment_uid = ?`, enrollment.UID).Scan(&stored))
	assert.NotEqual(t, credential, stored)
	assert.Len(t, stored, 64)
	handshake, err := svc.Authenticate(t.Context(), credential, "spoke-a")
	require.NoError(t, err)
	assert.Equal(t, "member-a", handshake.Member)
	require.NoError(t, svc.Revoke(t.Context(), enrollment.UID))
	_, err = svc.Authenticate(t.Context(), credential, "spoke-a")
	assert.ErrorIs(t, err, db.ErrFederationUnauthorized)
}
