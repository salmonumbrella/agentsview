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
		_ = json.NewEncoder(w).Encode(HandshakeResponse{HubArchiveID: identity, ProtocolVersions: []int{1}, EnrollmentUID: "enr-a", Member: "member-a", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest})
	}))
	t.Cleanup(hub.Close)
	token := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(token, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"), 0600))
	svc := NewService("spoke", "spoke-a", policy, archive)
	require.Error(t, svc.Join(t.Context(), hub.URL+"/av", "wrong-hub", token))
	_, err = archive.GetFederationLink(t.Context())
	require.Error(t, err)
	require.NoError(t, svc.Join(t.Context(), hub.URL+"/av", "hub-a", token))
	beforeLink, err := archive.GetFederationLink(t.Context())
	require.NoError(t, err)
	first, err := svc.Status(t.Context())
	require.NoError(t, err)
	assert.Equal(t, HubOK, first.Hub.State)
	policy.Processing = "aggregated"
	digest, err = export.DigestCanonical(policy)
	require.NoError(t, err)
	status, err := svc.Status(t.Context())
	require.NoError(t, err)
	require.NotNil(t, status.Link)
	assert.Equal(t, HubOK, status.Hub.State)
	assert.Equal(t, digest, status.Hub.PolicyDigest)
	assert.Equal(t, "aggregated", status.Hub.Policy.Processing)
	afterLink, err := archive.GetFederationLink(t.Context())
	require.NoError(t, err)
	assert.Equal(t, beforeLink, afterLink)
	callsBeforeJoin := calls
	err = svc.Join(t.Context(), hub.URL, "hub-a", token)
	assert.ErrorContains(t, err, "already linked")
	assert.Equal(t, callsBeforeJoin, calls)
	identity = "hub-b"
	blocked, err := svc.Status(t.Context())
	require.NoError(t, err)
	assert.Equal(t, HubBlocked, blocked.Hub.State)
	assert.Nil(t, blocked.Hub.Policy)
	before := calls
	_, err = svc.Status(t.Context())
	require.NoError(t, err)
	assert.Equal(t, before, calls)
	link, err := archive.GetFederationLink(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "blocked", link.State)
	callsBeforeJoin = calls
	err = svc.Join(t.Context(), hub.URL, "hub-a", "missing")
	assert.ErrorContains(t, err, "already linked")
	assert.Equal(t, callsBeforeJoin, calls)
	unchanged, err := archive.GetFederationLink(t.Context())
	require.NoError(t, err)
	assert.Equal(t, link, unchanged)
	require.NoError(t, svc.Leave(t.Context()))
	identity = "hub-a"
	require.NoError(t, svc.Join(t.Context(), hub.URL+"/av", "hub-a", token))
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
	response := HandshakeResponse{HubArchiveID: "hub-a", ProtocolVersions: []int{1}, EnrollmentUID: "enr-a", Member: "member-a", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest}
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(response) }))
	t.Cleanup(hub.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0600))
	svc := NewService("spoke", "spoke-a", policy, archive)
	badFile := filepath.Join(testutil.PrivateTempDir(t), "bad")
	require.NoError(t, os.WriteFile(badFile, []byte("bad"), 0600))
	for _, tc := range []struct {
		name, hubID, path, digest, message string
		version                            int
	}{
		{"relative", "hub-a", "relative", digest, "credential file path must be absolute", 1},
		{"missing", "hub-a", filepath.Join(t.TempDir(), "missing"), digest, "cannot open credential file", 1},
		{"format", "hub-a", badFile, digest, "invalid federation credential", 1},
		{"identity", "different", file, digest, "federation hub identity mismatch", 1},
		{"protocol", "hub-a", file, digest, "unsupported federation protocol", 2},
		{"digest", "hub-a", file, "wrong", "invalid federation policy digest", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response.ProtocolVersions, response.PolicyDigest = []int{tc.version}, tc.digest
			assert.EqualError(t, svc.Join(t.Context(), hub.URL, tc.hubID, tc.path), tc.message)
			_, err := archive.GetFederationLink(t.Context())
			require.Error(t, err)
		})
	}
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
	assert.Equal(t, credentialDigest(credential), stored)
	handshake, err := svc.Authenticate(t.Context(), credential, "spoke-a")
	require.NoError(t, err)
	assert.Equal(t, "member-a", handshake.Member)
	assert.Equal(t, "enrolled", handshake.EnrollmentState)
}

func TestEnrollmentNormalizesAndRejectsInvalidFields(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	svc := NewService("hub", "hub-a", config.FederationHubConfig{}, archive)
	for _, tc := range []struct{ archive, member, name, message string }{
		{" ", "m", "", "spoke archive ID is required"}, {"a", " ", "", "member is required"},
	} {
		_, _, err := svc.Enroll(t.Context(), tc.archive, tc.member, tc.name)
		require.EqualError(t, err, tc.message)
	}
	rows, err := svc.List(t.Context())
	require.NoError(t, err)
	assert.Empty(t, rows)
	e, token, err := svc.Enroll(t.Context(), " spoke-a ", " member-a ", " laptop ")
	require.NoError(t, err)
	assert.Equal(t, "spoke-a", e.SpokeArchiveID)
	assert.Equal(t, "laptop", e.SpokeName)
	_, err = svc.Authenticate(t.Context(), token, "spoke-a")
	require.NoError(t, err)
	_, _, err = svc.Enroll(t.Context(), "spoke-a", "member-a", "")
	assert.EqualError(t, err, "an active enrollment already exists for this spoke archive and member; revoke it first")
}

func TestEnrollmentStateValidation(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	response := HandshakeResponse{HubArchiveID: "hub-a", ProtocolVersions: []int{1}, EnrollmentUID: "enr-a", Member: "member-a", Policy: policy, PolicyDigest: digest}
	omit := false
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if omit {
			_, _ = w.Write([]byte(`{"hub_archive_id":"hub-a","protocol_versions":[1],"enrollment_uid":"enr-a","member":"member-a"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(hub.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0600))
	svc := NewService("spoke", "spoke-a", policy, archive)
	for _, missing := range []bool{false, true} {
		omit = missing
		response.EnrollmentState = "revoked"
		assert.EqualError(t, svc.Join(t.Context(), hub.URL, "hub-a", file), "unsupported enrollment state")
		_, err := archive.GetFederationLink(t.Context())
		require.Error(t, err)
	}
	omit = false
	response.EnrollmentState = "enrolled"
	require.NoError(t, svc.Join(t.Context(), hub.URL, "hub-a", file))
	response.EnrollmentState = "revoked"
	status, err := svc.Status(t.Context())
	require.NoError(t, err)
	assert.Equal(t, HubError, status.Hub.State)
	assert.Equal(t, "unsupported enrollment state", status.Hub.Message)
	response.EnrollmentState = "enrolled"
	response.PolicyDigest = "wrong"
	status, err = svc.Status(t.Context())
	require.NoError(t, err)
	assert.Equal(t, HubError, status.Hub.State)
	assert.Equal(t, "invalid federation policy digest", status.Hub.Message)
}
