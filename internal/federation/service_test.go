package federation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestEnrollmentNormalizesAndRejectsInvalidFields(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	svc := NewService("hub", "hub-a", config.FederationHubConfig{}, archive)
	for _, tc := range []struct{ archive, member, name, message string }{
		{" ", "m", "", "spoke archive ID is required"}, {"a", " ", "", "member is required"},
		{"a\x00", "m", "", "spoke archive ID has invalid characters"},
		{strings.Repeat("a", 129), "m", "", "spoke archive ID is too long"},
		{"a", strings.Repeat("m", 129), "", "member is too long"},
		{"a", "m", strings.Repeat("n", 257), "spoke name is too long"},
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

func TestUnsupportedLinkCanBeLeftWithoutContact(t *testing.T) {
	for _, tc := range []struct {
		version int
		state   string
	}{{2, LinkActive}, {ProtocolVersion, "paused"}} {
		t.Run(tc.state, func(t *testing.T) {
			archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, archive.Close()) })
			calls := 0
			hub := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
			t.Cleanup(hub.Close)
			link := db.FederationLink{UID: "link-a", HubOrigin: hub.URL, HubArchiveID: "hub-a", EnrollmentUID: "enr-a", Member: "member-a", TokenFile: "missing", ProtocolVersion: tc.version, State: tc.state}
			require.NoError(t, archive.PutFederationLink(t.Context(), link))
			before, err := archive.GetFederationLink(t.Context())
			require.NoError(t, err)
			svc := NewService("spoke", "spoke-a", config.FederationHubConfig{}, archive)
			status, err := svc.Status(t.Context())
			require.NoError(t, err)
			assert.Equal(t, HubUnsupported, status.Hub.State)
			assert.Nil(t, status.Hub.Policy)
			err = svc.Join(t.Context(), hub.URL, "hub-a", "missing")
			assert.ErrorContains(t, err, "already linked")
			after, err := archive.GetFederationLink(t.Context())
			require.NoError(t, err)
			assert.Equal(t, before, after)
			assert.Zero(t, calls)
			require.NoError(t, svc.Leave(t.Context()))
		})
	}
}
