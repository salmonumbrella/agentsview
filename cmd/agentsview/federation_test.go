package main

import (
	"bytes"
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
	"go.kenn.io/agentsview/internal/federation"
	"go.kenn.io/agentsview/internal/testutil"
)

func TestFederationJoinResolvesCredentialBeforeHandoff(t *testing.T) {
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte("avfc_fixture"), 0600))
	t.Chdir(filepath.Dir(file))
	relative := "credential"
	var got struct {
		CredentialFile string `json:"credential_file"`
		Hub            string `json:"hub"`
		HubArchive     string `json:"hub_archive"`
	}
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/federation/link", r.URL.Path)
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_, _ = w.Write([]byte(`{"joined":true}`))
	}))
	t.Cleanup(daemon.Close)
	err := joinFederation(t.Context(), daemon.URL, "", "https://hub.example/av", "hub-a", relative)
	require.NoError(t, err)
	assert.Equal(t, file, got.CredentialFile)
	assert.Equal(t, "https://hub.example/av", got.Hub)
	assert.Equal(t, "hub-a", got.HubArchive)
}

func TestFederationRelativeCredentialRemainsUsableAfterDaemonDirectoryChanges(t *testing.T) {
	database, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(federation.HandshakeResponse{HubArchiveID: "hub-a", ProtocolVersions: []int{1}, EnrollmentUID: "enr-a", Member: "member-a", Policy: policy, PolicyDigest: digest})
	}))
	t.Cleanup(hub.Close)
	svc := federation.NewService("spoke", "spoke-a", policy, database)
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Hub            string `json:"hub"`
			HubArchive     string `json:"hub_archive"`
			CredentialFile string `json:"credential_file"`
		}
		if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&input)) {
			http.Error(w, "bad input", http.StatusBadRequest)
			return
		}
		if !assert.NoError(t, svc.Join(r.Context(), input.Hub, input.HubArchive, input.CredentialFile)) {
			http.Error(w, "join failed", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"joined":true}`))
	}))
	t.Cleanup(daemon.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0600))
	t.Chdir(filepath.Dir(file))
	relative := "credential"
	require.NoError(t, joinFederation(t.Context(), daemon.URL, "", hub.URL, "hub-a", relative))
	t.Chdir(t.TempDir())
	status, err := svc.Status(t.Context())
	require.NoError(t, err)
	require.NotNil(t, status.Link)
	assert.Equal(t, file, status.Link.TokenFile)
}

func TestFederationEnrollmentShowsCredentialOnlyOnce(t *testing.T) {
	var stdout, stderr bytes.Buffer
	credential := "avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	require.NoError(t, printFederationEnrollment(&stdout, &stderr, credential, "enr-a", "hub-a"))
	assert.Equal(t, credential+"\n", stdout.String())
	assert.Equal(t, 1, strings.Count(stdout.String(), credential))
	assert.NotContains(t, stderr.String(), credential)
	assert.Contains(t, stderr.String(), "hub-a")
}

func TestFederationRequestReturnsDaemonMessage(t *testing.T) {
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"x"}`))
	}))
	t.Cleanup(daemon.Close)
	err := federationRequest(t.Context(), daemon.URL, "", http.MethodGet, "/", nil, nil)
	assert.EqualError(t, err, "federation: x")
}
