package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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

func TestFederationRelativeCredentialRemainsUsableAfterDaemonDirectoryChanges(t *testing.T) {
	database, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(federation.HandshakeResponse{HubArchiveID: "hub-a", ProtocolVersions: []int{1}, EnrollmentUID: "enr-a", Member: "member-a", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest})
	}))
	t.Cleanup(hub.Close)
	svc := federation.NewService("spoke", "spoke-a", policy, database)
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/federation/link", r.URL.Path)
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

func TestShareConfirmationPostsOnlyOnYes(t *testing.T) {
	for _, tc := range []struct {
		input string
		posts int
	}{{"n\n", 0}, {"", 0}, {"y\n", 1}} {
		t.Run(tc.input, func(t *testing.T) {
			posts := 0
			daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/federation/shares/preview" {
					_ = json.NewEncoder(w).Encode(federation.SharePreview{PolicyDigest: "shown"})
					return
				}
				posts++
				var p federation.SharePreview
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&p))
				assert.Equal(t, "shown", p.PolicyDigest)
				_, _ = io.WriteString(w, `{}`)
			}))
			t.Cleanup(daemon.Close)
			var out bytes.Buffer
			require.NoError(t, addFederationShare(t.Context(), daemon.URL, "", federation.ShareGrant{}, strings.NewReader(tc.input), &out))
			assert.Equal(t, tc.posts, posts)
		})
	}
}
func TestFederationDryRunStreamsLargeResponse(t *testing.T) {
	body := strings.Repeat("x", (1<<20)+1024)
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
	t.Cleanup(daemon.Close)
	var out bytes.Buffer
	require.NoError(t, streamFederationDryRun(t.Context(), daemon.URL, "", &out))
	assert.Equal(t, body, out.String())
}

func TestFederationPushRequiresDryRun(t *testing.T) {
	cmd := newFederationPushCommand()
	cmd.SetArgs(nil)
	err := cmd.ExecuteContext(t.Context())
	assert.ErrorContains(t, err, "--dry-run is required")
}

type failingShareWriter struct{}

func (failingShareWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestSharePreviewWriteFailureDoesNotPostConsent(t *testing.T) {
	posts := 0
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/federation/shares/preview" {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		posts++
	}))
	t.Cleanup(daemon.Close)
	err := addFederationShare(t.Context(), daemon.URL, "", federation.ShareGrant{}, strings.NewReader("y\n"), failingShareWriter{})
	assert.ErrorContains(t, err, "write failed")
	assert.Zero(t, posts)
}

func TestFederationDryRunReturnsDaemonMessage(t *testing.T) {
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"hub policy unavailable"}`)
	}))
	t.Cleanup(daemon.Close)
	var out bytes.Buffer
	assert.ErrorContains(t, streamFederationDryRun(t.Context(), daemon.URL, "", &out), "hub policy unavailable")
}
