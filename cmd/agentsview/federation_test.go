package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
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
	"go.kenn.io/agentsview/internal/server"
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
		_ = json.NewEncoder(w).Encode(federation.HandshakeResponse{HubArchiveID: "hub-a", ProtocolVersions: []int{federation.ProtocolVersion}, EnrollmentUID: "enr-a", Member: "member-a", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest})
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

func TestFederationPulseResponseAndOverflow(t *testing.T) {
	oversize := false
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/federation/pulse", r.URL.Path)
		assert.Equal(t, "2025-01-02", r.URL.Query().Get("since"))
		assert.Equal(t, "Bearer operator", r.Header.Get("Authorization"))
		if oversize {
			_, _ = io.WriteString(w, `{"padding":"`+strings.Repeat("x", 4<<20)+`"}`)
			return
		}
		_, _ = io.WriteString(w, `{"since":"2025-01-02","closed_through":"2025-01-03T12:00:00Z","totals":{"tokens":{"value":null,"state":"suppressed"},"cost_microdollars":{"value":600,"state":"partial"}},"projects":[{"key":"safe","totals":{"tokens":{"value":60,"state":"available"}}}],"suppressed":true}`)
	}))
	t.Cleanup(daemon.Close)
	var pulse db.FederationPulse
	require.NoError(t, fetchFederationPulse(t.Context(), daemon.URL, "operator", "2025-01-02", &pulse))
	assert.Nil(t, pulse.Totals["tokens"].Value)
	assert.Equal(t, "suppressed", pulse.Totals["tokens"].State)
	assert.Equal(t, "partial", pulse.Totals["cost_microdollars"].State)
	require.NotNil(t, pulse.Totals["cost_microdollars"].Value)
	assert.EqualValues(t, 600, *pulse.Totals["cost_microdollars"].Value)
	require.Len(t, pulse.Projects, 1)
	require.NotNil(t, pulse.Projects[0].Totals["tokens"].Value)
	assert.EqualValues(t, 60, *pulse.Projects[0].Totals["tokens"].Value)
	encoded, err := json.Marshal(pulse)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"tokens":{"value":null,"state":"suppressed"}`)
	assert.Contains(t, string(encoded), `"cost_microdollars":{"value":600,"state":"partial"}`)
	var out bytes.Buffer
	require.NoError(t, printFederationPulse(&out, pulse))
	assert.Contains(t, out.String(), "tokens: 60")
	assert.Contains(t, out.String(), "tokens: suppressed")
	assert.Contains(t, out.String(), "cost_microdollars: 600 (partial)")
	assert.Contains(t, out.String(), "withheld")
	oversize = true
	err = fetchFederationPulse(t.Context(), daemon.URL, "operator", "2025-01-02", &pulse)
	assert.ErrorContains(t, err, "response too large")
}

func TestFederationPulseTextUsesReleasedStatesAndSeparateLinks(t *testing.T) {
	count := int64(3)
	since, contact := "2025-01-02", "2025-01-03T10:00:00Z"
	pulse := db.FederationPulse{
		Since: &since, ClosedThrough: "2025-01-03T12:00:00Z", Suppressed: true,
		Totals: map[string]db.FederationPulseMetric{
			"sessions": {Value: &count, State: "available"},
			"tokens":   {State: "suppressed"}, "cost_microdollars": {State: "unavailable"},
		},
		Links: []db.FederationPulseLink{{SpokeName: "spoke", State: "contacted", LastContactAt: &contact, StoredShareBatchRefusals: []string{"collision"}}},
	}
	var text bytes.Buffer
	require.NoError(t, printFederationPulse(&text, pulse))
	assert.Contains(t, text.String(), "sessions: 3")
	assert.Contains(t, text.String(), "tokens: suppressed")
	assert.Contains(t, text.String(), "cost_microdollars: unavailable")
	assert.Contains(t, text.String(), "Some values are withheld.")
	assert.Contains(t, text.String(), "Spoke: spoke; state: contacted; last contact: 2025-01-03T10:00:00Z; last accepting batch: unavailable; backlog lag: unavailable")
	assert.Contains(t, text.String(), "Stored per-share batch refusals: collision")
}

func TestFederationPulseDefaultStartIsNotDisclosed(t *testing.T) {
	for _, state := range []string{"suppressed", "available", "unavailable"} {
		pulse := db.FederationPulse{ClosedThrough: "2026-07-29T00:00:00Z", Totals: map[string]db.FederationPulseMetric{"sessions": {State: state}}}
		encoded, err := json.Marshal(pulse)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"since":null`)
		assert.NotContains(t, string(encoded), "2026-07-28")
		var out bytes.Buffer
		require.NoError(t, printFederationPulse(&out, pulse))
		assert.Contains(t, out.String(), "UTC window: default start not disclosed to 2026-07-29T00:00:00Z")
		assert.NotContains(t, out.String(), "2026-07-28")
	}
	since := "2026-07-27"
	var out bytes.Buffer
	require.NoError(t, printFederationPulse(&out, db.FederationPulse{Since: &since, ClosedThrough: "2026-07-29T00:00:00Z", Suppressed: true}))
	assert.Contains(t, out.String(), "UTC window: 2026-07-27 to")
}

func TestFederationPulseCommandHidesDefaultStart(t *testing.T) {
	dir := testDataDir(t)
	t.Setenv("AGENTSVIEW_NO_DAEMON", "1")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[federation]\nrole = 'hub'\n"), 0600))
	database, err := db.OpenIsolated(t.Context(), filepath.Join(dir, "sessions.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	svc := federation.NewService("hub", "archive", config.FederationHubConfig{MinGroupSize: 3}, database)
	daemon := httptest.NewUnstartedServer(nil)
	port := daemon.Listener.Addr().(*net.TCPAddr).Port
	srv := server.New(config.Config{Host: "127.0.0.1", Port: port}, database, nil, server.WithFederation(svc))
	daemon.Config.Handler = srv.Handler()
	daemon.Start()
	t.Cleanup(daemon.Close)
	ep := serverEndpoint(t, daemon)
	_, err = WriteDaemonRuntime(dir, ep.Host, ep.Port, version, false)
	require.NoError(t, err)
	run := func(args ...string) string {
		out, err := executeCommand(newRootCommand(), append([]string{"federation", "pulse"}, args...)...)
		require.NoError(t, err)
		return out
	}
	assert.Contains(t, run("--json"), `"since":null`)
	for i, name := range []string{"a", "b", "c"} {
		enrollment, spoke, share := "e-"+name, "s-"+name, "h-"+name
		require.NoError(t, database.CreateFederationEnrollment(t.Context(), db.FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: name, CredentialSHA256: "digest-" + name}))
		_, err := database.PutFederationHubShare(t.Context(), spoke, db.FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		start := "2026-07-28T09:00:00Z"
		record := db.FederationHubRecord{UID: name, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: db.SessionBatchWrite{Session: db.Session{ID: name, Project: "example/repo", Agent: "codex", StartedAt: &start}, Signals: db.SessionSignalUpdate{Outcome: "unknown"}}}
		_, err = database.CommitFederationBatch(t.Context(), enrollment, spoke, share, "policy", 1, 1, "batch", []db.FederationHubRecord{record})
		require.NoError(t, err)
		if i == 1 {
			continue
		}
		jsonOut := run("--json")
		assert.Contains(t, jsonOut, `"since":null`)
		assert.NotContains(t, jsonOut, "2026-07-28")
		if i == 0 {
			assert.Contains(t, jsonOut, `"state":"suppressed"`)
			assert.Contains(t, run("--json", "--since", "2026-07-27"), `"since":"2026-07-27"`)
		}
		text := run()
		assert.Contains(t, text, "UTC window: default start not disclosed to ")
		assert.NotContains(t, text, "2026-07-28")
	}
}

func TestShareRemoveReportsPendingCleanup(t *testing.T) {
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/federation/shares/share-a", r.URL.Path)
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(daemon.Close)
	var out bytes.Buffer
	require.NoError(t, removeFederationShare(t.Context(), daemon.URL, "", "share-a", &out))
	assert.Equal(t, "Share delivery stopped; hub cleanup is pending. Run federation push, then check federation status or share show.\n", out.String())
}

func TestShareConfirmationPostsOnlyOnYes(t *testing.T) {
	for _, tc := range []struct {
		name, input  string
		posts        int
		writeFailure bool
	}{
		{"no", "n\n", 0, false}, {"empty", "", 0, false}, {"yes", "y\n", 1, false}, {"write failure", "y\n", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			var writer io.Writer = &out
			if tc.writeFailure {
				writer = failingShareWriter{}
			}
			err := addFederationShare(t.Context(), daemon.URL, "", federation.ShareGrant{}, strings.NewReader(tc.input), writer)
			if tc.writeFailure {
				assert.ErrorContains(t, err, "write failed")
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.posts, posts)
			if tc.posts == 0 && !tc.writeFailure {
				assert.Contains(t, out.String(), "Aborted; no share was created.")
			}
		})
	}
}

func TestFederationDryRunStream(t *testing.T) {
	// The copier is content-opaque; this body is not NDJSON.
	body := strings.Repeat("x", (1<<20)+1024)
	for _, tc := range []struct {
		name, body, errorMessage string
		status                   int
	}{
		{"large response", body, "", http.StatusOK},
		{"daemon error", `{"error":"hub policy unavailable"}`, "hub policy unavailable", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, "/api/v1/federation/dry-run", r.URL.Path)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(daemon.Close)
			var out bytes.Buffer
			err := streamFederationDryRun(t.Context(), daemon.URL, "", &out)
			if tc.errorMessage != "" {
				assert.ErrorContains(t, err, tc.errorMessage)
				assert.Empty(t, out.String())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.body, out.String())
			}
		})
	}
}

func TestFederationPushCallsDaemon(t *testing.T) {
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/federation/push", r.URL.Path)
		_, _ = io.WriteString(w, `{"sent":2,"unchanged":1,"refused":0,"quarantined":1}`)
	}))
	t.Cleanup(daemon.Close)
	var output bytes.Buffer
	require.NoError(t, pushFederation(t.Context(), daemon.URL, "", &output))
	assert.Equal(t, "Sent: 2; unchanged: 1; refused: 0; quarantined: 1\n", output.String())
}

type failingShareWriter struct{}

func (failingShareWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestShareListSeparatesSuggestionsFromJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	shares := federation.ShareList{Shares: []db.FederationShare{{UID: "share-a"}}, Suggestions: []string{"github.com/example/api"}}
	require.NoError(t, printFederationShares(&stdout, &stderr, shares))
	var listed []db.FederationShare
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &listed))
	require.Len(t, listed, 1)
	assert.Equal(t, "share-a", listed[0].UID)
	assert.Equal(t, "Suggested: federation share add --project github.com/example/api --level summary\n", stderr.String())
}

func TestFederationHubDisablesLocalDiscovery(t *testing.T) {
	cfg := config.Config{}
	cfg.Federation.Role = "hub"
	backend := &localArchiveWriteBackend{appCfg: cfg}
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"sync", func() error {
			_, _, err := coordinateLocalSync(t.Context(), cfg, nil, false, nil, false, nil, nil)
			return err
		}},
		{"watch", func() error { _, err := backend.startWatchEngine(t.Context(), nil); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) { require.EqualError(t, tc.run(), "local discovery is disabled on a federation hub") })
	}
}

func TestFederationStatusPrintsStopReceipts(t *testing.T) {
	var out bytes.Buffer
	status := federation.Status{ArchiveID: "spoke", History: []federation.DeliveryHistory{
		{ShareUID: "share-a", HubOrigin: "https://a.example", HubArchiveID: "hub-a", NormalizedRemote: "example.org/a", StopIntent: "remove", StopReceipt: "purged"},
		{ShareUID: "share-b", HubOrigin: "https://b.example", HubArchiveID: "hub-b", NormalizedRemote: "example.org/b", StopIntent: "leave", StopReceipt: "retained"},
	}}
	printFederationStatus(&out, status)
	assert.Contains(t, out.String(), "Share share-a (current: false): hub https://a.example, archive hub-a, repository example.org/a; sent 0, refused 0, tombstoned 0, unconfirmed 0; stop remove, receipt purged\n")
	assert.Contains(t, out.String(), "Share share-b (current: false): hub https://b.example, archive hub-b, repository example.org/b; sent 0, refused 0, tombstoned 0, unconfirmed 0; stop leave, receipt retained\n")
	encoded, err := json.Marshal(status)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"stop_receipt":"purged"`)
	assert.Contains(t, string(encoded), `"stop_receipt":"retained"`)
}

func TestFederationPulseTextQualifiesPartialCost(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, printFederationPulse(&out, db.FederationPulse{Totals: map[string]db.FederationPulseMetric{"cost_microdollars": {Value: new(int64(600)), State: "partial"}}}))
	assert.Contains(t, out.String(), "cost_microdollars: 600 (partial)")
}

func TestFederationPulseSurfacesDateInputError(t *testing.T) {
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "2026-02-30", r.URL.Query().Get("since"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"detail":"since must be a non-future date in YYYY-MM-DD format"}`)
	}))
	t.Cleanup(daemon.Close)
	var pulse db.FederationPulse
	err := fetchFederationPulse(t.Context(), daemon.URL, "", "2026-02-30", &pulse)
	assert.ErrorContains(t, err, "since must be a non-future date in YYYY-MM-DD format")
}

func TestFederationPulseCommandStoredRefusalsAcrossShares(t *testing.T) {
	dir := testDataDir(t)
	t.Setenv("AGENTSVIEW_NO_DAEMON", "1")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[federation]\nrole = 'hub'\n"), 0600))
	database, err := db.OpenIsolated(t.Context(), filepath.Join(dir, "sessions.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	ctx := t.Context()
	require.NoError(t, database.CreateFederationEnrollment(ctx, db.FederationEnrollment{UID: "e", SpokeArchiveID: "spoke", Member: "member", SpokeName: "fixture-spoke", CredentialSHA256: "digest"}))
	for _, share := range []string{"a", "b"} {
		_, err := database.PutFederationHubShare(ctx, "spoke", db.FederationHubShare{UID: share, EnrollmentUID: "e", Remote: "example/" + share, ProjectKey: share, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
	}
	require.NoError(t, database.UpsertSession(ctx, db.Session{ID: "local", Project: "local", Machine: "host", Agent: "codex"}))
	collision := db.FederationHubRecord{UID: "secret-record", Hash: "hash", Remote: "example/a", ProjectKey: "a", Write: db.SessionBatchWrite{Session: db.Session{ID: "local", Project: "example/a", Agent: "codex"}}}
	refused, err := database.CommitFederationBatch(ctx, "e", "spoke", "a", "policy", 1, 1, "batch-a", []db.FederationHubRecord{collision})
	require.NoError(t, err)
	assert.Equal(t, db.FederationCollision, refused.Refused["secret-record"])
	accepted := db.FederationHubRecord{UID: "b-record", Hash: "hash", Remote: "example/b", ProjectKey: "b", Write: db.SessionBatchWrite{Session: db.Session{ID: "remote", Project: "example/b", Agent: "codex"}, Signals: db.SessionSignalUpdate{Outcome: "unknown"}}}
	_, err = database.CommitFederationBatch(ctx, "e", "spoke", "b", "policy", 1, 1, "batch-b", []db.FederationHubRecord{accepted})
	require.NoError(t, err)
	svc := federation.NewService("hub", "archive", config.FederationHubConfig{MinGroupSize: 3}, database)
	pulse, err := svc.Pulse(ctx, "")
	require.NoError(t, err)
	require.Len(t, pulse.Links, 1)
	assert.Equal(t, []string{"collision"}, pulse.Links[0].StoredShareBatchRefusals)
	assert.NotNil(t, pulse.Links[0].LastDeliveryAt)
	daemon := httptest.NewUnstartedServer(nil)
	port := daemon.Listener.Addr().(*net.TCPAddr).Port
	srv := server.New(config.Config{Host: "127.0.0.1", Port: port}, database, nil, server.WithFederation(svc))
	daemon.Config.Handler = srv.Handler()
	daemon.Start()
	t.Cleanup(daemon.Close)
	ep := serverEndpoint(t, daemon)
	_, err = WriteDaemonRuntime(dir, ep.Host, ep.Port, version, false)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, daemon.URL+"/api/v1/federation/pulse", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), `"stored_share_batch_refusals":["collision"]`)
	jsonOut, err := executeCommand(newRootCommand(), "federation", "pulse", "--json")
	require.NoError(t, err)
	assert.Contains(t, jsonOut, `"stored_share_batch_refusals":["collision"]`)
	textOut, err := executeCommand(newRootCommand(), "federation", "pulse")
	require.NoError(t, err)
	assert.Contains(t, textOut, "Stored per-share batch refusals: collision")
	assert.Contains(t, textOut, "last accepting batch:")
	assert.Contains(t, textOut, "backlog lag: unavailable")
	for _, secret := range []string{"secret-record", "example/a", "session ID unavailable"} {
		assert.NotContains(t, string(body), secret)
		assert.NotContains(t, jsonOut, secret)
		assert.NotContains(t, textOut, secret)
	}
}
