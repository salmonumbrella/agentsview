package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/dbtest"
	"go.kenn.io/agentsview/internal/export"
	"go.kenn.io/agentsview/internal/federation"
	"go.kenn.io/agentsview/internal/money"
	"go.kenn.io/agentsview/internal/testutil"
)

func revokeForTest(s *federation.Service, ctx context.Context, uid string) error {
	_, err := s.Revoke(ctx, uid)
	return err
}

func TestFederationCredentialIsolation(t *testing.T) {
	for _, role := range []string{"hub", "spoke", "off"} {
		for _, requireAuth := range []bool{false, true} {
			t.Run(role+map[bool]string{false: "_auth_off", true: "_auth_on"}[requireAuth], func(t *testing.T) {
				database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "archive.db"))
				svc := federation.NewService("hub", "hub-a", config.FederationHubConfig{}, database)
				enrollment, token, err := svc.Enroll(t.Context(), "spoke-a", "member-a", "")
				require.NoError(t, err)
				if role == "spoke" {
					svc = federation.NewService("spoke", "spoke-a", config.FederationHubConfig{}, database)
				}
				var options []Option
				if role != "off" {
					options = append(options, WithFederation(svc))
				}
				srv := New(config.Config{Host: "127.0.0.1", Port: 8080, AuthToken: "personal", RequireAuth: requireAuth}, database, nil, options...)
				type operation struct{ method, path string }
				ops := []operation{{http.MethodGet, "/"}, {http.MethodGet, "/api/ping"}, {http.MethodGet, "/debug/pprof/"}, {http.MethodGet, "/api/v1/federation/pulse"}, {http.MethodGet, "/api/v1/federation/enrollments"}, {http.MethodPost, "/api/v1/federation/enrollments"}, {http.MethodPost, "/api/v1/federation/enrollments/enr-a/revoke"}}
				ops = append(ops, operation{http.MethodPost, "/api/v1/federation/shares/preview"}, operation{http.MethodPost, "/api/v1/federation/shares"}, operation{http.MethodGet, "/api/v1/federation/shares"}, operation{http.MethodGet, "/api/v1/federation/shares/x"}, operation{http.MethodPost, "/api/v1/federation/shares/x/pause"}, operation{http.MethodPost, "/api/v1/federation/shares/x/resume"}, operation{http.MethodDelete, "/api/v1/federation/shares/x"}, operation{http.MethodPost, "/api/v1/federation/exclusions"}, operation{http.MethodGet, "/api/v1/federation/dry-run"})
				ops = append(ops, operation{http.MethodPost, federationHandshakePath}, operation{http.MethodGet, "/api/v1/federation/shares/x/batches"}, operation{http.MethodPut, "/api/v1/federation/shares/"}, operation{http.MethodPost, "/api/v1/federation/shares/x/batches/extra"}, operation{http.MethodPut, "/api/v1/federation/shares/x%2Fy"})
				for _, peerOp := range []operation{{http.MethodPut, "/api/v1/federation/shares/x"}, {http.MethodPost, "/api/v1/federation/shares/x/batches"}, {http.MethodPost, "/api/v1/federation/shares/x/reconcile"}} {
					req := httptest.NewRequest(peerOp.method, peerOp.path, strings.NewReader(`{}`))
					req.Header.Set("Authorization", "Bearer "+token)
					req.Header.Set(federation.SpokeArchiveHeader, "spoke-a")
					req.Header.Set("Content-Type", "application/json")
					rec := httptest.NewRecorder()
					srv.Handler().ServeHTTP(rec, req)
					if role == "hub" {
						assert.Equal(t, http.StatusBadRequest, rec.Code)
					} else {
						assert.Equal(t, http.StatusUnauthorized, rec.Code)
					}
					req = httptest.NewRequest(peerOp.method, peerOp.path+"?token="+token, strings.NewReader(`{}`))
					rec = httptest.NewRecorder()
					srv.Handler().ServeHTTP(rec, req)
					assert.Equal(t, http.StatusUnauthorized, rec.Code)
				}
				for path, item := range srv.api.OpenAPI().Paths {
					if path == federationHandshakePath {
						continue
					}
					for method, present := range map[string]bool{http.MethodGet: item.Get != nil, http.MethodPost: item.Post != nil, http.MethodPut: item.Put != nil, http.MethodPatch: item.Patch != nil, http.MethodDelete: item.Delete != nil, http.MethodHead: item.Head != nil, http.MethodOptions: item.Options != nil, http.MethodTrace: item.Trace != nil} {
						if present {
							ops = append(ops, operation{method, path})
						}
					}
				}
				for _, op := range ops {
					path := regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(op.path, "x")
					for _, query := range []bool{false, true} {
						req := httptest.NewRequest(op.method, path, nil)
						req.Header.Set(federation.SpokeArchiveHeader, "spoke-a")
						if query {
							q := req.URL.Query()
							q.Set("token", token)
							req.URL.RawQuery = q.Encode()
						} else {
							req.Header.Set("Authorization", "Bearer "+token)
						}
						rec := httptest.NewRecorder()
						srv.Handler().ServeHTTP(rec, req)
						assert.Equal(t, http.StatusUnauthorized, rec.Code, "%s %s query=%v", op.method, path, query)
						assert.Equal(t, "Unauthorized\n", rec.Body.String())
					}
				}
				if role != "hub" {
					req := httptest.NewRequest(http.MethodGet, federationHandshakePath, nil)
					req.Header.Set("Authorization", "Bearer "+token)
					rec := httptest.NewRecorder()
					srv.Handler().ServeHTTP(rec, req)
					assert.Equal(t, http.StatusUnauthorized, rec.Code)
					assert.Equal(t, "Unauthorized\n", rec.Body.String())
					return
				}
				var schemeResults []*httptest.ResponseRecorder
				for _, header := range []string{token, "bearer " + token} {
					req := httptest.NewRequest(http.MethodGet, federationHandshakePath, nil)
					req.Header.Set("Authorization", header)
					req.Header.Set(federation.SpokeArchiveHeader, "spoke-a")
					rec := httptest.NewRecorder()
					srv.Handler().ServeHTTP(rec, req)
					assert.Equal(t, http.StatusUnauthorized, rec.Code)
					assert.Equal(t, "Unauthorized\n", rec.Body.String())
					rows, err := svc.List(t.Context())
					require.NoError(t, err)
					assert.Empty(t, rows[0].LastHandshakeAt)
					schemeResults = append(schemeResults, rec)
				}
				req := httptest.NewRequest(http.MethodGet, "/api/v1/federation/handshake", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set(federation.SpokeArchiveHeader, "spoke-a")
				rec := httptest.NewRecorder()
				srv.Handler().ServeHTTP(rec, req)
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Contains(t, rec.Body.String(), `"enrollment_state":"enrolled"`)
				wrong := httptest.NewRequest(http.MethodGet, "/api/v1/federation/handshake", nil)
				wrong.Header.Set("Authorization", "Bearer "+token)
				wrong.Header.Set(federation.SpokeArchiveHeader, "wrong")
				wrongResult := httptest.NewRecorder()
				srv.Handler().ServeHTTP(wrongResult, wrong)
				assert.Equal(t, http.StatusUnauthorized, wrongResult.Code)
				for _, schemeResult := range schemeResults {
					assert.Equal(t, wrongResult.Body.String(), schemeResult.Body.String())
					assert.Equal(t, wrongResult.Header(), schemeResult.Header())
				}
				require.NoError(t, revokeForTest(svc, t.Context(), enrollment.UID))
				for _, pair := range [][2]string{{"", "spoke-a"}, {"avfc_bad", "spoke-a"}, {token, "wrong"}, {token, "spoke-a"}, {"personal", "spoke-a"}} {
					req = httptest.NewRequest(http.MethodGet, "/api/v1/federation/handshake", nil)
					req.Header.Set("Authorization", "Bearer "+pair[0])
					req.Header.Set(federation.SpokeArchiveHeader, pair[1])
					rec = httptest.NewRecorder()
					srv.Handler().ServeHTTP(rec, req)
					assert.Equal(t, http.StatusUnauthorized, rec.Code)
					b, _ := io.ReadAll(rec.Result().Body)
					assert.Equal(t, wrongResult.Body.String(), string(b))
					assert.Equal(t, wrongResult.Header(), rec.Header())
				}
			})
		}
	}
}

func TestFederationPulseRoute(t *testing.T) {
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "archive.db"))
	_, schemaPresent := OpenAPISpec(VersionInfo{}).Paths["/api/v1/federation/pulse"]
	assert.True(t, schemaPresent)
	for _, role := range []string{"off", "spoke", "hub"} {
		var options []Option
		if role != "off" {
			options = append(options, WithFederation(federation.NewService(role, "archive", config.FederationHubConfig{MinGroupSize: 3}, database)))
		}
		srv := New(config.Config{Host: "127.0.0.1", Port: 8080, AuthToken: "personal", RequireAuth: true}, database, nil, options...)
		for _, tc := range []struct {
			query   string
			wantHub int
		}{{"?since=2026-02-30", http.StatusBadRequest}, {"?since=2026-7-28", http.StatusBadRequest}, {"?since=" + time.Now().UTC().AddDate(1, 0, 0).Format(time.DateOnly), http.StatusBadRequest}, {"?since=", http.StatusOK}, {"?since=" + time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly), http.StatusOK}} {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/federation/pulse"+tc.query, nil)
			req.Header.Set("Authorization", "Bearer personal")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			want := http.StatusNotFound
			if role == "hub" {
				want = tc.wantHub
			}
			assert.Equal(t, want, rec.Code, "%s %s", role, tc.query)
			if role == "hub" && want == http.StatusBadRequest {
				assert.Contains(t, rec.Body.String(), "since must be a non-future date in YYYY-MM-DD format")
			}
			if want == http.StatusOK {
				assert.Contains(t, rec.Body.String(), `"suppressed"`)
			}
		}
	}
}

func TestFederationPulseUsesOrdinaryHostAndOperatorAuth(t *testing.T) {
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "archive.db"))
	svc := federation.NewService("hub", "archive", config.FederationHubConfig{MinGroupSize: 3}, database)
	for _, required := range []bool{false, true} {
		srv := New(config.Config{Host: "127.0.0.1", Port: 8080, AuthToken: "personal", RequireAuth: required}, database, nil, WithFederation(svc))
		for _, tc := range []struct {
			name, host, token string
			want              int
		}{
			{"operator", "127.0.0.1:8080", "personal", http.StatusOK},
			{"no token", "127.0.0.1:8080", "", map[bool]int{true: http.StatusUnauthorized, false: http.StatusOK}[required]},
			{"untrusted host", "untrusted.example:8080", "personal", http.StatusForbidden},
		} {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/federation/pulse", nil)
				req.Host, req.RemoteAddr = tc.host, "192.0.2.1:1234"
				if tc.token != "" {
					req.Header.Set("Authorization", "Bearer "+tc.token)
				}
				rec := httptest.NewRecorder()
				srv.Handler().ServeHTTP(rec, req)
				assert.Equal(t, tc.want, rec.Code)
				if tc.want == http.StatusOK {
					assert.Contains(t, rec.Body.String(), `"closed_through"`)
					assert.NotContains(t, rec.Body.String(), `"member"`)
				}
			})
		}
	}
}

func TestFederationPulseHTTPReleasesOnlySafeProjects(t *testing.T) {
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "archive.db"))
	ctx := t.Context()
	date := time.Now().UTC().AddDate(0, 0, -2).Format(time.DateOnly)
	for _, f := range []struct {
		id, project string
		tokens      int
	}{{"a", "safe", 10}, {"b", "safe", 20}, {"c", "safe", 30}, {"private-session", "private-project", 9}} {
		enrollment, spoke, share := "enr-"+f.id, "spoke-"+f.id, "share-"+f.id
		remote := "example/" + f.project
		require.NoError(t, database.CreateFederationEnrollment(ctx, db.FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: f.id, CredentialSHA256: "digest-" + f.id}))
		_, err := database.PutFederationHubShare(ctx, spoke, db.FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: remote, ProjectKey: f.project, Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		started := date + "T09:00:00Z"
		record := db.FederationHubRecord{UID: f.id, Hash: "hash", Remote: remote, ProjectKey: f.project, Write: db.SessionBatchWrite{
			Session: db.Session{ID: f.id, Project: remote, Agent: "codex", StartedAt: &started}, Signals: db.SessionSignalUpdate{Outcome: "unknown"},
			UsageEvents: []db.UsageEvent{{Source: "fixture", Model: "model", InputTokens: f.tokens, OccurredAt: started, DedupKey: f.id}},
		}}
		_, err = database.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []db.FederationHubRecord{record})
		require.NoError(t, err)
	}
	svc := federation.NewService("hub", "archive", config.FederationHubConfig{MinGroupSize: 3}, database)
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080, AuthToken: "personal", RequireAuth: true}, database, nil, WithFederation(svc))
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/federation/pulse?since="+date, nil)
	req.Header.Set("Authorization", "Bearer personal")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var pulse db.FederationPulse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pulse))
	assert.True(t, pulse.Suppressed)
	assert.Nil(t, pulse.Totals["tokens"].Value)
	assert.Equal(t, "suppressed", pulse.Totals["tokens"].State)
	require.Len(t, pulse.Projects, 1)
	assert.Equal(t, "safe", pulse.Projects[0].Key)
	require.NotNil(t, pulse.Projects[0].Totals["tokens"].Value)
	assert.EqualValues(t, 60, *pulse.Projects[0].Totals["tokens"].Value)
	for _, secret := range []string{"private-project", "private-session", "enr-a", "share-a", "digest-a"} {
		assert.NotContains(t, rec.Body.String(), secret)
	}
}

func TestFederationPulseHTTPDoesNotExposeInferredStart(t *testing.T) {
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "archive.db"))
	ctx := t.Context()
	svc := federation.NewService("hub", "archive", config.FederationHubConfig{MinGroupSize: 3}, database)
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, database, nil, WithFederation(svc))
	get := func(query string) string {
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/federation/pulse"+query, nil))
		require.Equal(t, http.StatusOK, response.Code)
		return response.Body.String()
	}
	assert.Contains(t, get(""), `"since":null`)
	for i, name := range []string{"a", "b", "c"} {
		enrollment, spoke, share := "e-"+name, "s-"+name, "h-"+name
		require.NoError(t, database.CreateFederationEnrollment(ctx, db.FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: name, CredentialSHA256: "digest-" + name}))
		_, err := database.PutFederationHubShare(ctx, spoke, db.FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		start := "2026-07-28T09:00:00Z"
		record := db.FederationHubRecord{UID: name, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: db.SessionBatchWrite{Session: db.Session{ID: name, Project: "example/repo", Agent: "codex", StartedAt: &start}, Signals: db.SessionSignalUpdate{Outcome: "unknown"}}}
		_, err = database.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []db.FederationHubRecord{record})
		require.NoError(t, err)
		if i == 1 {
			continue
		}
		body := get("")
		assert.Contains(t, body, `"since":null`)
		assert.NotContains(t, body, "2026-07-28")
		if i == 0 {
			assert.Contains(t, body, `"state":"suppressed"`)
		}
	}
	assert.Contains(t, get("?since=2026-07-27"), `"since":"2026-07-27"`)
}

func TestFederationOffPreservesOrdinaryAuth(t *testing.T) {
	for _, required := range []bool{false, true} {
		database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "archive.db"))
		srv := New(config.Config{Host: "127.0.0.1", Port: 8080, AuthToken: "personal", RequireAuth: required}, database, nil)
		var plain *httptest.ResponseRecorder
		for _, tc := range []struct {
			path, header string
			refused      bool
		}{
			{"/api/ping", "", required},
			{"/api/ping", "Bearer other", required},
			{"/api/ping", "Bearer personal", false},
			{"/api/ping", "Bearer avfc_x", true},
			{"/api/ping?token=avfc_x", "", true},
		} {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Host = "127.0.0.1:8080"
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if tc.refused {
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				assert.Equal(t, "Unauthorized\n", rec.Body.String())
			} else {
				assert.Equal(t, http.StatusOK, rec.Code)
			}
			if tc.header == "" && tc.path == "/api/ping" {
				plain = rec
			}
			if !required && tc.header == "Bearer other" {
				assert.Equal(t, plain.Code, rec.Code)
				assert.Equal(t, plain.Body.String(), rec.Body.String())
			}
		}
	}
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "archive.db"))
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080, AuthToken: "avfc_personal", RequireAuth: true}, database, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	req.Header.Set("Authorization", "Bearer avfc_personal")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "Unauthorized\n", rec.Body.String())
}

func TestFederationControlRequiresDirectLoopback(t *testing.T) {
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "archive.db"))
	svc := federation.NewService("hub", "hub-a", config.FederationHubConfig{}, database)
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, database, nil, WithFederation(svc))
	for _, tc := range []struct {
		remote, forwarded string
		want              int
	}{{"192.0.2.1:1234", "", http.StatusForbidden}, {"127.0.0.1:1234", "192.0.2.1", http.StatusForbidden}, {"127.0.0.1:1234", "", http.StatusOK}} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/federation/enrollments", nil)
		req.RemoteAddr = tc.remote
		if tc.forwarded != "" {
			req.Header.Set("X-Forwarded-For", tc.forwarded)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, tc.want, rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/federation/enrollments", strings.NewReader("{"))
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestFederationHandshakeRegistrationByRole(t *testing.T) {
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "archive.db"))
	for _, role := range []string{"off", "spoke", "hub"} {
		var options []Option
		if role != "off" {
			options = append(options, WithFederation(federation.NewService(role, "archive-a", config.FederationHubConfig{}, database)))
		}
		srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, database, nil, options...)
		_, found := srv.api.OpenAPI().Paths[federationHandshakePath]
		assert.Equal(t, role == "hub", found, role)
		for _, route := range []struct{ path, owner string }{{"/api/v1/federation/enrollments", "hub"}, {"/api/v1/federation/link", "spoke"}} {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080"+route.path, nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("Origin", "http://127.0.0.1:8080")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if role == route.owner {
				assert.Equal(t, http.StatusOK, rec.Code, "%s %s", role, route.path)
			} else {
				assert.Equal(t, http.StatusNotFound, rec.Code, "%s %s", role, route.path)
			}
		}
	}
	for _, role := range []string{"off", "spoke", "hub"} {
		var options []Option
		if role != "off" {
			options = append(options, WithFederation(federation.NewService(role, "archive-a", config.FederationHubConfig{}, database)))
		}
		srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, database, nil, options...)
		for _, route := range []struct{ method, path string }{
			{http.MethodPost, "/api/v1/federation/shares/preview"}, {http.MethodPost, "/api/v1/federation/shares"}, {http.MethodGet, "/api/v1/federation/shares"}, {http.MethodGet, "/api/v1/federation/shares/x"}, {http.MethodPost, "/api/v1/federation/shares/x/pause"}, {http.MethodPost, "/api/v1/federation/shares/x/resume"}, {http.MethodDelete, "/api/v1/federation/shares/x"}, {http.MethodPost, "/api/v1/federation/exclusions"}, {http.MethodGet, "/api/v1/federation/dry-run"},
		} {
			req := httptest.NewRequest(route.method, "http://127.0.0.1:8080"+route.path, strings.NewReader("{"))
			req.RemoteAddr = "192.0.2.1:1234"
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "http://127.0.0.1:8080")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if role == "spoke" {
				assert.Equal(t, http.StatusForbidden, rec.Code, route.path)
			} else {
				assert.Equal(t, http.StatusNotFound, rec.Code, route.path)
			}
		}
	}
	_, found := OpenAPISpec(VersionInfo{}).Paths[federationHandshakePath]
	assert.True(t, found)
}

func TestFederationHubSpokeLifecycle(t *testing.T) {
	var logs bytes.Buffer
	previousLog := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousLog) })
	hubDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "hub.db"))
	spokeDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "spoke.db"))
	cfg, err := config.Default()
	require.NoError(t, err)
	cfg.Federation.Role = "hub"
	policy := cfg.Federation.Hub
	hub := federation.NewService("hub", "hub-a", policy, hubDB)
	enrollment, token, err := hub.Enroll(t.Context(), "spoke-a", "member-a", "")
	require.NoError(t, err)
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, hubDB, nil, WithFederation(hub))
	httpHub := httptest.NewServer(srv.Handler())
	t.Cleanup(httpHub.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte(token), 0600))
	spoke := federation.NewService("spoke", "spoke-a", policy, spokeDB)
	require.ErrorContains(t, spoke.Join(t.Context(), httpHub.URL, "wrong-hub", file), "federation hub identity mismatch")
	rows, err := hub.List(t.Context())
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "contacted", rows[0].State)
	pulse, err := hub.Pulse(t.Context(), "")
	require.NoError(t, err)
	require.Len(t, pulse.Links, 1)
	assert.Equal(t, "contacted", pulse.Links[0].State)
	assert.NotNil(t, pulse.Links[0].LastContactAt)
	assert.Nil(t, pulse.Links[0].LastDeliveryAt)
	_, err = spokeDB.GetFederationLink(t.Context())
	require.Error(t, err)
	require.NoError(t, spoke.Join(t.Context(), httpHub.URL, "hub-a", file))
	status, err := spoke.Status(t.Context())
	require.NoError(t, err)
	assert.Zero(t, status.Shares)
	require.NotNil(t, status.Hub)
	assert.Equal(t, federation.HubOK, status.Hub.State)
	data, err := json.Marshal(status.Hub.Policy)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"suggested_projects":[]`)
	require.NotNil(t, status.Link)
	assert.Equal(t, "member-a", status.Link.Member)
	require.NoError(t, revokeForTest(hub, t.Context(), enrollment.UID))
	status, err = spoke.Status(t.Context())
	require.NoError(t, err)
	require.NotNil(t, status.Link)
	assert.Equal(t, federation.LinkActive, status.Link.State)
	assert.Equal(t, federation.HubError, status.Hub.State)
	assert.Equal(t, federation.ErrHubRefused.Error(), status.Hub.Message)
	assert.Nil(t, status.Hub.Policy)
	httpHub.Close()
	status, err = spoke.Status(t.Context())
	require.NoError(t, err)
	assert.Equal(t, federation.HubError, status.Hub.State)
	assert.Equal(t, "cannot reach hub", status.Hub.Message)
	require.NoError(t, spoke.Leave(t.Context()))
	status, err = spoke.Status(t.Context())
	require.NoError(t, err)
	assert.Nil(t, status.Link)
	assert.NotContains(t, logs.String(), token)
}

func TestFederationControlInputMessages(t *testing.T) {
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "hub.db"))
	svc := federation.NewService("hub", "hub-a", config.FederationHubConfig{}, database)
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, database, nil, WithFederation(svc))
	hub := httptest.NewServer(srv.Handler())
	t.Cleanup(hub.Close)
	enrollment, _, err := svc.Enroll(t.Context(), "spoke-a", "member-a", "")
	require.NoError(t, err)
	require.NotEmpty(t, enrollment.UID)
	padded, err := http.NewRequestWithContext(t.Context(), http.MethodPost, hub.URL+"/api/v1/federation/enrollments", strings.NewReader(`{"spoke_archive_id":" padded ","member":" member ","spoke_name":" laptop "}`))
	require.NoError(t, err)
	padded.Host = "127.0.0.1:8080"
	padded.Header.Set("Content-Type", "application/json")
	padded.Header.Set("Origin", "http://127.0.0.1:8080")
	created, err := http.DefaultClient.Do(padded)
	require.NoError(t, err)
	var createdBody struct {
		Enrollment struct {
			SpokeArchiveID string `json:"spoke_archive_id"`
			Member         string `json:"member"`
			SpokeName      string `json:"spoke_name"`
		} `json:"enrollment"`
		Credential string `json:"credential"`
	}
	require.NoError(t, json.NewDecoder(created.Body).Decode(&createdBody))
	require.NoError(t, created.Body.Close())
	require.Equal(t, http.StatusOK, created.StatusCode)
	assert.Equal(t, "padded", createdBody.Enrollment.SpokeArchiveID)
	assert.Equal(t, "member", createdBody.Enrollment.Member)
	assert.Equal(t, "laptop", createdBody.Enrollment.SpokeName)
	_, err = svc.Authenticate(t.Context(), createdBody.Credential, "padded")
	require.NoError(t, err)
	for _, tc := range []struct{ path, body, message string }{
		{"/api/v1/federation/enrollments", `{"spoke_archive_id":" ","member":"member-a"}`, "spoke archive ID is required"},
		{"/api/v1/federation/enrollments/missing/revoke", `{}`, "enrollment not found"},
		{"/api/v1/federation/enrollments", `{"spoke_archive_id":" spoke-a ","member":" member-a "}`, "an active enrollment already exists for this spoke archive and member; revoke it first"},
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, hub.URL+tc.path, strings.NewReader(tc.body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Host = "127.0.0.1:8080"
		req.Header.Set("Origin", "http://127.0.0.1:8080")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, string(data), tc.message)
		var decoded struct {
			Error string `json:"error"`
		}
		require.NoError(t, json.Unmarshal(data, &decoded))
		assert.Equal(t, tc.message, decoded.Error)
	}
}

func TestFederationJoinControlMessages(t *testing.T) {
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "spoke.db"))
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	response := federation.HandshakeResponse{HubArchiveID: "hub-a", ProtocolVersions: []int{federation.ProtocolVersion}, EnrollmentUID: "enr-a", Member: "member-a", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest}
	code := http.StatusOK
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(hub.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	credential := "avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	require.NoError(t, os.WriteFile(file, []byte(credential), 0600))
	svc := federation.NewService("spoke", "spoke-a", policy, database)
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, database, nil, WithFederation(svc))
	daemon := httptest.NewServer(srv.Handler())
	t.Cleanup(daemon.Close)
	cases := []struct {
		name, origin, hubID, path, message string
		version, status                    int
		digest                             string
	}{
		{"relative", hub.URL, "hub-a", "relative", "credential file path must be absolute", 1, 200, digest},
		{"refused", hub.URL, "hub-a", file, "hub refused this credential (revoked, unknown, or wrong archive)", 1, 401, digest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response.ProtocolVersions, response.PolicyDigest, code = []int{tc.version}, tc.digest, tc.status
			body, err := json.Marshal(map[string]string{"hub": tc.origin, "hub_archive": tc.hubID, "credential_file": tc.path})
			require.NoError(t, err)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, daemon.URL+"/api/v1/federation/link", bytes.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Host = "127.0.0.1:8080"
			req.Header.Set("Origin", "http://127.0.0.1:8080")
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			data, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Contains(t, string(data), tc.message)
			var decoded struct {
				Error string `json:"error"`
			}
			require.NoError(t, json.Unmarshal(data, &decoded))
			assert.Equal(t, tc.message, decoded.Error)
			assert.NotContains(t, string(data), credential)
			assert.NotContains(t, string(data), tc.path)
		})
	}
}

func TestFederationPeerOperationBoundary(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/api/v1/federation/handshake", true}, {"PUT", "/api/v1/federation/shares/x", true}, {"POST", "/api/v1/federation/shares/x/batches", true}, {"POST", "/api/v1/federation/shares/x/reconcile", true},
		{"GET", "/api/v1/federation/shares/x", false}, {"POST", "/api/v1/federation/shares/x", false}, {"PUT", "/api/v1/federation/shares/", false}, {"PUT", "/api/v1/federation/shares/a/b", false}, {"POST", "/api/v1/federation/shares/x/batches/extra", false}, {"POST", "/api/v1/federation/shares/x/reconcile/extra", false},
	} {
		assert.Equal(t, tc.want, federationPeerOperation(tc.method, tc.path), "%s %s", tc.method, tc.path)
	}
}

func TestFederationPulseHTTPReleasesPartialKnownCost(t *testing.T) {
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "archive.db"))
	ctx := t.Context()
	date := time.Now().UTC().AddDate(0, 0, -2).Format(time.DateOnly)
	for i, name := range []string{"a", "b", "c"} {
		enrollment, spoke, share := "e-"+name, "s-"+name, "h-"+name
		require.NoError(t, database.CreateFederationEnrollment(ctx, db.FederationEnrollment{UID: enrollment, SpokeArchiveID: spoke, Member: name, CredentialSHA256: "digest-" + name}))
		_, err := database.PutFederationHubShare(ctx, spoke, db.FederationHubShare{UID: share, EnrollmentUID: enrollment, Remote: "example/repo", ProjectKey: "project", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "policy", Epoch: 1, State: "active"})
		require.NoError(t, err)
		start := date + "T09:00:00Z"
		cost := money.Money{Microdollars: int64((i + 1) * 100)}
		record := db.FederationHubRecord{UID: name, Hash: "hash", Remote: "example/repo", ProjectKey: "project", Write: db.SessionBatchWrite{Session: db.Session{ID: name, Project: "example/repo", Agent: "codex", StartedAt: &start}, Signals: db.SessionSignalUpdate{Outcome: "unknown"}, UsageEvents: []db.UsageEvent{
			{Source: "fixture", Model: "known", InputTokens: 10, Cost: &cost, CostStatus: "exact", CostSource: "reported", OccurredAt: start, DedupKey: name + "-known"},
			{Source: "fixture", Model: "synthetic-unpriced-model", InputTokens: 20, OccurredAt: start, DedupKey: name + "-unknown"},
		}}}
		_, err = database.CommitFederationBatch(ctx, enrollment, spoke, share, "policy", 1, 1, "batch", []db.FederationHubRecord{record})
		require.NoError(t, err)
	}
	svc := federation.NewService("hub", "archive", config.FederationHubConfig{MinGroupSize: 3}, database)
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, database, nil, WithFederation(svc))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/federation/pulse?since="+date, nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var pulse db.FederationPulse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pulse))
	assert.Equal(t, "partial", pulse.Totals["cost_microdollars"].State)
	require.NotNil(t, pulse.Totals["cost_microdollars"].Value)
	assert.EqualValues(t, 600, *pulse.Totals["cost_microdollars"].Value)
	assert.Contains(t, rec.Body.String(), `"cost_microdollars":{"value":600,"state":"partial"}`)
	assert.NotContains(t, rec.Body.String(), "digest-a")
}
