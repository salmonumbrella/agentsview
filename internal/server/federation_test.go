package server

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/dbtest"
	"go.kenn.io/agentsview/internal/federation"
	"go.kenn.io/agentsview/internal/testutil"
)

func TestFederationCredentialIsolation(t *testing.T) {
	for _, requireAuth := range []bool{false, true} {
		t.Run(map[bool]string{false: "auth_off", true: "auth_on"}[requireAuth], func(t *testing.T) {
			database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "archive.db"))
			svc := federation.NewService("hub", "hub-a", config.FederationHubConfig{}, database)
			enrollment, token, err := svc.Enroll(t.Context(), "spoke-a", "member-a", "")
			require.NoError(t, err)
			srv := New(config.Config{Host: "127.0.0.1", Port: 8080, AuthToken: "personal", RequireAuth: requireAuth}, database, nil, WithFederation(svc))
			type operation struct{ method, path string }
			ops := []operation{{http.MethodGet, "/"}, {http.MethodGet, "/api/ping"}, {http.MethodGet, "/debug/pprof/"}, {http.MethodGet, "/api/v1/federation/enrollments"}, {http.MethodPost, "/api/v1/federation/enrollments"}, {http.MethodPost, "/api/v1/federation/enrollments/enr-a/revoke"}}
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
			req := httptest.NewRequest(http.MethodGet, "/api/v1/federation/handshake", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set(federation.SpokeArchiveHeader, "spoke-a")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
			wrong := httptest.NewRequest(http.MethodGet, "/api/v1/federation/handshake", nil)
			wrong.Header.Set("Authorization", "Bearer "+token)
			wrong.Header.Set(federation.SpokeArchiveHeader, "wrong")
			wrongResult := httptest.NewRecorder()
			srv.Handler().ServeHTTP(wrongResult, wrong)
			assert.Equal(t, http.StatusUnauthorized, wrongResult.Code)
			require.NoError(t, svc.Revoke(t.Context(), enrollment.UID))
			var body string
			for _, pair := range [][2]string{{"", "spoke-a"}, {"avfc_bad", "spoke-a"}, {token, "wrong"}, {token, "spoke-a"}, {"personal", "spoke-a"}} {
				req = httptest.NewRequest(http.MethodGet, "/api/v1/federation/handshake", nil)
				req.Header.Set("Authorization", "Bearer "+pair[0])
				req.Header.Set(federation.SpokeArchiveHeader, pair[1])
				rec = httptest.NewRecorder()
				srv.Handler().ServeHTTP(rec, req)
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				b, _ := io.ReadAll(rec.Result().Body)
				if body == "" {
					body = string(b)
				}
				assert.Equal(t, body, string(b))
				assert.Equal(t, wrongResult.Body.String(), string(b))
				assert.Equal(t, wrongResult.Header(), rec.Header())
			}
		})
	}
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
}

func TestFederationControlRejectsRemoteBeforeBodyValidation(t *testing.T) {
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "archive.db"))
	svc := federation.NewService("hub", "hub-a", config.FederationHubConfig{}, database)
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, database, nil, WithFederation(svc))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/federation/enrollments", strings.NewReader("{"))
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Content-Type", "application/json")
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
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	hub := federation.NewService("hub", "hub-a", policy, hubDB)
	enrollment, token, err := hub.Enroll(t.Context(), "spoke-a", "member-a", "")
	require.NoError(t, err)
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, hubDB, nil, WithFederation(hub))
	httpHub := httptest.NewServer(srv.Handler())
	t.Cleanup(httpHub.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte(token), 0600))
	spoke := federation.NewService("spoke", "spoke-a", policy, spokeDB)
	require.NoError(t, spoke.Join(t.Context(), httpHub.URL, "hub-a", file))
	status, err := spoke.Status(t.Context())
	require.NoError(t, err)
	assert.Zero(t, status.Shares)
	require.NotNil(t, status.Link)
	assert.Equal(t, "member-a", status.Link.Member)
	require.NoError(t, hub.Revoke(t.Context(), enrollment.UID))
	_, err = spoke.Status(t.Context())
	require.Error(t, err)
	require.NoError(t, spoke.Leave(t.Context()))
	status, err = spoke.Status(t.Context())
	require.NoError(t, err)
	assert.Nil(t, status.Link)
	_, err = os.Stat(file)
	require.NoError(t, err)
	assert.NotContains(t, logs.String(), token)
}
