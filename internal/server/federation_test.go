package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/dbtest"
	"go.kenn.io/agentsview/internal/export"
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
	require.NoError(t, spoke.Join(t.Context(), httpHub.URL, "hub-a", file))
	status, err := spoke.Status(t.Context())
	require.NoError(t, err)
	assert.Zero(t, status.Shares)
	require.NotNil(t, status.Hub)
	assert.Equal(t, federation.HubOK, status.Hub.State)
	data, err := json.Marshal(status.Hub.Policy)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"suggested_projects":[]`)
	digest, err := export.DigestCanonical(*status.Hub.Policy)
	require.NoError(t, err)
	assert.Equal(t, digest, status.Hub.PolicyDigest)
	require.NotNil(t, status.Link)
	assert.Equal(t, "member-a", status.Link.Member)
	require.NoError(t, hub.Revoke(t.Context(), enrollment.UID))
	status, err = spoke.Status(t.Context())
	require.NoError(t, err)
	require.NotNil(t, status.Link)
	assert.Equal(t, federation.LinkActive, status.Link.State)
	assert.Equal(t, federation.HubRefused, status.Hub.State)
	assert.Nil(t, status.Hub.Policy)
	httpHub.Close()
	status, err = spoke.Status(t.Context())
	require.NoError(t, err)
	assert.Equal(t, federation.HubUnreachable, status.Hub.State)
	require.NoError(t, spoke.Leave(t.Context()))
	status, err = spoke.Status(t.Context())
	require.NoError(t, err)
	assert.Nil(t, status.Link)
	_, err = os.Stat(file)
	require.NoError(t, err)
	assert.NotContains(t, logs.String(), token)
}

func TestFederationControlInputMessages(t *testing.T) {
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "hub.db"))
	svc := federation.NewService("hub", "hub-a", config.FederationHubConfig{}, database)
	srv := New(config.Config{Host: "127.0.0.1", Port: 8080}, database, nil, WithFederation(svc))
	hub := httptest.NewServer(srv.Handler())
	t.Cleanup(hub.Close)
	enrollment, secret, err := svc.Enroll(t.Context(), "spoke-a", "member-a", "")
	require.NoError(t, err)
	require.NotEmpty(t, enrollment.UID)
	padded, err := http.NewRequestWithContext(t.Context(), http.MethodPost, hub.URL+"/api/v1/federation/enrollments", strings.NewReader(`{"spoke_archive_id":" padded ","member":" member ","spoke_name":" laptop "}`))
	require.NoError(t, err)
	padded.Header.Set("Content-Type", "application/json")
	padded.Header.Set("Origin", hub.URL)
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
		{"/api/v1/federation/enrollments", `{"spoke_archive_id":"` + strings.Repeat("a", 129) + `","member":"member-a"}`, "spoke archive ID is too long"},
		{"/api/v1/federation/enrollments", `{"spoke_archive_id":"a","member":"` + strings.Repeat("m", 129) + `"}`, "member is too long"},
		{"/api/v1/federation/enrollments", `{"spoke_archive_id":"a","member":"m","spoke_name":"` + strings.Repeat("n", 257) + `"}`, "spoke name is too long"},
		{"/api/v1/federation/enrollments/missing/revoke", `{}`, "enrollment not found"},
		{"/api/v1/federation/enrollments", `{"spoke_archive_id":" spoke-a ","member":" member-a "}`, "an active enrollment already exists for this spoke archive and member; revoke it first"},
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, hub.URL+tc.path, strings.NewReader(tc.body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", hub.URL)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, string(data), tc.message)
		assert.NotContains(t, string(data), secret)
	}
	// Route registration is role-specific; change the synthetic service role after
	// registration to exercise its defensive role refusal through the real server.
	wrongRole := New(config.Config{Host: "127.0.0.1", Port: 8080}, database, nil, WithFederation(svc))
	wrongRole.federation = federation.NewService("spoke", "spoke-a", config.FederationHubConfig{}, database)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/federation/enrollments", strings.NewReader(`{"spoke_archive_id":"a","member":"m"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	wrongRole.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "hub role required")
}

func TestFederationJoinControlMessages(t *testing.T) {
	database := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "spoke.db"))
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, SuggestedProjects: []string{}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	response := federation.HandshakeResponse{HubArchiveID: "hub-a", ProtocolVersions: []int{1}, EnrollmentUID: "enr-a", Member: "member-a", Policy: policy, PolicyDigest: digest}
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
	badFile := filepath.Join(testutil.PrivateTempDir(t), "bad")
	require.NoError(t, os.WriteFile(badFile, []byte("bad"), 0600))
	realDB := dbtest.OpenTestDBAt(t, filepath.Join(t.TempDir(), "real-hub.db"))
	realHub := federation.NewService("hub", "hub-a", policy, realDB)
	enrollment, revoked, err := realHub.Enroll(t.Context(), "spoke-a", "member-a", "")
	require.NoError(t, err)
	require.NoError(t, realHub.Revoke(t.Context(), enrollment.UID))
	realServer := New(config.Config{Host: "127.0.0.1", Port: 8080}, realDB, nil, WithFederation(realHub))
	realHTTP := httptest.NewServer(realServer.Handler())
	t.Cleanup(realHTTP.Close)
	revokedFile := filepath.Join(testutil.PrivateTempDir(t), "revoked")
	require.NoError(t, os.WriteFile(revokedFile, []byte(revoked), 0600))
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
		{"missing", hub.URL, "hub-a", filepath.Join(t.TempDir(), "missing"), "cannot open credential file", 1, 200, digest},
		{"format", hub.URL, "hub-a", badFile, "invalid federation credential", 1, 200, digest},
		{"url", "http://example.invalid", "hub-a", file, "invalid federation hub URL", 1, 200, digest},
		{"identity", hub.URL, "different", file, "federation hub identity mismatch", 1, 200, digest},
		{"protocol", hub.URL, "hub-a", file, "unsupported federation protocol", 2, 200, digest},
		{"digest", hub.URL, "hub-a", file, "invalid federation policy digest", 1, 200, "wrong"},
		{"refused", hub.URL, "hub-a", file, "hub refused this credential (revoked, unknown, or wrong archive)", 1, 401, digest},
		{"revoked", realHTTP.URL, "hub-a", revokedFile, "hub refused this credential (revoked, unknown, or wrong archive)", 1, 200, digest},
	}
	if runtime.GOOS != "windows" {
		permissive := filepath.Join(testutil.PrivateTempDir(t), "permissive")
		require.NoError(t, os.WriteFile(permissive, []byte(credential), 0600))
		require.NoError(t, os.Chmod(permissive, 0644))
		cases = append(cases, struct {
			name, origin, hubID, path, message string
			version, status                    int
			digest                             string
		}{"mode", hub.URL, "hub-a", permissive, "credential file must be a regular file readable only by its owner (mode 0600)", 1, 200, digest})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response.ProtocolVersions, response.PolicyDigest, code = []int{tc.version}, tc.digest, tc.status
			body, err := json.Marshal(map[string]string{"hub": tc.origin, "hub_archive": tc.hubID, "credential_file": tc.path})
			require.NoError(t, err)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, daemon.URL+"/api/v1/federation/link", bytes.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", daemon.URL)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			data, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Contains(t, string(data), tc.message)
			assert.NotContains(t, string(data), credential)
			assert.NotContains(t, string(data), revoked)
			assert.NotContains(t, string(data), tc.path)
		})
	}
}
