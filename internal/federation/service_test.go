package federation

import (
	"database/sql"
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

func TestShareConsentAndPolicyChange(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	policy := config.FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 5, SuggestedProjects: []string{"github.com/example/*", "git.example/*"}, Processing: "none"}
	digest, err := export.DigestCanonical(policy)
	require.NoError(t, err)
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/federation/handshake", r.URL.Path)
		_ = json.NewEncoder(w).Encode(HandshakeResponse{HubArchiveID: "hub-a", ProtocolVersions: []int{1}, EnrollmentUID: "enr-a", Member: "member-a", EnrollmentState: "enrolled", Policy: policy, PolicyDigest: digest})
	}))
	t.Cleanup(hub.Close)
	file := filepath.Join(testutil.PrivateTempDir(t), "credential")
	require.NoError(t, os.WriteFile(file, []byte("avfc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0600))
	svc := NewService("spoke", "spoke-a", policy, archive)
	require.NoError(t, svc.Join(t.Context(), hub.URL, "hub-a", file))

	require.NoError(t, archive.Update(t.Context(), func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO pg_sync_state (key,value) VALUES ('artifact_local_installation_id','install-a')`,
			`INSERT INTO sessions (id,project,machine,agent,file_path,cwd,git_branch,first_message,display_name,started_at) VALUES ('session-a','fixture','install-a','claude','fixture','CANARY-cwd','CANARY-branch','CANARY-first','CANARY-title','2026-01-02T00:00:00Z')`,
			`INSERT INTO local_session_source_baselines (session_id,machine,agent,file_path) VALUES ('session-a','install-a','claude','fixture')`,
			`INSERT INTO session_project_identity_snapshots (session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES ('session-a','fixture','install-a','2026-01-01T00:00:00Z','resolved',1,'github.com/example/api','git_remote','key')`,
			`INSERT INTO messages (id,session_id,ordinal,role,content) VALUES (100,'session-a',0,'assistant','CANARY-message')`,
			`INSERT INTO tool_calls (message_id,session_id,tool_name,category,input_json,result_content) VALUES (100,'session-a','fixture','CANARY-category','CANARY-input','CANARY-result')`,
		} {
			if _, err := tx.ExecContext(t.Context(), q); err != nil {
				return err
			}
		}
		for _, id := range []string{"unshared", "ambiguous", "repo-less", "imported", "child", "before", "remote-only"} {
			machine := "install-a"
			started := "2026-01-02T00:00:00Z"
			if id == "remote-only" {
				machine = "install-b"
			}
			if id == "before" {
				started = "2026-01-01T23:59:59Z"
			}
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO sessions (id,project,machine,agent,file_path,cwd,git_branch,first_message,display_name,started_at,parent_session_id) VALUES (?,'fixture',?,'claude',?,'CANARY-cwd','CANARY-branch','CANARY-first','CANARY-title',?,'session-a')`, id, machine, id, started); err != nil {
				return err
			}
			if id != "imported" {
				if _, err := tx.ExecContext(t.Context(), `INSERT INTO local_session_source_baselines (session_id,machine,agent,file_path) VALUES (?,?,'claude',?)`, id, machine, id); err != nil {
					return err
				}
			}
			remote := "github.com/example/api"
			if id == "remote-only" {
				remote = "github.com/example/remote-only"
			}
			if id == "unshared" || id == "child" {
				remote = "github.com/example/private"
			}
			count := 1
			if id == "ambiguous" {
				count = 2
			}
			keySource := "git_remote"
			if id == "repo-less" {
				keySource = "root_path"
			}
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO session_project_identity_snapshots (session_id,project,machine,observed_at,remote_resolution,remote_candidate_count,normalized_remote,key_source,key) VALUES (?,'fixture',?,'2026-01-01T00:00:00Z','resolved',?,?,?,'key')`, id, machine, count, remote, keySource); err != nil {
				return err
			}
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO messages (session_id,ordinal,role,content) VALUES (?,0,'assistant','CANARY-message')`, id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO tool_calls (message_id,session_id,tool_name,category,input_json,result_content) SELECT id,session_id,'fixture','CANARY-category','CANARY-input','CANARY-result' FROM messages WHERE session_id=? AND ordinal=0`, id); err != nil {
				return err
			}
		}
		return nil
	}))
	listed, err := svc.Shares(t.Context())
	require.NoError(t, err)
	assert.Empty(t, listed.Shares)
	assert.Contains(t, listed.Suggestions, "github.com/example/api")
	assert.NotContains(t, listed.Suggestions, "github.com/example/remote-only")
	grant := ShareGrant{Project: "github.com/example/api", Level: "summary", Attribution: "pooled", Since: "2026-01-02"}
	preview, err := svc.PreviewShare(t.Context(), grant)
	require.NoError(t, err)
	assert.Equal(t, policy, preview.Policy)
	previewJSON, err := json.Marshal(preview)
	require.NoError(t, err)
	var previewFields map[string]any
	require.NoError(t, json.Unmarshal(previewJSON, &previewFields))
	assert.Contains(t, previewFields, "records_array_bytes")
	assert.NotContains(t, previewFields, "bytes")
	empty, err := svc.PreviewShare(t.Context(), ShareGrant{Project: "github.com/example/empty", Level: "summary"})
	require.NoError(t, err)
	assert.Empty(t, empty.Records)
	assert.Equal(t, 2, empty.RecordsArrayBytes)
	assert.Contains(t, preview.Disclosure, "bearer token")
	assert.Contains(t, preview.DeliveryNotice, "nothing is sent")
	assert.Contains(t, preview.Omits, "content")
	link, err := archive.GetFederationLink(t.Context())
	require.NoError(t, err)
	shares, err := archive.ListFederationShares(t.Context(), link.UID)
	require.NoError(t, err)
	assert.Empty(t, shares)
	tampered := preview
	tampered.Policy.MinGroupSize++
	assert.ErrorContains(t, svc.AddShare(t.Context(), tampered), "preview again")
	tampered = preview
	tampered.Disclosure = ""
	assert.ErrorContains(t, svc.AddShare(t.Context(), tampered), "preview again")
	require.NoError(t, svc.AddShare(t.Context(), preview))
	records, err := svc.DryRun(t.Context())
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "session-a", records[0].SessionID)
	assert.Equal(t, 1, records[0].ToolCount)
	encoded, err := json.Marshal(records)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(encoded), "CANARY"))

	shares, err = archive.ListFederationShares(t.Context(), link.UID)
	require.NoError(t, err)
	require.Len(t, shares, 1)
	shown, err := json.Marshal(preview)
	require.NoError(t, err)
	assert.JSONEq(t, string(shown), shares[0].ConsentJSON)
	var storedPreview SharePreview
	require.NoError(t, json.Unmarshal([]byte(shares[0].ConsentJSON), &storedPreview))
	assert.Equal(t, policy, storedPreview.Policy)
	listed, err = svc.Shares(t.Context())
	require.NoError(t, err)
	listedJSON, err := json.Marshal(listed)
	require.NoError(t, err)
	assert.NotContains(t, string(listedJSON), "consent_json")
	details, err := svc.Share(t.Context(), shares[0].UID)
	require.NoError(t, err)
	assert.Equal(t, shares[0].ConsentJSON, details.Share.ConsentJSON)
	require.NoError(t, archive.PutFederationShare(t.Context(), db.FederationShare{UID: "share-paused", LinkUID: link.UID, NormalizedRemote: "github.com/example/private", Level: "summary", Attribution: "pooled", Audience: "operators", State: "paused", ConsentJSON: `{}`, PolicyDigest: digest}))
	_, err = svc.Status(t.Context())
	require.NoError(t, err)
	paused, err := archive.GetFederationShare(t.Context(), link.UID, "share-paused")
	require.NoError(t, err)
	assert.Equal(t, "paused", paused.State)
	active, err := archive.GetFederationShare(t.Context(), link.UID, shares[0].UID)
	require.NoError(t, err)
	assert.Equal(t, "active", active.State)
	policy.Processing = "aggregated"
	digest, err = export.DigestCanonical(policy)
	require.NoError(t, err)
	status, err := svc.Status(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 2, status.Shares)
	shares, err = archive.ListFederationShares(t.Context(), link.UID)
	require.NoError(t, err)
	require.Len(t, shares, 2)
	assert.Equal(t, "paused", shares[1].State)
	assert.Equal(t, "policy_paused", shares[0].State)
	next, err := svc.PreviewShare(t.Context(), grant)
	require.NoError(t, err)
	require.NoError(t, svc.AddShare(t.Context(), next))
	pausedGrant := ShareGrant{Project: "github.com/example/private", Level: "summary"}
	pausedPreview, err := svc.PreviewShare(t.Context(), pausedGrant)
	require.NoError(t, err)
	require.NoError(t, svc.AddShare(t.Context(), pausedPreview))
	records, err = svc.DryRun(t.Context())
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.NoError(t, svc.ResumeShare(t.Context(), "share-paused"))
	records, err = svc.DryRun(t.Context())
	require.NoError(t, err)
	require.Len(t, records, 3)
	assert.Equal(t, "child", records[1].SessionID)
	assert.Equal(t, "unshared", records[2].SessionID)
	require.NoError(t, svc.PauseShare(t.Context(), "share-paused"))
	policy.MinGroupSize = 6
	digest, err = export.DigestCanonical(policy)
	require.NoError(t, err)
	require.NoError(t, svc.ResumeShare(t.Context(), "share-paused"))
	records, err = svc.DryRun(t.Context())
	require.NoError(t, err)
	assert.Empty(t, records)
	paused, err = archive.GetFederationShare(t.Context(), link.UID, "share-paused")
	require.NoError(t, err)
	assert.Equal(t, "policy_paused", paused.State)
	policy.SuggestedProjects = []string{}
	digest, err = export.DigestCanonical(policy)
	require.NoError(t, err)
	wirePreview, err := svc.PreviewShare(t.Context(), grant)
	require.NoError(t, err)
	wire, err := json.Marshal(wirePreview)
	require.NoError(t, err)
	var decoded SharePreview
	require.NoError(t, json.Unmarshal(wire, &decoded))
	require.NotNil(t, decoded.Policy.SuggestedProjects)
	require.NoError(t, svc.AddShare(t.Context(), decoded))
	hub.Close()
	records, err = svc.DryRun(t.Context())
	assert.Error(t, err)
	assert.Empty(t, records)

}

func TestShareRejectsUnshareableGrant(t *testing.T) {
	policy := config.FederationHubConfig{AllowedLevels: []string{"summary"}}
	hub := &HubStatus{Policy: &policy}
	for _, tc := range []struct {
		grant   ShareGrant
		message string
	}{
		{ShareGrant{Project: "local-label", Level: "summary"}, "no repository identity another machine can match"},
		{ShareGrant{Project: "github.com/example/api", Level: "transcript"}, "not available yet"},
		{ShareGrant{Project: "github.com/example/api", Level: "unknown"}, "not allowed"},
	} {
		_, err := validateGrant(tc.grant, hub)
		assert.ErrorContains(t, err, tc.message)
	}
}

func TestShareLocalStateAndExclusionErrors(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	require.NoError(t, archive.PutFederationLink(t.Context(), db.FederationLink{UID: "link-a", HubOrigin: "http://127.0.0.1:1", HubArchiveID: "hub-a", EnrollmentUID: "enr-a", Member: "member-a", TokenFile: "missing", ProtocolVersion: 1, State: "active"}))
	require.NoError(t, archive.PutFederationShare(t.Context(), db.FederationShare{UID: "share-a", LinkUID: "link-a", NormalizedRemote: "github.com/example/api", Level: "summary", Attribution: "pooled", Audience: "operators", State: "paused", ConsentJSON: `{}`, PolicyDigest: "digest"}))
	svc := NewService("spoke", "spoke-a", config.FederationHubConfig{}, archive)
	require.NoError(t, svc.ResumeShare(t.Context(), "share-a"))
	assert.EqualError(t, svc.ResumeShare(t.Context(), "share-a"), "share is already active")
	require.NoError(t, svc.PauseShare(t.Context(), "share-a"))
	assert.EqualError(t, svc.PauseShare(t.Context(), "share-a"), "share is already paused")
	require.ErrorIs(t, svc.PauseShare(t.Context(), "missing"), sql.ErrNoRows)
	require.ErrorIs(t, svc.ResumeShare(t.Context(), "missing"), sql.ErrNoRows)
	_, err = svc.Share(t.Context(), "missing")
	require.ErrorIs(t, err, sql.ErrNoRows)
	require.ErrorIs(t, svc.RemoveShare(t.Context(), "missing"), sql.ErrNoRows)
	require.NoError(t, svc.ResumeShare(t.Context(), "share-a"))
	require.NoError(t, archive.PauseFederationSharesForPolicy(t.Context(), "link-a", "changed"))
	assert.EqualError(t, svc.ResumeShare(t.Context(), "share-a"), "policy changed; run federation share add to review and accept")
	assert.EqualError(t, svc.PauseShare(t.Context(), "share-a"), "policy changed; run federation share add to review and accept")
	for _, tc := range []struct{ id, message string }{{"", "session ID is required"}, {"missing", "session not found"}} {
		err := svc.Exclude(t.Context(), tc.id, "")
		var input *InputError
		require.ErrorAs(t, err, &input)
		assert.Equal(t, tc.message, input.Message)
	}
}

func TestShareOperationsWithoutLink(t *testing.T) {
	archive, err := db.OpenIsolated(t.Context(), filepath.Join(t.TempDir(), "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	svc := NewService("spoke", "spoke-a", config.FederationHubConfig{}, archive)
	operations := []func() error{
		func() error { _, err := svc.Shares(t.Context()); return err },
		func() error { _, err := svc.Share(t.Context(), "missing"); return err },
		func() error { return svc.PauseShare(t.Context(), "missing") },
		func() error { return svc.ResumeShare(t.Context(), "missing") },
		func() error { return svc.RemoveShare(t.Context(), "missing") },
	}
	for _, operation := range operations {
		err := operation()
		var input *InputError
		require.ErrorAs(t, err, &input)
		assert.EqualError(t, err, "join a hub first")
	}
	require.NoError(t, archive.Update(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO sessions (id,project,first_message) VALUES ('session-a','fixture','')`)
		return err
	}))
	require.NoError(t, svc.Exclude(t.Context(), "session-a", "private"))
}
