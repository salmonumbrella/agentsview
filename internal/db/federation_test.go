package db

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederationEnrollmentLifecycle(t *testing.T) {
	db := testDB(t)
	ctx := t.Context()
	enrollment := FederationEnrollment{UID: "enr-a", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest-a"}
	require.NoError(t, db.CreateFederationEnrollment(ctx, enrollment))
	rows, err := db.ListFederationEnrollments(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "member-a", rows[0].Member)
	_, err = db.AuthenticateFederationCredential(ctx, "unknown", "spoke-a")
	assert.True(t, errors.Is(err, ErrFederationUnauthorized))
	_, err = db.AuthenticateFederationCredential(ctx, "digest-a", "spoke-b")
	assert.True(t, errors.Is(err, ErrFederationUnauthorized))
	got, err := db.AuthenticateFederationCredential(ctx, "digest-a", "spoke-a")
	require.NoError(t, err)
	assert.Equal(t, "enr-a", got.UID)
	rows, err = db.ListFederationEnrollments(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, rows[0].LastHandshakeAt)
	require.Error(t, db.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-b", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest-b"}))
	require.NoError(t, db.RevokeFederationEnrollment(ctx, "enr-a"))
	require.NoError(t, db.RevokeFederationEnrollment(ctx, "enr-a"))
	require.Error(t, db.RevokeFederationEnrollment(ctx, "missing"))
	_, err = db.AuthenticateFederationCredential(ctx, "digest-a", "spoke-a")
	assert.True(t, errors.Is(err, ErrFederationUnauthorized))
}

func TestFederationCopyPreservesEnrollmentAndLink(t *testing.T) {
	source := testDB(t)
	target := testDB(t)
	ctx := t.Context()
	require.NoError(t, source.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-a", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest"}))
	require.NoError(t, source.PutFederationLink(ctx, FederationLink{UID: "link-a", HubOrigin: "https://hub.example/av", HubArchiveID: "hub-a", EnrollmentUID: "enr-a", Member: "member-a", TokenFile: "/fixture/credential", ProtocolVersion: 1, PolicyJSON: "{}", PolicyDigest: "digest", State: "active"}))
	require.NoError(t, target.CopyFederationStateFrom(ctx, source.Path()))
	rows, err := target.ListFederationEnrollments(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "enr-a", rows[0].UID)
	link, err := target.GetFederationLink(ctx)
	require.NoError(t, err)
	assert.Equal(t, "https://hub.example/av", link.HubOrigin)
}

func TestFederationCopySkipsLegacyArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	_, err = legacy.ExecContext(t.Context(), `CREATE TABLE legacy_marker (value TEXT)`)
	require.NoError(t, err)
	require.NoError(t, legacy.Close())
	target := testDB(t)
	require.NoError(t, target.CopyFederationStateFrom(t.Context(), path))
	rows, err := target.ListFederationEnrollments(t.Context())
	require.NoError(t, err)
	assert.Empty(t, rows)
}
