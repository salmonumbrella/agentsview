package db

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

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
	assert.Equal(t, "enrolled", rows[0].State)
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
	assert.Equal(t, "contacted", rows[0].State)
	require.Error(t, db.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-b", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest-b"}))
	require.NoError(t, db.RevokeFederationEnrollment(ctx, "enr-a"))
	require.NoError(t, db.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-b", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest-b"}))
	rows, err = db.ListFederationEnrollments(ctx)
	require.NoError(t, err)
	assert.Equal(t, "revoked", rows[0].State)
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
	require.NoError(t, source.PutFederationLink(ctx, FederationLink{UID: "link-a", HubOrigin: "https://hub.example/av", HubArchiveID: "hub-a", EnrollmentUID: "enr-a", Member: "member-a", TokenFile: "/fixture/credential", ProtocolVersion: 1, State: "active"}))
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

func TestFederationUnknownCredentialDoesNotWaitForWriter(t *testing.T) {
	database := testDB(t)
	database.mu.Lock()
	defer database.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for _, tc := range []struct{ digest, archive string }{{"unknown", "spoke-a"}, {"bad", "wrong"}, {"", ""}} {
		_, err := database.AuthenticateFederationCredential(ctx, tc.digest, tc.archive)
		assert.ErrorIs(t, err, ErrFederationUnauthorized)
	}
}

func TestFederationCopyUsesNamedColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reordered.db")
	source, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	_, err = source.ExecContext(t.Context(), `CREATE TABLE federation_enrollments (member TEXT, revoked_at TEXT, enrollment_uid TEXT, credential_sha256 TEXT, created_at TEXT, spoke_name TEXT, last_handshake_at TEXT, spoke_archive_id TEXT)`)
	require.NoError(t, err)
	_, err = source.ExecContext(t.Context(), `INSERT INTO federation_enrollments VALUES ('member-a','','enr-a','digest','created','name','','spoke-a')`)
	require.NoError(t, err)
	require.NoError(t, source.Close())
	target := testDB(t)
	require.NoError(t, target.CopyFederationStateFrom(t.Context(), path))
	rows, err := target.ListFederationEnrollments(t.Context())
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "enr-a", rows[0].UID)
	assert.Equal(t, "spoke-a", rows[0].SpokeArchiveID)
	assert.Equal(t, "member-a", rows[0].Member)
}

func TestFederationRevokedAfterLookupBeforeStamp(t *testing.T) {
	database := testDB(t)
	ctx := t.Context()
	require.NoError(t, database.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-a", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest-a"}))
	reader, writer := database.rawReader(), database.rawWriter()
	// A returned reader connection is closed, making the completed lookup observable.
	reader.SetMaxIdleConns(0)
	writer.SetMaxOpenConns(1)
	conn, err := writer.Conn(ctx)
	require.NoError(t, err)
	defer conn.Close()
	readClosed, writeWaits := reader.Stats().MaxIdleClosed, writer.Stats().WaitCount
	result := make(chan error, 1)
	go func() { _, err := database.AuthenticateFederationCredential(ctx, "digest-a", "spoke-a"); result <- err }()
	require.Eventually(t, func() bool {
		return reader.Stats().MaxIdleClosed > readClosed && writer.Stats().WaitCount > writeWaits
	}, 10*time.Second, time.Second, "lookup must finish before the stamp waits for the writer")
	_, err = conn.ExecContext(ctx, `UPDATE federation_enrollments SET revoked_at = 'revoked' WHERE enrollment_uid = 'enr-a'`)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	select {
	case err := <-result:
		assert.ErrorIs(t, err, ErrFederationUnauthorized)
	case <-time.After(10 * time.Second):
		t.Fatal("authentication did not finish")
	}
	rows, err := database.ListFederationEnrollments(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Empty(t, rows[0].LastHandshakeAt)
	assert.Equal(t, "revoked", rows[0].State)
}

func TestFederationUserVersion(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "archive.db")
	database, err := OpenIsolated(ctx, path)
	require.NoError(t, err)
	raw := func() int {
		var version int
		require.NoError(t, database.Reader().QueryRow(ctx, `PRAGMA user_version`).Scan(&version))
		return version
	}
	assert.Equal(t, CurrentDataVersion(), raw())
	require.NoError(t, database.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO stats (key, value) VALUES ('fixture', '1')`)
		return err
	}))
	assert.Equal(t, CurrentDataVersion(), raw())
	link := FederationLink{UID: "link-a", HubOrigin: "https://hub.example", HubArchiveID: "hub-a", EnrollmentUID: "enr-a", Member: "member-a", TokenFile: "/fixture/credential", ProtocolVersion: 1, State: "active"}
	require.NoError(t, database.PutFederationLink(ctx, link))
	assert.Equal(t, federationVersionBase+CurrentDataVersion(), raw())
	require.NoError(t, database.DeleteFederationLink(ctx))
	assert.Equal(t, CurrentDataVersion(), raw())
	require.NoError(t, database.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-a", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest-a"}))
	version := raw()
	assert.Equal(t, federationVersionBase+CurrentDataVersion(), version)
	assert.Greater(t, version, CurrentDataVersion())
	decoded, archiveOnly := DecodeUserVersion(version)
	assert.Equal(t, CurrentDataVersion(), decoded)
	assert.False(t, archiveOnly)
	require.NoError(t, database.RevokeFederationEnrollment(ctx, "enr-a"))
	assert.Equal(t, version, raw())
	require.NoError(t, database.PutFederationLink(ctx, link))
	require.NoError(t, database.DeleteFederationLink(ctx))
	assert.Equal(t, version, raw())
	require.NoError(t, database.Close())
	require.NoError(t, CheckDataVersion(ctx, path))
	database, err = OpenIsolated(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	assert.Equal(t, version, raw())
	require.NoError(t, database.EnableArchiveOnly(ctx))
	assert.Equal(t, archiveOnlyVersionBase+federationVersionBase+CurrentDataVersion(), raw())
}

func TestDecodeFederationUserVersion(t *testing.T) {
	for _, tc := range []struct {
		version     int
		archiveOnly bool
	}{
		{179, false}, {archiveOnlyVersionBase + 179, true},
		{federationVersionBase + 179, false}, {archiveOnlyVersionBase + federationVersionBase + 179, true},
	} {
		version, archiveOnly := DecodeUserVersion(tc.version)
		assert.Equal(t, 179, version)
		assert.Equal(t, tc.archiveOnly, archiveOnly)
	}
}

func TestArchiveOnlyGainsFederationVersion(t *testing.T) {
	database := testDB(t)
	ctx := t.Context()
	require.NoError(t, database.EnableArchiveOnly(ctx))
	require.NoError(t, database.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-a", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest-a"}))
	var raw int
	require.NoError(t, database.Reader().QueryRow(ctx, `PRAGMA user_version`).Scan(&raw))
	assert.Equal(t, archiveOnlyVersionBase+federationVersionBase+CurrentDataVersion(), raw)
}
