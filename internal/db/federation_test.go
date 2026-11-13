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
	require.ErrorIs(t, db.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-b", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest-b"}), ErrFederationEnrollmentExists)
	require.NoError(t, db.RevokeFederationEnrollment(ctx, "enr-a"))
	require.NoError(t, db.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-b", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest-b"}))
	rows, err = db.ListFederationEnrollments(ctx)
	require.NoError(t, err)
	assert.Equal(t, "revoked", rows[0].State)
	require.NoError(t, db.RevokeFederationEnrollment(ctx, "enr-a"))
	require.ErrorIs(t, db.RevokeFederationEnrollment(ctx, "missing"), sql.ErrNoRows)
	_, err = db.AuthenticateFederationCredential(ctx, "digest-a", "spoke-a")
	assert.True(t, errors.Is(err, ErrFederationUnauthorized))
}

func TestFederationCopyPreservesEnrollmentAndLink(t *testing.T) {
	source := testDB(t)
	target := testDB(t)
	ctx := t.Context()
	require.NoError(t, source.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-a", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest"}))
	require.NoError(t, source.RevokeFederationEnrollment(ctx, "enr-a"))
	sourceRows, err := source.ListFederationEnrollments(ctx)
	require.NoError(t, err)
	require.Len(t, sourceRows, 1)
	require.NotEmpty(t, sourceRows[0].RevokedAt)
	require.NoError(t, source.PutFederationLink(ctx, FederationLink{UID: "link-a", HubOrigin: "https://hub.example/av", HubArchiveID: "hub-a", EnrollmentUID: "enr-a", Member: "member-a", TokenFile: "/fixture/credential", ProtocolVersion: 1, State: "active"}))
	require.NoError(t, target.CopyFederationStateFrom(ctx, source.Path()))
	rows, err := target.ListFederationEnrollments(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "enr-a", rows[0].UID)
	assert.Equal(t, sourceRows[0].RevokedAt, rows[0].RevokedAt)
	link, err := target.GetFederationLink(ctx)
	require.NoError(t, err)
	assert.Equal(t, "https://hub.example/av", link.HubOrigin)
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
	other := testDB(t)
	require.NoError(t, other.EnableArchiveOnly(ctx))
	require.NoError(t, other.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-a", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest-a"}))
	var reverse int
	require.NoError(t, other.Reader().QueryRow(ctx, `PRAGMA user_version`).Scan(&reverse))
	assert.Equal(t, archiveOnlyVersionBase+federationVersionBase+CurrentDataVersion(), reverse)
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

func TestFederationShareStateSurvivesCopyAndLeave(t *testing.T) {
	ctx := t.Context()
	source, target := testDB(t), testDB(t)
	link := FederationLink{UID: "link-a", HubOrigin: "https://hub.example", HubArchiveID: "hub-a", EnrollmentUID: "enr-a", Member: "member-a", TokenFile: "/fixture/token", ProtocolVersion: 1, State: "active"}
	require.NoError(t, source.PutFederationLink(ctx, link))
	share := FederationShare{UID: "share-a", LinkUID: "link-a", NormalizedRemote: "github.com/example/api", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: `{"selected":1}`, PolicyDigest: "digest-a"}
	require.NoError(t, source.PutFederationShare(ctx, share))
	require.NoError(t, source.PutFederationExclusion(ctx, "session-a", "share-a", "private"))
	require.NoError(t, target.CopyFederationStateFrom(ctx, source.Path()))
	shares, err := target.ListFederationShares(ctx, "link-a")
	require.NoError(t, err)
	require.Len(t, shares, 1)
	assert.Equal(t, `{"selected":1}`, shares[0].ConsentJSON)
	require.NoError(t, target.PauseFederationSharesForPolicy(ctx, "link-a", "digest-b"))
	shares, err = target.ListFederationShares(ctx, "link-a")
	require.NoError(t, err)
	require.Len(t, shares, 1)
	assert.Equal(t, "policy_paused", shares[0].State)
	assert.Equal(t, `{"selected":1}`, shares[0].ConsentJSON)
	require.NoError(t, target.DeleteFederationLink(ctx))
	shares, err = target.ListFederationShares(ctx, "link-a")
	require.NoError(t, err)
	assert.Empty(t, shares)
	var reason string
	require.NoError(t, target.Reader().QueryRow(ctx, `SELECT reason FROM federation_exclusions WHERE session_id = 'session-a'`).Scan(&reason))
	assert.Equal(t, "private", reason)
	require.NoError(t, target.PutFederationLink(ctx, link))
	require.NoError(t, target.PutFederationShare(ctx, share))
	require.NoError(t, target.Reader().QueryRow(ctx, `SELECT reason FROM federation_exclusions WHERE session_id = 'session-a'`).Scan(&reason))
	assert.Equal(t, "private", reason)
	var version int
	require.NoError(t, target.Reader().QueryRow(ctx, `PRAGMA user_version`).Scan(&version))
	assert.Equal(t, federationVersionBase+CurrentDataVersion(), version)
}

func TestFederationShareDuplicateAndReconsent(t *testing.T) {
	database := testDB(t)
	ctx := t.Context()
	first := FederationShare{UID: "share-a", LinkUID: "link-a", NormalizedRemote: "github.com/example/api", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: `{"shown":1}`, PolicyDigest: "old"}
	require.NoError(t, database.PutFederationShare(ctx, first))
	var version int
	require.NoError(t, database.Reader().QueryRow(ctx, `PRAGMA user_version`).Scan(&version))
	assert.Equal(t, federationVersionBase+CurrentDataVersion(), version)
	next := first
	next.UID = "share-b"
	next.ConsentJSON = `{"shown":2}`
	next.PolicyDigest = "new"
	require.ErrorIs(t, database.PutFederationShare(ctx, next), ErrFederationShareExists)
	require.NoError(t, database.PauseFederationSharesForPolicy(ctx, "link-a", "new"))
	require.NoError(t, database.PutFederationShare(ctx, next))
	shares, err := database.ListFederationShares(ctx, "link-a")
	require.NoError(t, err)
	require.Len(t, shares, 1)
	assert.Equal(t, "share-a", shares[0].UID)
	assert.Equal(t, "active", shares[0].State)
	assert.Equal(t, `{"shown":2}`, shares[0].ConsentJSON)
	require.NoError(t, database.PutFederationExclusion(ctx, "session-a", "share-a", "private"))
	require.NoError(t, database.DeleteFederationShare(ctx, "link-a", "share-a"))
	require.NoError(t, database.PutFederationShare(ctx, next))
	var reason string
	require.NoError(t, database.Reader().QueryRow(ctx, `SELECT reason FROM federation_exclusions WHERE session_id='session-a'`).Scan(&reason))
	assert.Equal(t, "private", reason)

}

func TestFederationShareDeliveryLedgerStartsEmpty(t *testing.T) {
	database := testDB(t)
	count, err := database.FederationDeliveryCount(t.Context(), "share-a")
	require.NoError(t, err)
	assert.Zero(t, count)
}

func TestFederationTablesUpgradePreservesSessions(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "archive.db")
	archive, err := OpenIsolated(ctx, path)
	require.NoError(t, err)
	require.NoError(t, archive.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sessions (id,project,first_message) VALUES ('saved','fixture','preserve')`)
		return err
	}))
	require.NoError(t, archive.Close())
	old, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	_, err = old.ExecContext(ctx, `DROP TABLE federation_shares; DROP TABLE federation_exclusions; DROP TABLE federation_deliveries`)
	require.NoError(t, err)
	require.NoError(t, old.Close())
	archive, err = OpenIsolated(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	var message string
	require.NoError(t, archive.Reader().QueryRow(ctx, `SELECT first_message FROM sessions WHERE id='saved'`).Scan(&message))
	assert.Equal(t, "preserve", message)
	require.NoError(t, archive.PutFederationExclusion(ctx, "saved", "", "private"))
}
