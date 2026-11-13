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
	assert.Equal(t, federationVersionBase+CurrentDataVersion(), raw())
	require.NoError(t, database.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr-a", SpokeArchiveID: "spoke-a", Member: "member-a", CredentialSHA256: "digest-a"}))
	version := raw()
	assert.Equal(t, federationVersionBase+CurrentDataVersion(), version)
	assert.Greater(t, version, CurrentDataVersion())
	decoded, archiveOnly := DecodeUserVersion(version)
	assert.Equal(t, CurrentDataVersion(), decoded)
	assert.False(t, archiveOnly)
	require.NoError(t, database.RevokeFederationEnrollment(ctx, "enr-a"))
	assert.Equal(t, version, raw())
	link.UID = "link-b"
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
		{federationVersionBase + federationShareVersionBase + 179, false}, {archiveOnlyVersionBase + federationVersionBase + federationShareVersionBase + 179, true},
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
	require.NoError(t, source.RecordFederationAttempt(ctx, share.UID, []FederationDelivery{{RecordUID: "record", SessionID: "session-a", Hash: "confirmed"}}))
	require.NoError(t, source.RecordFederationDelivery(ctx, share.UID, []FederationDelivery{{RecordUID: "record", SessionID: "session-a", Hash: "confirmed", State: "sent"}}))
	require.NoError(t, source.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sessions (id,project,first_message) VALUES ('session-a','fixture','')`)
		return err
	}))
	require.NoError(t, source.PutFederationExclusion(ctx, "session-a", "private"))
	require.NoError(t, target.CopyFederationStateFrom(ctx, source.Path()))
	ledger, err := target.FederationLedger(ctx, share.UID)
	require.NoError(t, err)
	assert.Equal(t, "https://hub.example", ledger["record"].HubOrigin)
	assert.Equal(t, "hub-a", ledger["record"].HubArchiveID)
	assert.Equal(t, "github.com/example/api", ledger["record"].NormalizedRemote)
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
	require.Len(t, shares, 1)
	assert.Equal(t, "leave", shares[0].StopIntent)
	var afterLeave int
	require.NoError(t, target.Reader().QueryRow(ctx, `PRAGMA user_version`).Scan(&afterLeave))
	assert.Equal(t, federationVersionBase+federationShareVersionBase+federationDeliveryVersionBase+federationWithdrawalVersionBase+CurrentDataVersion(), afterLeave)
	ledger, err = target.FederationLedger(ctx, share.UID)
	require.NoError(t, err)
	assert.Equal(t, "confirmed", ledger["record"].Hash)
	assert.Equal(t, "https://hub.example", ledger["record"].HubOrigin)
	assert.Equal(t, "hub-a", ledger["record"].HubArchiveID)
	assert.Equal(t, "github.com/example/api", ledger["record"].NormalizedRemote)
	var reason string
	require.NoError(t, target.Reader().QueryRow(ctx, `SELECT reason FROM federation_exclusions WHERE session_id = 'session-a'`).Scan(&reason))
	assert.Equal(t, "private", reason)
}

func TestFederationShareDuplicateAndReconsent(t *testing.T) {
	database := testDB(t)
	ctx := t.Context()
	first := FederationShare{UID: "share-a", LinkUID: "link-a", NormalizedRemote: "github.com/example/api", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: `{"shown":1}`, PolicyDigest: "old"}
	require.NoError(t, database.PutFederationShare(ctx, first))
	var version int
	require.NoError(t, database.Reader().QueryRow(ctx, `PRAGMA user_version`).Scan(&version))
	assert.Equal(t, federationVersionBase+federationShareVersionBase+federationWithdrawalVersionBase+CurrentDataVersion(), version)
	next := first
	next.UID = "share-b"
	next.ConsentJSON = `{"shown":2}`
	next.PolicyDigest = "new"
	require.ErrorIs(t, database.PutFederationShare(ctx, next), ErrFederationShareExists)
	require.NoError(t, database.PauseFederationSharesForPolicy(ctx, "link-a", "new"))
	require.ErrorIs(t, database.PutFederationShare(ctx, next), ErrFederationShareExists)
	require.NoError(t, database.ReceiptFederationStop(ctx, "link-a", "share-a", "purged", 1, 0))
	require.NoError(t, database.PutFederationShare(ctx, next))
	shares, err := database.ListFederationShares(ctx, "link-a")
	require.NoError(t, err)
	require.Len(t, shares, 1)
	assert.Equal(t, "share-a", shares[0].UID)
	assert.Equal(t, "active", shares[0].State)
	assert.Equal(t, `{"shown":2}`, shares[0].ConsentJSON)
	require.NoError(t, database.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sessions (id,project,first_message) VALUES ('session-a','fixture','')`)
		return err
	}))
	require.NoError(t, database.PutFederationExclusion(ctx, "session-a", "private"))
	require.NoError(t, database.DeleteFederationShare(ctx, "link-a", "share-a"))
	require.ErrorIs(t, database.PutFederationShare(ctx, next), ErrFederationShareExists)
	require.NoError(t, database.ReceiptFederationStop(ctx, "link-a", "share-a", "purged", 2, 0))
	require.NoError(t, database.PutFederationShare(ctx, next))
	var reason string
	require.NoError(t, database.Reader().QueryRow(ctx, `SELECT reason FROM federation_exclusions WHERE session_id='session-a'`).Scan(&reason))
	assert.Equal(t, "private", reason)

	for _, receipt := range []string{"purged", "retained"} {
		t.Run("manual pause "+receipt, func(t *testing.T) {
			manual := FederationShare{UID: "manual-" + receipt, LinkUID: "link-a", NormalizedRemote: "github.com/example/" + receipt, Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: `{"shown":1}`, PolicyDigest: "old"}
			require.NoError(t, database.PutFederationShare(ctx, manual))
			require.NoError(t, database.StopFederationShare(ctx, "link-a", manual.UID, "pause"))
			updated := manual
			updated.PolicyDigest, updated.ConsentJSON = "new", `{"shown":2}`
			require.ErrorIs(t, database.PutFederationShare(ctx, updated), ErrFederationShareExists)
			pending, err := database.GetFederationShare(ctx, "link-a", manual.UID)
			require.NoError(t, err)
			assert.Equal(t, "old", pending.PolicyDigest)
			require.NoError(t, database.ReceiptFederationStop(ctx, "link-a", manual.UID, receipt, 1, 0))
			require.NoError(t, database.PutFederationShare(ctx, updated))
			paused, err := database.GetFederationShare(ctx, "link-a", manual.UID)
			require.NoError(t, err)
			assert.Equal(t, "paused", paused.State)
			assert.Equal(t, "pause", paused.StopIntent)
			assert.Equal(t, receipt, paused.StopReceipt)
			assert.Equal(t, "new", paused.PolicyDigest)
			require.NoError(t, database.ResumeFederationShare(ctx, "link-a", manual.UID))
		})
	}

	manual := FederationShare{UID: "share-m", LinkUID: "link-a", NormalizedRemote: "github.com/example/web", Level: "summary", Attribution: "pooled", Audience: "operators", State: "paused", ConsentJSON: `{}`, PolicyDigest: "old"}
	require.NoError(t, database.PutFederationShare(ctx, manual))
	for _, tc := range []struct {
		name, digest string
		conflict     bool
	}{{"same digest", "old", true}, {"new digest", "new", false}} {
		t.Run(tc.name, func(t *testing.T) {
			incoming := manual
			incoming.State, incoming.ConsentJSON, incoming.PolicyDigest = "active", `{"shown":2}`, tc.digest
			err := database.PutFederationShare(ctx, incoming)
			if tc.conflict {
				require.ErrorIs(t, err, ErrFederationShareExists)
				return
			}
			require.NoError(t, err)
			got, err := database.GetFederationShare(ctx, "link-a", "share-m")
			require.NoError(t, err)
			assert.Equal(t, "paused", got.State)
			assert.Equal(t, "new", got.PolicyDigest)
			assert.Equal(t, `{"shown":2}`, got.ConsentJSON)
		})
	}
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
	_, err = old.ExecContext(ctx, `DROP TABLE federation_shares; DROP TABLE federation_exclusions`)
	require.NoError(t, err)
	require.NoError(t, old.Close())
	archive, err = OpenIsolated(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, archive.Close()) })
	var message string
	require.NoError(t, archive.Reader().QueryRow(ctx, `SELECT first_message FROM sessions WHERE id='saved'`).Scan(&message))
	assert.Equal(t, "preserve", message)
	require.NoError(t, archive.PutFederationExclusion(ctx, "saved", "private"))
}

func TestFederationExclusionRequiresExistingSession(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.ErrorIs(t, d.PutFederationExclusion(ctx, "missing", "private"), ErrFederationSessionNotFound)
	var count int
	require.NoError(t, d.Reader().QueryRow(ctx, `SELECT count(*) FROM federation_exclusions`).Scan(&count))
	assert.Zero(t, count)
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sessions (id,project,first_message,machine,deleted_at) VALUES ('other','fixture','','other','2026-01-01')`)
		return err
	}))
	require.NoError(t, d.PutFederationExclusion(ctx, "other", "first"))
	require.NoError(t, d.PutFederationExclusion(ctx, "other", "second"))
	var reason string
	require.NoError(t, d.Reader().QueryRow(ctx, `SELECT reason FROM federation_exclusions WHERE session_id='other'`).Scan(&reason))
	assert.Equal(t, "first", reason)
}

func TestFederationDeliveryStateSurvivesCopyAndMarksVersion(t *testing.T) {
	source, target := testDB(t), testDB(t)
	ctx := t.Context()
	require.NoError(t, source.Update(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO federation_deliveries (share_uid,record_uid,session_id,hash,state) VALUES ('share','record','session','hash','sent')`,
			`INSERT INTO federation_quarantine VALUES ('share','invalid batch',7)`,
			`INSERT INTO federation_hub_shares VALUES ('share','enrollment','example.org/repo','key','summary','pooled','operators','digest',1,6,'batch','{"denied":"session ID unavailable"}','active')`,
			`INSERT INTO federation_records (share_uid,record_uid,session_id,hash) VALUES ('share','record','session','hash')`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return stampFederationVersion(ctx, tx)
	}))
	var version int
	require.NoError(t, source.rawReader().QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version))
	assert.NotZero(t, version&(1<<23))
	require.NoError(t, target.CopyFederationStateFrom(ctx, source.Path()))
	for _, table := range []string{"federation_deliveries", "federation_quarantine", "federation_hub_shares", "federation_records"} {
		var count int
		require.NoError(t, target.rawReader().QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count))
		assert.Equal(t, 1, count, table)
	}
	var record, session, hash, state string
	require.NoError(t, target.rawReader().QueryRowContext(ctx, `SELECT record_uid,session_id,hash,state FROM federation_deliveries WHERE share_uid='share'`).Scan(&record, &session, &hash, &state))
	assert.Equal(t, []string{"record", "session", "hash", "sent"}, []string{record, session, hash, state})
	var sequence int64
	var digest, refused string
	require.NoError(t, target.rawReader().QueryRowContext(ctx, `SELECT sequence,last_batch_digest,last_refused FROM federation_hub_shares WHERE share_uid='share'`).Scan(&sequence, &digest, &refused))
	assert.Equal(t, int64(6), sequence)
	assert.Equal(t, "batch", digest)
	assert.Equal(t, `{"denied":"session ID unavailable"}`, refused)
	require.NoError(t, target.rawReader().QueryRowContext(ctx, `SELECT record_uid,session_id,hash FROM federation_records WHERE share_uid='share'`).Scan(&record, &session, &hash))
	assert.Equal(t, []string{"record", "session", "hash"}, []string{record, session, hash})
	var failure string
	require.NoError(t, target.rawReader().QueryRowContext(ctx, `SELECT error,sequence FROM federation_quarantine WHERE share_uid='share'`).Scan(&failure, &sequence))
	assert.Equal(t, "invalid batch", failure)
	assert.Equal(t, int64(7), sequence)
}

func TestFederationAttemptPreservesAcknowledgmentAndQuarantine(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.PutFederationLink(ctx, FederationLink{UID: "link", HubOrigin: "https://hub.example", HubArchiveID: "hub", EnrollmentUID: "enrollment", Member: "member", TokenFile: "/fixture/token", ProtocolVersion: 1, State: "active"}))
	require.NoError(t, d.PutFederationShare(ctx, FederationShare{UID: "share", LinkUID: "link", NormalizedRemote: "github.com/example/api", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: `{}`, PolicyDigest: "digest"}))
	require.NoError(t, d.RecordFederationDelivery(ctx, "share", []FederationDelivery{{RecordUID: "old", SessionID: "old", Hash: "confirmed", State: "sent"}}))
	require.NoError(t, d.PutFederationQuarantine(ctx, FederationQuarantine{ShareUID: "share", Error: FederationCollision, Sequence: 3}))
	require.NoError(t, d.RecordFederationAttempt(ctx, "share", []FederationDelivery{{RecordUID: "old", SessionID: "old", Hash: "changed"}, {RecordUID: "new", SessionID: "new", Hash: "first"}}))
	ledger, err := d.FederationLedger(ctx, "share")
	require.NoError(t, err)
	assert.Equal(t, "sent", ledger["old"].State)
	assert.Equal(t, "confirmed", ledger["old"].Hash)
	assert.Equal(t, "changed", ledger["old"].AttemptHash)
	assert.Equal(t, "https://hub.example", ledger["old"].HubOrigin)
	assert.Equal(t, "hub", ledger["old"].HubArchiveID)
	assert.Equal(t, "github.com/example/api", ledger["old"].NormalizedRemote)
	assert.Equal(t, "unconfirmed", ledger["new"].State)
	assert.Empty(t, ledger["new"].Hash)
	assert.Equal(t, "first", ledger["new"].AttemptHash)
	require.NoError(t, d.RecordFederationDelivery(ctx, "share", []FederationDelivery{{RecordUID: "old", SessionID: "old", Hash: "changed", State: "sent"}}))
	ledger, err = d.FederationLedger(ctx, "share")
	require.NoError(t, err)
	assert.Equal(t, "changed", ledger["old"].Hash)
	assert.Empty(t, ledger["old"].AttemptHash)
	q, err := d.FederationQuarantines(ctx)
	require.NoError(t, err)
	require.Len(t, q, 1)
	assert.Equal(t, int64(3), q[0].Sequence)
	require.NoError(t, d.PutFederationQuarantine(ctx, FederationQuarantine{ShareUID: "share", Error: FederationCollision, Sequence: 4}))
	q, err = d.FederationQuarantines(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), q[0].Sequence)
}

func TestFederationShareReplacementAndRemovalKeepLedger(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	s := FederationShare{UID: "share", LinkUID: "link", NormalizedRemote: "example.org/repo", State: "active", Since: "2026-01-01", ConsentJSON: `{"delivery_notice":"old"}`}
	require.NoError(t, d.PutFederationShare(ctx, s))
	require.NoError(t, d.RecordFederationDelivery(ctx, s.UID, []FederationDelivery{{RecordUID: "record", SessionID: "session", Hash: "hash", State: "sent"}}))
	s.UID, s.Since = "replacement", "2026-02-01"
	require.NoError(t, d.PutFederationShare(ctx, s))
	got, err := d.GetFederationShare(ctx, "link", "share")
	require.NoError(t, err)
	assert.Equal(t, s.Since, got.Since)
	require.ErrorIs(t, d.PutFederationShare(ctx, s), ErrFederationShareExists)
	require.NoError(t, d.PutFederationQuarantine(ctx, FederationQuarantine{ShareUID: "share", Error: FederationCollision, Sequence: 1}))
	require.NoError(t, d.DeleteFederationShare(ctx, "link", "share"))
	q, err := d.FederationQuarantines(ctx)
	require.NoError(t, err)
	require.Len(t, q, 1)
	assert.Equal(t, FederationCollision, q[0].Error)
	ledger, err := d.FederationLedger(ctx, "share")
	require.NoError(t, err)
	assert.Equal(t, "hash", ledger["record"].Hash)
}

func TestFederationAttemptColumnUpgradesAndCopiesOldLedger(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	_, err = old.ExecContext(ctx, `CREATE TABLE federation_deliveries (share_uid TEXT NOT NULL, record_uid TEXT NOT NULL, session_id TEXT NOT NULL, hash TEXT NOT NULL, state TEXT NOT NULL, PRIMARY KEY(share_uid,record_uid)); INSERT INTO federation_deliveries VALUES('share','record','session','confirmed','sent')`)
	require.NoError(t, err)
	require.NoError(t, old.Close())
	target := testDB(t)
	require.NoError(t, target.CopyFederationStateFrom(ctx, path))
	copied, err := target.FederationLedger(ctx, "share")
	require.NoError(t, err)
	assert.Equal(t, "confirmed", copied["record"].Hash)
	assert.Empty(t, copied["record"].AttemptHash)
	assert.Empty(t, copied["record"].HubOrigin)
	assert.Empty(t, copied["record"].HubArchiveID)
	assert.Empty(t, copied["record"].NormalizedRemote)
	upgraded, err := OpenIsolated(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, upgraded.Close()) })
	ledger, err := upgraded.FederationLedger(ctx, "share")
	require.NoError(t, err)
	assert.Equal(t, "sent", ledger["record"].State)
	assert.Empty(t, ledger["record"].AttemptHash)
	assert.Empty(t, ledger["record"].HubOrigin)
}

func TestFederationDeliveryContextUpgradeUsesOriginalJoins(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "old.db")
	source, err := OpenIsolated(ctx, path)
	require.NoError(t, err)
	require.NoError(t, source.PutFederationLink(ctx, FederationLink{UID: "old-link", HubOrigin: "https://hub.example", HubArchiveID: "old-hub", EnrollmentUID: "enr", Member: "member", TokenFile: "/fixture/token", ProtocolVersion: 1, State: "active"}))
	require.NoError(t, source.PutFederationShare(ctx, FederationShare{UID: "old-share", LinkUID: "old-link", NormalizedRemote: "github.com/example/api", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: `{}`, PolicyDigest: "digest"}))
	require.NoError(t, source.RecordFederationAttempt(ctx, "old-share", []FederationDelivery{{RecordUID: "record", SessionID: "session", Hash: "attempt"}}))
	require.NoError(t, source.Close())
	old, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	_, err = old.ExecContext(ctx, `ALTER TABLE federation_deliveries DROP COLUMN hub_origin; ALTER TABLE federation_deliveries DROP COLUMN hub_archive_id; ALTER TABLE federation_deliveries DROP COLUMN normalized_remote`)
	require.NoError(t, err)
	require.NoError(t, old.Close())
	target := testDB(t)
	require.NoError(t, target.CopyFederationStateFrom(ctx, path))
	ledger, err := target.FederationLedger(ctx, "old-share")
	require.NoError(t, err)
	assert.Equal(t, "https://hub.example", ledger["record"].HubOrigin)
	assert.Equal(t, "old-hub", ledger["record"].HubArchiveID)
	assert.Equal(t, "github.com/example/api", ledger["record"].NormalizedRemote)
	assert.Equal(t, "attempt", ledger["record"].AttemptHash)
	upgraded, err := OpenIsolated(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, upgraded.Close()) })
	ledger, err = upgraded.FederationLedger(ctx, "old-share")
	require.NoError(t, err)
	assert.Equal(t, "https://hub.example", ledger["record"].HubOrigin)
	assert.Equal(t, "old-hub", ledger["record"].HubArchiveID)
	assert.Equal(t, "github.com/example/api", ledger["record"].NormalizedRemote)
}

func TestLegacyPausedSharesAcquirePendingStopOnOpenAndCopy(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "legacy.db")
	old, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	_, err = old.ExecContext(ctx, `CREATE TABLE federation_shares (
		share_uid TEXT PRIMARY KEY, link_uid TEXT NOT NULL, normalized_remote TEXT NOT NULL,
		level TEXT NOT NULL, attribution TEXT NOT NULL, since TEXT NOT NULL DEFAULT '',
		audience TEXT NOT NULL, state TEXT NOT NULL, consent_json TEXT NOT NULL,
		policy_digest TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT '2026-01-01');
		INSERT INTO federation_shares(share_uid,link_uid,normalized_remote,level,attribution,audience,state,consent_json,policy_digest) VALUES
		('manual','link','example.org/manual','summary','pooled','operators','paused','{}','digest'),
		('policy','link','example.org/policy','summary','pooled','operators','policy_paused','{}','digest');
		CREATE TABLE federation_exclusions(session_id TEXT PRIMARY KEY,reason TEXT NOT NULL,created_at TEXT NOT NULL);
		INSERT INTO federation_exclusions VALUES('excluded','private','2026-01-01');
		CREATE TABLE federation_deliveries(share_uid TEXT NOT NULL,record_uid TEXT NOT NULL,session_id TEXT NOT NULL,hash TEXT NOT NULL,state TEXT NOT NULL,attempt_hash TEXT NOT NULL DEFAULT '',PRIMARY KEY(share_uid,record_uid));
		INSERT INTO federation_deliveries VALUES('manual','record','record','confirmed','sent','attempt')`)
	require.NoError(t, err)
	require.NoError(t, old.Close())
	copy := testDB(t)
	require.NoError(t, copy.CopyFederationStateFrom(ctx, path))
	upgraded, err := OpenIsolated(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, upgraded.Close()) })
	for _, archive := range []*DB{copy, upgraded} {
		manual, err := archive.GetFederationShare(ctx, "link", "manual")
		require.NoError(t, err)
		assert.Equal(t, "paused", manual.State)
		assert.Equal(t, "pause", manual.StopIntent)
		assert.Equal(t, "pending", manual.StopReceipt)
		policy, err := archive.GetFederationShare(ctx, "link", "policy")
		require.NoError(t, err)
		assert.Equal(t, "policy_paused", policy.State)
		assert.Equal(t, "policy", policy.StopIntent)
		assert.Equal(t, "pending", policy.StopReceipt)
		ledger, err := archive.FederationLedger(ctx, "manual")
		require.NoError(t, err)
		assert.Equal(t, "confirmed", ledger["record"].Hash)
		assert.Equal(t, "attempt", ledger["record"].AttemptHash)
		var exclusion int
		require.NoError(t, archive.Reader().QueryRow(ctx, `SELECT count(*) FROM federation_exclusions WHERE session_id='excluded'`).Scan(&exclusion))
		assert.Equal(t, 1, exclusion)
	}
}

func TestFederationWithdrawalStateSurvivesCopy(t *testing.T) {
	source, target := testDB(t), testDB(t)
	ctx := t.Context()
	require.NoError(t, source.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO federation_shares
			(share_uid,link_uid,normalized_remote,level,attribution,audience,state,consent_json,policy_digest,epoch,sequence,source_generation,stop_intent,stop_receipt,pending_batch)
			VALUES('share','link','example.org/repo','summary','pooled','operators','paused','{}','policy',3,7,'generation','remove','pending','envelope')`)
		if err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
	}))
	require.NoError(t, target.CopyFederationStateFrom(ctx, source.Path()))
	var epoch, sequence, version int
	var generation, intent, receipt, pending string
	require.NoError(t, target.Reader().QueryRow(ctx, `SELECT epoch,sequence,source_generation,stop_intent,stop_receipt,pending_batch FROM federation_shares WHERE share_uid='share'`).Scan(&epoch, &sequence, &generation, &intent, &receipt, &pending))
	require.NoError(t, target.Reader().QueryRow(ctx, `PRAGMA user_version`).Scan(&version))
	assert.Equal(t, 3, epoch)
	assert.Equal(t, 7, sequence)
	assert.Equal(t, "generation", generation)
	assert.Equal(t, "remove", intent)
	assert.Equal(t, "pending", receipt)
	assert.Equal(t, "envelope", pending)
	assert.NotZero(t, version&federationWithdrawalVersionBase)
	decoded, _ := DecodeUserVersion(version)
	assert.Equal(t, CurrentDataVersion(), decoded)
}

func TestRemoveFederationShareRetainsStopIntentAndAccounting(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.PutFederationShare(ctx, FederationShare{UID: "share", LinkUID: "link", NormalizedRemote: "example.org/repo", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: "{}", PolicyDigest: "policy"}))
	require.NoError(t, d.RecordFederationDelivery(ctx, "share", []FederationDelivery{{RecordUID: "record", SessionID: "record", Hash: "confirmed", State: "sent"}}))
	require.NoError(t, d.DeleteFederationShare(ctx, "link", "share"))
	share, err := d.GetFederationShare(ctx, "link", "share")
	require.NoError(t, err)
	assert.Equal(t, "remove", share.StopIntent)
	assert.Equal(t, "pending", share.StopReceipt)
	ledger, err := d.FederationLedger(ctx, "share")
	require.NoError(t, err)
	assert.Equal(t, "confirmed", ledger["record"].Hash)
	assert.Equal(t, "sent", ledger["record"].State)
}

func TestFederationPendingBatchAndAcknowledgmentAreDurable(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.PutFederationLink(ctx, FederationLink{UID: "link", HubOrigin: "https://example.org", HubArchiveID: "hub", EnrollmentUID: "enr", Member: "member", TokenFile: "/fixture/token", ProtocolVersion: 2, State: "active"}))
	require.NoError(t, d.PutFederationShare(ctx, FederationShare{UID: "share", LinkUID: "link", NormalizedRemote: "example.org/repo", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: "{}", PolicyDigest: "policy"}))
	require.NoError(t, d.SaveFederationPending(ctx, "share", 1, `{"sequence":1}`, []FederationDelivery{{RecordUID: "item", SessionID: "item", Hash: "attempt"}}))
	share, err := d.GetFederationShare(ctx, "link", "share")
	require.NoError(t, err)
	assert.Equal(t, `{"sequence":1}`, share.PendingBatch)
	ledger, err := d.FederationLedger(ctx, "share")
	require.NoError(t, err)
	assert.Equal(t, "attempt", ledger["item"].AttemptHash)
	require.NoError(t, d.CommitFederationAcknowledgment(ctx, "share", 1, []FederationDelivery{{RecordUID: "item", SessionID: "item", Hash: "attempt", State: "sent"}}))
	share, err = d.GetFederationShare(ctx, "link", "share")
	require.NoError(t, err)
	assert.Empty(t, share.PendingBatch)
	assert.EqualValues(t, 1, share.Sequence)
	ledger, err = d.FederationLedger(ctx, "share")
	require.NoError(t, err)
	assert.Equal(t, "sent", ledger["item"].State)
	assert.Empty(t, ledger["item"].AttemptHash)
}

func TestFederationRebuildRetainsUncertainAttempt(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.PutFederationLink(ctx, FederationLink{UID: "link", HubOrigin: "https://example.org", HubArchiveID: "hub", EnrollmentUID: "enr", Member: "member", TokenFile: "/fixture/token", ProtocolVersion: 2, State: "active"}))
	require.NoError(t, d.PutFederationShare(ctx, FederationShare{UID: "share", LinkUID: "link", NormalizedRemote: "example.org/repo", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: "{}", PolicyDigest: "policy"}))
	require.NoError(t, d.SaveFederationPending(ctx, "share", 1, `{"sequence":1}`, []FederationDelivery{{RecordUID: "item", SessionID: "item", Hash: "attempt"}}))
	require.NoError(t, d.BeginFederationRebuild(ctx, "link", "share", 1))
	share, err := d.GetFederationShare(ctx, "link", "share")
	require.NoError(t, err)
	assert.EqualValues(t, 2, share.Epoch)
	assert.Empty(t, share.PendingBatch)
	assert.Equal(t, "rebuild", share.StopIntent)
	ledger, err := d.FederationLedger(ctx, "share")
	require.NoError(t, err)
	assert.Equal(t, "attempt", ledger["item"].AttemptHash)
}

func TestLeaveRetainsRetiredLinkAndStopsShares(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.PutFederationLink(ctx, FederationLink{UID: "link", HubOrigin: "https://example.org", HubArchiveID: "hub", EnrollmentUID: "enr", Member: "member", TokenFile: "/fixture/token", ProtocolVersion: 2, State: "active"}))
	require.NoError(t, d.PutFederationShare(ctx, FederationShare{UID: "share", LinkUID: "link", NormalizedRemote: "example.org/repo", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: "{}", PolicyDigest: "policy"}))
	require.NoError(t, d.DeleteFederationLink(ctx))
	_, err := d.GetFederationLink(ctx)
	require.ErrorIs(t, err, sql.ErrNoRows)
	links, err := d.ListFederationLinks(ctx)
	require.NoError(t, err)
	require.Len(t, links, 1)
	assert.Equal(t, "retired", links[0].State)
	share, err := d.GetFederationShare(ctx, "link", "share")
	require.NoError(t, err)
	assert.Equal(t, "leave", share.StopIntent)
	assert.Equal(t, "pending", share.StopReceipt)
}

func TestFederationReconcileConfirmsOnlyMatchingAttempt(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.PutFederationLink(ctx, FederationLink{UID: "link", HubOrigin: "https://example.org", HubArchiveID: "hub", EnrollmentUID: "enr", Member: "member", TokenFile: "/fixture/token", ProtocolVersion: 2, State: "active"}))
	require.NoError(t, d.PutFederationShare(ctx, FederationShare{UID: "share", LinkUID: "link", NormalizedRemote: "example.org/repo", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: "{}", PolicyDigest: "policy"}))
	require.NoError(t, d.RecordFederationAttempt(ctx, "share", []FederationDelivery{{RecordUID: "a", SessionID: "a", Hash: "attempt-a"}, {RecordUID: "b", SessionID: "b", Hash: "attempt-b"}}))
	require.NoError(t, d.ConfirmFederationMatches(ctx, "share", []FederationInventoryItem{{UID: "a", Hash: "attempt-a"}, {UID: "b", Hash: "different"}}))
	ledger, err := d.FederationLedger(ctx, "share")
	require.NoError(t, err)
	assert.Equal(t, "sent", ledger["a"].State)
	assert.Equal(t, "attempt-a", ledger["a"].Hash)
	assert.Empty(t, ledger["a"].AttemptHash)
	assert.Equal(t, "attempt-b", ledger["b"].AttemptHash)
}

func TestFederationGenerationChangeRequiresNewEpoch(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.PutFederationShare(ctx, FederationShare{UID: "share", LinkUID: "link", NormalizedRemote: "example.org/repo", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: "{}", PolicyDigest: "policy"}))
	changed, err := d.SetFederationGeneration(ctx, "link", "share", "one")
	require.NoError(t, err)
	assert.False(t, changed)
	require.NoError(t, d.AdvanceFederationCursors(ctx, "share", 1, "2026-01-01T00:00:00Z", 23, 19))
	changed, err = d.SetFederationGeneration(ctx, "link", "share", "two")
	require.NoError(t, err)
	assert.True(t, changed)
	share, err := d.GetFederationShare(ctx, "link", "share")
	require.NoError(t, err)
	assert.EqualValues(t, 2, share.Epoch)
	assert.Equal(t, "rebuild", share.StopIntent)
	assert.Empty(t, share.SyncCursor)
	assert.Zero(t, share.UsageCursor)
	assert.Zero(t, share.DeletionCursor)
}

func TestFederationChangeCursorsAdvanceAfterProcessing(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.PutFederationShare(ctx, FederationShare{UID: "share", LinkUID: "link", NormalizedRemote: "example.org/repo", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: "{}", PolicyDigest: "policy"}))
	require.NoError(t, d.AdvanceFederationCursors(ctx, "share", 1, "2026-01-01T00:00:00Z", 5, 7))
	share, err := d.GetFederationShare(ctx, "link", "share")
	require.NoError(t, err)
	assert.Equal(t, "2026-01-01T00:00:00Z", share.SyncCursor)
	assert.EqualValues(t, 5, share.UsageCursor)
	assert.EqualValues(t, 7, share.DeletionCursor)
	// A restored snapshot can keep the database identity while its journals
	// regress. The recovery transition must not carry those cursors forward.
	require.NoError(t, d.BeginFederationRebuild(ctx, "link", "share", 1))
	share, err = d.GetFederationShare(ctx, "link", "share")
	require.NoError(t, err)
	assert.Empty(t, share.SyncCursor)
	assert.Zero(t, share.UsageCursor)
	assert.Zero(t, share.DeletionCursor)
}

func TestFederationDeliveryAndStopSurviveReopen(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "archive.db")
	d, err := OpenIsolated(ctx, path)
	require.NoError(t, err)
	require.NoError(t, d.PutFederationLink(ctx, FederationLink{UID: "link", HubOrigin: "https://example.org", HubArchiveID: "hub", EnrollmentUID: "enr", Member: "member", TokenFile: "/fixture/token", ProtocolVersion: 2, State: "active"}))
	require.NoError(t, d.PutFederationShare(ctx, FederationShare{UID: "share", LinkUID: "link", NormalizedRemote: "example.org/repo", Level: "summary", Attribution: "pooled", Audience: "operators", State: "active", ConsentJSON: "{}", PolicyDigest: "policy"}))
	require.NoError(t, d.SaveFederationPending(ctx, "share", 1, `{"sequence":1}`, []FederationDelivery{{RecordUID: "item", SessionID: "item", Hash: "attempt"}}))
	require.NoError(t, d.Close())
	d, err = OpenIsolated(ctx, path)
	require.NoError(t, err)
	share, err := d.GetFederationShare(ctx, "link", "share")
	require.NoError(t, err)
	assert.Equal(t, `{"sequence":1}`, share.PendingBatch)
	ledger, err := d.FederationLedger(ctx, "share")
	require.NoError(t, err)
	assert.Equal(t, "attempt", ledger["item"].AttemptHash)
	require.NoError(t, d.CommitFederationAcknowledgment(ctx, "share", 1, []FederationDelivery{{RecordUID: "item", SessionID: "item", Hash: "attempt", State: "sent"}}))
	require.NoError(t, d.StopFederationShare(ctx, "link", "share", "remove"))
	require.NoError(t, d.Close())
	d, err = OpenIsolated(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	share, err = d.GetFederationShare(ctx, "link", "share")
	require.NoError(t, err)
	assert.EqualValues(t, 1, share.Sequence)
	assert.Empty(t, share.PendingBatch)
	assert.Equal(t, "pending", share.StopReceipt)
	ledger, err = d.FederationLedger(ctx, "share")
	require.NoError(t, err)
	assert.Equal(t, "attempt", ledger["item"].Hash)
	assert.Empty(t, ledger["item"].AttemptHash)
}

func TestLegacyHubRetentionIsNotInventedOnOpenOrCopy(t *testing.T) {
	for _, retention := range []string{"member-controlled", "org-retained"} {
		t.Run(retention, func(t *testing.T) {
			ctx := t.Context()
			path := filepath.Join(t.TempDir(), "legacy-hub.db")
			old, err := OpenIsolated(ctx, path)
			require.NoError(t, err)
			require.NoError(t, old.CreateFederationEnrollment(ctx, FederationEnrollment{UID: "enr", SpokeArchiveID: "spoke", Member: "member", CredentialSHA256: "credential"}))
			share := FederationHubShare{UID: "share", EnrollmentUID: "enr", Remote: "example.org/repo", ProjectKey: "key", Level: "summary", Attribution: "pooled", Audience: "operators", PolicyDigest: "accepted", Epoch: 1, State: "active", Retention: retention}
			_, err = old.PutFederationHubShare(ctx, "spoke", share)
			require.NoError(t, err)
			record := FederationHubRecord{UID: "owned", Hash: "hash", Remote: share.Remote, ProjectKey: share.ProjectKey, Write: SessionBatchWrite{Session: Session{ID: "owned", Project: "p", Machine: "federated", Agent: "claude"}}}
			_, err = old.CommitFederationBatch(ctx, "enr", "spoke", "share", "accepted", 1, 1, "batch", []FederationHubRecord{record})
			require.NoError(t, err)
			require.NoError(t, old.Close())
			legacy, err := sql.Open("sqlite3", path)
			require.NoError(t, err)
			_, err = legacy.ExecContext(ctx, `CREATE TABLE pre_withdrawal_share (
				share_uid TEXT PRIMARY KEY,enrollment_uid TEXT NOT NULL,normalized_remote TEXT NOT NULL,
				project_key TEXT NOT NULL,level TEXT NOT NULL,attribution TEXT NOT NULL,audience TEXT NOT NULL,
				policy_digest TEXT NOT NULL,epoch INTEGER NOT NULL,sequence INTEGER NOT NULL,
				last_batch_digest TEXT NOT NULL,last_refused TEXT NOT NULL,state TEXT NOT NULL);
				INSERT INTO pre_withdrawal_share SELECT share_uid,enrollment_uid,normalized_remote,project_key,level,attribution,audience,policy_digest,epoch,sequence,last_batch_digest,last_refused,state FROM federation_hub_shares;
				DROP TABLE federation_hub_shares;
				ALTER TABLE pre_withdrawal_share RENAME TO federation_hub_shares`)
			require.NoError(t, err)
			require.NoError(t, legacy.Close())
			copied := testDB(t)
			require.NoError(t, copied.CopyFederationStateFrom(ctx, path))
			require.NoError(t, copied.UpsertSession(ctx, Session{ID: "owned", Project: "p", Machine: "federated", Agent: "claude"}))
			upgraded, err := OpenIsolated(ctx, path)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, upgraded.Close()) })
			for _, archive := range []*DB{copied, upgraded} {
				var stored string
				require.NoError(t, archive.Reader().QueryRow(ctx, `SELECT retention FROM federation_hub_shares WHERE share_uid='share'`).Scan(&stored))
				assert.Empty(t, stored)
				err := archive.RevokeFederationEnrollment(ctx, "enr", FederationRetentionProof{PolicyDigest: "different", Retention: retention})
				require.ErrorIs(t, err, ErrFederationCleanupPending)
				var revoked string
				var owned int
				require.NoError(t, archive.Reader().QueryRow(ctx, `SELECT revoked_at FROM federation_enrollments WHERE enrollment_uid='enr'`).Scan(&revoked))
				assert.NotEmpty(t, revoked)
				require.NoError(t, archive.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id='owned'`).Scan(&owned))
				assert.Equal(t, 1, owned)
				require.NoError(t, archive.RevokeFederationEnrollment(ctx, "enr", FederationRetentionProof{PolicyDigest: "accepted", Retention: retention}))
				require.NoError(t, archive.Reader().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id='owned'`).Scan(&owned))
				if retention == "member-controlled" {
					assert.Zero(t, owned)
				} else {
					assert.Equal(t, 1, owned)
				}
			}
		})
	}
}
