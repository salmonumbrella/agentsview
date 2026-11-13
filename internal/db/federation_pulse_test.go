package db

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederationPulseScopeUsesOwnedLiveRecords(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	require.NoError(t, d.Update(ctx, func(tx *sql.Tx) error {
		statements := []string{
			`INSERT INTO federation_enrollments(enrollment_uid,spoke_archive_id,member,credential_sha256) VALUES('active','spoke-a','alice','digest-a'),('retained','spoke-b','alice','digest-b'),('missing','spoke-c','','digest-c')`,
			`UPDATE federation_enrollments SET revoked_at='2026-01-01' WHERE enrollment_uid='retained'`,
			`INSERT INTO federation_hub_shares(share_uid,enrollment_uid,normalized_remote,project_key,level,attribution,audience,policy_digest,epoch,state,retention) VALUES('a','active','example/a','project-a','summary','pooled','operators','policy',1,'active',''),('b','retained','example/b','project-b','summary','pooled','operators','policy',1,'stopped','org-retained'),('c','missing','example/c','project-c','summary','pooled','operators','policy',1,'active',''),('d','active','example/d','project-d','summary','pooled','operators','policy',1,'stopped','member-controlled')`,
			`INSERT INTO sessions(id,project,machine,agent) VALUES('owned','example/a','federated','claude'),('retained','example/b','federated','claude'),('missing-member','example/c','federated','claude'),('purged','example/d','federated','claude'),('local','example/a','federated','claude'),('deleted','example/a','federated','claude')`,
			`UPDATE sessions SET deleted_at='2026-01-01' WHERE id='deleted'`,
			`INSERT INTO federation_records(share_uid,record_uid,session_id,hash) VALUES('a','owned','owned','h'),('b','retained','retained','h'),('c','missing-member','missing-member','h'),('d','purged','purged','h'),('a','deleted','deleted','h'),('orphan','orphan','local','h')`,
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		return nil
	}))
	tx, err := d.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	got, err := federationPulseScope(ctx, tx)
	require.NoError(t, err)
	assert.Equal(t, map[string]federationPulseOwner{
		"owned":    {member: "alice", project: "project-a"},
		"retained": {member: "alice", project: "project-b"},
	}, got)
}

func TestFederationPulseSinceValidation(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		input   string
		want    *time.Time
		invalid bool
	}{
		{input: "", want: nil},
		{input: "2026-07-28", want: Ptr(time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC))},
		{input: "2026-08-01", want: Ptr(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))},
		{input: "2026-08-02", invalid: true},
		{input: "2026-7-28", invalid: true},
		{input: "2026-02-30", invalid: true},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseFederationPulseSince(tc.input, now)
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
