package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrFederationUnauthorized = errors.New("federation unauthorized")

type FederationEnrollment struct {
	UID              string `json:"enrollment_uid"`
	SpokeArchiveID   string `json:"spoke_archive_id"`
	Member           string `json:"member"`
	SpokeName        string `json:"spoke_name"`
	CredentialSHA256 string `json:"-"`
	CreatedAt        string `json:"created_at"`
	LastHandshakeAt  string `json:"last_handshake_at"`
	RevokedAt        string `json:"revoked_at"`
}

type FederationLink struct {
	UID             string `json:"link_uid"`
	HubOrigin       string `json:"hub_origin"`
	HubArchiveID    string `json:"hub_archive_id"`
	EnrollmentUID   string `json:"enrollment_uid"`
	Member          string `json:"member"`
	TokenFile       string `json:"token_file"`
	ProtocolVersion int    `json:"protocol_version"`
	PolicyJSON      string `json:"policy_json"`
	PolicyDigest    string `json:"policy_digest"`
	State           string `json:"state"`
	CreatedAt       string `json:"created_at"`
}

func (db *DB) CreateFederationEnrollment(ctx context.Context, e FederationEnrollment) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO federation_enrollments (enrollment_uid,spoke_archive_id,member,spoke_name,credential_sha256) VALUES (?,?,?,?,?)`, e.UID, e.SpokeArchiveID, e.Member, e.SpokeName, e.CredentialSHA256)
		return err
	})
}

func (db *DB) ListFederationEnrollments(ctx context.Context) ([]FederationEnrollment, error) {
	rows, err := db.getReader().QueryContext(ctx, `SELECT enrollment_uid,spoke_archive_id,member,spoke_name,created_at,last_handshake_at,revoked_at FROM federation_enrollments ORDER BY created_at,enrollment_uid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []FederationEnrollment{}
	for rows.Next() {
		var e FederationEnrollment
		if err := rows.Scan(&e.UID, &e.SpokeArchiveID, &e.Member, &e.SpokeName, &e.CreatedAt, &e.LastHandshakeAt, &e.RevokedAt); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

func (db *DB) RevokeFederationEnrollment(ctx context.Context, uid string) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_enrollments SET revoked_at = CASE WHEN revoked_at = '' THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') ELSE revoked_at END WHERE enrollment_uid = ?`, uid)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
}

func (db *DB) AuthenticateFederationCredential(ctx context.Context, digest, archive string) (FederationEnrollment, error) {
	var e FederationEnrollment
	err := db.Update(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT enrollment_uid,spoke_archive_id,member,spoke_name FROM federation_enrollments WHERE credential_sha256 = ? AND spoke_archive_id = ? AND revoked_at = ''`, digest, archive).Scan(&e.UID, &e.SpokeArchiveID, &e.Member, &e.SpokeName)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFederationUnauthorized
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE federation_enrollments SET last_handshake_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE enrollment_uid = ?`, e.UID)
		return err
	})
	return e, err
}

func (db *DB) GetFederationLink(ctx context.Context) (FederationLink, error) {
	var l FederationLink
	err := db.getReader().QueryRowContext(ctx, `SELECT link_uid,hub_origin,hub_archive_id,enrollment_uid,member,token_file,protocol_version,policy_json,policy_digest,state,created_at FROM federation_links LIMIT 1`).Scan(&l.UID, &l.HubOrigin, &l.HubArchiveID, &l.EnrollmentUID, &l.Member, &l.TokenFile, &l.ProtocolVersion, &l.PolicyJSON, &l.PolicyDigest, &l.State, &l.CreatedAt)
	return l, err
}
func (db *DB) PutFederationLink(ctx context.Context, l FederationLink) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM federation_links`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO federation_links (link_uid,hub_origin,hub_archive_id,enrollment_uid,member,token_file,protocol_version,policy_json,policy_digest,state) VALUES (?,?,?,?,?,?,?,?,?,?)`, l.UID, l.HubOrigin, l.HubArchiveID, l.EnrollmentUID, l.Member, l.TokenFile, l.ProtocolVersion, l.PolicyJSON, l.PolicyDigest, l.State)
		return err
	})
}
func (db *DB) RefreshFederationLink(ctx context.Context, uid, policy, digest string) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE federation_links SET policy_json = ?, policy_digest = ? WHERE link_uid = ? AND state = 'active'`, policy, digest, uid)
		return err
	})
}
func (db *DB) BlockFederationLink(ctx context.Context, uid string) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE federation_links SET state = 'blocked' WHERE link_uid = ?`, uid)
		return err
	})
}
func (db *DB) DeleteFederationLink(ctx context.Context) error {
	return db.Update(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, `DELETE FROM federation_links`); return err })
}

func (db *DB) CopyFederationStateFrom(ctx context.Context, sourcePath string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	conn, err := db.getWriter().Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `ATTACH DATABASE ? AS federation_old`, sourcePath); err != nil {
		return err
	}
	defer func() { _, _ = execWithoutCancel(ctx, conn, `DETACH DATABASE federation_old`) }()
	for _, table := range []string{"federation_enrollments", "federation_links"} {
		var present int
		if err = conn.QueryRowContext(ctx, `SELECT count(*) FROM federation_old.sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&present); err != nil {
			return err
		}
		if present == 0 {
			continue
		}
		if _, err = conn.ExecContext(ctx, `INSERT OR IGNORE INTO `+table+` SELECT * FROM federation_old.`+table); err != nil {
			return fmt.Errorf("copying federation state: %w", err)
		}
	}
	return nil
}
