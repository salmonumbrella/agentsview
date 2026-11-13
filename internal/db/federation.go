package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrFederationUnauthorized = errors.New("federation unauthorized")
var ErrFederationEnrollmentExists = errors.New("federation enrollment exists")
var ErrFederationLinkExists = errors.New("federation link exists")

type FederationEnrollment struct {
	UID              string `json:"enrollment_uid"`
	SpokeArchiveID   string `json:"spoke_archive_id"`
	Member           string `json:"member"`
	SpokeName        string `json:"spoke_name"`
	CredentialSHA256 string `json:"-"`
	CreatedAt        string `json:"created_at"`
	LastHandshakeAt  string `json:"last_handshake_at"`
	RevokedAt        string `json:"revoked_at"`
	State            string `json:"state"`
}

type FederationLink struct {
	UID             string `json:"link_uid"`
	HubOrigin       string `json:"hub_origin"`
	HubArchiveID    string `json:"hub_archive_id"`
	EnrollmentUID   string `json:"enrollment_uid"`
	Member          string `json:"member"`
	TokenFile       string `json:"token_file"`
	ProtocolVersion int    `json:"protocol_version"`
	State           string `json:"state"`
	CreatedAt       string `json:"created_at"`
}

func (db *DB) CreateFederationEnrollment(ctx context.Context, e FederationEnrollment) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM federation_enrollments WHERE spoke_archive_id = ? AND member = ? AND revoked_at = ''`, e.SpokeArchiveID, e.Member).Scan(&exists)
		if err == nil {
			return ErrFederationEnrollmentExists
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO federation_enrollments (enrollment_uid,spoke_archive_id,member,spoke_name,credential_sha256) VALUES (?,?,?,?,?)`, e.UID, e.SpokeArchiveID, e.Member, e.SpokeName, e.CredentialSHA256)
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
		e.State = "enrolled"
		if e.RevokedAt != "" {
			e.State = "revoked"
		} else if e.LastHandshakeAt != "" {
			e.State = "contacted"
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
	err := db.getReader().QueryRowContext(ctx, `SELECT enrollment_uid,spoke_archive_id,member,spoke_name FROM federation_enrollments WHERE credential_sha256 = ? AND spoke_archive_id = ? AND revoked_at = ''`, digest, archive).Scan(&e.UID, &e.SpokeArchiveID, &e.Member, &e.SpokeName)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrFederationUnauthorized
	}
	if err != nil {
		return e, err
	}
	err = db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_enrollments SET last_handshake_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE enrollment_uid = ? AND revoked_at = ''`, e.UID)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count == 0 {
			return ErrFederationUnauthorized
		}
		return nil
	})
	return e, err
}

func (db *DB) GetFederationLink(ctx context.Context) (FederationLink, error) {
	var l FederationLink
	err := db.getReader().QueryRowContext(ctx, `SELECT link_uid,hub_origin,hub_archive_id,enrollment_uid,member,token_file,protocol_version,state,created_at FROM federation_links ORDER BY created_at,link_uid LIMIT 1`).Scan(&l.UID, &l.HubOrigin, &l.HubArchiveID, &l.EnrollmentUID, &l.Member, &l.TokenFile, &l.ProtocolVersion, &l.State, &l.CreatedAt)
	return l, err
}
func (db *DB) PutFederationLink(ctx context.Context, l FederationLink) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM federation_links LIMIT 1`).Scan(&exists)
		if err == nil {
			return ErrFederationLinkExists
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO federation_links (link_uid,hub_origin,hub_archive_id,enrollment_uid,member,token_file,protocol_version,state) VALUES (?,?,?,?,?,?,?,?)`, l.UID, l.HubOrigin, l.HubArchiveID, l.EnrollmentUID, l.Member, l.TokenFile, l.ProtocolVersion, l.State)
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
	for table, columns := range map[string]string{"federation_enrollments": "enrollment_uid,spoke_archive_id,member,spoke_name,credential_sha256,created_at,last_handshake_at,revoked_at", "federation_links": "link_uid,hub_origin,hub_archive_id,enrollment_uid,member,token_file,protocol_version,state,created_at"} {
		var present int
		if err = conn.QueryRowContext(ctx, `SELECT count(*) FROM federation_old.sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&present); err != nil {
			return err
		}
		if present == 0 {
			continue
		}
		if _, err = conn.ExecContext(ctx, `INSERT OR IGNORE INTO `+table+` (`+columns+`) SELECT `+columns+` FROM federation_old.`+table); err != nil {
			return fmt.Errorf("copying federation state: %w", err)
		}
	}
	return nil
}
