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
		_, err := tx.ExecContext(ctx, `INSERT INTO federation_enrollments (enrollment_uid,spoke_archive_id,member,spoke_name,credential_sha256) VALUES (?,?,?,?,?)`, e.UID, e.SpokeArchiveID, e.Member, e.SpokeName, e.CredentialSHA256)
		if isSQLiteUniqueConstraint(err) {
			return ErrFederationEnrollmentExists
		}
		if err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
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
		if err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
	})
}
func (db *DB) BlockFederationLink(ctx context.Context, uid string) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE federation_links SET state = 'blocked' WHERE link_uid = ?`, uid)
		return err
	})
}
func (db *DB) DeleteFederationLink(ctx context.Context) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM federation_shares WHERE link_uid IN (SELECT link_uid FROM federation_links)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM federation_links`); err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
	})
}

func stampFederationVersion(ctx context.Context, tx *sql.Tx) error {
	version, _, err := readUserVersion(ctx, tx)
	if err != nil {
		return err
	}
	return writeUserVersion(ctx, tx, version)
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
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for table, columns := range map[string]string{"federation_enrollments": "enrollment_uid,spoke_archive_id,member,spoke_name,credential_sha256,created_at,last_handshake_at,revoked_at", "federation_links": "link_uid,hub_origin,hub_archive_id,enrollment_uid,member,token_file,protocol_version,state,created_at", "federation_shares": "share_uid,link_uid,normalized_remote,level,attribution,since,audience,state,consent_json,policy_digest,created_at", "federation_exclusions": "session_id,share_uid,reason,created_at", "federation_deliveries": "share_uid,session_id,record_uid,transcript_revision,hash,state"} {
		var present int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM federation_old.sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&present); err != nil {
			return err
		}
		if present == 0 {
			continue
		}
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO `+table+` (`+columns+`) SELECT `+columns+` FROM federation_old.`+table); err != nil {
			return fmt.Errorf("copying federation state: %w", err)
		}
	}
	if err := stampFederationVersion(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// FederationShare records the grant and the exact preview accepted by the member.
type FederationShare struct {
	UID              string `json:"share_uid"`
	LinkUID          string `json:"link_uid"`
	NormalizedRemote string `json:"normalized_remote"`
	Level            string `json:"level"`
	Attribution      string `json:"attribution"`
	Since            string `json:"since"`
	Audience         string `json:"audience"`
	State            string `json:"state"`
	ConsentJSON      string `json:"consent_json"`
	PolicyDigest     string `json:"policy_digest"`
	CreatedAt        string `json:"created_at"`
}

func (db *DB) PutFederationShare(ctx context.Context, s FederationShare) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `INSERT INTO federation_shares (share_uid,link_uid,normalized_remote,level,attribution,since,audience,state,consent_json,policy_digest) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(link_uid,normalized_remote) DO UPDATE SET level=excluded.level,attribution=excluded.attribution,since=excluded.since,audience=excluded.audience,state=excluded.state,consent_json=excluded.consent_json,policy_digest=excluded.policy_digest WHERE federation_shares.state='policy_paused'`, s.UID, s.LinkUID, s.NormalizedRemote, s.Level, s.Attribution, s.Since, s.Audience, s.State, s.ConsentJSON, s.PolicyDigest)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count == 0 {
			return ErrFederationShareExists
		}
		return stampFederationVersion(ctx, tx)
	})
}

var ErrFederationShareExists = errors.New("federation share exists")

func (db *DB) ListFederationShares(ctx context.Context, linkUID string) ([]FederationShare, error) {
	rows, err := db.getReader().QueryContext(ctx, `SELECT share_uid,link_uid,normalized_remote,level,attribution,since,audience,state,consent_json,policy_digest,created_at FROM federation_shares WHERE link_uid=? ORDER BY normalized_remote`, linkUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FederationShare{}
	for rows.Next() {
		var s FederationShare
		if err := rows.Scan(&s.UID, &s.LinkUID, &s.NormalizedRemote, &s.Level, &s.Attribution, &s.Since, &s.Audience, &s.State, &s.ConsentJSON, &s.PolicyDigest, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
func (db *DB) PauseFederationSharesForPolicy(ctx context.Context, linkUID, digest string) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE federation_shares SET state='policy_paused' WHERE link_uid=? AND state<>'policy_paused' AND policy_digest<>?`, linkUID, digest); err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
	})
}
func (db *DB) PutFederationExclusion(ctx context.Context, sessionID, shareUID, reason string) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO federation_exclusions (session_id,share_uid,reason) VALUES (?,?,?) ON CONFLICT(session_id) DO NOTHING`, sessionID, shareUID, reason); err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
	})
}

func (db *DB) GetFederationShare(ctx context.Context, linkUID, uid string) (FederationShare, error) {
	var s FederationShare
	err := db.getReader().QueryRowContext(ctx, `SELECT share_uid,link_uid,normalized_remote,level,attribution,since,audience,state,consent_json,policy_digest,created_at FROM federation_shares WHERE link_uid=? AND share_uid=?`, linkUID, uid).Scan(&s.UID, &s.LinkUID, &s.NormalizedRemote, &s.Level, &s.Attribution, &s.Since, &s.Audience, &s.State, &s.ConsentJSON, &s.PolicyDigest, &s.CreatedAt)
	return s, err
}

func (db *DB) SetFederationShareState(ctx context.Context, linkUID, uid, from, to string) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_shares SET state=? WHERE link_uid=? AND share_uid=? AND state=?`, to, linkUID, uid, from)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return sql.ErrNoRows
		}
		return stampFederationVersion(ctx, tx)
	})
}
func (db *DB) DeleteFederationShare(ctx context.Context, linkUID, uid string) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM federation_shares WHERE link_uid=? AND share_uid=?`, linkUID, uid)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return sql.ErrNoRows
		}
		return stampFederationVersion(ctx, tx)
	})
}

func (db *DB) FederationDeliveryCount(ctx context.Context, shareUID string) (int, error) {
	var count int
	err := db.getReader().QueryRowContext(ctx, `SELECT count(*) FROM federation_deliveries WHERE share_uid=? AND state='sent'`, shareUID).Scan(&count)
	return count, err
}
