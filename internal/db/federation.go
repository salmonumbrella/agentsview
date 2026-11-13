package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var ErrFederationUnauthorized = errors.New("federation unauthorized")
var ErrFederationEnrollmentExists = errors.New("federation enrollment exists")
var ErrFederationLinkExists = errors.New("federation link exists")
var ErrFederationCleanupPending = errors.New("federation cleanup pending: restore the previously accepted policy and retry revoke")

type FederationRetentionProof struct {
	PolicyDigest string
	Retention    string
}

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

func (db *DB) RevokeFederationEnrollment(ctx context.Context, uid string, proof ...FederationRetentionProof) (bool, error) {
	var unresolved bool
	var purged []string
	var pending recallEvidenceRevocationEvents
	err := db.Update(ctx, func(tx *sql.Tx) error {
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
		rows, err := tx.QueryContext(ctx, `SELECT share_uid,retention,policy_digest FROM federation_hub_shares WHERE enrollment_uid=?`, uid)
		if err != nil {
			return err
		}
		type ownedShare struct{ uid, retention, digest string }
		var shares []ownedShare
		for rows.Next() {
			var s ownedShare
			if err = rows.Scan(&s.uid, &s.retention, &s.digest); err != nil {
				rows.Close()
				return err
			}
			shares = append(shares, s)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err = rows.Close(); err != nil {
			return err
		}
		for _, share := range shares {
			if share.retention == "" && len(proof) == 1 && proof[0].PolicyDigest == share.digest && (proof[0].Retention == "member-controlled" || proof[0].Retention == "org-retained") {
				share.retention = proof[0].Retention
				if _, err := tx.ExecContext(ctx, `UPDATE federation_hub_shares SET retention=? WHERE share_uid=? AND retention=''`, share.retention, share.uid); err != nil {
					return err
				}
			}
			if share.retention != "member-controlled" && share.retention != "org-retained" {
				unresolved = true
			}
			if share.retention == "member-controlled" {
				ids, err := federationOwnedSessionIDsTx(ctx, tx, share.uid, nil)
				if err != nil {
					return err
				}
				removed, err := purgeFederationRecordsTx(ctx, tx, share.uid, ids, &pending)
				if err != nil {
					return err
				}
				purged = append(purged, removed...)
			}
			if _, err = tx.ExecContext(ctx, `UPDATE federation_hub_shares SET state='stopped',last_batch_digest='',last_refused='{}' WHERE share_uid=?`, share.uid); err != nil {
				return err
			}
		}
		return stampFederationVersion(ctx, tx)
	})
	if err == nil {
		db.notifyUsageSessions(purged)
		pending.flush()
		if unresolved {
			return len(purged) > 0, ErrFederationCleanupPending
		}
	}
	return err == nil && len(purged) > 0, err
}

func (db *DB) AuthenticateFederationCredential(ctx context.Context, digest, archive string) (FederationEnrollment, error) {
	return db.authenticateFederationCredential(ctx, digest, archive, true)
}

func (db *DB) LookupFederationCredential(ctx context.Context, digest, archive string) (FederationEnrollment, error) {
	return db.authenticateFederationCredential(ctx, digest, archive, false)
}

func (db *DB) authenticateFederationCredential(ctx context.Context, digest, archive string, stamp bool) (FederationEnrollment, error) {
	var e FederationEnrollment
	err := db.getReader().QueryRowContext(ctx, `SELECT enrollment_uid,spoke_archive_id,member,spoke_name FROM federation_enrollments WHERE credential_sha256 = ? AND spoke_archive_id = ? AND revoked_at = ''`, digest, archive).Scan(&e.UID, &e.SpokeArchiveID, &e.Member, &e.SpokeName)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrFederationUnauthorized
	}
	if err != nil {
		return e, err
	}
	if !stamp {
		return e, nil
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
	err := db.getReader().QueryRowContext(ctx, `SELECT link_uid,hub_origin,hub_archive_id,enrollment_uid,member,token_file,protocol_version,state,created_at FROM federation_links WHERE state<>'retired' ORDER BY created_at,link_uid LIMIT 1`).Scan(&l.UID, &l.HubOrigin, &l.HubArchiveID, &l.EnrollmentUID, &l.Member, &l.TokenFile, &l.ProtocolVersion, &l.State, &l.CreatedAt)
	return l, err
}
func (db *DB) PutFederationLink(ctx context.Context, l FederationLink) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM federation_links WHERE state<>'retired' LIMIT 1`).Scan(&exists)
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
		if _, err := tx.ExecContext(ctx, `UPDATE federation_shares SET state='paused',stop_intent='leave',stop_receipt='pending' WHERE link_uid IN (SELECT link_uid FROM federation_links WHERE state<>'retired') AND stop_intent<>'remove'`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE federation_links SET state='retired' WHERE state<>'retired'`); err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
	})
}
func (db *DB) ListFederationLinks(ctx context.Context) ([]FederationLink, error) {
	rows, err := db.getReader().QueryContext(ctx, `SELECT link_uid,hub_origin,hub_archive_id,enrollment_uid,member,token_file,protocol_version,state,created_at FROM federation_links ORDER BY created_at,link_uid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var links []FederationLink
	for rows.Next() {
		var l FederationLink
		if err = rows.Scan(&l.UID, &l.HubOrigin, &l.HubArchiveID, &l.EnrollmentUID, &l.Member, &l.TokenFile, &l.ProtocolVersion, &l.State, &l.CreatedAt); err != nil {
			return nil, err
		}
		links = append(links, l)
	}
	return links, rows.Err()
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
	for table, columns := range map[string]string{"federation_enrollments": "enrollment_uid,spoke_archive_id,member,spoke_name,credential_sha256,created_at,last_handshake_at,last_delivery_at,revoked_at", "federation_links": "link_uid,hub_origin,hub_archive_id,enrollment_uid,member,token_file,protocol_version,state,created_at", "federation_shares": "share_uid,link_uid,normalized_remote,level,attribution,since,audience,state,consent_json,policy_digest,created_at,epoch,sequence,source_generation,sync_cursor,usage_cursor,deletion_cursor,pending_batch,stop_intent,stop_receipt", "federation_exclusions": "session_id,reason,created_at", "federation_deliveries": "share_uid,record_uid,session_id,hash,state,attempt_hash,hub_origin,hub_archive_id,normalized_remote", "federation_quarantine": "share_uid,error,sequence", "federation_hub_shares": "share_uid,enrollment_uid,normalized_remote,project_key,level,attribution,audience,policy_digest,epoch,sequence,last_batch_digest,last_refused,state,retention,reconcile_round,reconcile_boundary,completed_epoch", "federation_records": "share_uid,record_uid,session_id,hash,assistant_count,epoch"} {
		var present int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM federation_old.sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&present); err != nil {
			return err
		}
		if present == 0 {
			continue
		}
		// Older archives lack additive columns. Copy their declared defaults while
		// preserving every field present in newer archives.
		var expressions []string
		for _, column := range strings.Split(columns, ",") {
			var present int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info(?,'federation_old') WHERE name=?`, table, column).Scan(&present); err != nil {
				return err
			}
			if present != 0 {
				expressions = append(expressions, column)
			} else if table == "federation_shares" && column == "stop_intent" {
				expressions = append(expressions, "CASE state WHEN 'paused' THEN 'pause' WHEN 'policy_paused' THEN 'policy' ELSE '' END")
			} else if table == "federation_shares" && column == "stop_receipt" {
				expressions = append(expressions, "CASE WHEN state IN ('paused','policy_paused') THEN 'pending' ELSE '' END")
			} else if table == "federation_enrollments" && column == "last_delivery_at" {
				expressions = append(expressions, "NULL")
			} else if column == "epoch" {
				expressions = append(expressions, "1")
			} else if column == "sequence" || column == "usage_cursor" || column == "deletion_cursor" || column == "completed_epoch" {
				expressions = append(expressions, "0")
			} else {
				expressions = append(expressions, "''")
			}
		}
		selectColumns := strings.Join(expressions, ",")
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO `+table+` (`+columns+`) SELECT `+selectColumns+` FROM federation_old.`+table); err != nil {
			return fmt.Errorf("copying federation state: %w", err)
		}
	}
	// Recover older live rows from the source joins, independent of table copy order.
	var joins int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM federation_old.sqlite_master WHERE type='table' AND name IN ('federation_shares','federation_links')`).Scan(&joins); err != nil {
		return err
	}
	if joins == 2 {
		_, err = tx.ExecContext(ctx, `UPDATE federation_deliveries AS d SET hub_origin=COALESCE((SELECT l.hub_origin FROM federation_old.federation_shares s JOIN federation_old.federation_links l ON l.link_uid=s.link_uid WHERE s.share_uid=d.share_uid),''),hub_archive_id=COALESCE((SELECT l.hub_archive_id FROM federation_old.federation_shares s JOIN federation_old.federation_links l ON l.link_uid=s.link_uid WHERE s.share_uid=d.share_uid),''),normalized_remote=COALESCE((SELECT s.normalized_remote FROM federation_old.federation_shares s WHERE s.share_uid=d.share_uid),'') WHERE d.hub_origin='' AND d.hub_archive_id='' AND d.normalized_remote=''`)
		if err != nil {
			return err
		}
	}
	if err := stampFederationVersion(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// FederationShare records the grant and the exact preview accepted by the member.
type FederationShare struct {
	UID                         string `json:"share_uid"`
	LinkUID                     string `json:"link_uid"`
	NormalizedRemote            string `json:"normalized_remote"`
	Level                       string `json:"level"`
	Attribution                 string `json:"attribution"`
	Since                       string `json:"since"`
	Audience                    string `json:"audience"`
	State                       string `json:"state"`
	ConsentJSON                 string `json:"consent_json,omitempty"`
	PolicyDigest                string `json:"policy_digest"`
	CreatedAt                   string `json:"created_at"`
	Epoch                       int64  `json:"epoch"`
	Sequence                    int64  `json:"sequence"`
	StopIntent                  string `json:"stop_intent,omitempty"`
	StopReceipt                 string `json:"stop_receipt,omitempty"`
	PendingBatch                string `json:"-"`
	SourceGeneration            string `json:"-"`
	SyncCursor                  string `json:"-"`
	UsageCursor, DeletionCursor int64  `json:"-"`
}

func (db *DB) PutFederationShare(ctx context.Context, s FederationShare) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `INSERT INTO federation_shares (share_uid,link_uid,normalized_remote,level,attribution,since,audience,state,consent_json,policy_digest) VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(link_uid,normalized_remote) DO UPDATE SET
		level=excluded.level,attribution=excluded.attribution,since=excluded.since,audience=excluded.audience,
		state=CASE WHEN federation_shares.stop_intent='pause' OR federation_shares.state='paused' AND federation_shares.stop_intent='' THEN 'paused' WHEN federation_shares.stop_intent<>'' THEN 'active' ELSE excluded.state END,
		epoch=CASE WHEN (federation_shares.stop_intent<>'' AND federation_shares.stop_intent<>'pause') OR federation_shares.state='active' THEN federation_shares.epoch+1 ELSE federation_shares.epoch END,
		sequence=CASE WHEN (federation_shares.stop_intent<>'' AND federation_shares.stop_intent<>'pause') OR federation_shares.state='active' THEN 0 ELSE federation_shares.sequence END,
		pending_batch=CASE WHEN (federation_shares.stop_intent<>'' AND federation_shares.stop_intent<>'pause') OR federation_shares.state='active' THEN '' ELSE federation_shares.pending_batch END,
		stop_intent=CASE WHEN federation_shares.stop_intent='pause' THEN 'pause' WHEN federation_shares.stop_intent<>'' THEN 'resume' WHEN federation_shares.state='active' THEN 'rebuild' ELSE '' END,
		stop_receipt=CASE WHEN federation_shares.stop_intent='pause' THEN federation_shares.stop_receipt ELSE '' END,consent_json=excluded.consent_json,policy_digest=excluded.policy_digest
		WHERE (federation_shares.stop_intent<>'' AND federation_shares.stop_receipt IN ('purged','retained')) OR
		(federation_shares.stop_intent='' AND (federation_shares.state='policy_paused' OR
		(federation_shares.state='active' AND (federation_shares.since<>excluded.since OR federation_shares.attribution<>excluded.attribution OR federation_shares.level<>excluded.level OR COALESCE(json_extract(federation_shares.consent_json,'$.delivery_notice'),'')<>COALESCE(json_extract(excluded.consent_json,'$.delivery_notice'),''))) OR
		(federation_shares.state='paused' AND federation_shares.policy_digest<>excluded.policy_digest)))`, s.UID, s.LinkUID, s.NormalizedRemote, s.Level, s.Attribution, s.Since, s.Audience, s.State, s.ConsentJSON, s.PolicyDigest)
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
	rows, err := db.getReader().QueryContext(ctx, `SELECT share_uid,link_uid,normalized_remote,level,attribution,since,audience,state,consent_json,policy_digest,created_at,epoch,sequence,stop_intent,stop_receipt,pending_batch,source_generation,sync_cursor,usage_cursor,deletion_cursor FROM federation_shares WHERE link_uid=? ORDER BY normalized_remote`, linkUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FederationShare{}
	for rows.Next() {
		var s FederationShare
		if err := rows.Scan(&s.UID, &s.LinkUID, &s.NormalizedRemote, &s.Level, &s.Attribution, &s.Since, &s.Audience, &s.State, &s.ConsentJSON, &s.PolicyDigest, &s.CreatedAt, &s.Epoch, &s.Sequence, &s.StopIntent, &s.StopReceipt, &s.PendingBatch, &s.SourceGeneration, &s.SyncCursor, &s.UsageCursor, &s.DeletionCursor); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
func (db *DB) PauseFederationSharesForPolicy(ctx context.Context, linkUID, digest string) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE federation_shares SET state='policy_paused',stop_intent='policy',stop_receipt='pending' WHERE link_uid=? AND state='active' AND policy_digest<>?`, linkUID, digest); err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
	})
}

var ErrFederationSessionNotFound = errors.New("federation session not found")

func (db *DB) PutFederationExclusion(ctx context.Context, sessionID, reason string) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sessions WHERE id = ?)`, sessionID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrFederationSessionNotFound
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO federation_exclusions (session_id,reason) VALUES (?,?) ON CONFLICT(session_id) DO NOTHING`, sessionID, reason); err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
	})
}

func (db *DB) GetFederationShare(ctx context.Context, linkUID, uid string) (FederationShare, error) {
	var s FederationShare
	err := db.getReader().QueryRowContext(ctx, `SELECT share_uid,link_uid,normalized_remote,level,attribution,since,audience,state,consent_json,policy_digest,created_at,epoch,sequence,stop_intent,stop_receipt,pending_batch,source_generation,sync_cursor,usage_cursor,deletion_cursor FROM federation_shares WHERE link_uid=? AND share_uid=?`, linkUID, uid).Scan(&s.UID, &s.LinkUID, &s.NormalizedRemote, &s.Level, &s.Attribution, &s.Since, &s.Audience, &s.State, &s.ConsentJSON, &s.PolicyDigest, &s.CreatedAt, &s.Epoch, &s.Sequence, &s.StopIntent, &s.StopReceipt, &s.PendingBatch, &s.SourceGeneration, &s.SyncCursor, &s.UsageCursor, &s.DeletionCursor)
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
	return db.StopFederationShare(ctx, linkUID, uid, "remove")
}

func (db *DB) StopFederationShare(ctx context.Context, linkUID, uid, intent string) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_shares SET state='paused',stop_intent=?,stop_receipt='pending' WHERE link_uid=? AND share_uid=?`, intent, linkUID, uid)
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

func (db *DB) ReceiptFederationStop(ctx context.Context, linkUID, uid, receipt string, epoch, sequence int64) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_shares SET stop_receipt=?,sequence=?,pending_batch='' WHERE link_uid=? AND share_uid=? AND epoch=? AND stop_intent<>''`, receipt, sequence, linkUID, uid, epoch)
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

// AdvanceFederationStopEpoch fences a durable stop after an authenticated hub
// reports a newer grant. Pending delivery evidence remains in the ledger.
func (db *DB) AdvanceFederationStopEpoch(ctx context.Context, linkUID, uid string, oldEpoch, nextEpoch int64) error {
	if nextEpoch <= oldEpoch {
		return ErrFederationSequence
	}
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_shares SET epoch=?,sequence=0,stop_receipt='pending' WHERE link_uid=? AND share_uid=? AND epoch=? AND state<>'active' AND stop_receipt IN ('pending','retained') AND stop_intent IN ('pause','remove','leave','policy')`, nextEpoch, linkUID, uid, oldEpoch)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrFederationSequence
		}
		return stampFederationVersion(ctx, tx)
	})
}

// SyncFederationRetainedProgress records control progress only, never delivery
// acknowledgments. A concurrent pending envelope must not be overwritten.
func (db *DB) SyncFederationRetainedProgress(ctx context.Context, linkUID, uid string, epoch, sequence int64) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_shares SET sequence=? WHERE link_uid=? AND share_uid=? AND epoch=? AND state<>'active' AND stop_receipt='retained' AND pending_batch=''`, sequence, linkUID, uid, epoch)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrFederationSequence
		}
		return nil
	})
}

// Resume requires a completed stop receipt and uses a new epoch so a stale
// active registration cannot reopen the preceding grant.
func (db *DB) ResumeFederationShare(ctx context.Context, linkUID, uid string) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_shares SET state='active',epoch=epoch+1,sequence=0,pending_batch='',stop_intent='resume',stop_receipt='' WHERE link_uid=? AND share_uid=? AND state='paused' AND stop_intent='pause' AND stop_receipt IN ('purged','retained')`, linkUID, uid)
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
func (db *DB) ConfirmFederationResume(ctx context.Context, linkUID, uid string, epoch int64) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE federation_shares SET stop_intent='',stop_receipt='' WHERE link_uid=? AND share_uid=? AND epoch=? AND stop_intent IN ('resume','rebuild')`, linkUID, uid, epoch)
		return err
	})
}

func (db *DB) BeginFederationRebuild(ctx context.Context, linkUID, uid string, epoch int64) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_shares SET epoch=epoch+1,sequence=0,pending_batch='',stop_intent='rebuild',sync_cursor='',usage_cursor=0,deletion_cursor=0 WHERE link_uid=? AND share_uid=? AND state='active' AND epoch=?`, linkUID, uid, epoch)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrFederationSequence
		}
		return stampFederationVersion(ctx, tx)
	})
}

func (db *DB) SetFederationGeneration(ctx context.Context, linkUID, uid, generation string) (bool, error) {
	changed := false
	err := db.Update(ctx, func(tx *sql.Tx) error {
		var old, pending string
		if err := tx.QueryRowContext(ctx, `SELECT source_generation,pending_batch FROM federation_shares WHERE link_uid=? AND share_uid=? AND state='active'`, linkUID, uid).Scan(&old, &pending); err != nil {
			return err
		}
		if pending != "" {
			return ErrFederationSequence
		}
		changed = old != "" && old != generation
		if changed {
			_, err := tx.ExecContext(ctx, `UPDATE federation_shares SET source_generation=?,epoch=epoch+1,sequence=0,stop_intent='rebuild',sync_cursor='',usage_cursor=0,deletion_cursor=0 WHERE link_uid=? AND share_uid=?`, generation, linkUID, uid)
			if err != nil {
				return err
			}
		} else if old == "" {
			if _, err := tx.ExecContext(ctx, `UPDATE federation_shares SET source_generation=? WHERE link_uid=? AND share_uid=?`, generation, linkUID, uid); err != nil {
				return err
			}
		}
		return stampFederationVersion(ctx, tx)
	})
	return changed, err
}
func (db *DB) AdvanceFederationEpoch(ctx context.Context, linkUID, uid string, oldEpoch, nextEpoch int64) error {
	if nextEpoch <= oldEpoch {
		return ErrFederationSequence
	}
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_shares SET epoch=?,sequence=0,pending_batch='',stop_intent='rebuild' WHERE link_uid=? AND share_uid=? AND state='active' AND epoch=?`, nextEpoch, linkUID, uid, oldEpoch)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrFederationSequence
		}
		return stampFederationVersion(ctx, tx)
	})
}

func (db *DB) AdvanceFederationCursors(ctx context.Context, uid string, epoch int64, marker string, usage, deletion int64) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_shares SET sync_cursor=?,usage_cursor=?,deletion_cursor=? WHERE share_uid=? AND epoch=? AND (state='active' OR stop_receipt='retained') AND pending_batch=''`, marker, usage, deletion, uid, epoch)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrFederationSequence
		}
		return stampFederationVersion(ctx, tx)
	})
}

type FederationDelivery struct {
	ShareUID         string `json:"share_uid"`
	RecordUID        string `json:"record_uid"`
	SessionID        string `json:"session_id"`
	Hash             string `json:"hash"`
	State            string `json:"state"`
	AttemptHash      string `json:"attempt_hash"`
	HubOrigin        string `json:"hub_origin"`
	HubArchiveID     string `json:"hub_archive_id"`
	NormalizedRemote string `json:"normalized_remote"`
}
type FederationQuarantine struct {
	ShareUID string `json:"share_uid"`
	Error    string `json:"error"`
	Sequence int64  `json:"sequence"`
}

func (db *DB) FederationLedger(ctx context.Context, share string) (map[string]FederationDelivery, error) {
	rows, err := db.getReader().QueryContext(ctx, `SELECT share_uid,record_uid,session_id,hash,state,attempt_hash,hub_origin,hub_archive_id,normalized_remote FROM federation_deliveries WHERE share_uid=?`, share)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]FederationDelivery{}
	for rows.Next() {
		var d FederationDelivery
		if err = rows.Scan(&d.ShareUID, &d.RecordUID, &d.SessionID, &d.Hash, &d.State, &d.AttemptHash, &d.HubOrigin, &d.HubArchiveID, &d.NormalizedRemote); err != nil {
			return nil, err
		}
		out[d.RecordUID] = d
	}
	return out, rows.Err()
}

func (db *DB) FederationLedgerShares(ctx context.Context) ([]string, error) {
	rows, err := db.getReader().QueryContext(ctx, `SELECT DISTINCT share_uid FROM federation_deliveries ORDER BY share_uid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var shares []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		shares = append(shares, uid)
	}
	return shares, rows.Err()
}

// SaveFederationPending records the exact envelope and attempt evidence in one
// transaction before any bytes leave the spoke.
func (db *DB) SaveFederationPending(ctx context.Context, share string, sequence int64, envelope string, attempts []FederationDelivery) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_shares SET pending_batch=? WHERE share_uid=? AND ((state='active' AND stop_intent IN ('','resume','rebuild')) OR (state<>'active' AND stop_receipt='retained')) AND sequence=? AND pending_batch=''`, envelope, share, sequence-1)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrFederationSequence
		}
		var origin, archive, remote string
		if err := tx.QueryRowContext(ctx, `SELECT l.hub_origin,l.hub_archive_id,s.normalized_remote FROM federation_shares s JOIN federation_links l ON l.link_uid=s.link_uid WHERE s.share_uid=?`, share).Scan(&origin, &archive, &remote); err != nil {
			return err
		}
		for _, d := range attempts {
			if _, err := tx.ExecContext(ctx, `INSERT INTO federation_deliveries(share_uid,record_uid,session_id,hash,state,attempt_hash,hub_origin,hub_archive_id,normalized_remote) VALUES(?,?,?,'','unconfirmed',?,?,?,?) ON CONFLICT(share_uid,record_uid) DO UPDATE SET session_id=excluded.session_id,attempt_hash=excluded.attempt_hash,hub_origin=CASE WHEN federation_deliveries.hub_origin='' THEN excluded.hub_origin ELSE federation_deliveries.hub_origin END,hub_archive_id=CASE WHEN federation_deliveries.hub_archive_id='' THEN excluded.hub_archive_id ELSE federation_deliveries.hub_archive_id END,normalized_remote=CASE WHEN federation_deliveries.normalized_remote='' THEN excluded.normalized_remote ELSE federation_deliveries.normalized_remote END`, share, d.RecordUID, d.SessionID, d.Hash, origin, archive, remote); err != nil {
				return err
			}
		}
		return stampFederationVersion(ctx, tx)
	})
}

// CommitFederationAcknowledgment advances the sequence and ledger together.
func (db *DB) CommitFederationAcknowledgment(ctx context.Context, share string, sequence int64, deliveries []FederationDelivery) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE federation_shares SET sequence=?,pending_batch='' WHERE share_uid=? AND sequence=? AND pending_batch<>''`, sequence, share, sequence-1)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrFederationSequence
		}
		var origin, archive, remote string
		if err := tx.QueryRowContext(ctx, `SELECT l.hub_origin,l.hub_archive_id,s.normalized_remote FROM federation_shares s JOIN federation_links l ON l.link_uid=s.link_uid WHERE s.share_uid=?`, share).Scan(&origin, &archive, &remote); err != nil {
			return err
		}
		for _, d := range deliveries {
			if _, err := tx.ExecContext(ctx, `INSERT INTO federation_deliveries(share_uid,record_uid,session_id,hash,state,hub_origin,hub_archive_id,normalized_remote) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(share_uid,record_uid) DO UPDATE SET session_id=excluded.session_id,hash=CASE WHEN excluded.state='tombstoned' THEN federation_deliveries.hash ELSE excluded.hash END,state=excluded.state,attempt_hash=CASE WHEN excluded.state='tombstoned' THEN federation_deliveries.attempt_hash ELSE '' END,hub_origin=CASE WHEN federation_deliveries.hub_origin='' THEN excluded.hub_origin ELSE federation_deliveries.hub_origin END,hub_archive_id=CASE WHEN federation_deliveries.hub_archive_id='' THEN excluded.hub_archive_id ELSE federation_deliveries.hub_archive_id END,normalized_remote=CASE WHEN federation_deliveries.normalized_remote='' THEN excluded.normalized_remote ELSE federation_deliveries.normalized_remote END`, share, d.RecordUID, d.SessionID, d.Hash, d.State, origin, archive, remote); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM federation_quarantine WHERE share_uid=? AND error<>?`, share, FederationCollision); err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
	})
}

func (db *DB) ConfirmFederationMatches(ctx context.Context, share string, matches []FederationInventoryItem) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		for _, item := range matches {
			if _, err := tx.ExecContext(ctx, `UPDATE federation_deliveries SET hash=attempt_hash,state='sent',attempt_hash='' WHERE share_uid=? AND record_uid=? AND attempt_hash<>'' AND attempt_hash=?`, share, item.UID, item.Hash); err != nil {
				return err
			}
		}
		return stampFederationVersion(ctx, tx)
	})
}

func (db *DB) PutFederationQuarantine(ctx context.Context, q FederationQuarantine) error {
	return db.Update(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO federation_quarantine(share_uid,error,sequence) VALUES(?,?,?) ON CONFLICT(share_uid) DO UPDATE SET sequence=CASE WHEN federation_quarantine.error=excluded.error THEN federation_quarantine.sequence ELSE excluded.sequence END,error=excluded.error`, q.ShareUID, q.Error, q.Sequence); err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
	})
}
func (db *DB) FederationQuarantines(ctx context.Context) ([]FederationQuarantine, error) {
	rows, err := db.getReader().QueryContext(ctx, `SELECT share_uid,error,sequence FROM federation_quarantine ORDER BY share_uid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FederationQuarantine
	for rows.Next() {
		var q FederationQuarantine
		if err = rows.Scan(&q.ShareUID, &q.Error, &q.Sequence); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

func (db *DB) FederationLedgerForIDs(ctx context.Context, share string, ids []string) (map[string]FederationDelivery, error) {
	out := make(map[string]FederationDelivery, len(ids))
	err := QueryChunkedSize(ids, maxSQLVars-1, func(chunk []string) error {
		placeholders, args := InPlaceholders(chunk)
		args = append([]any{share}, args...)
		rows, err := db.getReader().QueryContext(ctx, `SELECT share_uid,record_uid,session_id,hash,state,attempt_hash FROM federation_deliveries WHERE share_uid=? AND record_uid IN `+placeholders, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d FederationDelivery
			if err = rows.Scan(&d.ShareUID, &d.RecordUID, &d.SessionID, &d.Hash, &d.State, &d.AttemptHash); err != nil {
				return err
			}
			out[d.RecordUID] = d
		}
		return rows.Err()
	})
	return out, err
}
