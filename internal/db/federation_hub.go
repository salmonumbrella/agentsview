package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

var ErrFederationSequence = errors.New("federation sequence mismatch")
var ErrFederationInvalidBatch = errors.New("invalid federation batch")

const FederationCollision = "session ID unavailable"

type FederationHubShare struct {
	UID, EnrollmentUID, Remote, ProjectKey, Level, Attribution, Audience, PolicyDigest, State string
	Epoch, Sequence                                                                           int64
}
type FederationHubRecord struct {
	UID, Hash, Remote, ProjectKey string
	AssistantCount, ToolCount     int
	Write                         SessionBatchWrite
}
type FederationBatchResult struct {
	Committed int64             `json:"committed"`
	Refused   map[string]string `json:"refused"`
}

func (db *DB) PutFederationHubShare(ctx context.Context, spoke string, share FederationHubShare) (FederationHubShare, error) {
	err := db.Update(ctx, func(tx *sql.Tx) error {
		var active bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM federation_enrollments WHERE enrollment_uid=? AND spoke_archive_id=? AND revoked_at='')`, share.EnrollmentUID, spoke).Scan(&active); err != nil {
			return err
		}
		if !active {
			return sql.ErrNoRows
		}
		var owner, remote string
		err := tx.QueryRowContext(ctx, `SELECT enrollment_uid,normalized_remote FROM federation_hub_shares WHERE share_uid=?`, share.UID).Scan(&owner, &remote)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && (owner != share.EnrollmentUID || remote != share.Remote) {
			return sql.ErrNoRows
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO federation_hub_shares (share_uid,enrollment_uid,normalized_remote,project_key,level,attribution,audience,policy_digest,epoch,sequence,last_batch_digest,state) VALUES (?,?,?,?,?,?,?,?,?,0,'',?) ON CONFLICT(share_uid) DO UPDATE SET project_key=excluded.project_key,level=excluded.level,attribution=excluded.attribution,audience=excluded.audience,policy_digest=excluded.policy_digest,state=excluded.state`, share.UID, share.EnrollmentUID, share.Remote, share.ProjectKey, share.Level, share.Attribution, share.Audience, share.PolicyDigest, share.Epoch, share.State)
		if err != nil {
			return err
		}
		if err = tx.QueryRowContext(ctx, `SELECT sequence,epoch,state FROM federation_hub_shares WHERE share_uid=?`, share.UID).Scan(&share.Sequence, &share.Epoch, &share.State); err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
	})
	return share, err
}

func (db *DB) CommitFederationBatch(ctx context.Context, enrollment, spoke, share, policyDigest string, epoch, sequence int64, digest string, records []FederationHubRecord) (FederationBatchResult, error) {
	result := FederationBatchResult{Refused: map[string]string{}}
	if err := db.requireWritable(); err != nil {
		return result, err
	}
	if err := db.lockWriterCtx(ctx); err != nil {
		return result, err
	}
	defer db.mu.Unlock()
	if db.writerClosed.Load() {
		return result, ErrWriterClosed
	}
	tx, err := db.getWriter().Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var last, refusedJSON, remote, projectKey string
	err = tx.QueryRowContext(ctx, `SELECT h.sequence,h.last_batch_digest,h.last_refused,h.normalized_remote,h.project_key FROM federation_hub_shares h JOIN federation_enrollments e ON e.enrollment_uid=h.enrollment_uid WHERE h.share_uid=? AND h.enrollment_uid=? AND h.state='active' AND h.policy_digest=? AND h.epoch=? AND e.spoke_archive_id=? AND e.revoked_at=''`, share, enrollment, policyDigest, epoch, spoke).Scan(&result.Committed, &last, &refusedJSON, &remote, &projectKey)
	if err != nil {
		return result, err
	}
	if sequence == result.Committed && digest == last && sequence > 0 {
		if err = json.Unmarshal([]byte(refusedJSON), &result.Refused); err != nil {
			return result, err
		}
		return result, nil
	}
	if sequence != result.Committed+1 {
		return result, ErrFederationSequence
	}
	var writes []SessionBatchWrite
	for _, record := range records {
		id := record.Write.Session.ID
		if record.Remote != remote || record.ProjectKey != projectKey {
			return result, ErrFederationInvalidBatch
		}
		var owner, hash string
		e := tx.QueryRowContext(ctx, `SELECT share_uid,hash FROM federation_records WHERE session_id=?`, id).Scan(&owner, &hash)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return result, e
		}
		var unavailable bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sessions WHERE id=? AND deleted_at IS NOT NULL UNION ALL SELECT 1 FROM excluded_sessions WHERE id=?)`, id, id).Scan(&unavailable); err != nil {
			return result, err
		}
		collision := unavailable || (e == nil && owner != share)
		if errors.Is(e, sql.ErrNoRows) && !collision {
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sessions WHERE id=?)`, id).Scan(&collision); err != nil {
				return result, err
			}
		}
		if !collision && e == nil && owner == share && hash == record.Hash {
			continue
		}
		if collision {
			result.Refused[record.UID] = FederationCollision
			continue
		}
		if record.Write.Session.ParentSessionID != nil {
			var owned bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM federation_records WHERE share_uid=? AND session_id=?)`, share, *record.Write.Session.ParentSessionID).Scan(&owned); err != nil {
				return result, err
			}
			if !owned {
				record.Write.Session.ParentSessionID = nil
				record.Write.Session.RelationshipType = ""
			}
		}
		writes = append(writes, record.Write)
		if _, err = tx.ExecContext(ctx, `INSERT INTO federation_records(share_uid,record_uid,session_id,hash,assistant_count,tool_count) VALUES(?,?,?,?,?,?) ON CONFLICT(share_uid,record_uid) DO UPDATE SET hash=excluded.hash,assistant_count=excluded.assistant_count,tool_count=excluded.tool_count`, share, record.UID, id, record.Hash, record.AssistantCount, record.ToolCount); err != nil {
			return result, err
		}
	}
	_, ids, revocations, err := db.writeSessionBatchAtomicTx(ctx, tx, writes, false)
	if err != nil {
		return result, err
	}
	for _, write := range writes {
		if _, err = tx.ExecContext(ctx, `UPDATE sessions SET is_automated=?,parent_session_id=?,relationship_type=? WHERE id=?`, write.Session.IsAutomated, write.Session.ParentSessionID, write.Session.RelationshipType, write.Session.ID); err != nil {
			return result, err
		}
	}
	refused, err := json.Marshal(result.Refused)
	if err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE federation_hub_shares SET sequence=?,last_batch_digest=?,last_refused=? WHERE share_uid=?`, sequence, digest, string(refused), share); err != nil {
		return result, err
	}
	if err = stampFederationVersion(ctx, tx); err != nil {
		return result, err
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	db.notifyUsageSessions(ids)
	revocations.flush()
	result.Committed = sequence
	return result, nil
}

type FederationOrigins struct{ Federated, HubHost, Other int }

func (db *DB) FederationSessionOrigins(ctx context.Context) (FederationOrigins, error) {
	var out FederationOrigins
	err := db.getReader().QueryRowContext(ctx, `SELECT
 COALESCE(sum(CASE WHEN EXISTS(SELECT 1 FROM federation_records r WHERE r.session_id=s.id) THEN 1 ELSE 0 END),0),
 COALESCE(sum(CASE WHEN NOT EXISTS(SELECT 1 FROM federation_records r WHERE r.session_id=s.id) AND `+federationLocalOrigin+` THEN 1 ELSE 0 END),0),
 COALESCE(sum(CASE WHEN NOT EXISTS(SELECT 1 FROM federation_records r WHERE r.session_id=s.id) AND NOT `+federationLocalOrigin+` THEN 1 ELSE 0 END),0)
 FROM sessions s WHERE s.deleted_at IS NULL`).Scan(&out.Federated, &out.HubHost, &out.Other)
	return out, err
}
