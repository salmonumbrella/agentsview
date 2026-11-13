package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
)

var ErrFederationSequence = errors.New("federation sequence mismatch")
var ErrFederationInvalidBatch = errors.New("invalid federation batch")

const FederationCollision = "session ID unavailable"

type FederationHubShare struct {
	UID, EnrollmentUID, Remote, ProjectKey, Level, Attribution, Audience, PolicyDigest, State, Retention string
	Epoch, Sequence                                                                                      int64
	Resume, Rebuild                                                                                      bool
	Changed                                                                                              bool
}
type FederationHubRecord struct {
	UID, Hash, Remote, ProjectKey string
	AssistantCount                int
	Tombstone                     bool
	Write                         SessionBatchWrite
}
type FederationBatchResult struct {
	Committed int64             `json:"committed"`
	Refused   map[string]string `json:"refused"`
	Changed   bool              `json:"-"`
}

func (db *DB) PutFederationHubShare(ctx context.Context, spoke string, share FederationHubShare) (FederationHubShare, error) {
	var purged []string
	var pending recallEvidenceRevocationEvents
	err := db.Update(ctx, func(tx *sql.Tx) error {
		var active bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM federation_enrollments WHERE enrollment_uid=? AND spoke_archive_id=? AND revoked_at='')`, share.EnrollmentUID, spoke).Scan(&active); err != nil {
			return err
		}
		if !active {
			return sql.ErrNoRows
		}
		var owner, remote, state, digest, retention string
		var epoch int64
		err := tx.QueryRowContext(ctx, `SELECT enrollment_uid,normalized_remote,state,policy_digest,retention,epoch FROM federation_hub_shares WHERE share_uid=?`, share.UID).Scan(&owner, &remote, &state, &digest, &retention, &epoch)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if errors.Is(err, sql.ErrNoRows) {
			if share.Resume || (share.State != "active" && share.State != "stopped") {
				return sql.ErrNoRows
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO federation_hub_shares (share_uid,enrollment_uid,normalized_remote,project_key,level,attribution,audience,policy_digest,epoch,sequence,last_batch_digest,state,retention) VALUES (?,?,?,?,?,?,?,?,?,0,'',?,?)`, share.UID, share.EnrollmentUID, share.Remote, share.ProjectKey, share.Level, share.Attribution, share.Audience, share.PolicyDigest, share.Epoch, share.State, share.Retention)
			if err != nil {
				return err
			}
		} else {
			if owner != share.EnrollmentUID || remote != share.Remote || (digest != share.PolicyDigest && !(share.Resume && state == "stopped" && share.Epoch > epoch)) {
				return sql.ErrNoRows
			}
			if retention == "" {
				retention = share.Retention
			}
			if share.Retention != "" && retention != share.Retention && !(share.Resume && state == "stopped" && share.Epoch > epoch) {
				return ErrFederationInvalidBatch
			}
			if share.State == "stopped" && epoch == share.Epoch && state == "active" {
				if retention != "member-controlled" && retention != "org-retained" {
					return ErrFederationInvalidBatch
				}
				if retention == "member-controlled" {
					rows, err := tx.QueryContext(ctx, `SELECT session_id FROM federation_records WHERE share_uid=? ORDER BY session_id`, share.UID)
					if err != nil {
						return err
					}
					var ids []string
					for rows.Next() {
						var id string
						if err = rows.Scan(&id); err != nil {
							rows.Close()
							return err
						}
						ids = append(ids, id)
					}
					if err = rows.Err(); err != nil {
						rows.Close()
						return err
					}
					if err = rows.Close(); err != nil {
						return err
					}
					purged, err = purgeFederationRecordsTx(ctx, tx, share.UID, ids, &pending)
					if err != nil {
						return err
					}
				}
				_, err = tx.ExecContext(ctx, `UPDATE federation_hub_shares SET state='stopped',retention=?,last_batch_digest='',last_refused='{}' WHERE share_uid=?`, retention, share.UID)
				if err != nil {
					return err
				}
			} else if ((share.Resume && state == "stopped") || (share.Rebuild && state == "active")) && share.Epoch > epoch {
				if share.Resume {
					retention = share.Retention
				}
				_, err = tx.ExecContext(ctx, `UPDATE federation_hub_shares SET state='active',epoch=?,sequence=0,last_batch_digest='',last_refused='{}',retention=?,policy_digest=?,project_key=?,level=?,attribution=?,audience=? WHERE share_uid=?`, share.Epoch, retention, share.PolicyDigest, share.ProjectKey, share.Level, share.Attribution, share.Audience, share.UID)
				if err != nil {
					return err
				}
			}
		}
		if err = tx.QueryRowContext(ctx, `SELECT sequence,epoch,state,retention FROM federation_hub_shares WHERE share_uid=?`, share.UID).Scan(&share.Sequence, &share.Epoch, &share.State, &share.Retention); err != nil {
			return err
		}
		return stampFederationVersion(ctx, tx)
	})
	if err == nil {
		db.notifyUsageSessions(purged)
		pending.flush()
		share.Changed = len(purged) > 0
	}
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
	var last, refusedJSON, remote, projectKey, state, retention string
	err = tx.QueryRowContext(ctx, `SELECT h.sequence,h.last_batch_digest,h.last_refused,h.normalized_remote,h.project_key,h.state,h.retention FROM federation_hub_shares h JOIN federation_enrollments e ON e.enrollment_uid=h.enrollment_uid WHERE h.share_uid=? AND h.enrollment_uid=? AND (h.policy_digest=? OR (h.state='stopped' AND h.retention='org-retained')) AND h.epoch=? AND e.spoke_archive_id=? AND e.revoked_at=''`, share, enrollment, policyDigest, epoch, spoke).Scan(&result.Committed, &last, &refusedJSON, &remote, &projectKey, &state, &retention)
	if err != nil {
		return result, err
	}
	if state != "active" {
		if state != "stopped" || retention != "org-retained" {
			return result, sql.ErrNoRows
		}
		for _, record := range records {
			if !record.Tombstone {
				return result, ErrFederationInvalidBatch
			}
		}
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
	var purged []string
	var pending recallEvidenceRevocationEvents
	for _, record := range records {
		if record.Tombstone {
			ids, e := purgeFederationRecordsTx(ctx, tx, share, []string{record.UID}, &pending)
			if e != nil {
				return result, e
			}
			purged = append(purged, ids...)
			continue
		}
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
			if _, err = tx.ExecContext(ctx, `UPDATE federation_records SET epoch=? WHERE share_uid=? AND record_uid=?`, epoch, share, record.UID); err != nil {
				return result, err
			}
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
		if _, err = tx.ExecContext(ctx, `INSERT INTO federation_records(share_uid,record_uid,session_id,hash,assistant_count,epoch) VALUES(?,?,?,?,?,?) ON CONFLICT(share_uid,record_uid) DO UPDATE SET hash=excluded.hash,assistant_count=excluded.assistant_count,epoch=excluded.epoch`, share, record.UID, id, record.Hash, record.AssistantCount, epoch); err != nil {
			return result, err
		}
	}
	_, ids, revocations, err := db.writeSessionBatchAtomicTx(ctx, tx, writes, false)
	if err != nil {
		return result, err
	}
	for _, write := range writes {
		if _, err = tx.ExecContext(ctx, `UPDATE sessions SET is_automated=?,parent_session_id=?,relationship_type=?,outcome=?,health_grade=? WHERE id=?`, write.Session.IsAutomated, write.Session.ParentSessionID, write.Session.RelationshipType, write.Signals.Outcome, write.Signals.HealthGrade, write.Session.ID); err != nil {
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
	db.notifyUsageSessions(append(ids, purged...))
	revocations.flush()
	pending.flush()
	result.Committed = sequence
	result.Changed = len(ids) > 0 || len(purged) > 0
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

// purgeFederationRecordsTx deletes only rows this share owns. Unknown and
// foreign IDs are indistinguishable no-ops. The caller notifies caches after
// the surrounding transaction commits.
func purgeFederationRecordsTx(ctx context.Context, tx *sql.Tx, share string, ids []string, pending *recallEvidenceRevocationEvents) ([]string, error) {
	var deleted []string
	for _, id := range ids {
		var owned bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM federation_records WHERE share_uid=? AND session_id=?)`, share, id).Scan(&owned); err != nil {
			return nil, err
		}
		if !owned {
			continue
		}
		// Surviving entries may cite evidence from this session. Revoke their
		// provenance before the evidence cascades away with the session.
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT entry_id FROM recall_evidence WHERE session_id=?`, id)
		if err != nil {
			return nil, err
		}
		var entries []string
		for rows.Next() {
			var entry string
			if err = rows.Scan(&entry); err != nil {
				rows.Close()
				return nil, err
			}
			entries = append(entries, entry)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		if err = rows.Close(); err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if err = revokeRecallEvidenceEntryTx(ctx, tx, entry, id, recallEvidenceRevocationFederationWithdrawal, pending); err != nil {
				return nil, err
			}
		}
		// Only relationships within this share are federation-owned.
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET parent_session_id=NULL,relationship_type='' WHERE parent_session_id=? AND id IN (SELECT session_id FROM federation_records WHERE share_uid=?)`, id, share); err != nil {
			return nil, err
		}
		if _, err := deleteSessionPhysicalTx(ctx, tx, id); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM federation_records WHERE share_uid=? AND session_id=?`, share, id); err != nil {
			return nil, err
		}
		deleted = append(deleted, id)
	}
	return deleted, nil
}

type FederationInventoryItem struct {
	UID  string `json:"record_uid"`
	Hash string `json:"hash"`
}
type FederationInventoryPage struct {
	Round    string                    `json:"round"`
	Epoch    int64                     `json:"epoch"`
	Sequence int64                     `json:"sequence"`
	After    string                    `json:"after"`
	Through  string                    `json:"through"`
	Final    bool                      `json:"final"`
	Items    []FederationInventoryItem `json:"items"`
}
type FederationInventoryResult struct {
	Boundary string   `json:"boundary"`
	Covered  string   `json:"covered"`
	Missing  []string `json:"missing"`
	Extra    []string `json:"extra"`
	Complete bool     `json:"complete"`
	Changed  bool     `json:"-"`
}

// ReconcileFederationPage compares only the authenticated share's records.
// A range advances only when a repeated comparison observes no repairs needed.
func (db *DB) ReconcileFederationPage(ctx context.Context, enrollment, spoke, share string, page FederationInventoryPage) (FederationInventoryResult, error) {
	result := FederationInventoryResult{Missing: []string{}, Extra: []string{}}
	if page.Round == "" || len(page.Round) > 128 || len(page.Items) > 1000 || page.Epoch < 1 || page.Sequence < 0 || len(page.After) > 4096 || len(page.Through) > 4096 || (!page.Final && page.Through == "") || (page.Through != "" && page.Through <= page.After) {
		return result, ErrFederationInvalidBatch
	}
	previous := page.After
	for _, item := range page.Items {
		if item.UID <= previous || len(item.UID) > 4096 || item.Hash == "" || len(item.Hash) > 128 || (page.Through != "" && item.UID > page.Through) {
			return result, ErrFederationInvalidBatch
		}
		previous = item.UID
	}
	var purged []string
	var pending recallEvidenceRevocationEvents
	err := db.Update(ctx, func(tx *sql.Tx) error {
		var round, boundary string
		var epoch, sequence, completed int64
		err := tx.QueryRowContext(ctx, `SELECT h.reconcile_round,h.reconcile_boundary,h.epoch,h.sequence,h.completed_epoch FROM federation_hub_shares h JOIN federation_enrollments e ON e.enrollment_uid=h.enrollment_uid WHERE h.share_uid=? AND h.enrollment_uid=? AND h.state='active' AND e.spoke_archive_id=? AND e.revoked_at=''`, share, enrollment, spoke).Scan(&round, &boundary, &epoch, &sequence, &completed)
		if err != nil {
			return err
		}
		if epoch != page.Epoch || sequence != page.Sequence {
			return ErrFederationSequence
		}
		if round != page.Round {
			if page.After != "" {
				return ErrFederationSequence
			}
			round, boundary = page.Round, ""
			if _, err = tx.ExecContext(ctx, `UPDATE federation_hub_shares SET reconcile_round=?,reconcile_boundary='' WHERE share_uid=?`, round, share); err != nil {
				return err
			}
		}
		if page.After != boundary {
			return ErrFederationSequence
		}
		rows, err := tx.QueryContext(ctx, `SELECT record_uid,hash,epoch FROM federation_records WHERE share_uid=? AND record_uid>? AND (?='' OR record_uid<=?) ORDER BY record_uid LIMIT 1001`, share, page.After, page.Through, page.Through)
		if err != nil {
			return err
		}
		type record struct {
			id, hash string
			epoch    int64
		}
		var owned []record
		for rows.Next() {
			var r record
			if err = rows.Scan(&r.id, &r.hash, &r.epoch); err != nil {
				rows.Close()
				return err
			}
			owned = append(owned, r)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err = rows.Close(); err != nil {
			return err
		}
		end := page.Through
		if len(owned) > 1000 {
			end = owned[999].id
			owned = owned[:1000]
		}
		result.Boundary = end
		result.Covered = end
		desired := make(map[string]string, len(page.Items))
		for _, item := range page.Items {
			if end == "" || item.UID <= end {
				desired[item.UID] = item.Hash
			}
		}
		for _, r := range owned {
			hash, found := desired[r.id]
			if found {
				if hash != r.hash {
					result.Missing = append(result.Missing, r.id)
				} else if r.epoch != epoch {
					if _, err = tx.ExecContext(ctx, `UPDATE federation_records SET epoch=? WHERE share_uid=? AND record_uid=?`, epoch, share, r.id); err != nil {
						return err
					}
				}
				delete(desired, r.id)
			} else if completed >= epoch || r.epoch == epoch {
				result.Extra = append(result.Extra, r.id)
			}
		}
		for id := range desired {
			result.Missing = append(result.Missing, id)
		}
		sort.Strings(result.Missing)
		if len(result.Missing) > 0 || len(result.Extra) > 0 {
			result.Boundary = page.After
			return nil
		}
		if page.Final && end == "" {
			// The complete scan authorizes old-epoch cleanup, bounded per call.
			rows, err = tx.QueryContext(ctx, `SELECT session_id FROM federation_records WHERE share_uid=? AND epoch<>? ORDER BY session_id LIMIT 1000`, share, epoch)
			if err != nil {
				return err
			}
			var old []string
			for rows.Next() {
				var id string
				if err = rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				old = append(old, id)
			}
			if err = rows.Err(); err != nil {
				rows.Close()
				return err
			}
			if err = rows.Close(); err != nil {
				return err
			}
			purged, err = purgeFederationRecordsTx(ctx, tx, share, old, &pending)
			if err != nil {
				return err
			}
			if len(old) > 0 {
				result.Boundary = page.After
				return nil
			}
			result.Complete = true
			_, err = tx.ExecContext(ctx, `UPDATE federation_hub_shares SET completed_epoch=?,reconcile_boundary='' WHERE share_uid=?`, epoch, share)
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE federation_hub_shares SET reconcile_boundary=? WHERE share_uid=?`, end, share)
		return err
	})
	if err == nil {
		db.notifyUsageSessions(purged)
		pending.flush()
		result.Changed = len(purged) > 0
	}
	return result, err
}
