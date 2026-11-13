package db

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
)

const federationLocalOrigin = `(s.machine NOT IN ('', 'local') AND s.machine = COALESCE((SELECT value FROM pg_sync_state WHERE key='artifact_local_installation_id'),'')
   AND EXISTS (SELECT 1 FROM local_session_source_baselines b WHERE b.session_id=s.id AND b.machine=s.machine AND b.agent=s.agent AND b.file_path=s.file_path)
   AND NOT EXISTS (SELECT 1 FROM archive_session_provenance p WHERE p.session_id=s.id)
   AND NOT EXISTS (SELECT 1 FROM artifact_imported_sessions i WHERE i.imported_session_id=s.id))`

// The same grant applies to pages, candidates, parents, and usage peers.
const federationIdentityEligible = `(snap.normalized_remote<>'' AND snap.remote_resolution='resolved' AND snap.key_source='git_remote' AND snap.remote_candidate_count<=1)`
const federationGrantEligible = `(` + federationIdentityEligible + ` AND ` + federationLocalOrigin + ` AND NOT EXISTS (SELECT 1 FROM federation_exclusions e WHERE e.session_id=s.id) AND (?='' OR julianday(s.started_at)>=julianday(?)))`

// FederationSelection is a single archive snapshot, selected by each session's
// own repository identity and machine-local ownership evidence.
type FederationSelection struct {
	IDs             []string
	Rows            []SessionSummaryRow
	ProjectKeys     map[string]string
	ToolCounts      map[string]int
	Outcomes        map[string]string
	Health          map[string]*string
	EligibleParents map[string]bool
	NotLocal        int
	// NotIdentifiable counts ambiguous identities for this repository in both paths.
	// SelectFederationSessions also counts sessions without identity in the archive.
	NotIdentifiable int
	Excluded        int
}

func (db *DB) SelectFederationSessions(ctx context.Context, remote, since string) (FederationSelection, error) {
	tx, err := db.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return FederationSelection{}, err
	}
	defer tx.Rollback()
	out, err := db.selectFederationSessionIDs(ctx, tx, remote, since, "", 0, nil)
	if err != nil {
		return out, err
	}
	var withoutIdentity int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM sessions s WHERE s.deleted_at IS NULL AND NOT EXISTS (SELECT 1 FROM session_project_identity_snapshots i WHERE i.session_id=s.id)`).Scan(&withoutIdentity); err != nil {
		return out, err
	}
	out.NotIdentifiable += withoutIdentity
	allowed := make(map[string]bool, len(out.IDs))
	for _, id := range out.IDs {
		allowed[id] = true
	}
	err = QueryChunkedSize(out.IDs, maxSQLVars, func(ids []string) error {
		placeholders, args := InPlaceholders(ids)
		found, e := db.querySessionExportRowsFrom(ctx, tx, "sessions.id IN "+placeholders, args, 1e12, sessionExportCursorPayload{}, len(ids), sessionExportActivitySource{})
		if e != nil {
			return e
		}
		if _, e = db.attachSessionExportUsageWithin(ctx, tx, found, allowed); e != nil {
			return e
		}
		out.Rows = append(out.Rows, found...)
		return nil
	})
	if err != nil {
		return out, fmt.Errorf("selecting federation rows: %w", err)
	}
	sort.Slice(out.Rows, func(i, j int) bool { return out.Rows[i].ID < out.Rows[j].ID })
	if err = tx.Commit(); err != nil {
		return out, err
	}
	return out, nil
}

// SelectFederationSessionIDs selects candidates without loading summaries or usage.
func (db *DB) SelectFederationSessionIDs(ctx context.Context, remote, since string) (FederationSelection, error) {
	tx, err := db.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return FederationSelection{}, err
	}
	defer tx.Rollback()
	out, err := db.selectFederationSessionIDs(ctx, tx, remote, since, "", 0, nil)
	if err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	return out, nil
}

// selectFederationSessionIDs is the single grant owner. A zero limit retains
// preview diagnostics; bounded calls filter before applying the keyset limit.
func (db *DB) selectFederationSessionIDs(ctx context.Context, tx *sql.Tx, remote, since, after string, limit int, candidates []string) (FederationSelection, error) {
	out := FederationSelection{IDs: []string{}, ProjectKeys: map[string]string{}, ToolCounts: map[string]int{}, Outcomes: map[string]string{}, Health: map[string]*string{}, EligibleParents: map[string]bool{}}
	query := `SELECT s.id,snap.key,` + federationIdentityEligible + `,` + federationLocalOrigin + `,
		EXISTS (SELECT 1 FROM federation_exclusions e WHERE e.session_id=s.id),
		(?='' OR julianday(s.started_at)>=julianday(?)),
		(SELECT count(*) FROM tool_calls t WHERE t.session_id=s.id),s.outcome,s.health_grade
		FROM sessions s JOIN session_project_identity_snapshots snap ON snap.session_id=s.id
		WHERE s.deleted_at IS NULL AND snap.normalized_remote=?`
	args := []any{since, since, remote}
	if limit > 0 {
		query += ` AND s.id>? AND ` + federationGrantEligible
		args = append(args, after, since, since)
		if candidates != nil {
			placeholders, values := InPlaceholders(candidates)
			query += ` AND s.id IN ` + placeholders
			args = append(args, values...)
		}
	}
	query += ` ORDER BY s.id`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, key, outcome string
		var identity, local, excluded bool
		var inRange sql.NullBool
		var tools int
		var health sql.NullString
		if err = rows.Scan(&id, &key, &identity, &local, &excluded, &inRange, &tools, &outcome, &health); err != nil {
			return out, err
		}
		if !inRange.Valid || !inRange.Bool {
			continue
		}
		if !identity {
			out.NotIdentifiable++
			continue
		}
		if !local {
			out.NotLocal++
			continue
		}
		if excluded {
			out.Excluded++
			continue
		}
		out.IDs = append(out.IDs, id)
		out.ProjectKeys[id], out.ToolCounts[id], out.Outcomes[id], out.Health[id] = key, tools, outcome, nullStringPtr(health)
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	if err = rows.Close(); err != nil {
		return out, err
	}
	return out, nil
}

// FederationProjectRemotes lists candidates; callers must apply local-origin
// selection before suggesting a remote to the member.
func (db *DB) FederationProjectRemotes(ctx context.Context) ([]string, error) {
	rows, err := db.getReader().QueryContext(ctx, `SELECT DISTINCT normalized_remote FROM session_project_identity_snapshots WHERE normalized_remote<>'' AND remote_resolution='resolved' AND key_source='git_remote' AND remote_candidate_count<=1 ORDER BY normalized_remote`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var remote string
		if err := rows.Scan(&remote); err != nil {
			return nil, err
		}
		out = append(out, remote)
	}
	return out, rows.Err()
}

// SelectFederationPage reads a bounded ID-keyset and its summaries in one
// snapshot. Parent eligibility is evaluated independently of page membership.
func (db *DB) SelectFederationPage(ctx context.Context, remote, since, after string, limit int) (FederationSelection, error) {
	return db.selectFederationPage(ctx, remote, since, after, limit, nil)
}
func (db *DB) SelectFederationCandidates(ctx context.Context, remote, since string, candidates []string) (FederationSelection, error) {
	if len(candidates) == 0 {
		return FederationSelection{}, nil
	}
	return db.selectFederationPage(ctx, remote, since, "", len(candidates), candidates)
}
func (db *DB) selectFederationPage(ctx context.Context, remote, since, after string, limit int, candidates []string) (FederationSelection, error) {
	if limit < 1 || limit > 1000 {
		return FederationSelection{}, fmt.Errorf("invalid federation page limit")
	}
	tx, err := db.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return FederationSelection{}, err
	}
	defer tx.Rollback()
	out, err := db.selectFederationSessionIDs(ctx, tx, remote, since, after, limit, candidates)
	if err != nil {
		return out, err
	}
	if len(out.IDs) > 0 {
		placeholders, args := InPlaceholders(out.IDs)
		out.Rows, err = db.querySessionExportRowsFrom(ctx, tx, "sessions.id IN "+placeholders, args, 1e12, sessionExportCursorPayload{}, len(out.IDs), sessionExportActivitySource{})
		if err != nil {
			return out, err
		}
		filterPeers := func(ids []string) (map[string]bool, error) {
			allowed := make(map[string]bool)
			err := QueryChunkedSize(ids, 400, func(chunk []string) error {
				selected, err := db.selectFederationSessionIDs(ctx, tx, remote, since, "", len(chunk), chunk)
				if err != nil {
					return err
				}
				for _, id := range selected.IDs {
					allowed[id] = true
				}
				return nil
			})
			return allowed, err
		}
		if _, err = db.attachSessionExportUsageFiltered(ctx, tx, out.Rows, nil, filterPeers); err != nil {
			return out, err
		}
		var parents []string
		for _, row := range out.Rows {
			if row.ParentSessionID != nil {
				parents = append(parents, *row.ParentSessionID)
			}
		}
		if len(parents) > 0 {
			eligible, err := filterPeers(parents)
			if err != nil {
				return out, err
			}
			for _, id := range parents {
				out.EligibleParents[id] = eligible[id]
			}
		}
	}
	sort.Slice(out.Rows, func(i, j int) bool { return out.Rows[i].ID < out.Rows[j].ID })
	if err = tx.Commit(); err != nil {
		return out, err
	}
	return out, nil
}

// FederationChangedCandidates returns a bounded union of existing change
// signals and ledger-backed removals, without filtering by display labels.
func (db *DB) FederationChangedCandidates(ctx context.Context, share, marker string, usageAfter, usageThrough, deletionAfter, deletionThrough int64, after string, limit int) ([]string, error) {
	if limit < 1 || limit > 1000 || usageAfter > usageThrough || deletionAfter > deletionThrough {
		return nil, fmt.Errorf("invalid federation change window")
	}
	rows, err := db.getReader().QueryContext(ctx, `SELECT id FROM (
		SELECT id FROM sessions WHERE (?='' OR sync_marker>=?) AND id>?
		UNION SELECT session_id FROM usage_session_changes WHERE revision>? AND revision<=? AND session_id>?
		UNION SELECT session_id FROM session_deletion_changes WHERE revision>? AND revision<=? AND session_id>?
		UNION SELECT e.session_id FROM federation_exclusions e JOIN federation_deliveries d ON d.session_id=e.session_id WHERE d.share_uid=? AND d.state NOT IN ('refused','tombstoned') AND e.session_id>?
	) ORDER BY id LIMIT ?`, marker, marker, after, usageAfter, usageThrough, after, deletionAfter, deletionThrough, after, share, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// FederationRetainedExclusions returns a bounded page of explicit exclusions
// with outstanding delivery evidence for a stopped share.
func (db *DB) FederationRetainedExclusions(ctx context.Context, share, after string, limit int) ([]string, error) {
	rows, err := db.getReader().QueryContext(ctx, `SELECT d.record_uid FROM federation_deliveries d JOIN federation_exclusions e ON e.session_id=d.session_id WHERE d.share_uid=? AND d.state NOT IN ('refused','tombstoned') AND d.record_uid>? ORDER BY d.record_uid LIMIT ?`, share, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// FederationRetainedMissing reports unproven absence after a restore.
func (db *DB) FederationRetainedMissing(ctx context.Context, share string) (bool, error) {
	var missing bool
	err := db.getReader().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM federation_deliveries d WHERE d.share_uid=? AND d.state NOT IN ('refused','tombstoned') AND NOT EXISTS(SELECT 1 FROM sessions s WHERE s.id=d.session_id) AND NOT EXISTS(SELECT 1 FROM federation_exclusions e WHERE e.session_id=d.session_id))`, share).Scan(&missing)
	return missing, err
}

func (db *DB) FederationExplicitExclusions(ctx context.Context, share string, ids []string) (map[string]bool, error) {
	out := make(map[string]bool, len(ids))
	err := QueryChunkedSize(ids, 400, func(chunk []string) error {
		placeholders, args := InPlaceholders(chunk)
		args = append([]any{share}, args...)
		rows, err := db.getReader().QueryContext(ctx, `SELECT d.record_uid FROM federation_deliveries d JOIN federation_exclusions e ON e.session_id=d.session_id WHERE d.share_uid=? AND d.record_uid IN `+placeholders, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out[id] = true
		}
		return rows.Err()
	})
	return out, err
}
