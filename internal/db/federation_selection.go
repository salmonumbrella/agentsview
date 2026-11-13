package db

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
)

// FederationSelection is a single archive snapshot, selected by each session's
// own repository identity and machine-local ownership evidence.
type FederationSelection struct {
	IDs         []string
	Rows        []SessionSummaryRow
	ProjectKeys map[string]string
	ToolCounts  map[string]int
	Outcomes    map[string]string
	Health      map[string]*string
	NotLocal    int
	// NotIdentifiable counts sessions without repository identity anywhere in the
	// archive and sessions whose identity for this repository is ambiguous.
	NotIdentifiable int
	Excluded        int
}

func (db *DB) SelectFederationSessions(ctx context.Context, remote, since string) (FederationSelection, error) {
	tx, err := db.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return FederationSelection{}, err
	}
	defer tx.Rollback()
	out, err := db.selectFederationSessionIDs(ctx, tx, remote, since)
	if err != nil {
		return out, err
	}
	err = QueryChunkedSize(out.IDs, maxSQLVars, func(ids []string) error {
		placeholders, args := InPlaceholders(ids)
		found, e := db.querySessionExportRowsFrom(ctx, tx, "sessions.id IN "+placeholders, args, 1e12, sessionExportCursorPayload{}, len(ids), sessionExportActivitySource{})
		if e != nil {
			return e
		}
		if _, e = db.attachSessionExportUsage(ctx, tx, found); e != nil {
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
	out, err := db.selectFederationSessionIDs(ctx, tx, remote, since)
	if err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	return out, nil
}

func (db *DB) selectFederationSessionIDs(ctx context.Context, tx *sql.Tx, remote, since string) (FederationSelection, error) {
	out := FederationSelection{IDs: []string{}, ProjectKeys: map[string]string{}, ToolCounts: map[string]int{}, Outcomes: map[string]string{}, Health: map[string]*string{}}
	ids, err := sessionIDsForProjectRemotes(ctx, tx, []string{remote})
	if err != nil {
		return out, err
	}
	selectedIDs := make(map[string]bool, len(ids))
	for _, id := range ids {
		selectedIDs[id] = true
	}
	rows, err := tx.QueryContext(ctx, `SELECT s.id, snap.key,
  (s.machine NOT IN ('', 'local') AND s.machine = COALESCE((SELECT value FROM pg_sync_state WHERE key='artifact_local_installation_id'),'')
   AND EXISTS (SELECT 1 FROM local_session_source_baselines b WHERE b.session_id=s.id AND b.machine=s.machine AND b.agent=s.agent AND b.file_path=s.file_path)
   AND NOT EXISTS (SELECT 1 FROM archive_session_provenance p WHERE p.session_id=s.id)
   AND NOT EXISTS (SELECT 1 FROM artifact_imported_sessions i WHERE i.imported_session_id=s.id)),
  EXISTS (SELECT 1 FROM federation_exclusions e WHERE e.session_id=s.id),
  (? = '' OR julianday(s.started_at) >= julianday(?)),
  (SELECT count(*) FROM tool_calls t WHERE t.session_id=s.id),s.outcome,s.health_grade
 FROM sessions s JOIN session_project_identity_snapshots snap ON snap.session_id=s.id
 WHERE s.deleted_at IS NULL AND snap.normalized_remote=? ORDER BY s.id`, since, since, remote)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var id, key, outcome string
		var local, excluded bool
		var inRange sql.NullBool
		var tools int
		var health sql.NullString
		if err = rows.Scan(&id, &key, &local, &excluded, &inRange, &tools, &outcome, &health); err != nil {
			rows.Close()
			return out, err
		}
		if !inRange.Valid || !inRange.Bool {
			continue
		}
		if !selectedIDs[id] {
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
		out.ProjectKeys[id] = key
		out.ToolCounts[id] = tools
		out.Outcomes[id] = outcome
		out.Health[id] = nullStringPtr(health)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, err
	}
	if err = rows.Close(); err != nil {
		return out, err
	}
	var withoutIdentity int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM sessions s WHERE s.deleted_at IS NULL AND NOT EXISTS (SELECT 1 FROM session_project_identity_snapshots i WHERE i.session_id=s.id)`).Scan(&withoutIdentity); err != nil {
		return out, err
	}
	out.NotIdentifiable += withoutIdentity
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
