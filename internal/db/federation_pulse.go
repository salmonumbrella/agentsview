package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.kenn.io/agentsview/internal/export"
)

// federationPulseOwner is private authority evidence and must not enter a DTO.
type federationPulseOwner struct {
	member  string
	project string
}

// federationPulseScope reads record ownership and live sessions in the caller's
// snapshot. The session's machine or display project never establishes authority.
func federationPulseScope(ctx context.Context, tx *sql.Tx) (map[string]federationPulseOwner, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT s.id, e.member, h.project_key
		FROM federation_records r
		JOIN sessions s ON s.id=r.session_id
		JOIN federation_hub_shares h ON h.share_uid=r.share_uid
		JOIN federation_enrollments e ON e.enrollment_uid=h.enrollment_uid
		WHERE s.deleted_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM excluded_sessions x WHERE x.id=s.id)
		  AND NOT EXISTS (SELECT 1 FROM federation_exclusions x WHERE x.session_id=s.id)
		  AND ((h.state='active' AND e.revoked_at='') OR
		       (h.state='stopped' AND h.retention='org-retained'))`)
	if err != nil {
		return nil, fmt.Errorf("query federation pulse scope: %w", err)
	}
	defer rows.Close()
	owners := map[string]federationPulseOwner{}
	for rows.Next() {
		var id string
		var owner federationPulseOwner
		if err := rows.Scan(&id, &owner.member, &owner.project); err != nil {
			return nil, fmt.Errorf("scan federation pulse scope: %w", err)
		}
		if strings.TrimSpace(owner.member) == "" || owner.project == "" {
			continue
		}
		owners[id] = owner
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read federation pulse scope: %w", err)
	}
	return owners, nil
}

func parseFederationPulseSince(value string, now time.Time) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	date, err := time.Parse(time.DateOnly, value)
	if err != nil || date.Format(time.DateOnly) != value {
		return nil, fmt.Errorf("invalid pulse date %q: expected YYYY-MM-DD", value)
	}
	if date.After(now.UTC().Truncate(24 * time.Hour)) {
		return nil, fmt.Errorf("pulse date is in the future")
	}
	return &date, nil
}

// readFederationPulseSnapshot holds one archive snapshot for all authority,
// range and daily inputs. The callback must not retain daily source graphs.
func (db *DB) readFederationPulseSnapshot(
	ctx context.Context, since string, now time.Time,
	visit func(*sql.Tx, time.Time, time.Time, map[string]federationPulseOwner, reportingDaySource) error,
) (ReportingRange, error) {
	if now.IsZero() {
		now = time.Now()
	}
	requested, err := parseFederationPulseSince(since, now)
	if err != nil {
		return ReportingRange{}, err
	}
	release, err := db.acquireBulkRead(ctx)
	if err != nil {
		return ReportingRange{}, err
	}
	defer release()
	tx, err := db.getReader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ReportingRange{}, fmt.Errorf("begin federation pulse snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	owners, err := federationPulseScope(ctx, tx)
	if err != nil {
		return ReportingRange{}, err
	}
	scope := make(map[string]struct{}, len(owners))
	for id := range owners {
		scope[id] = struct{}{}
	}
	rng, err := reportingRangeFrom(ctx, tx, now, scope)
	if err != nil {
		return ReportingRange{}, err
	}
	start := requested
	if start == nil && rng.EarliestDate != nil {
		date, parseErr := time.Parse(time.DateOnly, *rng.EarliestDate)
		if parseErr != nil {
			return ReportingRange{}, parseErr
		}
		start = &date
	}
	cutoff := now.UTC().Truncate(time.Hour)
	if start != nil {
		for date := *start; date.Before(cutoff); date = date.AddDate(0, 0, 1) {
			if err := ctx.Err(); err != nil {
				return ReportingRange{}, err
			}
			end := date.AddDate(0, 0, 1)
			if end.After(cutoff) {
				end = cutoff
			}
			source, err := db.loadReportingExportSourceScoped(ctx, tx, date, end, export.ReportingJointSchemaVersion, scope)
			if err != nil {
				return ReportingRange{}, err
			}
			if err := visit(tx, date, end, owners, source.forDate(date, end)); err != nil {
				return ReportingRange{}, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return ReportingRange{}, fmt.Errorf("commit federation pulse snapshot: %w", err)
	}
	return rng, nil
}

// federationPulseSuppression closes all numeric projections of a project when
// either a cell or an atom formed by intersecting cells has too little support.
// Its keys and support sets are private and never enter the released response.
func federationPulseSuppression(
	support map[string]map[string]map[string]struct{}, owners map[string]federationPulseOwner, minimum int,
) (map[string]bool, bool) {
	if minimum < 1 {
		minimum = 1
	}
	hidden := map[string]bool{}
	for project, cells := range support {
		memberships := map[string][]string{}
		for cell, sessions := range cells {
			members := map[string]struct{}{}
			for id := range sessions {
				owner, ok := owners[id]
				if !ok || owner.member == "" {
					hidden[project] = true
					continue
				}
				members[owner.member] = struct{}{}
				memberships[id] = append(memberships[id], cell)
			}
			if len(sessions) > 0 && len(members) < minimum {
				hidden[project] = true
			}
		}
		atoms := map[string]map[string]struct{}{}
		for id, cells := range memberships {
			slices.Sort(cells)
			// JSON gives an unambiguous representation of arbitrary cell names.
			key, _ := json.Marshal(cells)
			if atoms[string(key)] == nil {
				atoms[string(key)] = map[string]struct{}{}
			}
			atoms[string(key)][owners[id].member] = struct{}{}
		}
		for _, members := range atoms {
			if len(members) < minimum {
				hidden[project] = true
			}
		}
	}
	return hidden, len(hidden) > 0
}
