package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
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
