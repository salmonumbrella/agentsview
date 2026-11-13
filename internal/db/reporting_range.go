package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"go.kenn.io/agentsview/internal/activity"
)

// ReportingRange discovers dated evidence in closed UTC reporting hours.
// Its schema is independent of the hour, day, and digest schemas.
type ReportingRange struct {
	SchemaVersion int     `json:"schema_version"`
	EarliestDate  *string `json:"earliest_date"`
	ClosedThrough string  `json:"closed_through"`
}

// ExportReportingRange returns a conservative starting date and an exclusive
// closed-hour cutoff. It reads timestamp metadata in one SQLite statement;
// discovery does not aggregate bodies, deduplicate usage, or promise completeness.
func (db *DB) ExportReportingRange(ctx context.Context, now time.Time) (ReportingRange, error) {
	return reportingRangeFrom(ctx, db.getReader(), now, nil)
}

func reportingRangeFrom(ctx context.Context, reader sessionExportQuerier, now time.Time, scope map[string]struct{}) (ReportingRange, error) {
	result, _, err := reportingEvidenceDaysFrom(ctx, reader, now, scope, false)
	return result, err
}

// reportingEvidenceDaysFrom shares the range timestamp selection with pulse's
// private itinerary. Both reads use the caller's snapshot and ownership scope.
func reportingEvidenceDaysFrom(ctx context.Context, reader sessionExportQuerier, now time.Time, scope map[string]struct{}, collect bool) (ReportingRange, []time.Time, error) {
	if now.IsZero() {
		now = time.Now()
	}
	cutoff := now.UTC().Truncate(time.Hour)
	result := ReportingRange{SchemaVersion: 1, ClosedThrough: cutoff.Format(time.RFC3339)}
	var earliest sql.NullInt64
	// Keep the activity eligibility used by reportingHoursFromSnapshot. Usage
	// eligibility is independent: a session with no activity may still have cost.
	// ponytail: scan timestamp metadata; index normalized bounds if discovery
	// becomes a measured bottleneck on large archives.
	activityWhere, _ := (AnalyticsFilter{IncludeSubagents: true, IncludeForks: true}).buildWhereWithDate("", false, "s.id")
	if scope != nil {
		activityWhere = "s.deleted_at IS NULL"
	}
	existenceWhere := "s.deleted_at IS NULL"
	var hasCursorUsage bool
	err := reader.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'cursor_usage_events'
	)`).Scan(&hasCursorUsage)
	if err != nil {
		return ReportingRange{}, nil, fmt.Errorf("checking standalone reporting usage table: %w", err)
	}
	standaloneUsage := ""
	if hasCursorUsage && scope == nil {
		standaloneUsage = `UNION ALL
			SELECT agentsview_timestamp_unix_micro(occurred_at)
			FROM cursor_usage_events`
	}
	var args []any
	scopeWhere := ""
	if scope != nil {
		ids := make([]string, 0, len(scope))
		for id := range scope {
			ids = append(ids, id)
		}
		encoded, err := json.Marshal(ids)
		if err != nil {
			return ReportingRange{}, nil, fmt.Errorf("encode reporting scope: %w", err)
		}
		args = append(args, string(encoded))
		scopeWhere = " AND s.id IN (SELECT value FROM json_each(?1))"
	}
	timestamps := `
		WITH timestamps(ts) AS (
			SELECT COALESCE(agentsview_timestamp_unix_micro(COALESCE(s.started_at, '')),
				agentsview_timestamp_unix_micro(s.created_at))
			FROM sessions s WHERE (` + existenceWhere + `)` + scopeWhere + `
			UNION ALL
			SELECT agentsview_timestamp_unix_micro(COALESCE(
				NULLIF(m.timestamp, ''), NULLIF(s.started_at, ''), s.created_at))
			FROM messages m JOIN sessions s ON s.id = m.session_id
			WHERE ((` + activityWhere + `) OR (` + usageMessageEligibility + `))` + scopeWhere + `
			UNION ALL
			SELECT agentsview_timestamp_unix_micro(COALESCE(
				NULLIF(ue.occurred_at, ''), NULLIF(s.started_at, ''), s.created_at))
			FROM usage_events ue JOIN sessions s ON s.id = ue.session_id
			WHERE (` + usageEventEligibility + `)` + scopeWhere + `
			UNION ALL
			SELECT agentsview_timestamp_unix_micro(COALESCE(
				NULLIF(tre.timestamp, ''), NULLIF(s.started_at, ''), s.created_at))
			FROM tool_result_events tre JOIN sessions s ON s.id = tre.session_id
			WHERE ` + activityWhere + ` AND tre.source = 'tool_execution'
				AND tre.status IN ('completed', 'errored')` + scopeWhere + `
			` + standaloneUsage + `
		)`
	err = reader.QueryRowContext(ctx, timestamps+` SELECT MIN(ts) FROM timestamps`, args...).Scan(&earliest)
	if err != nil {
		return ReportingRange{}, nil, fmt.Errorf("query reporting range: %w", err)
	}
	if earliest.Valid && earliest.Int64 < cutoff.UnixMicro() {
		result.EarliestDate = new(time.UnixMicro(earliest.Int64).UTC().Format(time.DateOnly))
	}
	if !collect {
		return result, nil, nil
	}
	days := make(map[time.Time]struct{})
	addDay := func(at time.Time) {
		at = at.UTC()
		if at.Before(cutoff) {
			days[time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)] = struct{}{}
		}
	}
	// A selected session may use creation as first-seen when its earlier start
	// is outside the requested day. Include that day when the source window
	// can select the session; timed usage already contributes its own date.
	creation := ""
	if scope != nil {
		creation = ` UNION ALL
			SELECT agentsview_timestamp_unix_micro(s.created_at) FROM sessions s
			WHERE s.deleted_at IS NULL` + scopeWhere + `
			AND agentsview_timestamp_unix_micro(s.created_at) >= COALESCE(
				agentsview_timestamp_unix_micro(NULLIF(s.started_at,'')),
				agentsview_timestamp_unix_micro(s.created_at))
			AND (agentsview_timestamp_unix_micro(s.ended_at) >= agentsview_timestamp_unix_micro(s.created_at)
			 OR (COALESCE(s.ended_at,'')='' AND EXISTS (SELECT 1 FROM messages m WHERE m.session_id=s.id
				 AND agentsview_timestamp_unix_micro(m.timestamp) >= agentsview_timestamp_unix_micro(s.created_at)))
			 OR EXISTS (SELECT 1 FROM tool_result_events tre WHERE tre.session_id=s.id AND tre.source='tool_execution'
				 AND tre.status IN ('completed','errored') AND agentsview_timestamp_unix_micro(tre.timestamp) >= agentsview_timestamp_unix_micro(s.created_at)))`
	}
	rows, err := reader.QueryContext(ctx, timestamps+` SELECT ts FROM timestamps WHERE ts IS NOT NULL`+creation, args...)
	if err != nil {
		return ReportingRange{}, nil, fmt.Errorf("query reporting evidence dates: %w", err)
	}
	for rows.Next() {
		var ts int64
		if err := rows.Scan(&ts); err != nil {
			_ = rows.Close()
			return ReportingRange{}, nil, err
		}
		addDay(time.UnixMicro(ts))
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return ReportingRange{}, nil, err
	}
	if err := rows.Close(); err != nil {
		return ReportingRange{}, nil, err
	}
	// Preserve ordinal adjacency, including malformed timestamps, as the existing
	// first-seen operation does. A later event can close an interval before cutoff.
	if scope != nil {
		rows, err := reader.QueryContext(ctx, `SELECT s.id, agentsview_timestamp_unix_micro(m.timestamp)
   FROM messages m JOIN sessions s ON s.id=m.session_id
   WHERE (`+activityWhere+`)`+scopeWhere+` AND m.timestamp IS NOT NULL AND m.timestamp != ''
   ORDER BY s.id, m.ordinal`, args...)
		if err != nil {
			return ReportingRange{}, nil, fmt.Errorf("query reporting activity dates: %w", err)
		}
		query, err := activity.ResolveQuery(activity.QueryInput{Preset: "custom", From: cutoff.Add(-time.Hour).Format(time.RFC3339), To: cutoff.Format(time.RFC3339), Timezone: "UTC"}, cutoff)
		if err != nil {
			_ = rows.Close()
			return ReportingRange{}, nil, err
		}
		var previousID string
		var previous sql.NullInt64
		for rows.Next() {
			var id string
			var current sql.NullInt64
			if err := rows.Scan(&id, &current); err != nil {
				_ = rows.Close()
				return ReportingRange{}, nil, err
			}
			if id == previousID && previous.Valid && current.Valid {
				from := time.UnixMicro(previous.Int64).UTC()
				to := time.UnixMicro(current.Int64).UTC()
				start, end, ok := activity.EffectiveIntervalBounds(from, to, from, cutoff, time.Duration(query.GapCapSeconds)*time.Second)
				if ok {
					addDay(start)
					addDay(end.Add(-time.Nanosecond))
				}
			}
			previousID, previous = id, current
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return ReportingRange{}, nil, err
		}
		if err := rows.Close(); err != nil {
			return ReportingRange{}, nil, err
		}
	}
	ordered := make([]time.Time, 0, len(days))
	for day := range days {
		ordered = append(ordered, day)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Before(ordered[j]) })
	return result, ordered, nil
}
