package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"go.kenn.io/agentsview/internal/activity"
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
	observe func(*sql.Tx) error,
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
	if observe != nil {
		if err := observe(tx); err != nil {
			return ReportingRange{}, err
		}
	}
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
	var start *time.Time
	if rng.EarliestDate != nil {
		date, parseErr := time.Parse(time.DateOnly, *rng.EarliestDate)
		if parseErr != nil {
			return ReportingRange{}, parseErr
		}
		if requested != nil && requested.After(date) {
			date = *requested
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

func federationPulseSignals(ctx context.Context, tx *sql.Tx, ids []string) (map[string]SignalRow, error) {
	out := make(map[string]SignalRow, len(ids))
	err := queryChunked(ids, func(chunk []string) error {
		ph, args := InPlaceholders(chunk)
		rows, err := tx.QueryContext(ctx, `SELECT id, outcome, health_grade FROM sessions WHERE id IN `+ph, args...)
		if err != nil {
			return fmt.Errorf("query pulse signals: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var row SignalRow
			var grade sql.NullString
			if err := rows.Scan(&row.ID, &row.Outcome, &grade); err != nil {
				return fmt.Errorf("scan pulse signals: %w", err)
			}
			if grade.Valid {
				row.HealthGrade = &grade.String
			}
			out[row.ID] = row
		}
		return rows.Err()
	})
	return out, err
}

// FederationPulseMetric makes missing evidence and privacy withholding explicit.
type FederationPulseMetric struct {
	Value *int64 `json:"value"`
	State string `json:"state"`
}

type FederationPulseRatio struct {
	Value *float64 `json:"value"`
	State string   `json:"state"`
}

type FederationPulseGroup struct {
	Key     string                           `json:"key"`
	Metrics map[string]FederationPulseMetric `json:"metrics"`
}

type FederationPulseProject struct {
	Key        string                           `json:"key"`
	Totals     map[string]FederationPulseMetric `json:"totals"`
	Ratios     map[string]FederationPulseRatio  `json:"ratios"`
	Agents     []FederationPulseGroup           `json:"agents"`
	Models     []FederationPulseGroup           `json:"models"`
	Outcomes   []FederationPulseGroup           `json:"outcomes"`
	Grades     []FederationPulseGroup           `json:"grades"`
	Categories []FederationPulseGroup           `json:"categories"`
}

type FederationPulseLink struct {
	SpokeName           string                `json:"spoke_name"`
	State               string                `json:"state"`
	LastContactAt       *string               `json:"last_contact_at"`
	LastDeliveryAt      *string               `json:"last_delivery_at"`
	BacklogLagSeconds   FederationPulseMetric `json:"backlog_lag_seconds"`
	LatestBatchRefusals []string              `json:"latest_batch_refusals"`
}

type FederationPulse struct {
	Since         *string                          `json:"since"`
	ClosedThrough string                           `json:"closed_through"`
	Totals        map[string]FederationPulseMetric `json:"totals"`
	Ratios        map[string]FederationPulseRatio  `json:"ratios"`
	Projects      []FederationPulseProject         `json:"projects"`
	Agents        []FederationPulseGroup           `json:"agents"`
	Models        []FederationPulseGroup           `json:"models"`
	Outcomes      []FederationPulseGroup           `json:"outcomes"`
	Grades        []FederationPulseGroup           `json:"grades"`
	Categories    []FederationPulseGroup           `json:"categories"`
	Links         []FederationPulseLink            `json:"links"`
	Suppressed    bool                             `json:"suppressed"`
}

type federationPulseCellKey struct{ kind, key, metric string }
type federationPulseCell struct {
	value    int64
	sessions map[string]struct{}
}
type federationPulseAccumulator struct {
	owners         map[string]federationPulseOwner
	projects       map[string]map[federationPulseCellKey]*federationPulseCell
	unsafeProjects map[string]bool
	invalid        bool
}

func newFederationPulseAccumulator(owners map[string]federationPulseOwner) *federationPulseAccumulator {
	return &federationPulseAccumulator{owners: owners, projects: map[string]map[federationPulseCellKey]*federationPulseCell{}, unsafeProjects: map[string]bool{}}
}

func (a *federationPulseAccumulator) add(id, kind, key, metric string, value int64) {
	owner, ok := a.owners[id]
	if !ok || owner.member == "" || owner.project == "" {
		a.invalid = true
		return
	}
	cells := a.projects[owner.project]
	if cells == nil {
		cells = map[federationPulseCellKey]*federationPulseCell{}
		a.projects[owner.project] = cells
	}
	cellKey := federationPulseCellKey{kind, key, metric}
	cell := cells[cellKey]
	if cell == nil {
		cell = &federationPulseCell{sessions: map[string]struct{}{}}
		cells[cellKey] = cell
	}
	if value > 0 && cell.value > math.MaxInt64-value || value < 0 && cell.value < math.MinInt64-value {
		a.invalid = true
		return
	}
	cell.value += value
	cell.sessions[id] = struct{}{}
}

var federationPulseTotalMetrics = []string{
	"sessions", "active_projects", "tokens", "cost_microdollars", "automated_sessions",
	"usage_observed_sessions", "health_observed_sessions", "outcome_observed_sessions",
}

func federationPulseMetrics(cells map[federationPulseCellKey]*federationPulseCell, kind, key string, defaults []string, suppressed bool) map[string]FederationPulseMetric {
	out := make(map[string]FederationPulseMetric, len(defaults))
	for _, metric := range defaults {
		state := "unavailable"
		if suppressed {
			state = "suppressed"
		}
		out[metric] = FederationPulseMetric{State: state}
	}
	for k, cell := range cells {
		if k.kind != kind || k.key != key {
			continue
		}
		if suppressed {
			out[k.metric] = FederationPulseMetric{State: "suppressed"}
		} else {
			value := cell.value
			out[k.metric] = FederationPulseMetric{Value: &value, State: "available"}
		}
	}
	return out
}

func federationPulseGroups(cells map[federationPulseCellKey]*federationPulseCell, kind string) []FederationPulseGroup {
	keys := map[string]struct{}{}
	for key := range cells {
		if key.kind == kind {
			keys[key.key] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	slices.Sort(ordered)
	out := make([]FederationPulseGroup, 0, len(ordered))
	for _, key := range ordered {
		out = append(out, FederationPulseGroup{Key: key, Metrics: federationPulseMetrics(cells, kind, key, nil, false)})
	}
	return out
}

func federationPulseRatios(totals map[string]FederationPulseMetric) map[string]FederationPulseRatio {
	out := map[string]FederationPulseRatio{}
	for name, numerator := range map[string]string{
		"automation_share": "automated_sessions", "usage_coverage": "usage_observed_sessions",
		"health_coverage": "health_observed_sessions", "outcome_coverage": "outcome_observed_sessions",
	} {
		n, d := totals[numerator], totals["sessions"]
		state := "unavailable"
		var value *float64
		if n.State == "suppressed" || d.State == "suppressed" {
			state = "suppressed"
		} else if n.Value != nil && d.Value != nil && *d.Value > 0 {
			ratio := float64(*n.Value) / float64(*d.Value)
			value, state = &ratio, "available"
		}
		out[name] = FederationPulseRatio{Value: value, State: state}
	}
	return out
}

func (a *federationPulseAccumulator) release(minimum int) FederationPulse {
	support := map[string]map[string]map[string]struct{}{}
	for project, cells := range a.projects {
		support[project] = map[string]map[string]struct{}{}
		for key, cell := range cells {
			encoded, _ := json.Marshal([]string{key.kind, key.key, key.metric})
			support[project][string(encoded)] = cell.sessions
		}
	}
	hidden, suppressGlobal := federationPulseSuppression(support, a.owners, minimum)
	for project := range a.unsafeProjects {
		hidden[project] = true
		suppressGlobal = true
	}
	suppressGlobal = suppressGlobal || a.invalid
	global := map[federationPulseCellKey]*federationPulseCell{}
	projects := make([]FederationPulseProject, 0, len(a.projects))
	keys := make([]string, 0, len(a.projects))
	for key := range a.projects {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		cells := a.projects[key]
		if !hidden[key] && !a.invalid {
			totals := federationPulseMetrics(cells, "total", "", federationPulseTotalMetrics, false)
			projects = append(projects, FederationPulseProject{Key: key,
				Totals: totals, Ratios: federationPulseRatios(totals),
				Agents: federationPulseGroups(cells, "agent"), Models: federationPulseGroups(cells, "model"),
				Outcomes: federationPulseGroups(cells, "outcome"), Grades: federationPulseGroups(cells, "grade"), Categories: federationPulseGroups(cells, "category")})
		}
		for cellKey, cell := range cells {
			g := global[cellKey]
			if g == nil {
				g = &federationPulseCell{sessions: map[string]struct{}{}}
				global[cellKey] = g
			}
			if cell.value > 0 && g.value > math.MaxInt64-cell.value || cell.value < 0 && g.value < math.MinInt64-cell.value {
				suppressGlobal = true
			} else {
				g.value += cell.value
			}
			for id := range cell.sessions {
				g.sessions[id] = struct{}{}
			}
		}
	}
	totals := federationPulseMetrics(global, "total", "", federationPulseTotalMetrics, suppressGlobal)
	result := FederationPulse{Totals: totals, Ratios: federationPulseRatios(totals), Projects: projects, Suppressed: suppressGlobal}
	if !suppressGlobal {
		result.Agents = federationPulseGroups(global, "agent")
		result.Models = federationPulseGroups(global, "model")
		result.Outcomes = federationPulseGroups(global, "outcome")
		result.Grades = federationPulseGroups(global, "grade")
		result.Categories = federationPulseGroups(global, "category")
	}
	return result
}

// readFederationPulse builds one private aggregate, then releases it once.
func (db *DB) readFederationPulse(ctx context.Context, since string, minimum int, now time.Time) (FederationPulse, error) {
	var accumulator *federationPulseAccumulator
	sessions := map[string]activity.SessionMeta{}
	signals := map[string]SignalRow{}
	usageSeen := map[string]bool{}
	modelsSeen := map[string]map[string]bool{}
	rememberModel := func(id, model string) {
		if model == "" {
			return
		}
		if modelsSeen[id] == nil {
			modelsSeen[id] = map[string]bool{}
		}
		modelsSeen[id][model] = true
	}
	var links []FederationPulseLink
	rng, err := db.readFederationPulseSnapshot(ctx, since, now, func(tx *sql.Tx) error {
		var err error
		links, err = federationPulseLinks(ctx, tx)
		return err
	}, func(tx *sql.Tx, start, end time.Time, owners map[string]federationPulseOwner, source reportingDaySource) error {
		if accumulator == nil {
			accumulator = newFederationPulseAccumulator(owners)
		}
		query, err := activity.ResolveQuery(activity.QueryInput{Preset: "custom", From: start.Format(time.RFC3339), To: end.Format(time.RFC3339), Timezone: "UTC"}, end)
		if err != nil {
			return err
		}
		usage, byID, err := reportingMaterializedUsage(query, source)
		if err != nil {
			return err
		}
		first, _ := reportingSessionEvidence(start, end, time.Duration(query.GapCapSeconds)*time.Second, mergeReportingSessions(source.activitySessions, source.usageSessions), source.createdAt, source.activityEvents, usage)
		for _, event := range source.activityEvents {
			at, err := parseTimestamp(event.Timestamp)
			if err == nil && !at.Before(start) && at.Before(end) {
				rememberModel(event.SessionID, event.Model)
			}
		}
		var newIDs []string
		for id := range first {
			if _, known := sessions[id]; known {
				continue
			}
			meta, ok := byID[id]
			if !ok {
				accumulator.invalid = true
				continue
			}
			sessions[id] = meta
			newIDs = append(newIDs, id)
		}
		stored, err := federationPulseSignals(ctx, tx, newIDs)
		if err != nil {
			return err
		}
		for id, row := range stored {
			signals[id] = row
		}
		// The joint owner selects the same hourly rows and accumulates the same
		// allocated usage as export, alongside private per-source evidence.
		for hour := start; hour.Before(end); hour = hour.Add(time.Hour) {
			support := reportingJointSupport{}
			_, err := jointReportingHour(hour, time.Hour, nil, nil, usage, byID, source.projects, source.references, nil, &support)
			if err != nil {
				return err
			}
			for key, contributors := range support {
				for identity, contribution := range contributors {
					id := identity.source
					origin, ok := owners[id]
					attributed, attributedOK := owners[identity.attributed]
					if !ok || !attributedOK {
						accumulator.invalid = true
						continue
					}
					if origin != attributed {
						accumulator.unsafeProjects[origin.project] = true
						accumulator.unsafeProjects[attributed.project] = true
						continue
					}
					// Export charges the survivor to the attributed session. Keep
					// its session/model coverage there while numeric support remains
					// tied to the source that supplied the observation.
					usageSeen[identity.attributed] = true
					rememberModel(identity.attributed, key.model)
					for _, amount := range []int64{contribution.usage.inputTokens, contribution.usage.outputTokens, contribution.usage.cacheCreationTokens, contribution.usage.cacheReadTokens} {
						for _, group := range [][2]string{{"total", ""}, {"agent", key.agent}, {"model", key.model}} {
							accumulator.add(id, group[0], group[1], "tokens", amount)
						}
					}
					if contribution.costObserved {
						for _, group := range [][2]string{{"total", ""}, {"agent", key.agent}, {"model", key.model}} {
							accumulator.add(id, group[0], group[1], "cost_microdollars", contribution.usage.cost.Microdollars)
						}
					}
				}
			}
		}

		return nil
	})
	if err != nil {
		return FederationPulse{}, err
	}
	if accumulator == nil {
		accumulator = newFederationPulseAccumulator(nil)
	}
	projects := map[string]bool{}
	for id, meta := range sessions {
		owner, ok := accumulator.owners[id]
		if !ok {
			accumulator.invalid = true
			continue
		}
		accumulator.add(id, "total", "", "sessions", 1)
		activeProject := int64(0)
		if !projects[owner.project] {
			activeProject = 1
			projects[owner.project] = true
		}
		accumulator.add(id, "total", "", "active_projects", activeProject)
		category := meta.ActivityCategory()
		automated := int64(0)
		if category == "automated" {
			automated = 1
		}
		accumulator.add(id, "total", "", "automated_sessions", automated)
		accumulator.add(id, "category", category, "sessions", 1)
		agent := meta.Agent
		if agent == "" {
			agent = "unknown"
		}
		accumulator.add(id, "agent", agent, "sessions", 1)
		for model := range modelsSeen[id] {
			accumulator.add(id, "model", model, "sessions", 1)
		}
		if usageSeen[id] {
			accumulator.add(id, "total", "", "usage_observed_sessions", 1)
			accumulator.add(id, "availability", "usage", "sessions", 1)
		} else {
			accumulator.add(id, "availability", "no_usage", "sessions", 1)
		}
		signal, ok := signals[id]
		if !ok {
			accumulator.invalid = true
			continue
		}
		outcomes, grades := storedSignalDistributions([]SignalRow{signal})
		for outcome := range outcomes {
			accumulator.add(id, "outcome", outcome, "sessions", 1)
			accumulator.add(id, "total", "", "outcome_observed_sessions", 1)
		}
		if len(outcomes) == 0 {
			accumulator.add(id, "availability", "no_outcome", "sessions", 1)
		}
		for grade := range grades {
			accumulator.add(id, "grade", grade, "sessions", 1)
			accumulator.add(id, "total", "", "health_observed_sessions", 1)
		}
		if len(grades) == 0 {
			accumulator.add(id, "availability", "no_health", "sessions", 1)
		}
	}
	result := accumulator.release(minimum)
	if since != "" {
		result.Since = &since
	}
	result.ClosedThrough = rng.ClosedThrough
	result.Links = links
	return result, nil
}

// FederationPulse reads a single scoped snapshot and returns only released values.
func (db *DB) FederationPulse(ctx context.Context, since string, minimum int) (FederationPulse, error) {
	return db.readFederationPulse(ctx, since, minimum, time.Now())
}

// federationPulseLinks exposes only contact and sanitized stored refusal facts.
func federationPulseLinks(ctx context.Context, tx *sql.Tx) ([]FederationPulseLink, error) {
	rows, err := tx.QueryContext(ctx, `SELECT e.enrollment_uid,e.spoke_name,e.last_handshake_at,e.last_delivery_at,e.revoked_at,h.last_refused
		FROM federation_enrollments e LEFT JOIN federation_hub_shares h ON h.enrollment_uid=e.enrollment_uid
		ORDER BY e.created_at,e.enrollment_uid,h.share_uid`)
	if err != nil {
		return nil, fmt.Errorf("query pulse links: %w", err)
	}
	defer rows.Close()
	links := []FederationPulseLink{}
	indices := map[string]int{}
	categories := map[string]map[string]bool{}
	for rows.Next() {
		var uid, name, contact, revoked string
		var delivery, refused sql.NullString
		if err := rows.Scan(&uid, &name, &contact, &delivery, &revoked, &refused); err != nil {
			return nil, fmt.Errorf("scan pulse link: %w", err)
		}
		index, found := indices[uid]
		if !found {
			link := FederationPulseLink{SpokeName: name, State: "enrolled", BacklogLagSeconds: FederationPulseMetric{State: "unavailable"}, LatestBatchRefusals: []string{}}
			if contact != "" {
				link.LastContactAt = &contact
				link.State = "contacted"
			}
			if revoked != "" {
				link.State = "revoked"
			}
			if delivery.Valid {
				value := delivery.String
				link.LastDeliveryAt = &value
			}
			index = len(links)
			indices[uid] = index
			links = append(links, link)
			categories[uid] = map[string]bool{}
		}
		if refused.Valid && refused.String != "" {
			var values map[string]string
			if err := json.Unmarshal([]byte(refused.String), &values); err != nil {
				return nil, fmt.Errorf("decode stored pulse refusals: %w", err)
			}
			for _, value := range values {
				category := "other"
				if value == FederationCollision {
					category = "collision"
				}
				categories[uid][category] = true
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read pulse links: %w", err)
	}
	for uid, index := range indices {
		for category := range categories[uid] {
			links[index].LatestBatchRefusals = append(links[index].LatestBatchRefusals, category)
		}
		slices.Sort(links[index].LatestBatchRefusals)
	}
	return links, nil
}
