package db

import (
	"fmt"
	"slices"
	"time"

	"go.kenn.io/agentsview/internal/activity"
	"go.kenn.io/agentsview/internal/export"
	"go.kenn.io/agentsview/internal/money"
)

// Apply scope after the complete day's survivor selection. Filtering duplicate
// candidates first would let a second project claim the same charged usage.
func scopeJointReporting(
	sessions []activity.SessionMeta, events []activity.ActivityEvent,
	usage []activity.UsageRow, sessionByID map[string]activity.SessionMeta,
	projects map[string]export.ProjectMapEntry, keys []string,
) ([]activity.SessionMeta, []string, []activity.ActivityEvent, []activity.UsageRow) {
	selectedKeys := make(map[string]bool, len(keys))
	for _, key := range keys {
		selectedKeys[key] = true
	}
	selected := func(project string) bool {
		return len(keys) == 0 || selectedKeys[export.ProjectKeyForEntry(projects[project])]
	}
	keptSessions := make([]activity.SessionMeta, 0, len(sessions))
	ids := make([]string, 0, len(sessions))
	for _, session := range sessions {
		if selected(session.Project) {
			keptSessions = append(keptSessions, session)
			ids = append(ids, session.SessionID)
		}
	}
	keptEvents := make([]activity.ActivityEvent, 0, len(events))
	for _, event := range events {
		session, known := sessionByID[event.SessionID]
		if len(keys) == 0 || known && selected(session.Project) {
			keptEvents = append(keptEvents, event)
		}
	}
	keptUsage := make([]activity.UsageRow, 0, len(usage))
	for _, row := range usage {
		session, known := sessionByID[row.SessionID]
		if len(keys) == 0 || known && selected(session.Project) {
			keptUsage = append(keptUsage, row)
		}
	}
	return keptSessions, ids, keptEvents, keptUsage
}

type reportingCellKey struct {
	bucket                               string
	projectKey, agent, model, automation string
}

type reportingCellState struct {
	cell  export.ReportingCell
	usage reportingUsageAccum
}

// reportingJointSupport stays private to the snapshot. It follows the same
// surviving, priced and allocated rows used to build each joint cell.
type reportingJointContributor struct{ source, attributed string }
type reportingJointSupport map[reportingCellKey]map[reportingJointContributor]*reportingJointContribution

type reportingJointContribution struct {
	usage           reportingUsageAccum
	costObserved    bool
	unpriced        bool
	proofRefs       []activity.UsageProofRef
	proofIncomplete bool
}

// walkReportingHourUsage normalizes each retained hourly row once for both
// public joint cells and private contributor support.
func walkReportingHourUsage(start time.Time, bucket time.Duration, usage []activity.UsageRow,
	sessions map[string]activity.SessionMeta, projects map[string]export.ProjectMapEntry,
	visit func(activity.UsageRow, activity.SessionMeta, bool, time.Time, reportingCellKey, reportingJointContributor) error,
) error {
	end := start.Add(time.Hour)
	for _, row := range usage {
		at, err := parseTimestamp(row.Timestamp)
		if err != nil || at.Before(start) || !at.Before(end) {
			continue
		}
		session, known := sessions[row.SessionID]
		agent, automation, projectKey := row.Agent, "unknown", ""
		if known {
			projectKey = export.ProjectKeyForEntry(projects[session.Project])
			automation = session.ActivityCategory()
			if agent == "" {
				agent = session.Agent
			}
		}
		if agent == "" {
			agent = "unknown"
		}
		model := row.Model
		if model == "" {
			model = "unknown"
		}
		at = at.UTC().Truncate(bucket)
		key := reportingCellKey{at.Format(time.RFC3339), projectKey, agent, model, automation}
		identity := reportingJointContributor{source: row.SourceSessionID, attributed: row.SessionID}
		if identity.source == "" {
			identity.source = row.SessionID
		}
		if err := visit(row, session, known, at, key, identity); err != nil {
			return err
		}
	}
	return nil
}

func addReportingJointSupport(support reportingJointSupport, key reportingCellKey, identity reportingJointContributor, row activity.UsageRow) error {
	if support[key] == nil {
		support[key] = map[reportingJointContributor]*reportingJointContribution{}
	}
	if support[key][identity] == nil {
		support[key][identity] = &reportingJointContribution{}
	}
	contribution := support[key][identity]
	if err := contribution.usage.add(row); err != nil {
		return fmt.Errorf("sum joint contributor usage: %w", err)
	}
	contribution.costObserved = contribution.costObserved || row.Priced || row.Cost.Microdollars != 0
	contribution.unpriced = contribution.unpriced || !row.Priced
	if row.ProofRef != 0 {
		contribution.proofRefs = append(contribution.proofRefs, row.ProofRef)
	} else {
		contribution.proofIncomplete = true
	}
	return nil
}

func reportingHourSupport(start time.Time, bucket time.Duration, usage []activity.UsageRow,
	sessions map[string]activity.SessionMeta, projects map[string]export.ProjectMapEntry,
) (reportingJointSupport, error) {
	support := reportingJointSupport{}
	// Preserve the public cell's checked money sums even when contributors
	// are separate. These values are validation only and are not released.
	type checkedCosts struct{ total, computed, allocated, reported money.Money }
	checked := map[reportingCellKey]*checkedCosts{}
	err := walkReportingHourUsage(start, bucket, usage, sessions, projects, func(row activity.UsageRow, _ activity.SessionMeta, _ bool, _ time.Time, key reportingCellKey, identity reportingJointContributor) error {
		costs := checked[key]
		if costs == nil {
			costs = &checkedCosts{}
			checked[key] = costs
		}
		var err error
		costs.total, err = money.Add(costs.total, row.Cost)
		if err != nil {
			return fmt.Errorf("sum joint cell usage: %w", err)
		}
		partition := &costs.computed
		switch {
		case row.CostAllocated:
			partition = &costs.allocated
		case row.CostSource == export.CostSourceReported:
			partition = &costs.reported
		}
		*partition, err = money.Add(*partition, row.Cost)
		if err != nil {
			return fmt.Errorf("sum joint cell pricing: %w", err)
		}
		return addReportingJointSupport(support, key, identity, row)
	})
	return support, err
}

func jointReportingHour(
	start time.Time, bucket time.Duration, activityCells []activity.JointActivityCell, activitySessions []activity.SessionRow, usage []activity.UsageRow,
	sessions map[string]activity.SessionMeta, projects map[string]export.ProjectMapEntry,
	references map[string]export.ProjectReference,
	projectKeys []string, support ...*reportingJointSupport,
) (*export.ReportingJoint, error) {
	states := make(map[reportingCellKey]*reportingCellState)
	contributors := make(map[string]bool)
	for _, session := range activitySessions {
		if session.AgentMinutes != nil && *session.AgentMinutes > 0 {
			contributors[session.SessionID] = true
		}
	}
	cellFor := func(bucket time.Time, project, projectKey, agent, model, automation string) *reportingCellState {
		if model == "" {
			model = "unknown"
		}
		if agent == "" {
			agent = "unknown"
		}
		key := reportingCellKey{
			bucket.UTC().Format(time.RFC3339),
			projectKey, agent, model, automation,
		}
		state := states[key]
		label := export.SafeProjectDisplayLabel(project)
		if state == nil {
			state = &reportingCellState{cell: export.ReportingCell{
				BucketStart: key.bucket, Project: label, ProjectKey: key.projectKey,
				Agent: agent, Model: model, Automation: automation,
			}}
			states[key] = state
		} else if label < state.cell.Project {
			state.cell.Project = label
		}
		return state
	}
	for _, cell := range activityCells {
		state := cellFor(cell.BucketStart, cell.Project, cell.ProjectKey, cell.Agent, cell.Model, cell.Category)
		state.cell.AgentMinutes += cell.AgentMinutes
		state.cell.MaxAgents = cell.MaxAgents
	}
	err := walkReportingHourUsage(start, bucket, usage, sessions, projects, func(row activity.UsageRow, session activity.SessionMeta, known bool, at time.Time, key reportingCellKey, identity reportingJointContributor) error {
		if known {
			contributors[row.SessionID] = true
		}
		state := cellFor(at, session.Project, key.projectKey, key.agent, key.model, key.automation)
		if err := state.usage.add(row); err != nil {
			return fmt.Errorf("sum joint cell usage: %w", err)
		}
		if len(support) > 0 && support[0] != nil {
			if err := addReportingJointSupport(*support[0], key, identity, row); err != nil {
				return err
			}
		}
		if !row.Priced {
			state.cell.Pricing.UnpricedRows++
		}
		// An unpriced token row can still carry a known service fee.
		cost := &state.cell.Pricing.ComputedCost
		switch {
		case row.CostAllocated:
			cost = &state.cell.Pricing.AllocatedCost
		case row.CostSource == export.CostSourceReported:
			cost = &state.cell.Pricing.ReportedCost
		}
		var err error
		*cost, err = money.Add(*cost, row.Cost)
		if err != nil {
			return fmt.Errorf("sum joint cell pricing: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	keys := slices.Clone(projectKeys)
	slices.Sort(keys)
	joint := &export.ReportingJoint{ProjectKeys: slices.Compact(keys), Cells: make([]export.ReportingCell, 0, len(states))}
	joint.Projects = reportingProjectEvidence(contributors, sessions, projects, references)
	for _, state := range states {
		state.cell.Usage = export.ReportingUsageTotals{
			InputTokens: state.usage.inputTokens, OutputTokens: state.usage.outputTokens,
			CacheCreationTokens: state.usage.cacheCreationTokens, CacheReadTokens: state.usage.cacheReadTokens,
			Cost: state.usage.cost,
		}
		joint.Cells = append(joint.Cells, state.cell)
	}
	return joint, nil
}
