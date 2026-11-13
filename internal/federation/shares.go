package federation

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"slices"
	"sort"
	"time"

	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/export"
	"go.kenn.io/agentsview/internal/money"
)

const (
	shareIncludes          = "Session identity, repository, agent, models, times, counts, usage, cost, automation, outcome and health"
	shareOmits             = "Content, paths, titles, tool inputs and results, and tool categories"
	shareDisclosure        = "Anyone holding the hub bearer token can read everything the hub stores"
	shareAttributionNotice = "Member attribution is a request for a later release"
	shareDeliveryNotice    = "This release records the share only; nothing is sent"
)

type ShareGrant struct {
	Project     string `json:"project"`
	Level       string `json:"level"`
	Since       string `json:"since"`
	Attribution string `json:"attribution"`
}
type SummaryRecord struct {
	SessionID             string       `json:"session_id"`
	ProjectKey            string       `json:"project_key"`
	Remote                string       `json:"normalized_remote"`
	Agent                 string       `json:"agent"`
	Models                []string     `json:"models"`
	StartedAt             *string      `json:"started_at"`
	EndedAt               *string      `json:"ended_at"`
	MessageCount          int          `json:"message_count"`
	UserMessageCount      int          `json:"user_message_count"`
	AssistantMessageCount int          `json:"assistant_message_count"`
	ToolCount             int          `json:"total_tool_count"`
	Usage                 SummaryUsage `json:"usage"`
	Automated             bool         `json:"is_automated"`
	Outcome               string       `json:"outcome"`
	Health                *string      `json:"health"`
	ParentID              *string      `json:"parent_session_id,omitempty"`
	Relationship          *string      `json:"relationship_type,omitempty"`
}
type SummaryUsage struct {
	InputTokens              int         `json:"input_tokens"`
	OutputTokens             int         `json:"output_tokens"`
	CacheCreationInputTokens int         `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int         `json:"cache_read_input_tokens"`
	ReasoningTokens          int         `json:"reasoning_tokens"`
	Cost                     money.Money `json:"cost"`
	HasCost                  bool        `json:"has_cost"`
}
type SharePreview struct {
	Grant             ShareGrant      `json:"grant"`
	PolicyDigest      string          `json:"policy_digest"`
	Retention         string          `json:"retention"`
	Processing        string          `json:"processing"`
	Audience          string          `json:"audience"`
	Includes          string          `json:"includes"`
	Omits             string          `json:"omits"`
	Disclosure        string          `json:"disclosure"`
	AttributionNotice string          `json:"attribution_notice"`
	DeliveryNotice    string          `json:"delivery_notice"`
	Selected          int             `json:"selected"`
	Bytes             int             `json:"bytes"`
	NotLocal          int             `json:"not_provably_local"`
	NotIdentifiable   int             `json:"not_identifiable"`
	Excluded          int             `json:"excluded"`
	Held              int             `json:"held"`
	FirstStart        *string         `json:"first_start"`
	LastEnd           *string         `json:"last_end"`
	Agents            []string        `json:"agents"`
	Models            []string        `json:"models"`
	Usage             SummaryUsage    `json:"usage"`
	Records           []SummaryRecord `json:"-"`
}

func (s *Service) livePolicy(ctx context.Context) (db.FederationLink, *HubStatus, error) {
	status, err := s.Status(ctx)
	if err != nil {
		return db.FederationLink{}, nil, err
	}
	if status.Link == nil {
		return db.FederationLink{}, nil, inputError("join a hub first")
	}
	if status.Hub == nil || status.Hub.State != HubOK {
		return db.FederationLink{}, nil, inputError("hub policy unavailable")
	}
	return *status.Link, status.Hub, nil
}
func validateGrant(g ShareGrant, h *HubStatus) (ShareGrant, error) {
	remotes, err := export.NormalizeProjectRemotes([]string{g.Project})
	if err != nil || len(remotes) != 1 || remotes[0] != g.Project {
		return g, inputError("project must be a normalized repository remote; a machine-root project has no repository identity another machine can match")
	}
	g.Project = remotes[0]
	if g.Level == "transcript" {
		return g, inputError("transcript is not available yet")
	}
	if g.Level != "summary" || !slices.Contains(h.Policy.AllowedLevels, g.Level) {
		return g, inputError("level is not allowed by the hub")
	}
	if g.Attribution == "" {
		g.Attribution = "pooled"
	}
	if g.Attribution != "pooled" && g.Attribution != "member" {
		return g, inputError("attribution must be pooled or member")
	}
	if g.Since != "" {
		if _, err := time.Parse("2006-01-02", g.Since); err != nil {
			return g, inputError("since must be YYYY-MM-DD")
		}
	}
	return g, nil
}
func (s *Service) PreviewShare(ctx context.Context, g ShareGrant) (SharePreview, error) {
	var p SharePreview
	_, hub, err := s.livePolicy(ctx)
	if err != nil {
		return p, err
	}
	g, err = validateGrant(g, hub)
	if err != nil {
		return p, err
	}
	return s.previewWithPolicy(ctx, g, hub)
}
func (s *Service) previewWithPolicy(ctx context.Context, g ShareGrant, hub *HubStatus) (SharePreview, error) {
	var p SharePreview
	selected, err := s.db.SelectFederationSessions(ctx, g.Project, g.Since)
	if err != nil {
		return p, err
	}
	p = SharePreview{Grant: g, PolicyDigest: hub.PolicyDigest, Retention: hub.Policy.Retention, Processing: hub.Policy.Processing, Audience: "operators", Includes: shareIncludes, Omits: shareOmits, Disclosure: shareDisclosure, AttributionNotice: shareAttributionNotice, DeliveryNotice: shareDeliveryNotice, Selected: len(selected.IDs), NotLocal: selected.NotLocal, NotIdentifiable: selected.NotIdentifiable, Excluded: selected.Excluded, Records: []SummaryRecord{}}
	agents, models := map[string]bool{}, map[string]bool{}
	selectedIDs := make(map[string]bool, len(selected.IDs))
	for _, id := range selected.IDs {
		selectedIDs[id] = true
	}
	p.Usage.HasCost = len(selected.Rows) > 0
	for _, row := range selected.Rows {
		agents[row.Agent] = true
		for _, model := range row.ModelUsage.Models {
			models[model] = true
		}
		p.FirstStart = previewBoundary(p.FirstStart, row.StartedAt, true)
		p.LastEnd = previewBoundary(p.LastEnd, row.EndedAt, false)
		u := row.ModelUsage
		p.Usage.InputTokens += u.InputTokens
		p.Usage.OutputTokens += u.OutputTokens
		p.Usage.CacheCreationInputTokens += u.CacheCreationInputTokens
		p.Usage.CacheReadInputTokens += u.CacheReadInputTokens
		p.Usage.ReasoningTokens += u.ReasoningTokens
		var sumErr error
		p.Usage.Cost, sumErr = money.Add(p.Usage.Cost, u.Cost)
		if sumErr != nil {
			return p, sumErr
		}
		p.Usage.HasCost = p.Usage.HasCost && u.HasCost
		record := SummaryRecord{SessionID: row.ID, ProjectKey: selected.ProjectKeys[row.ID], Remote: g.Project, Agent: row.Agent, Models: row.ModelUsage.Models, StartedAt: row.StartedAt, EndedAt: row.EndedAt, MessageCount: row.MessageCount, UserMessageCount: row.UserMessageCount, AssistantMessageCount: row.AssistantMessageCount, ToolCount: selected.ToolCounts[row.ID], Usage: SummaryUsage{InputTokens: row.ModelUsage.InputTokens, OutputTokens: row.ModelUsage.OutputTokens, CacheCreationInputTokens: row.ModelUsage.CacheCreationInputTokens, CacheReadInputTokens: row.ModelUsage.CacheReadInputTokens, ReasoningTokens: row.ModelUsage.ReasoningTokens, Cost: row.ModelUsage.Cost, HasCost: row.ModelUsage.HasCost}, Automated: row.IsAutomated, Outcome: selected.Outcomes[row.ID], Health: selected.Health[row.ID]}
		if row.ParentSessionID != nil && selectedIDs[*row.ParentSessionID] {
			record.ParentID = row.ParentSessionID
			record.Relationship = row.RelationshipType
		}
		p.Records = append(p.Records, record)
	}
	for agent := range agents {
		p.Agents = append(p.Agents, agent)
	}
	for model := range models {
		p.Models = append(p.Models, model)
	}
	sort.Strings(p.Agents)
	sort.Strings(p.Models)
	data, err := export.MarshalCanonical(p.Records)
	if err != nil {
		return p, err
	}
	p.Bytes = len(data)
	return p, nil
}
func previewBoundary(current, candidate *string, earliest bool) *string {
	if candidate == nil {
		return current
	}
	t, err := time.Parse(time.RFC3339Nano, *candidate)
	if err != nil {
		return current
	}
	if current == nil {
		return candidate
	}
	old, err := time.Parse(time.RFC3339Nano, *current)
	if err != nil || (earliest && t.Before(old)) || (!earliest && t.After(old)) {
		return candidate
	}
	return current
}
func (s *Service) AddShare(ctx context.Context, p SharePreview) error {
	link, hub, err := s.livePolicy(ctx)
	if err != nil {
		return err
	}
	g, err := validateGrant(p.Grant, hub)
	if err != nil {
		return err
	}
	if g != p.Grant || p.PolicyDigest != hub.PolicyDigest || p.Audience != "operators" || p.Retention != hub.Policy.Retention || p.Processing != hub.Policy.Processing || p.Includes != shareIncludes || p.Omits != shareOmits || p.Disclosure != shareDisclosure || p.AttributionNotice != shareAttributionNotice || p.DeliveryNotice != shareDeliveryNotice {
		return inputError("policy or grant changed; preview again")
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return inputError("preview is too large")
	}
	uid, err := randomID("share_", 16)
	if err != nil {
		return err
	}
	err = s.db.PutFederationShare(ctx, db.FederationShare{UID: uid, LinkUID: link.UID, NormalizedRemote: g.Project, Level: g.Level, Attribution: g.Attribution, Since: g.Since, Audience: p.Audience, State: "active", ConsentJSON: string(data), PolicyDigest: p.PolicyDigest})
	if errors.Is(err, db.ErrFederationShareExists) {
		return inputError("share already exists")
	}
	return err
}

type ShareList struct {
	Shares      []db.FederationShare `json:"shares"`
	Suggestions []string             `json:"suggestions"`
}

func (s *Service) Shares(ctx context.Context) (ShareList, error) {
	out := ShareList{Shares: []db.FederationShare{}, Suggestions: []string{}}
	link, err := s.db.GetFederationLink(ctx)
	if err != nil {
		return out, err
	}
	// Status remains useful offline; only a validated handshake supplies suggestions.
	status, err := s.Status(ctx)
	if err != nil {
		return out, err
	}
	out.Shares, err = s.db.ListFederationShares(ctx, link.UID)
	if err != nil {
		return out, err
	}
	if status.Hub == nil || status.Hub.State != HubOK {
		return out, nil
	}
	remotes, err := s.db.FederationProjectRemotes(ctx)
	if err != nil {
		return out, err
	}
	for _, remote := range remotes {
		already := false
		for _, share := range out.Shares {
			if share.NormalizedRemote == remote {
				already = true
				break
			}
		}
		if already {
			continue
		}
		matches := false
		for _, pattern := range status.Hub.Policy.SuggestedProjects {
			if ok, _ := path.Match(pattern, remote); ok {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		selection, err := s.db.SelectFederationSessionIDs(ctx, remote, "")
		if err != nil {
			return out, err
		}
		if len(selection.IDs) > 0 {
			out.Suggestions = append(out.Suggestions, remote)
		}
	}
	return out, nil
}

type ShareDetails struct {
	Share db.FederationShare `json:"share"`
}

func (s *Service) Share(ctx context.Context, uid string) (ShareDetails, error) {
	var out ShareDetails
	link, err := s.db.GetFederationLink(ctx)
	if err != nil {
		return out, err
	}
	out.Share, err = s.db.GetFederationShare(ctx, link.UID, uid)
	if err != nil {
		return out, err
	}
	return out, nil
}

const policyPausedMessage = "policy changed; run federation share add to review and accept"

func (s *Service) PauseShare(ctx context.Context, uid string) error {
	link, err := s.db.GetFederationLink(ctx)
	if err != nil {
		return err
	}
	share, err := s.db.GetFederationShare(ctx, link.UID, uid)
	if err != nil {
		return err
	}
	switch share.State {
	case "paused":
		return inputError("share is already paused")
	case "policy_paused":
		return inputError(policyPausedMessage)
	}
	return s.db.SetFederationShareState(ctx, link.UID, uid, "active", "paused")
}
func (s *Service) ResumeShare(ctx context.Context, uid string) error {
	link, err := s.db.GetFederationLink(ctx)
	if err != nil {
		return err
	}
	share, err := s.db.GetFederationShare(ctx, link.UID, uid)
	if err != nil {
		return err
	}
	switch share.State {
	case "policy_paused":
		return inputError(policyPausedMessage)
	case "active":
		return inputError("share is already active")
	}
	return s.db.SetFederationShareState(ctx, link.UID, uid, "paused", "active")
}
func (s *Service) RemoveShare(ctx context.Context, uid string) error {
	link, err := s.db.GetFederationLink(ctx)
	if err != nil {
		return err
	}
	return s.db.DeleteFederationShare(ctx, link.UID, uid)
}
func (s *Service) Exclude(ctx context.Context, id, reason string) error {
	if id == "" {
		return inputError("session ID is required")
	}
	_, err := s.db.GetFederationLink(ctx)
	if err != nil {
		return err
	}
	err = s.db.PutFederationExclusion(ctx, id, reason)
	if errors.Is(err, db.ErrFederationSessionNotFound) {
		return inputError("session not found")
	}
	return err
}
func (s *Service) DryRun(ctx context.Context) ([]SummaryRecord, error) {
	link, hub, err := s.livePolicy(ctx)
	if err != nil {
		return nil, err
	}
	shares, err := s.db.ListFederationShares(ctx, link.UID)
	if err != nil {
		return nil, err
	}
	records := []SummaryRecord{}
	for _, share := range shares {
		if share.State != "active" || share.PolicyDigest != hub.PolicyDigest {
			continue
		}
		p, err := s.previewWithPolicy(ctx, ShareGrant{Project: share.NormalizedRemote, Level: share.Level, Attribution: share.Attribution, Since: share.Since}, hub)
		if err != nil {
			return nil, err
		}
		records = append(records, p.Records...)
	}
	return records, nil
}
