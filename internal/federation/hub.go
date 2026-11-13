package federation

import (
	"context"
	"slices"

	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/export"
)

func (s *Service) RegisterShare(ctx context.Context, enrollment, spoke, uid string, m ShareManifest) (ShareView, error) {
	var out ShareView
	digest, err := export.DigestCanonical(s.policy)
	if err != nil {
		return out, err
	}
	normalized, ok := export.NormalizeGitRemote(m.Remote)
	identity := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: m.Remote})
	if s.role != "hub" || m.Protocol != ProtocolVersion || m.SpokeInstance != spoke || m.ShareUID != uid || uid == "" || m.Epoch < 1 || !ok || normalized != m.Remote || identity.Key != m.ProjectKey || m.Level != "summary" || (m.Attribution != "pooled" && m.Attribution != "member") || m.Audience != "operators" || (m.Action != "" && m.Action != "stop" && m.Action != "resume" && m.Action != "rebuild") {
		return out, inputError("invalid federation share")
	}
	retention := s.policy.Retention
	if m.Action == "stop" {
		if m.Policy == nil || m.Policy.Validate() != nil {
			return out, inputError("invalid federation share")
		}
		consentDigest, e := export.DigestCanonical(*m.Policy)
		if e != nil || consentDigest != m.PolicyDigest {
			return out, inputError("invalid federation share")
		}
		retention = m.Policy.Retention
	} else if m.PolicyDigest != digest || !slices.Contains(s.policy.AllowedLevels, m.Level) {
		return out, inputError("invalid federation share")
	}
	state := "active"
	if m.Action == "stop" {
		state = "stopped"
	}
	stored, err := s.db.PutFederationHubShare(ctx, spoke, db.FederationHubShare{UID: uid, EnrollmentUID: enrollment, Remote: m.Remote, ProjectKey: m.ProjectKey, Level: m.Level, Attribution: m.Attribution, Audience: m.Audience, PolicyDigest: m.PolicyDigest, Epoch: m.Epoch, State: state, Retention: retention, Resume: m.Action == "resume", Rebuild: m.Action == "rebuild"})
	if err != nil {
		return out, err
	}
	state = stored.State
	if state == "active" {
		state = "accepted"
	}
	return ShareView{State: state, Committed: stored.Sequence, Epoch: stored.Epoch, Changed: stored.Changed}, nil
}

func (s *Service) ApplyBatch(ctx context.Context, enrollment, spoke, uid string, batch Batch) (BatchAck, error) {
	var out BatchAck
	if s.role != "hub" || batch.Protocol != ProtocolVersion || batch.SpokeInstance != spoke || batch.ShareUID != uid || batch.Epoch < 1 || batch.Sequence < 1 || len(batch.Records) == 0 || len(batch.Records) > 1000 {
		return out, inputError("invalid federation batch")
	}
	records := make([]db.FederationHubRecord, 0, len(batch.Records))
	seen := map[string]bool{}
	for _, r := range batch.Records {
		if r.RecordUID == "" || seen[r.RecordUID] {
			return out, inputError("invalid federation batch")
		}
		seen[r.RecordUID] = true
		if r.Kind == "tombstone" {
			if r.Payload != nil || r.Hash != "" {
				return out, inputError("invalid federation batch")
			}
			records = append(records, db.FederationHubRecord{UID: r.RecordUID, Tombstone: true})
			continue
		}
		if r.Kind != "session_summary" || r.Payload == nil || r.RecordUID != r.Payload.SessionID {
			return out, inputError("invalid federation batch")
		}
		digest, err := export.DigestCanonical(r.Payload)
		if err != nil || digest != r.Hash {
			return out, inputError("invalid federation batch")
		}
		p := r.Payload
		identity := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: p.Remote})
		normalized, ok := export.NormalizeGitRemote(p.Remote)
		if !ok || normalized != p.Remote || identity.Key != p.ProjectKey || p.Agent == "" || p.MessageCount < 0 || p.UserMessageCount < 0 || p.AssistantMessageCount < 0 || p.ToolCount < 0 || (p.ParentID != nil && *p.ParentID == p.SessionID) || !slices.Contains([]string{"", "completed", "abandoned", "errored", "unknown"}, p.Outcome) || (p.Health != nil && !slices.Contains([]string{"A", "B", "C", "D", "F"}, *p.Health)) {
			return out, inputError("invalid federation batch")
		}
		session := db.Session{ID: p.SessionID, Project: p.Remote, Machine: "federated", Agent: p.Agent, StartedAt: p.StartedAt, EndedAt: p.EndedAt, MessageCount: p.MessageCount, UserMessageCount: p.UserMessageCount, IsAutomated: p.Automated, ParentSessionID: p.ParentID}
		if p.Relationship != nil {
			session.RelationshipType = *p.Relationship
		}
		write := db.SessionBatchWrite{Session: session, DataVersion: db.CurrentDataVersion(), IdentityObservation: export.ProjectIdentityObservation{SessionID: p.SessionID, Project: p.Remote, Machine: "federated", GitRemote: p.Remote}, Signals: db.SessionSignalUpdate{Outcome: p.Outcome, HealthGrade: p.Health}}
		for model, u := range p.ByModel {
			event := db.UsageEvent{SessionID: p.SessionID, Source: "federation", Model: model, InputTokens: u.InputTokens, OutputTokens: u.OutputTokens, CacheCreationInputTokens: u.CacheCreationInputTokens, CacheReadInputTokens: u.CacheReadInputTokens, ReasoningTokens: u.ReasoningTokens, DedupKey: model}
			if p.StartedAt != nil {
				event.OccurredAt = *p.StartedAt
			}
			if u.HasCost {
				cost := u.Cost
				event.Cost = &cost
				event.CostSource = "reported"
				event.CostStatus = "exact"
			}
			write.UsageEvents = append(write.UsageEvents, event)
			if u.OutputTokens > 0 {
				write.Session.TotalOutputTokens += u.OutputTokens
				write.Session.HasTotalOutputTokens = true
			}
		}
		records = append(records, db.FederationHubRecord{UID: r.RecordUID, Hash: r.Hash, Remote: p.Remote, ProjectKey: p.ProjectKey, AssistantCount: p.AssistantMessageCount, Write: write})
	}
	digest, err := export.DigestCanonical(batch)
	if err != nil {
		return out, err
	}
	policyDigest, err := export.DigestCanonical(s.policy)
	if err != nil {
		return out, err
	}
	result, err := s.db.CommitFederationBatch(ctx, enrollment, spoke, uid, policyDigest, batch.Epoch, batch.Sequence, digest, records)
	return BatchAck{Committed: result.Committed, Refused: result.Refused, Changed: result.Changed}, err
}

func (s *Service) Reconcile(ctx context.Context, enrollment, spoke, uid string, request ReconcileRequest) (db.FederationInventoryResult, error) {
	if s.role != "hub" || request.Protocol != ProtocolVersion || request.SpokeInstance != spoke || request.ShareUID != uid {
		return db.FederationInventoryResult{}, inputError("invalid federation inventory")
	}
	return s.db.ReconcileFederationPage(ctx, enrollment, spoke, uid, request.FederationInventoryPage)
}
