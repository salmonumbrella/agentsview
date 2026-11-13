package federation

import (
	"context"
	"database/sql"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/http"
	"sort"

	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/export"
)

type PushResult struct {
	Sent        int `json:"sent"`
	Unchanged   int `json:"unchanged"`
	Refused     int `json:"refused"`
	Quarantined int `json:"quarantined"`
}

func (s *Service) Push(ctx context.Context) (PushResult, error) {
	var out PushResult
	release, err := s.acquirePush(ctx)
	if err != nil {
		return out, err
	}
	defer release()
	link, err := s.db.GetFederationLink(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	shares, err := s.db.ListFederationShares(ctx, link.UID)
	if err != nil {
		return out, err
	}
	active := false
	for _, share := range shares {
		if share.State == "active" {
			active = true
			break
		}
	}
	if !active {
		return out, nil
	}
	link, hub, err := s.livePolicy(ctx)
	if err != nil {
		return out, err
	}
	token, err := readCredential(ctx, link.TokenFile)
	if err != nil {
		return out, err
	}
	for _, share := range shares {
		share, err = s.db.GetFederationShare(ctx, link.UID, share.UID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return out, err
		}
		if share.State != "active" || share.PolicyDigest != hub.PolicyDigest {
			continue
		}
		var consent SharePreview
		if json.Unmarshal([]byte(share.ConsentJSON), &consent) != nil || consent.DeliveryNotice != shareDeliveryNotice {
			continue
		}
		key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: share.NormalizedRemote}).Key
		manifest := ShareManifest{Protocol: ProtocolVersion, SpokeInstance: s.archiveID, ShareUID: share.UID, Epoch: 1, Remote: share.NormalizedRemote, ProjectKey: key, Level: share.Level, Attribution: share.Attribution, Audience: share.Audience, PolicyDigest: share.PolicyDigest}
		view, err := PutShare(ctx, link.HubOrigin, token, s.archiveID, manifest)
		if err != nil {
			return out, err
		}
		if view.State != "accepted" || view.Epoch != 1 {
			continue
		}
		preview, err := s.previewWithPolicy(ctx, ShareGrant{Project: share.NormalizedRemote, Level: share.Level, Attribution: share.Attribution, Since: share.Since}, hub)
		if err != nil {
			return out, err
		}
		ledger, err := s.db.FederationLedger(ctx, share.UID)
		if err != nil {
			return out, err
		}
		records := orderSummaryParents(preview.Records)
		pending := make([]BatchRecord, 0, len(records))
		for _, record := range records {
			hash, err := export.DigestCanonical(record)
			if err != nil {
				return out, err
			}
			old, ok := ledger[record.SessionID]
			if ok && old.State == "refused" {
				out.Refused++
				continue
			}
			if ok && old.State == "sent" && old.Hash == hash && old.AttemptHash == "" {
				out.Unchanged++
				continue
			}
			pending = append(pending, BatchRecord{RecordUID: record.SessionID, Kind: "session_summary", Hash: hash, Payload: record})
		}
		for len(pending) > 0 {
			current, err := s.db.GetFederationShare(ctx, link.UID, share.UID)
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			if err != nil {
				return out, err
			}
			var currentConsent SharePreview
			if current.State != "active" || current.PolicyDigest != hub.PolicyDigest || json.Unmarshal([]byte(current.ConsentJSON), &currentConsent) != nil || currentConsent.DeliveryNotice != shareDeliveryNotice {
				break
			}
			fresh, err := s.previewWithPolicy(ctx, ShareGrant{Project: share.NormalizedRemote, Level: share.Level, Attribution: share.Attribution, Since: share.Since}, hub)
			if err != nil {
				return out, err
			}
			allowed := make(map[string]SummaryRecord, len(fresh.Records))
			for _, record := range fresh.Records {
				allowed[record.SessionID] = record
			}
			filtered := pending[:0]
			for _, record := range pending {
				if payload, ok := allowed[record.RecordUID]; ok {
					record.Payload = payload
					record.Hash, err = export.DigestCanonical(payload)
					if err != nil {
						return out, err
					}
					filtered = append(filtered, record)
				}
			}
			pending = filtered
			if len(pending) == 0 {
				break
			}
			batch := Batch{Protocol: ProtocolVersion, SpokeInstance: s.archiveID, ShareUID: share.UID, Epoch: 1, Sequence: view.Committed + 1, Records: []BatchRecord{}}
			envelope, err := jsonv2.Marshal(batch)
			if err != nil {
				return out, err
			}
			size := len(envelope)
			n := 0
			for n < len(pending) && n < 1000 {
				data, err := jsonv2.Marshal(pending[n])
				if err != nil {
					return out, err
				}
				extra := len(data)
				if n > 0 {
					extra++
				}
				if size+extra > 16<<20 {
					break
				}
				size += extra
				batch.Records = append(batch.Records, pending[n])
				n++
			}
			if n == 0 {
				if err = s.db.PutFederationQuarantine(ctx, db.FederationQuarantine{ShareUID: share.UID, Error: "record exceeds batch limit", Sequence: batch.Sequence}); err != nil {
					return out, err
				}
				out.Quarantined++
				break
			}
			attempts := make([]db.FederationDelivery, 0, n)
			for _, record := range batch.Records {
				attempts = append(attempts, db.FederationDelivery{RecordUID: record.RecordUID, SessionID: record.RecordUID, Hash: record.Hash})
			}
			if err = s.db.RecordFederationAttempt(ctx, share.UID, attempts); err != nil {
				return out, err
			}
			ack, err := PostBatch(ctx, link.HubOrigin, token, s.archiveID, batch)
			if err != nil {
				var peer *peerHTTPError
				if errors.As(err, &peer) && peer.Status == http.StatusConflict {
					break
				}
				if errors.As(err, &peer) && peer.Status == http.StatusBadRequest {
					if e := s.db.PutFederationQuarantine(ctx, db.FederationQuarantine{ShareUID: share.UID, Error: "hub rejected batch", Sequence: batch.Sequence}); e != nil {
						return out, e
					}
					out.Quarantined++
					break
				}
				return out, err
			}
			if ack.Committed != batch.Sequence {
				return out, inputError("invalid federation acknowledgment")
			}
			batchIDs := make(map[string]bool, n)
			for _, record := range batch.Records {
				batchIDs[record.RecordUID] = true
			}
			for id, refusal := range ack.Refused {
				if !batchIDs[id] || refusal != db.FederationCollision {
					return out, inputError("invalid federation acknowledgment")
				}
			}
			delivered := make([]db.FederationDelivery, 0, n)
			for _, record := range batch.Records {
				state := "sent"
				if _, ok := ack.Refused[record.RecordUID]; ok {
					state = "refused"
					out.Refused++
				} else {
					out.Sent++
				}
				delivered = append(delivered, db.FederationDelivery{RecordUID: record.RecordUID, SessionID: record.RecordUID, Hash: record.Hash, State: state})
			}
			if err = s.db.RecordFederationDelivery(ctx, share.UID, delivered); err != nil {
				return out, err
			}
			if len(ack.Refused) > 0 {
				if err = s.db.PutFederationQuarantine(ctx, db.FederationQuarantine{ShareUID: share.UID, Error: db.FederationCollision, Sequence: batch.Sequence}); err != nil {
					return out, err
				}
				out.Quarantined++
			}
			view.Committed = ack.Committed
			pending = pending[n:]
		}
	}
	return out, nil
}
func orderSummaryParents(records []SummaryRecord) []SummaryRecord {
	byID := map[string]SummaryRecord{}
	for _, r := range records {
		byID[r.SessionID] = r
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	state := map[string]uint8{}
	out := make([]SummaryRecord, 0, len(ids))
	var visit func(string)
	visit = func(id string) {
		if state[id] != 0 {
			return
		}
		state[id] = 1
		r := byID[id]
		if r.ParentID != nil {
			if _, ok := byID[*r.ParentID]; ok {
				visit(*r.ParentID)
			}
		}
		state[id] = 2
		out = append(out, r)
	}
	for _, id := range ids {
		visit(id)
	}
	return out
}
