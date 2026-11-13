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

func (s *Service) Push(ctx context.Context) (PushResult, error) { return s.push(ctx, true) }

// PushScheduled runs the existing job; full is set at startup and hourly.
func (s *Service) PushScheduled(ctx context.Context, full bool) (PushResult, error) {
	return s.push(ctx, full)
}

func (s *Service) push(ctx context.Context, full bool) (PushResult, error) {
	var out PushResult
	release, err := s.acquirePush(ctx)
	if err != nil {
		return out, err
	}
	defer release()
	links, err := s.db.ListFederationLinks(ctx)
	if err != nil {
		return out, err
	}
	for _, l := range links {
		shares, e := s.db.ListFederationShares(ctx, l.UID)
		if e != nil {
			return out, e
		}
		if e = s.processFederationStops(ctx, l, shares); e != nil {
			return out, e
		}
		shares, e = s.db.ListFederationShares(ctx, l.UID)
		if e != nil {
			return out, e
		}
		if e = s.processRetainedNarrowing(ctx, l, shares, &out); e != nil {
			return out, e
		}
	}
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
		if json.Unmarshal([]byte(share.ConsentJSON), &consent) != nil || (consent.DeliveryNotice != shareDeliveryNotice && consent.DeliveryNotice != shareLegacyDeliveryNotice) {
			continue
		}
		key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: share.NormalizedRemote}).Key
		manifest := ShareManifest{Protocol: ProtocolVersion, SpokeInstance: s.archiveID, ShareUID: share.UID, Epoch: share.Epoch, Remote: share.NormalizedRemote, ProjectKey: key, Level: share.Level, Attribution: share.Attribution, Audience: share.Audience, PolicyDigest: share.PolicyDigest}
		if share.StopIntent == "resume" || share.StopIntent == "rebuild" {
			manifest.Action = share.StopIntent
		}
		view, err := PutShare(ctx, link.HubOrigin, token, s.archiveID, manifest)
		if err != nil {
			return out, err
		}
		if view.State != "accepted" {
			continue
		}
		if view.Epoch > share.Epoch {
			if err = s.db.AdvanceFederationEpoch(ctx, link.UID, share.UID, share.Epoch, view.Epoch+1); err != nil {
				return out, err
			}
			continue
		}
		if view.Epoch != share.Epoch {
			continue
		}
		if share.StopIntent == "resume" || share.StopIntent == "rebuild" {
			if err = s.db.ConfirmFederationResume(ctx, link.UID, share.UID, share.Epoch); err != nil {
				return out, err
			}
		}
		if share.PendingBatch != "" {
			var batch Batch
			if err = json.Unmarshal([]byte(share.PendingBatch), &batch); err != nil || batch.ShareUID != share.UID || batch.Epoch != share.Epoch || batch.Sequence != share.Sequence+1 {
				return out, inputError("invalid stored federation batch")
			}
			ids := make([]string, 0, len(batch.Records))
			for _, record := range batch.Records {
				ids = append(ids, record.RecordUID)
			}
			allowed, parents, e := s.federationEligibility(ctx, share, ids)
			if e != nil {
				return out, e
			}
			safe := true
			for _, record := range batch.Records {
				if record.Kind == "session_summary" && (record.Payload == nil || !allowed[record.RecordUID] || (record.Payload.ParentID != nil && !parents[*record.Payload.ParentID])) {
					safe = false
					break
				}
			}
			if !safe || (view.Committed != share.Sequence && view.Committed != batch.Sequence) {
				if e = s.db.BeginFederationRebuild(ctx, link.UID, share.UID, share.Epoch); e != nil {
					return out, e
				}
				continue
			}
			if e = s.deliverPending(ctx, link, token, batch, &out); e != nil {
				return out, e
			}
			share.Sequence, share.PendingBatch, view.Committed = batch.Sequence, "", batch.Sequence
		} else if view.Committed != share.Sequence {
			if err = s.db.BeginFederationRebuild(ctx, link.UID, share.UID, share.Epoch); err != nil {
				return out, err
			}
			continue
		}
		generation, err := s.db.GetDatabaseID(ctx)
		if err != nil {
			return out, err
		}
		changed, err := s.db.SetFederationGeneration(ctx, link.UID, share.UID, generation)
		if err != nil {
			return out, err
		}
		if changed {
			continue
		}
		needsInventory := full || share.SourceGeneration == "" || share.StopIntent == "resume" || share.StopIntent == "rebuild"
		if err = s.pushFederationChanges(ctx, link, token, share, hub, &view, &out); err != nil {
			return out, err
		}
		if needsInventory {
			if err = s.reconcileShare(ctx, link, token, share, hub, &view, &out); err != nil {
				return out, err
			}
		}

	}
	return out, nil
}
func (s *Service) processFederationStops(ctx context.Context, link db.FederationLink, shares []db.FederationShare) error {
	// A stop is durable before contacting the hub and remains retryable offline.
	// It must be processed even when there are no active shares.
	for _, share := range shares {
		if share.StopIntent == "" || share.StopIntent == "resume" || share.StopIntent == "rebuild" || share.StopReceipt != "pending" {
			continue
		}
		var consent SharePreview
		if json.Unmarshal([]byte(share.ConsentJSON), &consent) != nil || (consent.DeliveryNotice != shareDeliveryNotice && consent.DeliveryNotice != shareLegacyDeliveryNotice) {
			continue
		}
		digest, e := export.DigestCanonical(consent.Policy)
		if e != nil || digest != share.PolicyDigest || consent.Policy.Validate() != nil {
			continue
		}
		token, e := readCredential(ctx, link.TokenFile)
		if e != nil {
			return e
		}
		handshake, e := Handshake(ctx, link.HubOrigin, token, s.archiveID)
		if e != nil {
			return e
		}
		if e = validateHandshake(handshake, link.HubArchiveID); e != nil {
			return e
		}
		key := export.BuildProjectIdentity(export.ProjectIdentityInput{GitRemote: share.NormalizedRemote}).Key
		manifest := ShareManifest{Protocol: ProtocolVersion, SpokeInstance: s.archiveID, ShareUID: share.UID, Epoch: share.Epoch, Remote: share.NormalizedRemote, ProjectKey: key, Level: share.Level, Attribution: share.Attribution, Audience: share.Audience, PolicyDigest: share.PolicyDigest, Action: "stop", Policy: &consent.Policy}
		view, e := PutShare(ctx, link.HubOrigin, token, s.archiveID, manifest)
		if e != nil {
			return e
		}
		if view.State != "stopped" || view.Epoch != share.Epoch {
			return inputError("invalid federation stop receipt")
		}
		receipt := "purged"
		if consent.Policy.Retention == "org-retained" {
			receipt = "retained"
		}
		if e = s.db.ReceiptFederationStop(ctx, link.UID, share.UID, receipt, share.Epoch, view.Committed); e != nil {
			return e
		}
	}
	return nil
}

func (s *Service) deliverPending(ctx context.Context, link db.FederationLink, token string, batch Batch, out *PushResult) error {
	ack, err := PostBatch(ctx, link.HubOrigin, token, s.archiveID, batch)
	if err != nil {
		var peer *peerHTTPError
		if errors.As(err, &peer) && peer.Status == http.StatusBadRequest {
			if e := s.db.PutFederationQuarantine(ctx, db.FederationQuarantine{ShareUID: batch.ShareUID, Error: "hub rejected batch", Sequence: batch.Sequence}); e != nil {
				return e
			}
			out.Quarantined++
		}
		return err
	}
	if ack.Committed != batch.Sequence {
		return inputError("invalid federation acknowledgment")
	}
	batchIDs := make(map[string]bool, len(batch.Records))
	for _, record := range batch.Records {
		batchIDs[record.RecordUID] = true
	}
	for id, refusal := range ack.Refused {
		if !batchIDs[id] || refusal != db.FederationCollision {
			return inputError("invalid federation acknowledgment")
		}
	}
	delivered := make([]db.FederationDelivery, 0, len(batch.Records))
	for _, record := range batch.Records {
		state := "sent"
		if record.Kind == "tombstone" {
			state = "tombstoned"
		}
		if _, refused := ack.Refused[record.RecordUID]; refused {
			state = "refused"
			out.Refused++
		} else if state == "sent" {
			out.Sent++
		}
		delivered = append(delivered, db.FederationDelivery{RecordUID: record.RecordUID, SessionID: record.RecordUID, Hash: record.Hash, State: state})
	}
	if err = s.db.CommitFederationAcknowledgment(ctx, batch.ShareUID, batch.Sequence, delivered); err != nil {
		return err
	}
	if len(ack.Refused) > 0 {
		if err = s.db.PutFederationQuarantine(ctx, db.FederationQuarantine{ShareUID: batch.ShareUID, Error: db.FederationCollision, Sequence: batch.Sequence}); err != nil {
			return err
		}
		out.Quarantined++
	}
	return nil
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

// reconcileShare repeats each bounded keyset range after its repairs.
func (s *Service) reconcileShare(ctx context.Context, link db.FederationLink, token string, share db.FederationShare, hub *HubStatus, view *ShareView, out *PushResult) error {
	round, err := randomID("round_", 16)
	if err != nil {
		return err
	}
	after := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		selected, err := s.db.SelectFederationPage(ctx, share.NormalizedRemote, share.Since, after, 400)
		if err != nil {
			return err
		}
		preview, err := previewFromSelection(ShareGrant{Project: share.NormalizedRemote, Level: share.Level, Attribution: share.Attribution, Since: share.Since}, hub, selected)
		if err != nil {
			return err
		}
		ledger, err := s.db.FederationLedgerForIDs(ctx, share.UID, selected.IDs)
		if err != nil {
			return err
		}
		byID := make(map[string]BatchRecord, len(preview.Records))
		items := make([]db.FederationInventoryItem, 0, len(preview.Records))
		for _, record := range preview.Records {
			if d, ok := ledger[record.SessionID]; ok && d.State == "refused" {
				continue
			}
			hash, err := export.DigestCanonical(record)
			if err != nil {
				return err
			}
			copy := record
			byID[record.SessionID] = BatchRecord{RecordUID: record.SessionID, Kind: "session_summary", Hash: hash, Payload: &copy}
			items = append(items, db.FederationInventoryItem{UID: record.SessionID, Hash: hash})
		}
		final, through := len(selected.IDs) < 400, ""
		if !final {
			through = selected.IDs[len(selected.IDs)-1]
		}
		request := ReconcileRequest{Protocol: ProtocolVersion, SpokeInstance: s.archiveID, ShareUID: share.UID, FederationInventoryPage: db.FederationInventoryPage{Round: round, Epoch: share.Epoch, Sequence: view.Committed, After: after, Through: through, Final: final, Items: items}}
		result, err := PostReconcile(ctx, link.HubOrigin, token, s.archiveID, request)
		if err != nil {
			return err
		}
		if err = validateFederationInventoryResponse(request.FederationInventoryPage, result); err != nil {
			return err
		}
		missing := make(map[string]bool, len(result.Missing))
		for _, id := range result.Missing {
			missing[id] = true
		}
		var matched []db.FederationInventoryItem
		for _, item := range items {
			if (result.Covered == "" || item.UID <= result.Covered) && !missing[item.UID] {
				matched = append(matched, item)
			}
		}
		if err = s.db.ConfirmFederationMatches(ctx, share.UID, matched); err != nil {
			return err
		}
		if result.Complete {
			return nil
		}
		if len(result.Missing) == 0 && len(result.Extra) == 0 {
			if result.Boundary == after {
				if final {
					continue
				}
				return inputError("invalid federation inventory response")
			}
			if result.Boundary < after || (through != "" && result.Boundary > through) {
				return inputError("invalid federation inventory response")
			}
			after = result.Boundary
			continue
		}
		if result.Boundary != after {
			return inputError("invalid federation inventory response")
		}
		ids := append(append([]string{}, result.Missing...), result.Extra...)
		allowed, parents, err := s.federationEligibility(ctx, share, ids)
		if err != nil {
			return err
		}
		var repairs []BatchRecord
		seen := map[string]bool{}
		for _, id := range result.Missing {
			record, ok := byID[id]
			if !ok || seen[id] {
				return inputError("invalid federation inventory response")
			}
			seen[id] = true
			if !allowed[id] {
				continue
			}
			if record.Payload.ParentID != nil && !parents[*record.Payload.ParentID] {
				record.Payload.ParentID, record.Payload.Relationship = nil, nil
				record.Hash, err = export.DigestCanonical(record.Payload)
				if err != nil {
					return err
				}
			}
			repairs = append(repairs, record)
		}
		for _, id := range result.Extra {
			if id == "" || seen[id] || id <= after || (through != "" && id > through) {
				return inputError("invalid federation inventory response")
			}
			seen[id] = true
			if allowed[id] {
				continue
			}
			repairs = append(repairs, BatchRecord{RecordUID: id, Kind: "tombstone"})
		}
		if err = s.postFederationRecords(ctx, link, token, share, view, repairs, out); err != nil {
			return err
		}
	}
}

// Validate the entire peer response before using it as delivery evidence or
// allowing it to advance a scan. The authenticated peer is still a boundary.
func validateFederationInventoryResponse(page db.FederationInventoryPage, result db.FederationInventoryResult) error {
	invalid := func() error { return inputError("invalid federation inventory response") }
	if result.Covered == "" {
		if !page.Final {
			return invalid()
		}
	} else if result.Covered <= page.After || (page.Through != "" && result.Covered > page.Through) {
		return invalid()
	}
	items := make(map[string]bool, len(page.Items))
	for _, item := range page.Items {
		items[item.UID] = true
	}
	seen := make(map[string]bool, len(result.Missing)+len(result.Extra))
	for _, id := range result.Missing {
		if !items[id] || seen[id] || (result.Covered != "" && id > result.Covered) {
			return invalid()
		}
		seen[id] = true
	}
	for _, id := range result.Extra {
		if id <= page.After || seen[id] || items[id] || (result.Covered != "" && id > result.Covered) {
			return invalid()
		}
		seen[id] = true
	}
	if result.Complete {
		if !page.Final || result.Covered != "" || result.Boundary != "" || len(seen) != 0 {
			return invalid()
		}
	} else if len(seen) != 0 {
		if result.Boundary != page.After {
			return invalid()
		}
	} else if result.Boundary != result.Covered && !(page.Final && result.Covered == "" && result.Boundary == page.After) {
		return invalid()
	}
	return nil
}

func (s *Service) pushFederationChanges(ctx context.Context, link db.FederationLink, token string, share db.FederationShare, hub *HubStatus, view *ShareView, out *PushResult) error {
	cutoff, err := s.db.MirrorPushCutoff(ctx)
	if err != nil {
		return err
	}
	usage, err := s.db.UsageChangeRevision(ctx)
	if err != nil {
		return err
	}
	deletion, err := s.db.SessionDeletionPublicationRevision(ctx)
	if err != nil {
		return err
	}
	if usage < share.UsageCursor || deletion < share.DeletionCursor {
		if err := s.db.BeginFederationRebuild(ctx, link.UID, share.UID, share.Epoch); err != nil {
			return err
		}
		return db.ErrFederationSequence
	}
	after := ""
	for {
		ids, err := s.db.FederationChangedCandidates(ctx, share.UID, share.SyncCursor, share.UsageCursor, usage, share.DeletionCursor, deletion, after, 400)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			break
		}
		selected, err := s.db.SelectFederationCandidates(ctx, share.NormalizedRemote, share.Since, ids)
		if err != nil {
			return err
		}
		preview, err := previewFromSelection(ShareGrant{Project: share.NormalizedRemote, Level: share.Level, Attribution: share.Attribution, Since: share.Since}, hub, selected)
		if err != nil {
			return err
		}
		ledger, err := s.db.FederationLedgerForIDs(ctx, share.UID, ids)
		if err != nil {
			return err
		}
		eligible := make(map[string]bool, len(selected.IDs))
		var records []BatchRecord
		for _, record := range orderSummaryParents(preview.Records) {
			eligible[record.SessionID] = true
			old, ok := ledger[record.SessionID]
			if ok && old.State == "refused" {
				out.Refused++
				continue
			}
			hash, err := export.DigestCanonical(record)
			if err != nil {
				return err
			}
			if ok && old.State == "sent" && old.Hash == hash && old.AttemptHash == "" {
				out.Unchanged++
				continue
			}
			copy := record
			records = append(records, BatchRecord{RecordUID: record.SessionID, Kind: "session_summary", Hash: hash, Payload: &copy})
		}
		for _, id := range ids {
			old, ok := ledger[id]
			if !eligible[id] && ok && old.State != "refused" && old.State != "tombstoned" {
				records = append(records, BatchRecord{RecordUID: id, Kind: "tombstone"})
			}
		}
		if err = s.postFederationRecords(ctx, link, token, share, view, records, out); err != nil {
			return err
		}
		after = ids[len(ids)-1]
	}
	return s.db.AdvanceFederationCursors(ctx, share.UID, share.Epoch, cutoff, usage, deletion)
}

// postFederationRecords rechecks eligibility for each bounded envelope before
// persisting it. Excluded payloads are never replayed to settle an attempt.
func (s *Service) postFederationRecords(ctx context.Context, link db.FederationLink, token string, share db.FederationShare, view *ShareView, records []BatchRecord, out *PushResult) error {
	for len(records) > 0 {
		batch := Batch{Protocol: ProtocolVersion, SpokeInstance: s.archiveID, ShareUID: share.UID, Epoch: share.Epoch, Sequence: view.Committed + 1, Records: []BatchRecord{}}
		size := 512
		for len(records) > 0 && len(batch.Records) < 400 {
			data, err := jsonv2.Marshal(records[0])
			if err != nil {
				return err
			}
			if size+len(data)+1 > 16<<20 {
				break
			}
			size += len(data) + 1
			batch.Records = append(batch.Records, records[0])
			records = records[1:]
		}
		if len(batch.Records) == 0 {
			return inputError("record exceeds federation batch limit")
		}
		ids := make([]string, 0, len(batch.Records))
		for _, record := range batch.Records {
			ids = append(ids, record.RecordUID)
		}
		selection, err := s.db.SelectFederationCandidates(ctx, share.NormalizedRemote, share.Since, ids)
		if err != nil {
			return err
		}
		var consent SharePreview
		if err = json.Unmarshal([]byte(share.ConsentJSON), &consent); err != nil {
			return inputError("invalid federation consent")
		}
		preview, err := previewFromSelection(ShareGrant{Project: share.NormalizedRemote, Level: share.Level, Attribution: share.Attribution, Since: share.Since}, &HubStatus{PolicyDigest: share.PolicyDigest, Policy: &consent.Policy}, selection)
		if err != nil {
			return err
		}
		fresh := make(map[string]SummaryRecord, len(preview.Records))
		for _, record := range preview.Records {
			fresh[record.SessionID] = record
		}
		allowed := make(map[string]bool, len(selection.IDs))
		for _, id := range selection.IDs {
			allowed[id] = true
		}
		filtered := batch.Records[:0]
		for _, record := range batch.Records {
			if record.Kind == "tombstone" {
				if !allowed[record.RecordUID] {
					filtered = append(filtered, record)
				}
				continue
			}
			payload, ok := fresh[record.RecordUID]
			if !allowed[record.RecordUID] || !ok || record.Payload == nil {
				continue
			}
			record.Payload = &payload
			record.Hash, err = export.DigestCanonical(record.Payload)
			if err != nil {
				return err
			}
			filtered = append(filtered, record)
		}
		batch.Records = filtered
		if len(batch.Records) == 0 {
			continue
		}
		encoded, err := jsonv2.Marshal(batch)
		if err != nil {
			return err
		}
		if len(encoded) > 16<<20 {
			return inputError("federation batch exceeds size limit")
		}
		var attempts []db.FederationDelivery
		for _, record := range batch.Records {
			if record.Kind == "session_summary" {
				attempts = append(attempts, db.FederationDelivery{RecordUID: record.RecordUID, SessionID: record.RecordUID, Hash: record.Hash})
			}
		}
		if err = s.db.SaveFederationPending(ctx, share.UID, batch.Sequence, string(encoded), attempts); err != nil {
			return err
		}
		if err = s.deliverPending(ctx, link, token, batch, out); err != nil {
			return err
		}
		view.Committed = batch.Sequence
	}
	return nil
}

func (s *Service) federationEligibility(ctx context.Context, share db.FederationShare, ids []string) (map[string]bool, map[string]bool, error) {
	allowed, parents := map[string]bool{}, map[string]bool{}
	for start := 0; start < len(ids); start += 400 {
		end := min(start+400, len(ids))
		selection, err := s.db.SelectFederationCandidates(ctx, share.NormalizedRemote, share.Since, ids[start:end])
		if err != nil {
			return nil, nil, err
		}
		for _, id := range selection.IDs {
			allowed[id] = true
		}
		for id, eligible := range selection.EligibleParents {
			if eligible {
				parents[id] = true
			}
		}
	}
	return allowed, parents, nil
}

// A retained stop permits only individually identified deletions. It never
// treats a stopped share as an empty desired inventory.
func (s *Service) processRetainedNarrowing(ctx context.Context, link db.FederationLink, shares []db.FederationShare, out *PushResult) error {
	for _, share := range shares {
		if share.State == "active" || share.StopReceipt != "retained" {
			continue
		}
		generation, err := s.db.GetDatabaseID(ctx)
		if err != nil {
			return err
		}
		if share.SourceGeneration == "" || share.SourceGeneration != generation {
			return inputError("retained share archive generation changed; fresh consent is required before further delivery")
		}
		token, err := readCredential(ctx, link.TokenFile)
		if err != nil {
			return err
		}
		handshake, err := Handshake(ctx, link.HubOrigin, token, s.archiveID)
		if err != nil {
			return err
		}
		if err = validateHandshake(handshake, link.HubArchiveID); err != nil {
			return err
		}
		view := ShareView{Committed: share.Sequence, Epoch: share.Epoch}
		if share.PendingBatch != "" {
			var batch Batch
			if err = json.Unmarshal([]byte(share.PendingBatch), &batch); err != nil || batch.ShareUID != share.UID || batch.Epoch != share.Epoch || batch.Sequence != share.Sequence+1 {
				return inputError("invalid stored federation batch")
			}
			for _, record := range batch.Records {
				if record.Kind != "tombstone" {
					return inputError("retained share has unresolved delivery")
				}
			}
			ids := make([]string, 0, len(batch.Records))
			for _, record := range batch.Records {
				ids = append(ids, record.RecordUID)
			}
			allowed, _, e := s.federationEligibility(ctx, share, ids)
			if e != nil {
				return e
			}
			for _, id := range ids {
				if allowed[id] {
					return inputError("retained share has unresolved deletion after restore")
				}
			}
			if err = s.deliverPending(ctx, link, token, batch, out); err != nil {
				return err
			}
			view.Committed = batch.Sequence
		}
		cutoff, err := s.db.MirrorPushCutoff(ctx)
		if err != nil {
			return err
		}
		usage, err := s.db.UsageChangeRevision(ctx)
		if err != nil {
			return err
		}
		deletion, err := s.db.SessionDeletionPublicationRevision(ctx)
		if err != nil {
			return err
		}
		usageAfter, deletionAfter := share.UsageCursor, share.DeletionCursor
		if usageAfter > usage {
			usageAfter = 0
		}
		if deletionAfter > deletion {
			deletionAfter = 0
		}
		after := ""
		for {
			ids, err := s.db.FederationChangedCandidates(ctx, share.UID, share.SyncCursor, usageAfter, usage, deletionAfter, deletion, after, 400)
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				break
			}
			ledger, err := s.db.FederationLedgerForIDs(ctx, share.UID, ids)
			if err != nil {
				return err
			}
			allowed, _, err := s.federationEligibility(ctx, share, ids)
			if err != nil {
				return err
			}
			var tombstones []BatchRecord
			for _, id := range ids {
				d, ok := ledger[id]
				if ok && d.State != "refused" && d.State != "tombstoned" && !allowed[id] {
					tombstones = append(tombstones, BatchRecord{RecordUID: id, Kind: "tombstone"})
				}
			}
			if err = s.postFederationRecords(ctx, link, token, share, &view, tombstones, out); err != nil {
				return err
			}
			after = ids[len(ids)-1]
		}
		if err = s.db.AdvanceFederationCursors(ctx, share.UID, share.Epoch, cutoff, usage, deletion); err != nil {
			return err
		}
	}
	return nil
}
