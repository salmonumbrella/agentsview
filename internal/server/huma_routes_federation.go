package server

import (
	"context"
	"database/sql"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"log"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/federation"
)

type federationHandshakeInput struct {
	Authorization string `header:"Authorization"`
	SpokeArchive  string `header:"X-AgentsView-Spoke-Archive"`
}
type federationEnrollInput struct {
	Body struct {
		SpokeArchiveID string `json:"spoke_archive_id"`
		Member         string `json:"member"`
		SpokeName      string `json:"spoke_name"`
	}
}
type federationEnrollOutput struct {
	Enrollment   db.FederationEnrollment `json:"enrollment"`
	Credential   string                  `json:"credential"`
	HubArchiveID string                  `json:"hub_archive_id"`
}
type federationRevokeInput struct {
	UID string `path:"uid"`
}
type federationJoinInput struct {
	Body struct {
		Hub            string `json:"hub"`
		HubArchive     string `json:"hub_archive"`
		CredentialFile string `json:"credential_file"`
	}
}

func (s *Server) registerFederationRoutes() {
	if !s.federationSchemaOnly && s.federation == nil {
		return
	}
	group := huma.NewGroup(s.api, "/api/v1/federation")
	configureRouteGroup(group, "Federation")
	if s.federationSchemaOnly || s.federation.Role() == "hub" {
		registerRoute(group, http.MethodGet, "/handshake", "Read federation handshake", s.humaFederationHandshake, s.humaTimeout())
	}
	if s.federation == nil {
		return
	}
	hidden := func(op *huma.Operation) {
		op.Hidden = true
		op.Middlewares = append(op.Middlewares, func(ctx huma.Context, next func(huma.Context)) {
			req, writer := humago.Unwrap(ctx)
			if !isLocalhostRequest(req) {
				http.Error(writer, "Forbidden", http.StatusForbidden)
				return
			}
			next(ctx)
		})
	}
	if s.federation.Role() == "hub" {
		peer := func(op *huma.Operation) { op.Hidden = true }
		registerRoute(group, http.MethodPut, "/shares/{uid}", "Register share", s.humaFederationPutShare, peer, maxBodyBytes(16<<20))
		registerRoute(group, http.MethodPost, "/shares/{uid}/batches", "Deliver batch", s.humaFederationBatch, peer, maxBodyBytes(16<<20))
		registerRoute(group, http.MethodPost, "/shares/{uid}/reconcile", "Reconcile share", s.humaFederationReconcile, peer, maxBodyBytes(16<<20))
		registerRoute(group, http.MethodPost, "/enrollments", "Enroll a spoke", s.humaFederationEnroll, hidden)
		registerRoute(group, http.MethodGet, "/enrollments", "List enrollments", s.humaFederationList, hidden)
		registerRoute(group, http.MethodPost, "/enrollments/{uid}/revoke", "Revoke an enrollment", s.humaFederationRevoke, hidden)
	}
	if s.federation.Role() == "spoke" {
		registerRoute(group, http.MethodPost, "/push", "Deliver shares", s.humaFederationPush, hidden)
		registerRoute(group, http.MethodPost, "/link", "Join a hub", s.humaFederationJoin, hidden)
		registerRoute(group, http.MethodGet, "/link", "Read federation status", s.humaFederationStatus, hidden)
		registerRoute(group, http.MethodDelete, "/link", "Leave a hub", s.humaFederationLeave, hidden)
		registerRoute(group, http.MethodPost, "/shares/preview", "Preview share", s.humaSharePreview, hidden)
		registerRoute(group, http.MethodPost, "/shares", "Add share", s.humaShareAdd, hidden)
		registerRoute(group, http.MethodGet, "/shares", "List shares", s.humaShares, hidden)
		registerRoute(group, http.MethodGet, "/shares/{uid}", "Show share", s.humaShare, hidden)
		registerRoute(group, http.MethodPost, "/shares/{uid}/pause", "Pause share", s.humaSharePause, hidden)
		registerRoute(group, http.MethodPost, "/shares/{uid}/resume", "Resume share", s.humaShareResume, hidden)
		registerRoute(group, http.MethodDelete, "/shares/{uid}", "Remove share", s.humaShareRemove, hidden)
		registerRoute(group, http.MethodPost, "/exclusions", "Exclude session", s.humaExclude, hidden)
		s.stream(group, http.MethodGet, "/dry-run", "Preview records", s.humaDryRun, hidden)

	}
}
func (s *Server) humaFederationHandshake(ctx context.Context, _ *federationHandshakeInput) (*jsonOutput[federation.HandshakeResponse], error) {
	h, ok := ctx.Value(ctxKeyFederationHandshake).(federation.HandshakeResponse)
	if !ok {
		return nil, huma.Error401Unauthorized("Unauthorized")
	}
	return &jsonOutput[federation.HandshakeResponse]{Body: h}, nil
}
func federationControlError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return huma.Error404NotFound("federation item not found")
	}
	if errors.Is(err, db.ErrWriterClosed) {
		return huma.Error503ServiceUnavailable("archive temporarily unavailable")
	}
	var input *federation.InputError
	if errors.As(err, &input) || errors.Is(err, federation.ErrHubRefused) {
		return huma.Error400BadRequest(err.Error())
	}
	log.Printf("federation operation failed: %v", err)
	return huma.Error500InternalServerError("federation operation failed")
}
func (s *Server) humaFederationEnroll(ctx context.Context, in *federationEnrollInput) (*jsonOutput[federationEnrollOutput], error) {
	e, token, err := s.federation.Enroll(ctx, in.Body.SpokeArchiveID, in.Body.Member, in.Body.SpokeName)
	if err = federationControlError(err); err != nil {
		return nil, err
	}
	return &jsonOutput[federationEnrollOutput]{Body: federationEnrollOutput{Enrollment: e, Credential: token, HubArchiveID: s.federation.ArchiveID()}}, nil
}
func (s *Server) humaFederationList(ctx context.Context, _ *emptyInput) (*jsonOutput[[]db.FederationEnrollment], error) {
	result, err := s.federation.List(ctx)
	if err = federationControlError(err); err != nil {
		return nil, err
	}
	return &jsonOutput[[]db.FederationEnrollment]{Body: result}, nil
}
func (s *Server) humaFederationRevoke(ctx context.Context, in *federationRevokeInput) (*jsonOutput[map[string]bool], error) {
	changed, err := s.federation.Revoke(ctx, in.UID)
	if changed {
		if s.broadcaster != nil {
			s.broadcaster.Emit("sessions")
		}
		s.notifySessionMutation()
	}
	if err = federationControlError(err); err != nil {
		return nil, err
	}
	return &jsonOutput[map[string]bool]{Body: map[string]bool{"revoked": true}}, nil
}
func (s *Server) humaFederationJoin(ctx context.Context, in *federationJoinInput) (*jsonOutput[map[string]bool], error) {
	if err := federationControlError(s.federation.Join(ctx, in.Body.Hub, in.Body.HubArchive, in.Body.CredentialFile)); err != nil {
		return nil, err
	}
	return &jsonOutput[map[string]bool]{Body: map[string]bool{"joined": true}}, nil
}
func (s *Server) humaFederationStatus(ctx context.Context, _ *emptyInput) (*jsonOutput[federation.Status], error) {
	status, err := s.federation.Status(ctx)
	if err = federationControlError(err); err != nil {
		return nil, err
	}
	return &jsonOutput[federation.Status]{Body: status}, nil
}
func (s *Server) humaFederationLeave(ctx context.Context, _ *emptyInput) (*jsonOutput[map[string]bool], error) {
	if err := federationControlError(s.federation.Leave(ctx)); err != nil {
		return nil, err
	}
	return &jsonOutput[map[string]bool]{Body: map[string]bool{"left": true}}, nil
}

type shareGrantInput struct{ Body federation.ShareGrant }
type sharePreviewInput struct{ Body federation.SharePreview }
type shareUIDInput struct {
	UID string `path:"uid"`
}
type excludeInput struct {
	Body struct {
		SessionID string `json:"session_id"`
		Reason    string `json:"reason"`
	}
}

func (s *Server) humaSharePreview(ctx context.Context, in *shareGrantInput) (*jsonOutput[federation.SharePreview], error) {
	v, err := s.federation.PreviewShare(ctx, in.Body)
	if err = federationControlError(err); err != nil {
		return nil, err
	}
	return &jsonOutput[federation.SharePreview]{Body: v}, nil
}
func (s *Server) humaShareAdd(ctx context.Context, in *sharePreviewInput) (*jsonOutput[map[string]bool], error) {
	if err := federationControlError(s.federation.AddShare(ctx, in.Body)); err != nil {
		return nil, err
	}
	return &jsonOutput[map[string]bool]{Body: map[string]bool{"added": true}}, nil
}
func (s *Server) humaShares(ctx context.Context, _ *emptyInput) (*jsonOutput[federation.ShareList], error) {
	v, err := s.federation.Shares(ctx)
	if err = federationControlError(err); err != nil {
		return nil, err
	}
	return &jsonOutput[federation.ShareList]{Body: v}, nil
}
func (s *Server) humaShare(ctx context.Context, in *shareUIDInput) (*jsonOutput[federation.ShareDetails], error) {
	v, err := s.federation.Share(ctx, in.UID)
	if err = federationControlError(err); err != nil {
		return nil, err
	}
	return &jsonOutput[federation.ShareDetails]{Body: v}, nil
}
func (s *Server) humaSharePause(ctx context.Context, in *shareUIDInput) (*jsonOutput[map[string]bool], error) {
	if err := federationControlError(s.federation.PauseShare(ctx, in.UID)); err != nil {
		return nil, err
	}
	return &jsonOutput[map[string]bool]{Body: map[string]bool{"paused": true}}, nil
}
func (s *Server) humaShareResume(ctx context.Context, in *shareUIDInput) (*jsonOutput[map[string]bool], error) {
	if err := federationControlError(s.federation.ResumeShare(ctx, in.UID)); err != nil {
		return nil, err
	}
	return &jsonOutput[map[string]bool]{Body: map[string]bool{"resumed": true}}, nil
}
func (s *Server) humaShareRemove(ctx context.Context, in *shareUIDInput) (*jsonOutput[map[string]bool], error) {
	if err := federationControlError(s.federation.RemoveShare(ctx, in.UID)); err != nil {
		return nil, err
	}
	return &jsonOutput[map[string]bool]{Body: map[string]bool{"removed": true}}, nil
}
func (s *Server) humaExclude(ctx context.Context, in *excludeInput) (*jsonOutput[map[string]bool], error) {
	if err := federationControlError(s.federation.Exclude(ctx, in.Body.SessionID, in.Body.Reason)); err != nil {
		return nil, err
	}
	return &jsonOutput[map[string]bool]{Body: map[string]bool{"excluded": true}}, nil
}
func (s *Server) humaDryRun(ctx context.Context, _ *emptyInput) (*huma.StreamResponse, error) {
	records, err := s.federation.DryRun(ctx)
	if err = federationControlError(err); err != nil {
		return nil, err
	}
	return &huma.StreamResponse{Body: func(hctx huma.Context) {
		hctx.SetHeader("Content-Type", "application/x-ndjson")
		enc := json.NewEncoder(hctx.BodyWriter())
		for _, record := range records {
			if err := enc.Encode(record); err != nil {
				return
			}
		}
	}}, nil
}

type federationPeerInput struct {
	UID     string `path:"uid"`
	RawBody []byte `contentType:"application/json"`
}
type federationBatchOutput struct {
	Status int
	Body   federation.BatchAck
}

func peerIdentity(ctx context.Context) (federation.HandshakeResponse, error) {
	h, ok := ctx.Value(ctxKeyFederationHandshake).(federation.HandshakeResponse)
	if !ok {
		return h, huma.Error401Unauthorized("Unauthorized")
	}
	return h, nil
}
func (s *Server) humaFederationPutShare(ctx context.Context, in *federationPeerInput) (*jsonOutput[federation.ShareView], error) {
	h, err := peerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	var m federation.ShareManifest
	if err = jsonv2.Unmarshal(in.RawBody, &m, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, huma.Error400BadRequest("invalid federation share")
	}
	v, err := s.federation.RegisterShare(ctx, h.EnrollmentUID, h.SpokeArchiveID, in.UID, m)
	if err = federationControlError(err); err != nil {
		return nil, err
	}
	if v.Changed {
		if s.broadcaster != nil {
			s.broadcaster.Emit("sessions")
		}
		s.notifySessionMutation()
	}
	return &jsonOutput[federation.ShareView]{Body: v}, nil
}
func (s *Server) humaFederationBatch(ctx context.Context, in *federationPeerInput) (*federationBatchOutput, error) {
	h, err := peerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	b, err := federation.DecodeBatch(in.RawBody)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid federation batch")
	}
	v, err := s.federation.ApplyBatch(ctx, h.EnrollmentUID, h.SpokeArchiveID, in.UID, b)
	if errors.Is(err, db.ErrFederationInvalidBatch) {
		return nil, huma.Error400BadRequest("invalid federation batch")
	}
	if errors.Is(err, db.ErrFederationSequence) {
		return &federationBatchOutput{Status: http.StatusConflict, Body: v}, nil
	}
	if err = federationControlError(err); err != nil {
		return nil, err
	}
	if v.Changed {
		if s.broadcaster != nil {
			s.broadcaster.Emit("sessions")
		}
		s.notifySessionMutation()
	}
	return &federationBatchOutput{Status: http.StatusOK, Body: v}, nil
}
func (s *Server) humaFederationPush(ctx context.Context, _ *emptyInput) (*jsonOutput[federation.PushResult], error) {
	v, err := s.federation.Push(ctx)
	if err = federationControlError(err); err != nil {
		return nil, err
	}
	return &jsonOutput[federation.PushResult]{Body: v}, nil
}

func (s *Server) humaFederationReconcile(ctx context.Context, in *federationPeerInput) (*jsonOutput[db.FederationInventoryResult], error) {
	h, err := peerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	var page federation.ReconcileRequest
	if err = jsonv2.Unmarshal(in.RawBody, &page, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, huma.Error400BadRequest("invalid federation inventory")
	}
	result, err := s.federation.Reconcile(ctx, h.EnrollmentUID, h.SpokeArchiveID, in.UID, page)
	if errors.Is(err, db.ErrFederationInvalidBatch) {
		return nil, huma.Error400BadRequest("invalid federation inventory")
	}
	if errors.Is(err, db.ErrFederationSequence) {
		return nil, huma.Error409Conflict("federation inventory out of sequence")
	}
	if err = federationControlError(err); err != nil {
		return nil, err
	}
	if result.Changed {
		if s.broadcaster != nil {
			s.broadcaster.Emit("sessions")
		}
		s.notifySessionMutation()
	}
	return &jsonOutput[db.FederationInventoryResult]{Body: result}, nil
}
