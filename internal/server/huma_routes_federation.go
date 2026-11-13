package server

import (
	"context"
	"errors"
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
		registerRoute(group, http.MethodPost, "/enrollments", "Enroll a spoke", s.humaFederationEnroll, hidden)
		registerRoute(group, http.MethodGet, "/enrollments", "List enrollments", s.humaFederationList, hidden)
		registerRoute(group, http.MethodPost, "/enrollments/{uid}/revoke", "Revoke an enrollment", s.humaFederationRevoke, hidden)
	}
	if s.federation.Role() == "spoke" {
		registerRoute(group, http.MethodPost, "/link", "Join a hub", s.humaFederationJoin, hidden)
		registerRoute(group, http.MethodGet, "/link", "Read federation status", s.humaFederationStatus, hidden)
		registerRoute(group, http.MethodDelete, "/link", "Leave a hub", s.humaFederationLeave, hidden)
	}
}
func (s *Server) humaFederationHandshake(ctx context.Context, _ *federationHandshakeInput) (*jsonOutput[federation.HandshakeResponse], error) {
	h, ok := ctx.Value(ctxKeyFederationHandshake).(federation.HandshakeResponse)
	if !ok {
		return nil, huma.Error401Unauthorized("Unauthorized")
	}
	return &jsonOutput[federation.HandshakeResponse]{Body: h}, nil
}
func federationControlError(ctx context.Context, err error) error {
	if !isLocalhostContext(ctx) {
		return huma.Error403Forbidden("Forbidden")
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, db.ErrWriterClosed) {
		return huma.Error503ServiceUnavailable("archive temporarily unavailable")
	}
	return huma.Error400BadRequest("federation operation failed")
}
func (s *Server) humaFederationEnroll(ctx context.Context, in *federationEnrollInput) (*jsonOutput[federationEnrollOutput], error) {
	if err := federationControlError(ctx, nil); err != nil {
		return nil, err
	}
	e, token, err := s.federation.Enroll(ctx, in.Body.SpokeArchiveID, in.Body.Member, in.Body.SpokeName)
	if err = federationControlError(ctx, err); err != nil {
		return nil, err
	}
	return &jsonOutput[federationEnrollOutput]{Body: federationEnrollOutput{Enrollment: e, Credential: token, HubArchiveID: s.federation.ArchiveID()}}, nil
}
func (s *Server) humaFederationList(ctx context.Context, _ *emptyInput) (*jsonOutput[[]db.FederationEnrollment], error) {
	if err := federationControlError(ctx, nil); err != nil {
		return nil, err
	}
	result, err := s.federation.List(ctx)
	if err = federationControlError(ctx, err); err != nil {
		return nil, err
	}
	return &jsonOutput[[]db.FederationEnrollment]{Body: result}, nil
}
func (s *Server) humaFederationRevoke(ctx context.Context, in *federationRevokeInput) (*jsonOutput[map[string]bool], error) {
	if err := federationControlError(ctx, nil); err != nil {
		return nil, err
	}
	if err := federationControlError(ctx, s.federation.Revoke(ctx, in.UID)); err != nil {
		return nil, err
	}
	return &jsonOutput[map[string]bool]{Body: map[string]bool{"revoked": true}}, nil
}
func (s *Server) humaFederationJoin(ctx context.Context, in *federationJoinInput) (*jsonOutput[map[string]bool], error) {
	if err := federationControlError(ctx, nil); err != nil {
		return nil, err
	}
	if err := federationControlError(ctx, s.federation.Join(ctx, in.Body.Hub, in.Body.HubArchive, in.Body.CredentialFile)); err != nil {
		return nil, err
	}
	return &jsonOutput[map[string]bool]{Body: map[string]bool{"joined": true}}, nil
}
func (s *Server) humaFederationStatus(ctx context.Context, _ *emptyInput) (*jsonOutput[federation.Status], error) {
	if err := federationControlError(ctx, nil); err != nil {
		return nil, err
	}
	status, err := s.federation.Status(ctx)
	if err = federationControlError(ctx, err); err != nil {
		return nil, err
	}
	return &jsonOutput[federation.Status]{Body: status}, nil
}
func (s *Server) humaFederationLeave(ctx context.Context, _ *emptyInput) (*jsonOutput[map[string]bool], error) {
	if err := federationControlError(ctx, nil); err != nil {
		return nil, err
	}
	if err := federationControlError(ctx, s.federation.Leave(ctx)); err != nil {
		return nil, err
	}
	return &jsonOutput[map[string]bool]{Body: map[string]bool{"left": true}}, nil
}
