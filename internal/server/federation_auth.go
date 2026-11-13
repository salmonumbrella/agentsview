package server

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/federation"
)

const federationHandshakePath = "/api/v1/federation/handshake"

// federationAuth returns true when it has handled the request; a nil service
// still refuses federation credentials.
func (s *Server) federationAuth(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
	token, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	unauthorized := func() { setCORSOnAuthError(w, r); http.Error(w, "Unauthorized", http.StatusUnauthorized) }
	if s.federation == nil || r.URL.Path != federationHandshakePath || s.federation.Role() != "hub" {
		queryCredential := false
		for _, value := range r.URL.Query()["token"] {
			if strings.HasPrefix(value, "avfc_") {
				queryCredential = true
			}
		}
		if strings.HasPrefix(token, "avfc_") || queryCredential {
			unauthorized()
			return true
		}
		return false
	}
	if !hasBearer || r.Method != http.MethodGet {
		unauthorized()
		return true
	}
	s.mu.RLock()
	timeout := s.cfg.WriteTimeout
	s.mu.RUnlock()
	authCtx := r.Context()
	cancel := func() {}
	if timeout > 0 {
		authCtx, cancel = context.WithTimeout(authCtx, timeout)
	}
	defer cancel()
	result, err := s.federation.Authenticate(authCtx, token, r.Header.Get(federation.SpokeArchiveHeader))
	if err != nil {
		if errors.Is(err, db.ErrWriterClosed) {
			http.Error(w, "archive temporarily unavailable", http.StatusServiceUnavailable)
		} else if errors.Is(err, db.ErrFederationUnauthorized) {
			unauthorized()
		} else {
			http.Error(w, "federation authentication failed", http.StatusInternalServerError)
		}
		return true
	}
	ctx := context.WithValue(r.Context(), ctxKeyFederationHandshake, result)
	ctx = context.WithValue(ctx, ctxKeyRemoteAuth, true)
	next.ServeHTTP(w, r.WithContext(ctx))
	return true
}
