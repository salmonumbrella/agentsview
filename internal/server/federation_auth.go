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

func federationPeerOperation(method, path string) bool {
	if method == http.MethodGet && path == federationHandshakePath {
		return true
	}
	const prefix = "/api/v1/federation/shares/"
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	if len(parts) == 1 && parts[0] != "" && method == http.MethodPut {
		return true
	}
	return len(parts) == 2 && parts[0] != "" && parts[1] == "batches" && method == http.MethodPost
}

// federationAuth returns true when it has handled the request; a nil service
// still refuses federation credentials.
func (s *Server) federationAuth(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
	token, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	unauthorized := func() { setCORSOnAuthError(w, r); http.Error(w, "Unauthorized", http.StatusUnauthorized) }
	if s.federation == nil || !federationPeerOperation(r.Method, r.URL.Path) || r.URL.EscapedPath() != r.URL.Path || s.federation.Role() != "hub" {
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
	queryCredential := false
	for _, v := range r.URL.Query()["token"] {
		if strings.HasPrefix(v, "avfc_") {
			queryCredential = true
		}
	}
	if !hasBearer || queryCredential {
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
	result, err := s.federation.AuthenticatePeer(authCtx, token, r.Header.Get(federation.SpokeArchiveHeader), r.URL.Path == federationHandshakePath)
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
