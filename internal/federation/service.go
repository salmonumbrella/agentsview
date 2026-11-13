package federation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/export"
	"go.kenn.io/agentsview/internal/requestsign"
)

type Service struct {
	role, archiveID string
	policy          config.FederationHubConfig
	db              *db.DB
}

func NewService(role, archiveID string, policy config.FederationHubConfig, database *db.DB) *Service {
	return &Service{role: role, archiveID: archiveID, policy: policy, db: database}
}
func (s *Service) Role() string      { return s.role }
func (s *Service) ArchiveID() string { return s.archiveID }
func randomID(prefix string, n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}
func credentialDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func readCredential(ctx context.Context, path string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("credential file path must be absolute")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot open credential file")
	}
	defer f.Close()
	if !requestsign.IsPrivateFile(f) {
		return "", errors.New("credential file must be owner-only and regular")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return "", errors.New("cannot read credential file")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	encoded, ok := strings.CutPrefix(token, "avfc_")
	decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if !ok || decodeErr != nil || len(decoded) != 32 {
		return "", errors.New("invalid federation credential")
	}
	return token, nil
}
func (s *Service) Enroll(ctx context.Context, archive, member, name string) (db.FederationEnrollment, string, error) {
	var e db.FederationEnrollment
	if s.role != "hub" || strings.TrimSpace(archive) == "" || strings.TrimSpace(member) == "" {
		return e, "", errors.New("hub, spoke archive and member required")
	}
	token, err := randomID("avfc_", 32)
	if err != nil {
		return e, "", err
	}
	uid, err := randomID("enr_", 16)
	if err != nil {
		return e, "", err
	}
	e = db.FederationEnrollment{UID: uid, SpokeArchiveID: archive, Member: member, SpokeName: name, CredentialSHA256: credentialDigest(token)}
	if err = s.db.CreateFederationEnrollment(ctx, e); err != nil {
		return db.FederationEnrollment{}, "", err
	}
	e.CredentialSHA256 = ""
	return e, token, nil
}
func (s *Service) List(ctx context.Context) ([]db.FederationEnrollment, error) {
	if s.role != "hub" {
		return nil, errors.New("hub role required")
	}
	return s.db.ListFederationEnrollments(ctx)
}
func (s *Service) Revoke(ctx context.Context, uid string) error {
	if s.role != "hub" {
		return errors.New("hub role required")
	}
	return s.db.RevokeFederationEnrollment(ctx, uid)
}
func (s *Service) Authenticate(ctx context.Context, token, archive string) (HandshakeResponse, error) {
	var out HandshakeResponse
	if s.role != "hub" || !strings.HasPrefix(token, "avfc_") {
		return out, db.ErrFederationUnauthorized
	}
	e, err := s.db.AuthenticateFederationCredential(ctx, credentialDigest(token), archive)
	if err != nil {
		return out, err
	}
	digest, err := export.DigestCanonical(s.policy)
	if err != nil {
		return out, err
	}
	return HandshakeResponse{HubArchiveID: s.archiveID, ProtocolVersions: []int{1}, EnrollmentUID: e.UID, Member: e.Member, Policy: s.policy, PolicyDigest: digest}, nil
}
func validateHandshake(h HandshakeResponse, expected string) error {
	if h.HubArchiveID != expected || h.EnrollmentUID == "" || h.Member == "" {
		return errors.New("federation hub identity mismatch")
	}
	supported := false
	for _, v := range h.ProtocolVersions {
		if v == 1 {
			supported = true
		}
	}
	if !supported {
		return errors.New("unsupported federation protocol")
	}
	if h.Policy.SuggestedProjects == nil {
		return errors.New("invalid federation policy")
	}
	if err := (config.FederationConfig{Role: "hub", Hub: h.Policy}).Validate(); err != nil {
		return errors.New("invalid federation policy")
	}
	digest, err := export.DigestCanonical(h.Policy)
	if err != nil || digest != h.PolicyDigest {
		return errors.New("invalid federation policy digest")
	}
	return nil
}
func (s *Service) Join(ctx context.Context, origin, hubID, tokenFile string) error {
	if s.role != "spoke" || hubID == "" {
		return errors.New("spoke role and hub archive required")
	}
	origin, err := ParseHubOrigin(origin)
	if err != nil {
		return err
	}
	token, err := readCredential(ctx, tokenFile)
	if err != nil {
		return err
	}
	h, err := Handshake(ctx, origin, token, s.archiveID)
	if err != nil {
		return err
	}
	if err = validateHandshake(h, hubID); err != nil {
		return err
	}
	policy, err := json.Marshal(h.Policy)
	if err != nil {
		return err
	}
	uid, err := randomID("link_", 16)
	if err != nil {
		return err
	}
	return s.db.PutFederationLink(ctx, db.FederationLink{UID: uid, HubOrigin: origin, HubArchiveID: hubID, EnrollmentUID: h.EnrollmentUID, Member: h.Member, TokenFile: tokenFile, ProtocolVersion: 1, PolicyJSON: string(policy), PolicyDigest: h.PolicyDigest, State: "active"})
}

type Status struct {
	ArchiveID string             `json:"archive_id"`
	Link      *db.FederationLink `json:"link,omitempty"`
	Shares    int                `json:"shares"`
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	out := Status{ArchiveID: s.archiveID}
	if s.role != "spoke" {
		return out, errors.New("spoke role required")
	}
	link, err := s.db.GetFederationLink(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Link = &link
	if link.State != "active" {
		return out, nil
	}
	token, err := readCredential(ctx, link.TokenFile)
	if err != nil {
		return out, err
	}
	h, err := Handshake(ctx, link.HubOrigin, token, s.archiveID)
	if err != nil {
		return out, err
	}
	if h.HubArchiveID != link.HubArchiveID {
		if err := s.db.BlockFederationLink(ctx, link.UID); err != nil {
			return out, err
		}
		link.State = "blocked"
		return out, nil
	}
	if err = validateHandshake(h, link.HubArchiveID); err != nil {
		return out, err
	}
	if h.EnrollmentUID != link.EnrollmentUID || h.Member != link.Member {
		return out, errors.New("federation enrollment changed")
	}
	policy, err := json.Marshal(h.Policy)
	if err != nil {
		return out, err
	}
	if err = s.db.RefreshFederationLink(ctx, link.UID, string(policy), h.PolicyDigest); err != nil {
		return out, err
	}
	link.PolicyJSON = string(policy)
	link.PolicyDigest = h.PolicyDigest
	return out, nil
}
func (s *Service) Leave(ctx context.Context) error {
	if s.role != "spoke" {
		return errors.New("spoke role required")
	}
	return s.db.DeleteFederationLink(ctx)
}
