package federation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/export"
	"go.kenn.io/agentsview/internal/requestsign"
)

const (
	ProtocolVersion = 2
	LinkActive      = "active"
	LinkBlocked     = "blocked"
	HubOK           = "ok"
	HubError        = "error"
	HubBlocked      = "blocked"
)

type Service struct {
	pushSem         chan struct{}
	role, archiveID string
	policy          config.FederationHubConfig
	db              *db.DB
}

func NewService(role, archiveID string, policy config.FederationHubConfig, database *db.DB) *Service {
	if policy.SuggestedProjects == nil {
		policy.SuggestedProjects = []string{}
	}
	return &Service{role: role, archiveID: archiveID, policy: policy, db: database, pushSem: make(chan struct{}, 1)}
}
func (s *Service) Role() string      { return s.role }
func (s *Service) ArchiveID() string { return s.archiveID }

// Pulse returns the aggregate released under the hub's configured policy.
func (s *Service) Pulse(ctx context.Context, since string) (db.FederationPulse, error) {
	if s.role != "hub" {
		return db.FederationPulse{}, inputError("pulse requires the hub role")
	}
	if s.policy.MinGroupSize < 1 {
		return db.FederationPulse{}, inputError("pulse requires a positive minimum group size")
	}
	pulse, err := s.db.FederationPulse(ctx, since, s.policy.MinGroupSize)
	if errors.Is(err, db.ErrFederationPulseSince) {
		return db.FederationPulse{}, inputError("since must be a non-future date in YYYY-MM-DD format")
	}
	return pulse, err
}
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
		return "", inputError("credential file path must be absolute")
	}
	b, err := requestsign.ReadPrivate(path, 4096)
	if err != nil {
		switch {
		case errors.Is(err, requestsign.ErrPrivateMode):
			return "", inputError("credential file must be a regular file readable only by its owner (mode 0600)")
		default:
			return "", inputError("cannot open credential file")
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	encoded, ok := strings.CutPrefix(token, "avfc_")
	decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if !ok || decodeErr != nil || len(decoded) != 32 {
		return "", inputError("invalid federation credential")
	}
	return token, nil
}
func normalizeIdentifier(value, field string, required bool) (string, error) {
	value = strings.TrimSpace(value)
	if required && value == "" {
		return "", inputError(field + " is required")
	}
	return value, nil
}
func (s *Service) Enroll(ctx context.Context, archive, member, name string) (db.FederationEnrollment, string, error) {
	var e db.FederationEnrollment
	var err error
	if archive, err = normalizeIdentifier(archive, "spoke archive ID", true); err != nil {
		return e, "", err
	}
	if member, err = normalizeIdentifier(member, "member", true); err != nil {
		return e, "", err
	}
	if name, err = normalizeIdentifier(name, "spoke name", false); err != nil {
		return e, "", err
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
		if errors.Is(err, db.ErrFederationEnrollmentExists) {
			return db.FederationEnrollment{}, "", inputError("an active enrollment already exists for this spoke archive and member; revoke it first")
		}
		return db.FederationEnrollment{}, "", err
	}
	e.CredentialSHA256 = ""
	e.State = "enrolled"
	return e, token, nil
}
func (s *Service) List(ctx context.Context) ([]db.FederationEnrollment, error) {
	return s.db.ListFederationEnrollments(ctx)
}
func (s *Service) Revoke(ctx context.Context, uid string) (bool, error) {
	var proof []db.FederationRetentionProof
	if s.policy.Validate() == nil {
		digest, err := export.DigestCanonical(s.policy)
		if err != nil {
			return false, err
		}
		proof = append(proof, db.FederationRetentionProof{PolicyDigest: digest, Retention: s.policy.Retention})
	}
	changed, err := s.db.RevokeFederationEnrollment(ctx, uid, proof...)
	if errors.Is(err, db.ErrFederationCleanupPending) {
		return changed, inputError(err.Error())
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, inputError("enrollment not found")
	}
	return changed, err
}
func (s *Service) Authenticate(ctx context.Context, token, archive string) (HandshakeResponse, error) {
	return s.AuthenticatePeer(ctx, token, archive, true)
}
func (s *Service) AuthenticatePeer(ctx context.Context, token, archive string, stamp bool) (HandshakeResponse, error) {
	var out HandshakeResponse
	if !strings.HasPrefix(token, "avfc_") {
		return out, db.ErrFederationUnauthorized
	}
	var e db.FederationEnrollment
	var err error
	if stamp {
		e, err = s.db.AuthenticateFederationCredential(ctx, credentialDigest(token), archive)
	} else {
		e, err = s.db.LookupFederationCredential(ctx, credentialDigest(token), archive)
	}
	if err != nil {
		return out, err
	}
	digest, err := export.DigestCanonical(s.policy)
	if err != nil {
		return out, err
	}
	return HandshakeResponse{HubArchiveID: s.archiveID, SpokeArchiveID: e.SpokeArchiveID, ProtocolVersions: []int{ProtocolVersion}, EnrollmentUID: e.UID, Member: e.Member, EnrollmentState: "enrolled", Policy: s.policy, PolicyDigest: digest}, nil
}
func validateHandshake(h HandshakeResponse, expected string) error {
	if h.HubArchiveID != expected || h.EnrollmentUID == "" || h.Member == "" {
		return inputError("federation hub identity mismatch")
	}
	supported := false
	for _, v := range h.ProtocolVersions {
		if v == ProtocolVersion {
			supported = true
		}
	}
	if !supported {
		return inputError("unsupported federation protocol")
	}
	if h.EnrollmentState != "enrolled" {
		return inputError("unsupported enrollment state")
	}
	if h.Policy.SuggestedProjects == nil {
		return inputError("invalid federation policy")
	}
	if err := h.Policy.Validate(); err != nil {
		return inputError("invalid federation policy")
	}
	digest, err := export.DigestCanonical(h.Policy)
	if err != nil || digest != h.PolicyDigest {
		return inputError("invalid federation policy digest")
	}
	return nil
}
func (s *Service) Join(ctx context.Context, origin, hubID, tokenFile string) error {
	_, err := s.db.GetFederationLink(ctx)
	if err == nil {
		return inputError("already linked to a hub; run federation leave first")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if hubID == "" {
		return inputError("hub archive ID is required")
	}
	origin, err = ParseHubOrigin(origin)
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
	uid, err := randomID("link_", 16)
	if err != nil {
		return err
	}
	err = s.db.PutFederationLink(ctx, db.FederationLink{UID: uid, HubOrigin: origin, HubArchiveID: hubID, EnrollmentUID: h.EnrollmentUID, Member: h.Member, TokenFile: tokenFile, ProtocolVersion: ProtocolVersion, State: LinkActive})
	if errors.Is(err, db.ErrFederationLinkExists) {
		return inputError("already linked to a hub; run federation leave first")
	}
	return err
}

type Status struct {
	ArchiveID  string                    `json:"archive_id"`
	Link       *db.FederationLink        `json:"link,omitempty"`
	Shares     int                       `json:"shares"`
	Delivery   DeliveryCounts            `json:"delivery"`
	Quarantine []db.FederationQuarantine `json:"quarantine"`
	Hub        *HubStatus                `json:"hub,omitempty"`
	History    []DeliveryHistory         `json:"history"`
}
type DeliveryHistory struct {
	ShareUID         string         `json:"share_uid"`
	HubOrigin        string         `json:"hub_origin"`
	HubArchiveID     string         `json:"hub_archive_id"`
	NormalizedRemote string         `json:"normalized_remote"`
	Delivery         DeliveryCounts `json:"delivery"`
	Current          bool           `json:"current"`
	StopIntent       string         `json:"stop_intent,omitempty"`
	StopReceipt      string         `json:"stop_receipt,omitempty"`
}
type HubStatus struct {
	State        string                      `json:"state"`
	Message      string                      `json:"message,omitempty"`
	Policy       *config.FederationHubConfig `json:"policy,omitempty"`
	PolicyDigest string                      `json:"policy_digest,omitempty"`
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	out := Status{ArchiveID: s.archiveID}
	uids, err := s.db.FederationLedgerShares(ctx)
	if err != nil {
		return out, err
	}
	for _, uid := range uids {
		ledger, e := s.db.FederationLedger(ctx, uid)
		if e != nil {
			return out, e
		}
		entry := DeliveryHistory{ShareUID: uid, Delivery: deliveryCounts(ledger)}
		for _, d := range ledger {
			entry.HubOrigin, entry.HubArchiveID, entry.NormalizedRemote = d.HubOrigin, d.HubArchiveID, d.NormalizedRemote
			break
		}
		out.History = append(out.History, entry)
	}
	links, err := s.db.ListFederationLinks(ctx)
	if err != nil {
		return out, err
	}
	for _, old := range links {
		oldShares, e := s.db.ListFederationShares(ctx, old.UID)
		if e != nil {
			return out, e
		}
		for _, share := range oldShares {
			index := -1
			for i := range out.History {
				if out.History[i].ShareUID == share.UID {
					index = i
					break
				}
			}
			if index < 0 {
				out.History = append(out.History, DeliveryHistory{ShareUID: share.UID})
				index = len(out.History) - 1
			}
			entry := &out.History[index]
			if entry.HubOrigin == "" {
				entry.HubOrigin = old.HubOrigin
			}
			if entry.HubArchiveID == "" {
				entry.HubArchiveID = old.HubArchiveID
			}
			if entry.NormalizedRemote == "" {
				entry.NormalizedRemote = share.NormalizedRemote
			}
			entry.StopIntent, entry.StopReceipt = share.StopIntent, share.StopReceipt
		}
	}
	out.Quarantine, err = s.db.FederationQuarantines(ctx)
	if err != nil {
		return out, err
	}
	link, err := s.db.GetFederationLink(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Link = &link
	shares, err := s.db.ListFederationShares(ctx, link.UID)
	if err != nil {
		return out, err
	}
	out.Shares = len(shares)
	for i := range out.History {
		for _, share := range shares {
			if out.History[i].ShareUID == share.UID {
				out.History[i].Current = true
				counts := out.History[i].Delivery
				out.Delivery.Tombstoned += counts.Tombstoned
				out.Delivery.Sent += counts.Sent
				out.Delivery.Refused += counts.Refused
				out.Delivery.Unconfirmed += counts.Unconfirmed
				break
			}
		}
	}
	out.Hub = &HubStatus{}
	if link.State == LinkBlocked {
		out.Hub.State = HubBlocked
		return out, nil
	}
	token, err := readCredential(ctx, link.TokenFile)
	if err != nil {
		var input *InputError
		if errors.As(err, &input) {
			out.Hub.State, out.Hub.Message = HubError, err.Error()
			return out, nil
		}
		return out, err
	}
	h, err := Handshake(ctx, link.HubOrigin, token, s.archiveID)
	if err != nil {
		var input *InputError
		var peer *peerHTTPError
		if errors.Is(err, ErrHubRefused) || errors.As(err, &input) || errors.As(err, &peer) {
			out.Hub.State, out.Hub.Message = HubError, err.Error()
			return out, nil
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		out.Hub.State, out.Hub.Message = HubError, "hub unavailable"
		return out, nil
	}
	if h.HubArchiveID != link.HubArchiveID {
		if err := s.db.BlockFederationLink(ctx, link.UID); err != nil {
			return out, err
		}
		link.State = LinkBlocked
		out.Hub.State, out.Hub.Message = HubBlocked, "federation hub identity mismatch"
		return out, nil
	}
	if err = validateHandshake(h, link.HubArchiveID); err != nil {
		out.Hub.State, out.Hub.Message = HubError, err.Error()
		return out, nil
	}
	if h.EnrollmentUID != link.EnrollmentUID || h.Member != link.Member {
		out.Hub.State, out.Hub.Message = HubError, "federation enrollment changed"
		return out, nil
	}
	for _, share := range shares {
		if share.State == "active" && share.PolicyDigest != h.PolicyDigest {
			if err := s.db.PauseFederationSharesForPolicy(ctx, link.UID, h.PolicyDigest); err != nil {
				return out, err
			}
			break
		}
	}
	out.Hub.State, out.Hub.Policy, out.Hub.PolicyDigest = HubOK, &h.Policy, h.PolicyDigest
	return out, nil
}
func (s *Service) acquirePush(ctx context.Context) (func(), error) {
	select {
	case s.pushSem <- struct{}{}:
		return func() { <-s.pushSem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *Service) Leave(ctx context.Context) error {
	release, err := s.acquirePush(ctx)
	if err != nil {
		return err
	}
	defer release()
	return s.db.DeleteFederationLink(ctx)
}
