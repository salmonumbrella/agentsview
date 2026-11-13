package federation

import "go.kenn.io/agentsview/internal/config"

type HandshakeResponse struct {
	HubArchiveID     string                     `json:"hub_archive_id"`
	ProtocolVersions []int                      `json:"protocol_versions"`
	EnrollmentUID    string                     `json:"enrollment_uid"`
	Member           string                     `json:"member"`
	Policy           config.FederationHubConfig `json:"policy"`
	PolicyDigest     string                     `json:"policy_digest"`
}
