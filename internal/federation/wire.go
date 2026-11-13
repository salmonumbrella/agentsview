package federation

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/db"
)

type HandshakeResponse struct {
	HubArchiveID     string                     `json:"hub_archive_id"`
	ProtocolVersions []int                      `json:"protocol_versions"`
	SpokeArchiveID   string                     `json:"-"`
	EnrollmentUID    string                     `json:"enrollment_uid"`
	Member           string                     `json:"member"`
	EnrollmentState  string                     `json:"enrollment_state"`
	Policy           config.FederationHubConfig `json:"policy"`
	PolicyDigest     string                     `json:"policy_digest"`
}

type ShareManifest struct {
	Protocol      int                         `json:"protocol"`
	SpokeInstance string                      `json:"spoke_instance"`
	ShareUID      string                      `json:"share_uid"`
	Epoch         int64                       `json:"epoch"`
	Remote        string                      `json:"normalized_remote"`
	ProjectKey    string                      `json:"project_key"`
	Level         string                      `json:"level"`
	Attribution   string                      `json:"attribution"`
	Audience      string                      `json:"audience"`
	PolicyDigest  string                      `json:"policy_digest"`
	Action        string                      `json:"action,omitempty"`
	Policy        *config.FederationHubConfig `json:"policy,omitempty"`
}
type ShareView struct {
	State     string `json:"state"`
	Committed int64  `json:"committed"`
	Epoch     int64  `json:"epoch"`
	Changed   bool   `json:"-"`
}
type Batch struct {
	Protocol      int           `json:"protocol"`
	SpokeInstance string        `json:"spoke_instance"`
	ShareUID      string        `json:"share_uid"`
	Epoch         int64         `json:"epoch"`
	Sequence      int64         `json:"sequence"`
	Records       []BatchRecord `json:"records"`
}
type BatchRecord struct {
	RecordUID string         `json:"record_uid"`
	Kind      string         `json:"kind"`
	Hash      string         `json:"hash"`
	Payload   *SummaryRecord `json:"payload,omitempty"`
}
type BatchAck struct {
	Committed int64             `json:"committed"`
	Refused   map[string]string `json:"refused"`
	Changed   bool              `json:"-"`
}

// DecodeBatch checks the record limit before allocating decoded payloads.
func DecodeBatch(data []byte) (Batch, error) {
	var batch Batch
	bad := func() (Batch, error) { return Batch{}, inputError("invalid federation batch") }
	if len(data) > 16<<20 {
		return bad()
	}
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	tok, err := dec.ReadToken()
	if err != nil || tok.Kind() != '{' {
		return bad()
	}
	foundRecords := false
	for dec.PeekKind() != '}' {
		name, err := dec.ReadToken()
		if err != nil {
			return bad()
		}
		if name.String() != "records" {
			if dec.SkipValue() != nil {
				return bad()
			}
			continue
		}
		if foundRecords {
			return bad()
		}
		foundRecords = true
		tok, err = dec.ReadToken()
		if err != nil || tok.Kind() != '[' {
			return bad()
		}
		n := 0
		for dec.PeekKind() != ']' {
			n++
			if n > 1000 {
				return bad()
			}
			if dec.SkipValue() != nil {
				return bad()
			}
		}
		if _, err = dec.ReadToken(); err != nil {
			return bad()
		}
	}
	if _, err = dec.ReadToken(); err != nil || !foundRecords {
		return bad()
	}
	if err = json.Unmarshal(data, &batch, json.RejectUnknownMembers(true)); err != nil {
		return bad()
	}
	return batch, nil
}

// ReconcileRequest carries only selected IDs and hashes for one bounded range.
type ReconcileRequest struct {
	Protocol      int    `json:"protocol"`
	SpokeInstance string `json:"spoke_instance"`
	ShareUID      string `json:"share_uid"`
	db.FederationInventoryPage
}
