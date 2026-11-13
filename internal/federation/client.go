package federation

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.kenn.io/agentsview/internal/config"
)

const SpokeArchiveHeader = "X-AgentsView-Spoke-Archive"

func ParseHubOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || (u.Fragment != "" || strings.Contains(raw, "#")) || u.Opaque != "" || (u.Scheme != "https" && !(u.Scheme == "http" && config.IsLoopbackHost(u.Hostname()))) {
		return "", inputError("invalid federation hub URL")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

type peerHTTPError struct {
	Status int
	Body   []byte
}

func (e *peerHTTPError) Error() string { return fmt.Sprintf("hub returned HTTP %d", e.Status) }

func peerRequest(ctx context.Context, base, credential, archive, method, path string, body any, result any) error {
	origin, err := ParseHubOrigin(base)
	if err != nil {
		return err
	}
	var input io.Reader
	if body != nil {
		data, e := json.Marshal(body)
		if e != nil {
			return e
		}
		input = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, origin+path, input)
	if err != nil {
		return inputError("invalid federation request")
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set(SpokeArchiveHeader, archive)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return inputError("cannot reach hub")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 {
		return inputError("invalid federation response")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrHubRefused
	}
	if resp.StatusCode != http.StatusOK {
		return &peerHTTPError{Status: resp.StatusCode, Body: data}
	}
	if err = json.Unmarshal(data, result, json.RejectUnknownMembers(true)); err != nil {
		return inputError("invalid federation response")
	}
	return nil
}
func Handshake(ctx context.Context, base, credential, archive string) (HandshakeResponse, error) {
	var result HandshakeResponse
	err := peerRequest(ctx, base, credential, archive, http.MethodGet, "/api/v1/federation/handshake", nil, &result)
	return result, err
}
func PutShare(ctx context.Context, base, credential, archive string, m ShareManifest) (ShareView, error) {
	var result ShareView
	err := peerRequest(ctx, base, credential, archive, http.MethodPut, "/api/v1/federation/shares/"+url.PathEscape(m.ShareUID), m, &result)
	return result, err
}
func PostBatch(ctx context.Context, base, credential, archive string, b Batch) (BatchAck, error) {
	var result BatchAck
	err := peerRequest(ctx, base, credential, archive, http.MethodPost, "/api/v1/federation/shares/"+url.PathEscape(b.ShareUID)+"/batches", b, &result)
	if e, ok := err.(*peerHTTPError); ok && e.Status == http.StatusConflict {
		_ = json.Unmarshal(e.Body, &result)
	}
	return result, err
}
