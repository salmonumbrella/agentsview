package federation

import (
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

func Handshake(ctx context.Context, base, credential, archive string) (HandshakeResponse, error) {
	var result HandshakeResponse
	origin, err := ParseHubOrigin(base)
	if err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/api/v1/federation/handshake", nil)
	if err != nil {
		return result, inputError("invalid federation request")
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set(SpokeArchiveHeader, archive)
	client := http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, inputError("cannot reach hub")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return result, ErrHubRefused
		}
		return result, inputError(fmt.Sprintf("hub returned HTTP %d", resp.StatusCode))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if err != nil || len(data) > 65536 {
		return result, inputError("invalid federation response")
	}
	if err := json.Unmarshal(data, &result, json.RejectUnknownMembers(true)); err != nil {
		return result, inputError("invalid federation response")
	}
	return result, nil
}
