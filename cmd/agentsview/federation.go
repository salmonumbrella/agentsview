package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/federation"
	"go.kenn.io/agentsview/internal/requestsign"
)

func federationRequest(ctx context.Context, base, token, method, path string, body any, out any, timeout ...time.Duration) error {
	duration := 30 * time.Second
	if len(timeout) > 0 {
		duration = timeout[0]
	}
	resp, err := federationResponse(ctx, base, token, method, path, body, duration)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	}
	return nil
}

func federationResponse(ctx context.Context, base, token, method, path string, body any, timeout time.Duration) (*http.Response, error) {
	var input io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		input = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, input)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Origin", daemonOriginURL(base))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client, err := requestsign.ClientFromEnvironment(base, &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("federation daemon request failed")
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		var response struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&response) == nil && response.Error != "" {
			return nil, fmt.Errorf("federation: %s", response.Error)
		}
		return nil, fmt.Errorf("federation daemon request returned HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func joinFederation(ctx context.Context, base, token, hub, hubArchive, credentialFile string) error {
	absolute, err := filepath.Abs(credentialFile)
	if err != nil {
		return err
	}
	return federationRequest(ctx, base, token, http.MethodPost, "/api/v1/federation/link", map[string]string{"hub": hub, "hub_archive": hubArchive, "credential_file": absolute}, nil)
}
func federationTransport(cmd *cobra.Command, role string) (transport, config.Config, error) {
	cfg, err := config.LoadPFlagsFor(cmd.Flags(), config.ScopeServer)
	if err != nil {
		return transport{}, cfg, err
	}
	if cfg.Federation.Role != role {
		return transport{}, cfg, fmt.Errorf("federation %s role required", role)
	}
	tr, err := ensureTransportContext(cmd.Context(), &cfg, transportIntentArchiveWrite, 30*time.Second)
	if err != nil {
		return tr, cfg, err
	}
	if tr.Mode != transportHTTP || tr.ReadOnly {
		return tr, cfg, errors.New("writable local daemon required")
	}
	return tr, cfg, nil
}
func printFederationEnrollment(out, diagnostic io.Writer, credential, enrollmentID, hubID string) error {
	if _, err := fmt.Fprintln(out, credential); err != nil {
		return err
	}
	_, err := fmt.Fprintf(diagnostic, "Enrollment: %s\nHub archive: %s\nUse federation join --hub <url> --hub-archive %s --credential-file <path>\n", enrollmentID, hubID, hubID)
	return err
}
func newFederationCommand() *cobra.Command {
	root := &cobra.Command{Use: "federation", Short: "Manage hub enrollments and spoke links", GroupID: groupData, SilenceUsage: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
	var archive, member, name string
	enroll := &cobra.Command{Use: "enroll", Short: "Issue a spoke credential", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		tr, cfg, err := federationTransport(cmd, "hub")
		if err != nil {
			return err
		}
		var result struct {
			Enrollment   db.FederationEnrollment `json:"enrollment"`
			Credential   string                  `json:"credential"`
			HubArchiveID string                  `json:"hub_archive_id"`
		}
		err = federationRequest(cmd.Context(), tr.URL, cfg.AuthToken, http.MethodPost, "/api/v1/federation/enrollments", map[string]string{"spoke_archive_id": archive, "member": member, "spoke_name": name}, &result)
		if err != nil {
			return err
		}
		return printFederationEnrollment(cmd.OutOrStdout(), cmd.ErrOrStderr(), result.Credential, result.Enrollment.UID, result.HubArchiveID)
	}}
	enroll.Flags().StringVar(&archive, "spoke-archive", "", "Spoke archive ID")
	enroll.Flags().StringVar(&member, "member", "", "Member handle")
	enroll.Flags().StringVar(&name, "spoke-name", "", "Spoke name")
	_ = enroll.MarkFlagRequired("spoke-archive")
	_ = enroll.MarkFlagRequired("member")
	list := &cobra.Command{Use: "list", Short: "List enrollments", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		tr, cfg, err := federationTransport(cmd, "hub")
		if err != nil {
			return err
		}
		var result []db.FederationEnrollment
		if err = federationRequest(cmd.Context(), tr.URL, cfg.AuthToken, http.MethodGet, "/api/v1/federation/enrollments", nil, &result); err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}}
	enrollments := &cobra.Command{Use: "enrollments", Short: "Inspect enrollments"}
	enrollments.AddCommand(list)
	revoke := &cobra.Command{Use: "revoke <enrollment-uid>", Short: "Revoke an enrollment", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		tr, cfg, err := federationTransport(cmd, "hub")
		if err != nil {
			return err
		}
		return federationRequest(cmd.Context(), tr.URL, cfg.AuthToken, http.MethodPost, "/api/v1/federation/enrollments/"+url.PathEscape(args[0])+"/revoke", nil, nil)
	}}
	var hub, hubID, file string
	join := &cobra.Command{Use: "join", Short: "Link this spoke to a hub", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		tr, cfg, err := federationTransport(cmd, "spoke")
		if err != nil {
			return err
		}
		return joinFederation(cmd.Context(), tr.URL, cfg.AuthToken, hub, hubID, file)
	}}
	join.Flags().StringVar(&hub, "hub", "", "Hub base URL")
	join.Flags().StringVar(&hubID, "hub-archive", "", "Expected hub archive ID")
	join.Flags().StringVar(&file, "credential-file", "", "Owner-only credential file")
	_ = join.MarkFlagRequired("hub")
	_ = join.MarkFlagRequired("hub-archive")
	_ = join.MarkFlagRequired("credential-file")
	var asJSON bool
	status := &cobra.Command{Use: "status", Short: "Show the spoke link and policy", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		tr, cfg, err := federationTransport(cmd, "spoke")
		if err != nil {
			return err
		}
		var value federation.Status
		if err = federationRequest(cmd.Context(), tr.URL, cfg.AuthToken, http.MethodGet, "/api/v1/federation/link", nil, &value); err != nil {
			return err
		}
		if asJSON {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(value)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Archive: %s\nShares: %d\nSent: %d\nRefused: %d\nTombstoned: %d\nUnconfirmed: %d\nQuarantined: %d\n", value.ArchiveID, value.Shares, value.Delivery.Sent, value.Delivery.Refused, value.Delivery.Tombstoned, value.Delivery.Unconfirmed, len(value.Quarantine))
		for _, h := range value.History {
			fmt.Fprintf(cmd.OutOrStdout(), "Share %s (current: %t): hub %s, archive %s, repository %s; sent %d, refused %d, tombstoned %d, unconfirmed %d; stop %s, receipt %s\n", h.ShareUID, h.Current, h.HubOrigin, h.HubArchiveID, h.NormalizedRemote, h.Delivery.Sent, h.Delivery.Refused, h.Delivery.Tombstoned, h.Delivery.Unconfirmed, h.StopIntent, h.StopReceipt)
		}
		for _, q := range value.Quarantine {
			fmt.Fprintf(cmd.OutOrStdout(), "Quarantine %s at sequence %d: %s\n", q.ShareUID, q.Sequence, q.Error)
		}
		if value.Link != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Hub: %s\nHub archive: %s\nMember: %s\nState: %s\n", value.Link.HubOrigin, value.Link.HubArchiveID, value.Link.Member, value.Link.State)
		}
		if value.Hub != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Hub state: %s\n", value.Hub.State)
			if value.Hub.Message != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Hub message: %s\n", value.Hub.Message)
			}
			if value.Hub.Policy != nil {
				policy, err := json.Marshal(value.Hub.Policy)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Policy: %s\nPolicy digest: %s\n", policy, value.Hub.PolicyDigest)
			}
		}
		return nil
	}}
	status.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	leave := &cobra.Command{Use: "leave", Short: "Remove the local link", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		tr, cfg, err := federationTransport(cmd, "spoke")
		if err != nil {
			return err
		}
		if err := federationRequest(cmd.Context(), tr.URL, cfg.AuthToken, http.MethodDelete, "/api/v1/federation/link", nil, nil); err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.ErrOrStderr(), "Link removed. The hub keeps this enrollment until its operator revokes it; the credential file was left in place.")
		return err
	}}
	root.AddCommand(enroll, enrollments, revoke, join, status, leave, newFederationShareCommand(), newFederationExcludeCommand(), newFederationPushCommand())
	return root
}

func addFederationShare(ctx context.Context, base, token string, grant federation.ShareGrant, in io.Reader, out io.Writer) error {
	var preview federation.SharePreview
	if err := federationRequest(ctx, base, token, http.MethodPost, "/api/v1/federation/shares/preview", grant, &preview, 0); err != nil {
		return err
	}
	data, err := json.MarshalIndent(preview, "", "  ")
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintln(out, string(data)); err != nil {
		return err
	}
	if !confirm(in, out, "Create this share?") {
		_, err = fmt.Fprintln(out, "Aborted; no share was created.")
		return err
	}
	return federationRequest(ctx, base, token, http.MethodPost, "/api/v1/federation/shares", preview, nil)
}
func streamFederationDryRun(ctx context.Context, base, token string, out io.Writer) error {
	resp, err := federationResponse(ctx, base, token, http.MethodGet, "/api/v1/federation/dry-run", nil, 0)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func removeFederationShare(ctx context.Context, base, token, uid string, out io.Writer) error {
	if err := federationRequest(ctx, base, token, http.MethodDelete, "/api/v1/federation/shares/"+url.PathEscape(uid), nil, nil); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, "Share delivery stopped; hub cleanup is pending. Run federation push, then check federation status or share show.")
	return err
}
func printFederationShares(out, diagnostic io.Writer, shares federation.ShareList) error {
	if err := json.NewEncoder(out).Encode(shares.Shares); err != nil {
		return err
	}
	for _, remote := range shares.Suggestions {
		if _, err := fmt.Fprintf(diagnostic, "Suggested: federation share add --project %s --level summary\n", remote); err != nil {
			return err
		}
	}
	return nil
}
func newFederationShareCommand() *cobra.Command {
	root := &cobra.Command{Use: "share", Short: "Manage repository shares"}
	var g federation.ShareGrant
	add := &cobra.Command{Use: "add", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		tr, cfg, err := federationTransport(cmd, "spoke")
		if err != nil {
			return err
		}
		return addFederationShare(cmd.Context(), tr.URL, cfg.AuthToken, g, cmd.InOrStdin(), cmd.OutOrStdout())
	}}
	add.Flags().StringVar(&g.Project, "project", "", "Repository remote")
	add.Flags().StringVar(&g.Level, "level", "", "Share level")
	add.Flags().StringVar(&g.Since, "since", "", "Earliest session start date (UTC)")
	add.Flags().StringVar(&g.Attribution, "attribution", "pooled", "Attribution request")
	_ = add.MarkFlagRequired("project")
	_ = add.MarkFlagRequired("level")
	root.AddCommand(add)
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		tr, cfg, err := federationTransport(cmd, "spoke")
		if err != nil {
			return err
		}
		var shares federation.ShareList
		if err = federationRequest(cmd.Context(), tr.URL, cfg.AuthToken, http.MethodGet, "/api/v1/federation/shares", nil, &shares); err != nil {
			return err
		}
		return printFederationShares(cmd.OutOrStdout(), cmd.ErrOrStderr(), shares)
	}}
	root.AddCommand(list)
	for _, action := range []string{"show", "pause", "resume", "remove"} {
		action := action
		root.AddCommand(&cobra.Command{Use: action + " <share-uid>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			tr, cfg, err := federationTransport(cmd, "spoke")
			if err != nil {
				return err
			}
			path := "/api/v1/federation/shares/" + url.PathEscape(args[0])
			if action == "remove" {
				return removeFederationShare(cmd.Context(), tr.URL, cfg.AuthToken, args[0], cmd.OutOrStdout())
			}
			method := http.MethodPost
			if action == "show" {
				method = http.MethodGet
			}
			if action != "show" {
				path += "/" + action
			}
			if action == "show" {
				var share federation.ShareDetails
				if err = federationRequest(cmd.Context(), tr.URL, cfg.AuthToken, method, path, nil, &share); err != nil {
					return err
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(share)
			}
			if err = federationRequest(cmd.Context(), tr.URL, cfg.AuthToken, method, path, nil, nil); err != nil {
				return err
			}
			return nil
		}})
	}
	return root
}
func newFederationExcludeCommand() *cobra.Command {
	var reason string
	cmd := &cobra.Command{Use: "exclude <session-id>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		tr, cfg, err := federationTransport(cmd, "spoke")
		if err != nil {
			return err
		}
		return federationRequest(cmd.Context(), tr.URL, cfg.AuthToken, http.MethodPost, "/api/v1/federation/exclusions", map[string]string{"session_id": args[0], "reason": reason}, nil)
	}}
	cmd.Flags().StringVar(&reason, "reason", "", "Reason")
	return cmd
}
func newFederationPushCommand() *cobra.Command {
	var dry bool
	cmd := &cobra.Command{Use: "push", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		tr, cfg, err := federationTransport(cmd, "spoke")
		if err != nil {
			return err
		}
		if dry {
			return streamFederationDryRun(cmd.Context(), tr.URL, cfg.AuthToken, cmd.OutOrStdout())
		}
		return pushFederation(cmd.Context(), tr.URL, cfg.AuthToken, cmd.OutOrStdout())
	}}
	cmd.Flags().BoolVar(&dry, "dry-run", false, "Print records without sending")
	return cmd
}

func pushFederation(ctx context.Context, base, token string, out io.Writer) error {
	var result federation.PushResult
	if err := federationRequest(ctx, base, token, http.MethodPost, "/api/v1/federation/push", nil, &result); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "Sent: %d; unchanged: %d; refused: %d; quarantined: %d\n", result.Sent, result.Unchanged, result.Refused, result.Quarantined)
	return err
}
