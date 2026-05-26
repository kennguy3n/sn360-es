package fastmail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/agent"
)

// DirectoryClient implements agent.DirectoryClient against Fastmail's
// JMAP Identity object.
//
// Fastmail does not expose a multi-tenant directory the way Google
// Workspace or Microsoft 365 do. Identities (RFC 8621 §6) represent
// the "From:" addresses the authenticated account is allowed to send
// as — these are the closest analogue to a single-tenant user list
// for SN360-ES onboarding purposes. ListGroups returns nil because
// JMAP has no group concept; the limitation is documented in the
// tenant-requirements guide.
type DirectoryClient struct {
	client *Client
}

// DirectoryClientConfig wires the directory client.
type DirectoryClientConfig struct {
	Client *Client
}

// NewDirectoryClient validates the config and returns a usable client.
func NewDirectoryClient(cfg DirectoryClientConfig) (*DirectoryClient, error) {
	if cfg.Client == nil {
		return nil, errors.New("fastmail: directory client requires a Client")
	}
	return &DirectoryClient{client: cfg.Client}, nil
}

// jmapIdentity is the subset of the JMAP Identity object we consume.
// See RFC 8621 §6.1 for the full definition.
type jmapIdentity struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	MayDelete bool   `json:"mayDelete"`
	TextSig   string `json:"textSignature"`
	HTMLSig   string `json:"htmlSignature"`
	ReplyTo   []struct {
		Email string `json:"email"`
	} `json:"replyTo,omitempty"`
}

// ListUsers calls JMAP Identity/get and projects each identity onto
// agent.DiscoveredUser.
func (c *DirectoryClient) ListUsers(ctx context.Context, tenantID string) ([]agent.DiscoveredUser, error) {
	_ = tenantID
	if c.client.accountID == "" {
		if _, err := c.client.Session(ctx); err != nil {
			return nil, err
		}
	}
	args := map[string]any{
		"accountId": c.client.accountID,
		"ids":       nil,
	}
	resp, err := c.client.Invoke(ctx, "Identity/get", args)
	if err != nil {
		return nil, fmt.Errorf("fastmail: identity/get: %w", err)
	}
	var decoded struct {
		AccountID string         `json:"accountId"`
		State     string         `json:"state"`
		List      []jmapIdentity `json:"list"`
		NotFound  []string       `json:"notFound"`
	}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return nil, fmt.Errorf("fastmail: decode identity/get: %w", err)
	}
	out := make([]agent.DiscoveredUser, 0, len(decoded.List))
	for _, id := range decoded.List {
		email := strings.ToLower(strings.TrimSpace(id.Email))
		if email == "" {
			continue
		}
		out = append(out, agent.DiscoveredUser{
			ID:          id.ID,
			Email:       email,
			DisplayName: id.Name,
		})
	}
	return out, nil
}

// ListGroups returns nil because Fastmail / JMAP does not model
// groups. Callers must rely on per-user sensitivity hints instead of
// group-based classification. Documented in
// blog/tenant-requirements-zoho-fastmail-workmail.md §2.5.
func (c *DirectoryClient) ListGroups(ctx context.Context, tenantID string) ([]agent.DiscoveredGroup, error) {
	_ = ctx
	_ = tenantID
	return nil, nil
}

// ListUsersDelta implements agent.DeltaSyncCapable. JMAP supports
// state-token-based change tracking via Identity/changes, which is
// far more efficient than a full Identity/get. We use the stored
// state string as the delta token. Empty token → run a full sync and
// return the resulting state.
func (c *DirectoryClient) ListUsersDelta(ctx context.Context, tenantID string, deltaToken string) ([]agent.DiscoveredUser, string, error) {
	if deltaToken == "" {
		users, err := c.ListUsers(ctx, tenantID)
		if err != nil {
			return nil, "", err
		}
		state, _ := c.currentState(ctx)
		if state == "" {
			state = time.Now().UTC().Format(time.RFC3339)
		}
		return users, state, nil
	}
	args := map[string]any{
		"accountId":  c.client.accountID,
		"sinceState": deltaToken,
	}
	resp, err := c.client.Invoke(ctx, "Identity/changes", args)
	if err != nil {
		// JMAP returns "cannotCalculateChanges" when the state is
		// too old. Fall back to a full sync rather than failing.
		users, ferr := c.ListUsers(ctx, tenantID)
		if ferr != nil {
			return nil, "", ferr
		}
		state, _ := c.currentState(ctx)
		if state == "" {
			state = time.Now().UTC().Format(time.RFC3339)
		}
		return users, state, nil
	}
	var changes struct {
		AccountID string   `json:"accountId"`
		OldState  string   `json:"oldState"`
		NewState  string   `json:"newState"`
		HasMore   bool     `json:"hasMoreChanges"`
		Created   []string `json:"created"`
		Updated   []string `json:"updated"`
	}
	if err := json.Unmarshal(resp, &changes); err != nil {
		return nil, "", fmt.Errorf("fastmail: decode identity/changes: %w", err)
	}
	wanted := append([]string{}, changes.Created...)
	wanted = append(wanted, changes.Updated...)
	if len(wanted) == 0 {
		return nil, changes.NewState, nil
	}
	args = map[string]any{
		"accountId": c.client.accountID,
		"ids":       wanted,
	}
	getResp, err := c.client.Invoke(ctx, "Identity/get", args)
	if err != nil {
		return nil, "", fmt.Errorf("fastmail: identity/get after changes: %w", err)
	}
	var decoded struct {
		List []jmapIdentity `json:"list"`
	}
	if err := json.Unmarshal(getResp, &decoded); err != nil {
		return nil, "", fmt.Errorf("fastmail: decode identity/get: %w", err)
	}
	out := make([]agent.DiscoveredUser, 0, len(decoded.List))
	for _, id := range decoded.List {
		email := strings.ToLower(strings.TrimSpace(id.Email))
		if email == "" {
			continue
		}
		out = append(out, agent.DiscoveredUser{
			ID:          id.ID,
			Email:       email,
			DisplayName: id.Name,
		})
	}
	return out, changes.NewState, nil
}

// currentState returns the current JMAP Identity state by issuing a
// no-op Identity/get and reading its state field.
func (c *DirectoryClient) currentState(ctx context.Context) (string, error) {
	args := map[string]any{
		"accountId": c.client.accountID,
		"ids":       []string{},
	}
	resp, err := c.client.Invoke(ctx, "Identity/get", args)
	if err != nil {
		return "", err
	}
	var decoded struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return "", err
	}
	return decoded.State, nil
}

// Compile-time interface checks.
var (
	_ agent.DirectoryClient  = (*DirectoryClient)(nil)
	_ agent.DeltaSyncCapable = (*DirectoryClient)(nil)
)
