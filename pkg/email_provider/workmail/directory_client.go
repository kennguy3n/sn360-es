package workmail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/agent"
)

// DirectoryClient implements agent.DirectoryClient against the
// WorkMail JSON API.
//
// WorkMail's user listing endpoint returns paginated results via a
// NextToken cursor. Each user object carries Email, DisplayName,
// State and UserRole which we map onto agent.DiscoveredUser. There
// is no native delta-sync API; ListUsersDelta therefore performs a
// full sync each call and returns the current timestamp as the
// token. Operators wanting incremental sync can periodically clear
// the token to force a full reconcile.
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
		return nil, errors.New("workmail: directory client requires a Client")
	}
	return &DirectoryClient{client: cfg.Client}, nil
}

// workMailUser is the subset of the WorkMail user object we consume.
type workMailUser struct {
	ID           string `json:"Id"`
	Email        string `json:"Email"`
	Name         string `json:"Name"`
	DisplayName  string `json:"DisplayName"`
	State        string `json:"State"`    // ENABLED | DISABLED | DELETED
	UserRole     string `json:"UserRole"` // USER | RESOURCE | SYSTEM_USER
	EnabledDate  string `json:"EnabledDate,omitempty"`
	DisabledDate string `json:"DisabledDate,omitempty"`
}

// listUsersOutput is the WorkMail ListUsers response shape.
type listUsersOutput struct {
	Users     []workMailUser `json:"Users"`
	NextToken string         `json:"NextToken,omitempty"`
}

// ListUsers enumerates the WorkMail organisation and projects each
// user onto agent.DiscoveredUser.
func (c *DirectoryClient) ListUsers(ctx context.Context, tenantID string) ([]agent.DiscoveredUser, error) {
	_ = tenantID // WorkMail tenancy is derived from the configured OrganizationId.
	var users []workMailUser
	var nextToken string
	for {
		in := map[string]any{
			"OrganizationId": c.client.orgID,
			"MaxResults":     100,
		}
		if nextToken != "" {
			in["NextToken"] = nextToken
		}
		var out listUsersOutput
		if err := c.client.Invoke(ctx, "ListUsers", in, &out); err != nil {
			return nil, fmt.Errorf("workmail: list users: %w", err)
		}
		users = append(users, out.Users...)
		if out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return mapWorkMailUsers(users), nil
}

// ListUsersDelta implements agent.DeltaSyncCapable. WorkMail has no
// native delta API so we always perform a full sync. The returned
// token is the current UTC RFC3339 timestamp; callers may use it for
// audit / observability.
func (c *DirectoryClient) ListUsersDelta(ctx context.Context, tenantID string, deltaToken string) ([]agent.DiscoveredUser, string, error) {
	_ = deltaToken
	users, err := c.ListUsers(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	return users, time.Now().UTC().Format(time.RFC3339), nil
}

// mapWorkMailUsers projects raw WorkMail user records onto
// agent.DiscoveredUser. RESOURCE users (shared mailboxes / meeting
// rooms) and SYSTEM_USER (service accounts) are kept with their
// flags set so the onboarding agent can record the full directory.
func mapWorkMailUsers(raw []workMailUser) []agent.DiscoveredUser {
	out := make([]agent.DiscoveredUser, 0, len(raw))
	for _, u := range raw {
		email := strings.ToLower(strings.TrimSpace(u.Email))
		if email == "" {
			continue
		}
		display := strings.TrimSpace(u.DisplayName)
		if display == "" {
			display = strings.TrimSpace(u.Name)
		}
		isShared := strings.EqualFold(u.UserRole, "RESOURCE")
		isService := strings.EqualFold(u.UserRole, "SYSTEM_USER")
		out = append(out, agent.DiscoveredUser{
			ID:               u.ID,
			Email:            email,
			DisplayName:      display,
			IsSuspended:      strings.EqualFold(u.State, "DISABLED") || strings.EqualFold(u.State, "DELETED"),
			IsSharedMailbox:  isShared,
			IsServiceAccount: isService,
		})
	}
	return out
}

// workMailGroup is the subset of the WorkMail group object we consume.
type workMailGroup struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Email string `json:"Email"`
	State string `json:"State"`
}

// listGroupsOutput is the WorkMail ListGroups response shape.
type listGroupsOutput struct {
	Groups    []workMailGroup `json:"Groups"`
	NextToken string          `json:"NextToken,omitempty"`
}

// ListGroups enumerates WorkMail groups (distribution lists).
func (c *DirectoryClient) ListGroups(ctx context.Context, tenantID string) ([]agent.DiscoveredGroup, error) {
	_ = tenantID
	var groups []workMailGroup
	var nextToken string
	for {
		in := map[string]any{
			"OrganizationId": c.client.orgID,
			"MaxResults":     100,
		}
		if nextToken != "" {
			in["NextToken"] = nextToken
		}
		var out listGroupsOutput
		if err := c.client.Invoke(ctx, "ListGroups", in, &out); err != nil {
			return nil, fmt.Errorf("workmail: list groups: %w", err)
		}
		groups = append(groups, out.Groups...)
		if out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	out := make([]agent.DiscoveredGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, agent.DiscoveredGroup{
			ID:    g.ID,
			Name:  g.Name,
			Email: strings.ToLower(g.Email),
		})
	}
	return out, nil
}

// Compile-time interface checks.
var (
	_ agent.DirectoryClient  = (*DirectoryClient)(nil)
	_ agent.DeltaSyncCapable = (*DirectoryClient)(nil)
)
