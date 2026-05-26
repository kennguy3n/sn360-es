package zoho

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/agent"
)

// DirectoryClient implements agent.DirectoryClient + agent.DeltaSyncCapable
// against the Zoho Mail Organisation REST API.
//
// Zoho's user endpoint is `/api/organization/{orgID}/accounts` and
// `/api/organization/{orgID}/groups`. Pagination uses `index` (1-based)
// and `limit` query parameters. Each user object carries department,
// designation (job title), role, and admin flags which we map onto
// agent.DiscoveredUser.
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
		return nil, errors.New("zoho: directory client requires a Client")
	}
	return &DirectoryClient{client: cfg.Client}, nil
}

// zohoUser is the subset of the user object we consume.
type zohoUser struct {
	ZUID          string `json:"zuid"`
	AccountID     string `json:"accountId"`
	PrimaryEmail  string `json:"primaryEmailAddress"`
	DisplayName   string `json:"displayName"`
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	Designation   string `json:"designation"`
	Department    string `json:"department"`
	Role          string `json:"role"`
	Status        string `json:"status"`        // "active" | "disabled" | …
	Type          string `json:"type"`          // "user" | "service" | …
	IsAdmin       bool   `json:"isAdmin"`
	IsSuperAdmin  bool   `json:"isSuperAdmin"`
	IsServiceAcct bool   `json:"isServiceAccount"`
	IsShared      bool   `json:"isSharedMailbox"`
	Aliases       []struct {
		Email string `json:"emailAddress"`
	} `json:"emailAliases"`
	GroupIDs    []string `json:"groupIds,omitempty"`
	ModifiedAt  int64    `json:"modifiedTime,omitempty"`
	ManagerZUID string   `json:"managerZuid,omitempty"`
}

// zohoGroup is the subset of the group object we consume.
type zohoGroup struct {
	GroupID     string `json:"groupId"`
	Name        string `json:"groupName"`
	Email       string `json:"emailId"`
	Description string `json:"description"`
	MemberCount int    `json:"memberCount"`
}

// ListUsers enumerates the Zoho organisation's users and maps them
// onto agent.DiscoveredUser. Disabled and shared mailboxes are
// included with the appropriate flags set so the onboarding agent
// can record the full directory.
func (c *DirectoryClient) ListUsers(ctx context.Context, tenantID string) ([]agent.DiscoveredUser, error) {
	_ = tenantID // Zoho infers tenancy from the configured org id.
	raw, err := c.pageUsers(ctx, 0)
	if err != nil {
		return nil, err
	}
	return mapZohoUsers(raw), nil
}

// ListUsersDelta implements agent.DeltaSyncCapable. The deltaToken is
// an RFC3339 timestamp; Zoho's user endpoint supports an
// `updatedAfter` filter (milliseconds since epoch). On empty token
// we run a full sync.
func (c *DirectoryClient) ListUsersDelta(ctx context.Context, tenantID string, deltaToken string) ([]agent.DiscoveredUser, string, error) {
	syncStart := time.Now().UTC()
	if deltaToken == "" {
		users, err := c.ListUsers(ctx, tenantID)
		if err != nil {
			return nil, "", err
		}
		return users, syncStart.Format(time.RFC3339), nil
	}
	since, err := time.Parse(time.RFC3339, deltaToken)
	if err != nil {
		// Token corrupted — fall back to a full sync rather than
		// returning a hard error. The next call gets a clean token.
		users, ferr := c.ListUsers(ctx, tenantID)
		if ferr != nil {
			return nil, "", ferr
		}
		return users, syncStart.Format(time.RFC3339), nil
	}
	raw, err := c.pageUsers(ctx, since.UnixMilli())
	if err != nil {
		return nil, "", fmt.Errorf("zoho: delta sync: %w", err)
	}
	return mapZohoUsers(raw), syncStart.Format(time.RFC3339), nil
}

// pageUsers walks Zoho's offset-based pagination and returns every
// matching user. updatedAfterMillis filters on modifiedTime when > 0.
func (c *DirectoryClient) pageUsers(ctx context.Context, updatedAfterMillis int64) ([]zohoUser, error) {
	const pageSize = 200
	var out []zohoUser
	index := 1
	for {
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", pageSize))
		q.Set("index", fmt.Sprintf("%d", index))
		if updatedAfterMillis > 0 {
			q.Set("updatedAfter", fmt.Sprintf("%d", updatedAfterMillis))
		}
		endpoint := fmt.Sprintf("%s/organization/%s/accounts?%s",
			c.client.baseURL, url.PathEscape(c.client.orgID), q.Encode())
		var page struct {
			Status struct {
				Code int `json:"code"`
			} `json:"status"`
			Data []zohoUser `json:"data"`
		}
		if err := c.client.do(ctx, http.MethodGet, endpoint, nil, &page); err != nil {
			return nil, fmt.Errorf("zoho: list users page %d: %w", index, err)
		}
		if len(page.Data) == 0 {
			break
		}
		out = append(out, page.Data...)
		if len(page.Data) < pageSize {
			break
		}
		index += pageSize
	}
	return out, nil
}

// mapZohoUsers projects raw Zoho user records onto agent.DiscoveredUser.
// Shared, disabled and service-account mailboxes are kept (flags set)
// so callers see the entire directory.
func mapZohoUsers(raw []zohoUser) []agent.DiscoveredUser {
	out := make([]agent.DiscoveredUser, 0, len(raw))
	zuidToID := make(map[string]string, len(raw))
	for _, u := range raw {
		if u.ZUID != "" {
			zuidToID[u.ZUID] = u.AccountID
		}
	}
	for _, u := range raw {
		email := strings.ToLower(strings.TrimSpace(u.PrimaryEmail))
		if email == "" {
			continue
		}
		display := strings.TrimSpace(u.DisplayName)
		if display == "" {
			display = strings.TrimSpace(strings.Join([]string{u.FirstName, u.LastName}, " "))
		}
		aliases := make([]string, 0, len(u.Aliases))
		for _, a := range u.Aliases {
			if strings.TrimSpace(a.Email) != "" {
				aliases = append(aliases, strings.ToLower(a.Email))
			}
		}
		out = append(out, agent.DiscoveredUser{
			ID:               u.AccountID,
			Email:            email,
			DisplayName:      display,
			Department:       u.Department,
			JobTitle:         u.Designation,
			IsAdmin:          u.IsAdmin || u.IsSuperAdmin,
			IsSuspended:      strings.EqualFold(u.Status, "disabled") || strings.EqualFold(u.Status, "deleted"),
			GroupIDs:         u.GroupIDs,
			ManagerID:        zuidToID[u.ManagerZUID],
			Aliases:          aliases,
			IsSharedMailbox:  u.IsShared,
			IsServiceAccount: u.IsServiceAcct || strings.EqualFold(u.Type, "service"),
		})
	}
	return out
}

// ListGroups enumerates the Zoho organisation's groups.
func (c *DirectoryClient) ListGroups(ctx context.Context, tenantID string) ([]agent.DiscoveredGroup, error) {
	_ = tenantID
	const pageSize = 200
	var out []agent.DiscoveredGroup
	index := 1
	for {
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", pageSize))
		q.Set("index", fmt.Sprintf("%d", index))
		endpoint := fmt.Sprintf("%s/organization/%s/groups?%s",
			c.client.baseURL, url.PathEscape(c.client.orgID), q.Encode())
		var page struct {
			Data []zohoGroup `json:"data"`
		}
		if err := c.client.do(ctx, http.MethodGet, endpoint, nil, &page); err != nil {
			return nil, fmt.Errorf("zoho: list groups page %d: %w", index, err)
		}
		if len(page.Data) == 0 {
			break
		}
		for _, g := range page.Data {
			out = append(out, agent.DiscoveredGroup{
				ID:          g.GroupID,
				Name:        g.Name,
				Email:       strings.ToLower(g.Email),
				Description: g.Description,
				MemberCount: g.MemberCount,
			})
		}
		if len(page.Data) < pageSize {
			break
		}
		index += pageSize
	}
	return out, nil
}

// Compile-time checks that DirectoryClient satisfies the agent
// interfaces.
var (
	_ agent.DirectoryClient  = (*DirectoryClient)(nil)
	_ agent.DeltaSyncCapable = (*DirectoryClient)(nil)
)
