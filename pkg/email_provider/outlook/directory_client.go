// Package outlook — Microsoft Graph directory client. Implements
// agent.DirectoryClient so the onboarding agent can enumerate users
// and groups for a tenant without dragging the full mailbox poller
// through.
//
// The client uses the standard application-permissions endpoints
// (https://graph.microsoft.com/v1.0/users / /groups) and reuses the
// same client-credentials token source that backs the
// MailboxProvider, LabelProvider, and BannerInjector — refreshing
// once per process.
package outlook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/service/agent"
)

// DirectoryClientConfig configures a DirectoryClient. BaseURL
// defaults to https://graph.microsoft.com/v1.0 when blank.
type DirectoryClientConfig struct {
	TokenSource TokenSource
	HTTPClient  *http.Client
	BaseURL     string
	TenantID    string
}

// DirectoryClient implements agent.DirectoryClient against Microsoft
// Graph.
type DirectoryClient struct {
	http     *http.Client
	tokens   TokenSource
	baseURL  string
	tenantID string
}

// NewDirectoryClient builds a DirectoryClient. Requires a token
// source.
func NewDirectoryClient(cfg DirectoryClientConfig) (*DirectoryClient, error) {
	if cfg.TokenSource == nil {
		return nil, errors.New("outlook: directory client requires a TokenSource")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://graph.microsoft.com/v1.0"
	}
	return &DirectoryClient{
		http:     cfg.HTTPClient,
		tokens:   cfg.TokenSource,
		baseURL:  base,
		tenantID: cfg.TenantID,
	}, nil
}

// graphDirectoryUser is the subset of the Graph user object the
// onboarding agent consumes. Named distinctly from the mailbox
// poller's graphUser to keep the two responsibilities decoupled.
type graphDirectoryUser struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	Department        string `json:"department"`
	JobTitle          string `json:"jobTitle"`
	AccountEnabled    bool   `json:"accountEnabled"`
}

type graphDirectoryUserList struct {
	Value    []graphDirectoryUser `json:"value"`
	NextLink string               `json:"@odata.nextLink,omitempty"`
}

// graphGroup is the subset of the Graph group object.
type graphGroup struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Mail        string `json:"mail"`
}

type graphGroupList struct {
	Value    []graphGroup `json:"value"`
	NextLink string       `json:"@odata.nextLink,omitempty"`
}

// ListUsers enumerates the directory users. Disabled accounts are
// surfaced via the IsSuspended hint so the onboarding agent can
// skip them.
func (c *DirectoryClient) ListUsers(ctx context.Context, tenantID string) ([]agent.DiscoveredUser, error) {
	_ = tenantID
	endpoint := c.baseURL + "/users?" + url.Values{
		"$select": []string{"id,displayName,userPrincipalName,mail,department,jobTitle,accountEnabled"},
		"$top":    []string{"200"},
	}.Encode()
	var out []agent.DiscoveredUser
	for endpoint != "" {
		var list graphDirectoryUserList
		if err := c.do(ctx, http.MethodGet, endpoint, &list); err != nil {
			return nil, fmt.Errorf("outlook: list users: %w", err)
		}
		for _, u := range list.Value {
			email := u.Mail
			if email == "" {
				email = u.UserPrincipalName
			}
			if email == "" {
				continue
			}
			out = append(out, agent.DiscoveredUser{
				ID:          u.ID,
				Email:       strings.ToLower(email),
				DisplayName: u.DisplayName,
				Department:  u.Department,
				JobTitle:    u.JobTitle,
				IsSuspended: !u.AccountEnabled,
			})
		}
		endpoint = list.NextLink
	}
	return out, nil
}

// ListGroups enumerates the directory groups.
func (c *DirectoryClient) ListGroups(ctx context.Context, tenantID string) ([]agent.DiscoveredGroup, error) {
	_ = tenantID
	endpoint := c.baseURL + "/groups?" + url.Values{
		"$select": []string{"id,displayName,description,mail"},
		"$top":    []string{"200"},
	}.Encode()
	var out []agent.DiscoveredGroup
	for endpoint != "" {
		var list graphGroupList
		if err := c.do(ctx, http.MethodGet, endpoint, &list); err != nil {
			return nil, fmt.Errorf("outlook: list groups: %w", err)
		}
		for _, g := range list.Value {
			out = append(out, agent.DiscoveredGroup{
				ID:          g.ID,
				Name:        g.DisplayName,
				Description: g.Description,
				Email:       strings.ToLower(g.Mail),
			})
		}
		endpoint = list.NextLink
	}
	return out, nil
}

// do reuses the LabelProvider transport so we don't duplicate request
// plumbing across the package.
func (c *DirectoryClient) do(ctx context.Context, method, endpoint string, out any) error {
	lp := &LabelProvider{
		baseURL: c.baseURL,
		http:    c.http,
		tokens:  c.tokens,
	}
	return lp.do(ctx, method, endpoint, nil, out)
}
