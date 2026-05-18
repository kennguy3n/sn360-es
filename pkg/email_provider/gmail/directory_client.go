// Package gmail — Workspace Admin SDK directory client. Implements
// agent.DirectoryClient so the onboarding agent can enumerate users
// and groups for a tenant without dragging the full mailbox poller
// through.
//
// The client is a thin wrapper over the Admin SDK Directory API
// (https://developers.google.com/admin-sdk/directory) and re-uses the
// same JWT bearer token source that backs MailboxProvider /
// LabelProvider so we only refresh OAuth credentials once per process.
package gmail

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/service/agent"
)

// DirectoryClientConfig configures a DirectoryClient. AdminBaseURL
// defaults to https://admin.googleapis.com when blank. Domain is the
// primary domain ("example.com") whose users we enumerate; when both
// Domain and CustomerID are blank the request falls back to
// `customer=my_customer` which the Admin SDK accepts for the calling
// account's own customer.
type DirectoryClientConfig struct {
	TokenSource  TokenSource
	HTTPClient   *http.Client
	AdminBaseURL string
	Domain       string
	CustomerID   string
}

// DirectoryClient implements agent.DirectoryClient.
type DirectoryClient struct {
	http       *http.Client
	tokens     TokenSource
	adminBase  string
	domain     string
	customerID string
}

// NewDirectoryClient builds a DirectoryClient. Requires a token
// source; everything else has sensible defaults.
func NewDirectoryClient(cfg DirectoryClientConfig) (*DirectoryClient, error) {
	if cfg.TokenSource == nil {
		return nil, errors.New("gmail: directory client requires a TokenSource")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	base := strings.TrimRight(cfg.AdminBaseURL, "/")
	if base == "" {
		base = "https://admin.googleapis.com"
	}
	customer := cfg.CustomerID
	if customer == "" {
		customer = "my_customer"
	}
	return &DirectoryClient{
		http:       cfg.HTTPClient,
		tokens:     cfg.TokenSource,
		adminBase:  base,
		domain:     cfg.Domain,
		customerID: customer,
	}, nil
}

// directoryUser is the subset of the Admin SDK user object the
// onboarding agent needs.
type directoryUser struct {
	ID           string `json:"id"`
	PrimaryEmail string `json:"primaryEmail"`
	Suspended    bool   `json:"suspended"`
	Archived     bool   `json:"archived"`
	IsAdmin      bool   `json:"isAdmin"`
	Name         struct {
		FullName string `json:"fullName"`
	} `json:"name"`
	OrganizationsRaw []struct {
		Department string `json:"department"`
		Title      string `json:"title"`
	} `json:"organizations"`
}

type directoryUserList struct {
	Users         []directoryUser `json:"users"`
	NextPageToken string          `json:"nextPageToken,omitempty"`
}

// directoryGroup is the subset of the Admin SDK group object.
type directoryGroup struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Email              string `json:"email"`
	Description        string `json:"description"`
	DirectMembersCount int    `json:"directMembersCount,string"`
}

type directoryGroupList struct {
	Groups        []directoryGroup `json:"groups"`
	NextPageToken string           `json:"nextPageToken,omitempty"`
}

// ListUsers enumerates the workspace users and returns them as
// agent.DiscoveredUser. Suspended and archived users are *included*
// in the result with the IsSuspended flag set so the onboarding
// agent can record the full directory and decide which mailboxes to
// seed itself (mailbox polling, by contrast, skips suspended users
// at the MailboxProvider layer — see mailbox_provider.go).
func (c *DirectoryClient) ListUsers(ctx context.Context, tenantID string) ([]agent.DiscoveredUser, error) {
	_ = tenantID
	var out []agent.DiscoveredUser
	page := ""
	for {
		q := url.Values{}
		if c.domain != "" {
			q.Set("domain", c.domain)
		} else {
			q.Set("customer", c.customerID)
		}
		q.Set("maxResults", "200")
		if page != "" {
			q.Set("pageToken", page)
		}
		endpoint := fmt.Sprintf("%s/admin/directory/v1/users?%s", c.adminBase, q.Encode())
		var list directoryUserList
		if err := c.do(ctx, http.MethodGet, endpoint, &list); err != nil {
			return nil, fmt.Errorf("gmail: list users: %w", err)
		}
		for _, u := range list.Users {
			if u.PrimaryEmail == "" {
				continue
			}
			dept := ""
			title := ""
			if len(u.OrganizationsRaw) > 0 {
				dept = u.OrganizationsRaw[0].Department
				title = u.OrganizationsRaw[0].Title
			}
			out = append(out, agent.DiscoveredUser{
				ID:          u.ID,
				Email:       strings.ToLower(u.PrimaryEmail),
				DisplayName: u.Name.FullName,
				Department:  dept,
				JobTitle:    title,
				IsAdmin:     u.IsAdmin,
				IsSuspended: u.Suspended || u.Archived,
			})
		}
		if list.NextPageToken == "" {
			break
		}
		page = list.NextPageToken
	}
	return out, nil
}

// ListGroups enumerates the workspace groups.
func (c *DirectoryClient) ListGroups(ctx context.Context, tenantID string) ([]agent.DiscoveredGroup, error) {
	_ = tenantID
	var out []agent.DiscoveredGroup
	page := ""
	for {
		q := url.Values{}
		if c.domain != "" {
			q.Set("domain", c.domain)
		} else {
			q.Set("customer", c.customerID)
		}
		q.Set("maxResults", "200")
		if page != "" {
			q.Set("pageToken", page)
		}
		endpoint := fmt.Sprintf("%s/admin/directory/v1/groups?%s", c.adminBase, q.Encode())
		var list directoryGroupList
		if err := c.do(ctx, http.MethodGet, endpoint, &list); err != nil {
			return nil, fmt.Errorf("gmail: list groups: %w", err)
		}
		for _, g := range list.Groups {
			out = append(out, agent.DiscoveredGroup{
				ID:          g.ID,
				Name:        g.Name,
				Description: g.Description,
				Email:       strings.ToLower(g.Email),
				MemberCount: g.DirectMembersCount,
			})
		}
		if list.NextPageToken == "" {
			break
		}
		page = list.NextPageToken
	}
	return out, nil
}

// do reuses the LabelProvider transport (which handles bearer-token
// injection and JSON decode) so we don't duplicate request plumbing.
func (c *DirectoryClient) do(ctx context.Context, method, endpoint string, out any) error {
	lp := &LabelProvider{
		baseURL: c.adminBase,
		http:    c.http,
		tokens:  c.tokens,
	}
	return lp.do(ctx, method, endpoint, nil, out)
}
