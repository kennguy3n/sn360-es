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
	UserType          string `json:"userType"`
	MailboxSettings   *struct {
		MailboxType string `json:"mailboxType"`
	} `json:"mailboxSettings,omitempty"`
	MemberOf []struct {
		ODataType   string `json:"@odata.type"`
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	} `json:"memberOf,omitempty"`
	Manager *struct {
		ID string `json:"id"`
	} `json:"manager,omitempty"`
	ProxyAddresses []string `json:"proxyAddresses"`
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
		"$select": []string{"id,displayName,userPrincipalName,mail,department,jobTitle,accountEnabled,userType,proxyAddresses,mailboxSettings"},
		"$expand": []string{"memberOf($select=id,displayName,@odata.type),manager($select=id)"},
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

			// Extract group IDs and detect admin roles from memberOf.
			var groupIDs []string
			isAdmin := false
			for _, m := range u.MemberOf {
				switch {
				case m.ODataType == "#microsoft.graph.group":
					groupIDs = append(groupIDs, m.ID)
				case m.ODataType == "#microsoft.graph.directoryRole":
					if strings.Contains(m.DisplayName, "Global Administrator") ||
						strings.Contains(m.DisplayName, "Exchange Administrator") {
						isAdmin = true
					}
				}
			}

			// Detect shared mailbox (resource/shared mailboxType only).
			isShared := false
			if u.MailboxSettings != nil && u.MailboxSettings.MailboxType == "shared" {
				isShared = true
			}

			// Detect service account (Guest users are external collaborators, not shared mailboxes).
			isServiceAccount := u.UserType == "Guest"

			// Extract aliases from proxyAddresses (smtp: prefixed).
			var aliases []string
			for _, addr := range u.ProxyAddresses {
				if strings.HasPrefix(strings.ToLower(addr), "smtp:") {
					alias := strings.TrimPrefix(strings.ToLower(addr), "smtp:")
					if alias != strings.ToLower(email) {
						aliases = append(aliases, alias)
					}
				}
			}

			// ManagerID resolved via $expand=manager in the initial query.
			var managerID string
			if u.Manager != nil {
				managerID = u.Manager.ID
			}

			out = append(out, agent.DiscoveredUser{
				ID:               u.ID,
				Email:            strings.ToLower(email),
				DisplayName:      u.DisplayName,
				Department:       u.Department,
				JobTitle:         u.JobTitle,
				IsAdmin:          isAdmin,
				IsSuspended:      !u.AccountEnabled,
				GroupIDs:         groupIDs,
				ManagerID:        managerID,
				Aliases:          aliases,
				IsSharedMailbox:  isShared,
				IsServiceAccount: isServiceAccount,
			})
		}
		endpoint = list.NextLink
	}
	return out, nil
}

// graphDeltaUserList is the response shape for /users/delta queries.
type graphDeltaUserList struct {
	Value     []graphDirectoryUser `json:"value"`
	NextLink  string               `json:"@odata.nextLink,omitempty"`
	DeltaLink string               `json:"@odata.deltaLink,omitempty"`
}

// ListUsersDelta performs an incremental user sync via the MS Graph
// delta query API. When deltaToken is empty an initial full delta sync
// is performed; otherwise the stored deltaLink URL is followed.
// Returns (changed users, new delta token, error).
func (c *DirectoryClient) ListUsersDelta(ctx context.Context, _ string, deltaToken string) ([]agent.DiscoveredUser, string, error) {
	var endpoint string
	if deltaToken != "" {
		endpoint = deltaToken
	} else {
		endpoint = c.baseURL + "/users/delta?" + url.Values{
			"$select": []string{"id,displayName,userPrincipalName,mail,department,jobTitle,accountEnabled,userType,proxyAddresses"},
			"$top":    []string{"200"},
		}.Encode()
	}

	var out []agent.DiscoveredUser
	var newDeltaToken string
	for endpoint != "" {
		var list graphDeltaUserList
		if err := c.do(ctx, http.MethodGet, endpoint, &list); err != nil {
			return nil, "", fmt.Errorf("outlook: delta users: %w", err)
		}
		for _, u := range list.Value {
			email := u.Mail
			if email == "" {
				email = u.UserPrincipalName
			}
			if email == "" {
				continue
			}
			var groupIDs []string
			isAdmin := false
			for _, m := range u.MemberOf {
				switch {
				case m.ODataType == "#microsoft.graph.group":
					groupIDs = append(groupIDs, m.ID)
				case m.ODataType == "#microsoft.graph.directoryRole":
					if strings.Contains(m.DisplayName, "Global Administrator") ||
						strings.Contains(m.DisplayName, "Exchange Administrator") {
						isAdmin = true
					}
				}
			}
			isShared := false
			if u.MailboxSettings != nil && u.MailboxSettings.MailboxType == "shared" {
				isShared = true
			}
			isServiceAccount := u.UserType == "Guest"
			var aliases []string
			for _, addr := range u.ProxyAddresses {
				if strings.HasPrefix(strings.ToLower(addr), "smtp:") {
					alias := strings.TrimPrefix(strings.ToLower(addr), "smtp:")
					if alias != strings.ToLower(email) {
						aliases = append(aliases, alias)
					}
				}
			}
			var managerID string
			if u.Manager != nil {
				managerID = u.Manager.ID
			}
			out = append(out, agent.DiscoveredUser{
				ID:               u.ID,
				Email:            strings.ToLower(email),
				DisplayName:      u.DisplayName,
				Department:       u.Department,
				JobTitle:         u.JobTitle,
				IsAdmin:          isAdmin,
				IsSuspended:      !u.AccountEnabled,
				GroupIDs:         groupIDs,
				ManagerID:        managerID,
				Aliases:          aliases,
				IsSharedMailbox:  isShared,
				IsServiceAccount: isServiceAccount,
			})
		}
		if list.DeltaLink != "" {
			newDeltaToken = list.DeltaLink
		}
		endpoint = list.NextLink
	}
	return out, newDeltaToken, nil
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
