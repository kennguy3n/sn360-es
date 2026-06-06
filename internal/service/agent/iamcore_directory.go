package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IAMCoreUserSource fetches a tenant's user roster from an external
// identity provider. It is the seam the directory-sync worker uses
// when configured with the iam-core directory source, kept as an
// interface so the worker can be unit-tested without standing up an
// HTTP server.
type IAMCoreUserSource interface {
	ListUsers(ctx context.Context, tenantID string) ([]DiscoveredUser, error)
}

// IAMCoreDirectoryClient reads users from uneycom/iam-core's
// Management API (GET /api/v1/management/users?tenant_id={tid}) and
// maps them onto the canonical DiscoveredUser shape so the rest of
// the directory-sync pipeline (sensitivity classification, org-graph
// construction) is unaware of the source.
//
// Only the user roster is sourced from iam-core; groups, memberships,
// sensitivity classification and the org-graph snapshot continue to be
// produced by sn360-es because they are email-security specific.
type IAMCoreDirectoryClient struct {
	baseURL  string
	token    string
	client   *http.Client
	pageSize int
}

// IAMCoreDirectoryConfig wires an IAMCoreDirectoryClient.
type IAMCoreDirectoryConfig struct {
	// BaseURL is the iam-core Management API origin (scheme + host,
	// e.g. https://iam.example.com). Required.
	BaseURL string
	// Token is the bearer token presented to the Management API. It
	// must carry the `read:users` scope. Required.
	Token string
	// HTTPClient performs the requests. Defaults to a client with a
	// 30s timeout when nil.
	HTTPClient *http.Client
	// PageSize is the per-request page size used when walking the
	// paginated Management API. Defaults to 100.
	PageSize int
}

// NewIAMCoreDirectoryClient constructs an IAMCoreDirectoryClient.
func NewIAMCoreDirectoryClient(cfg IAMCoreDirectoryConfig) (*IAMCoreDirectoryClient, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("agent: iam-core directory requires BaseURL")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("agent: iam-core directory requires Token")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	pageSize := cfg.PageSize
	if pageSize <= 0 {
		pageSize = 100
	}
	return &IAMCoreDirectoryClient{
		baseURL:  strings.TrimRight(cfg.BaseURL, "/"),
		token:    cfg.Token,
		client:   client,
		pageSize: pageSize,
	}, nil
}

// iamCoreUser is the subset of iam-core's Management API user shape
// sn360-es consumes. iam-core returns a richer object (see iam-core
// internal/management/handlers.go userBaseMap); we bind only the
// fields the directory pipeline needs.
type iamCoreUser struct {
	UserID   string         `json:"user_id"`
	Email    string         `json:"email"`
	Name     string         `json:"name"`
	Blocked  bool           `json:"blocked"`
	Metadata map[string]any `json:"metadata"`
}

// iamCoreUsersResponse mirrors the Management API list envelope.
type iamCoreUsersResponse struct {
	Total    int           `json:"total"`
	Page     int           `json:"page"`
	PageSize int           `json:"page_size"`
	Users    []iamCoreUser `json:"users"`
}

// ListUsers implements IAMCoreUserSource. It walks every page of the
// Management API list endpoint, accumulating the full tenant roster.
func (c *IAMCoreDirectoryClient) ListUsers(ctx context.Context, tenantID string) ([]DiscoveredUser, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("agent: iam-core ListUsers requires tenantID")
	}
	var out []DiscoveredUser
	// iam-core paginates from page 1. Stop on the first empty page,
	// or once we have collected the reported `total` — whichever
	// comes first. The `total` guard bounds the loop even if the API
	// ever returned a non-empty trailing page.
	for page := 1; ; page++ {
		resp, err := c.fetchPage(ctx, tenantID, page)
		if err != nil {
			return nil, err
		}
		for _, u := range resp.Users {
			out = append(out, mapIAMCoreUser(u))
		}
		if len(resp.Users) == 0 {
			break
		}
		if resp.Total > 0 && len(out) >= resp.Total {
			break
		}
	}
	return out, nil
}

func (c *IAMCoreDirectoryClient) fetchPage(ctx context.Context, tenantID string, page int) (*iamCoreUsersResponse, error) {
	q := url.Values{}
	q.Set("tenant_id", tenantID)
	q.Set("page", fmt.Sprintf("%d", page))
	q.Set("page_size", fmt.Sprintf("%d", c.pageSize))
	endpoint := c.baseURL + "/api/v1/management/users?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("agent: iam-core build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	// iam-core resolves the tenant from context/query/header; send
	// the header too so the request is unambiguous even behind
	// gateways that strip query strings from logs.
	req.Header.Set("X-Tenant-ID", tenantID)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent: iam-core list users: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: iam-core list users: unexpected status %d", resp.StatusCode)
	}
	var decoded iamCoreUsersResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("agent: iam-core decode users: %w", err)
	}
	return &decoded, nil
}

// mapIAMCoreUser projects an iam-core Management API user onto the
// canonical DiscoveredUser. Department and job title are read from the
// user's metadata when present — iam-core stores no first-class HR
// fields, and operators commonly carry them in app_metadata.
func mapIAMCoreUser(u iamCoreUser) DiscoveredUser {
	du := DiscoveredUser{
		ID:          u.UserID,
		Email:       u.Email,
		DisplayName: u.Name,
		IsSuspended: u.Blocked,
	}
	if u.Metadata != nil {
		du.Department = metadataString(u.Metadata, "department")
		du.JobTitle = metadataString(u.Metadata, "job_title", "jobTitle", "title")
	}
	return du
}

// metadataString returns the first string value among keys, or "".
func metadataString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
