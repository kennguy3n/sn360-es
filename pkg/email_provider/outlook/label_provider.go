// Package outlook provides a minimal Microsoft Graph client that
// implements action.LabelProvider for Outlook / Exchange Online.
//
// Outlook does not have an arbitrary user-defined label model like
// Gmail. Instead it has a per-mailbox "Master Category List" plus a
// `categories` array on each message. The closest equivalent of
// `EnsureLabel + ApplyLabel` is therefore:
//
//   - EnsureLabel  : POST /me/outlook/masterCategories (idempotent —
//     409 on duplicate is treated as success and we fetch the id).
//   - ApplyLabel   : PATCH /me/messages/{id} with `categories`
//     replaced by the union of the existing list and the new
//     category name. ("ID" for Outlook is just the category name.)
//   - RemoveLabel  : PATCH /me/messages/{id} with `categories`
//     reduced by the removed category.
//
// The HTTP shape matches the public Microsoft Graph v1.0 API. The
// implementation is intentionally dependency-free: we use net/http
// directly so the binary does not pull `github.com/microsoftgraph/...`.
package outlook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// TokenSource yields a fresh OAuth2 bearer token (typically a Microsoft
// Graph delegated or app-only token) on each call. Keeping the surface
// small lets the caller plug in MSAL, golang.org/x/oauth2, or a custom
// impersonation flow.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenSourceFunc adapts a function to TokenSource.
type TokenSourceFunc func(ctx context.Context) (string, error)

// Token implements TokenSource.
func (f TokenSourceFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// Config wires the Outlook LabelProvider.
type Config struct {
	// BaseURL overrides the Graph endpoint. Default is the public
	// endpoint at https://graph.microsoft.com.
	BaseURL string
	// HTTPClient is the transport. Default is http.Client with a 30s
	// timeout.
	HTTPClient *http.Client
	// TokenSource issues bearer tokens. Required.
	TokenSource TokenSource
}

// LabelProvider implements action.LabelProvider against Microsoft
// Graph.
type LabelProvider struct {
	baseURL string
	http    *http.Client
	tokens  TokenSource
}

// New constructs an Outlook LabelProvider. TokenSource is required.
func New(cfg Config) (*LabelProvider, error) {
	if cfg.TokenSource == nil {
		return nil, errors.New("outlook: token source is required")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://graph.microsoft.com"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &LabelProvider{baseURL: base, http: client, tokens: cfg.TokenSource}, nil
}

// Kind reports the provider identity used by action.LabelApplier.
func (p *LabelProvider) Kind() action.LabelProviderKind { return action.LabelProviderOutlook }

// outlookCategory is the wire shape for outlookMasterCategory.
type outlookCategory struct {
	ID          string `json:"id,omitempty"`
	DisplayName string `json:"displayName"`
	Color       string `json:"color,omitempty"`
}

type outlookCategoryList struct {
	Value []outlookCategory `json:"value"`
}

// EnsureLabel creates the master category in the user's mailbox if it
// does not already exist. Outlook category names are the canonical
// identifier — the returned "id" is the displayName so subsequent
// PATCH requests on messages.categories can use it directly.
func (p *LabelProvider) EnsureLabel(ctx context.Context, email, name string, color action.LabelColor) (string, error) {
	if email == "" || name == "" {
		return "", errors.New("outlook: email and category name are required")
	}
	// Outlook stores categories on the user's mailbox; we address the
	// mailbox by UPN, which Graph accepts at /users/{upn}.
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/outlook/masterCategories",
		p.baseURL, url.PathEscape(email))

	// Idempotent fast-path: if a category with this displayName
	// already exists, return its name without creating it again.
	if existing, err := p.findCategoryByName(ctx, email, name); err != nil {
		return "", err
	} else if existing != "" {
		return existing, nil
	}

	body := outlookCategory{DisplayName: name, Color: mapPreset(color)}
	var out outlookCategory
	err := p.do(ctx, http.MethodPost, endpoint, body, &out)
	if err != nil {
		var apiErr *APIError
		// Outlook returns 409 / "ObjectAlreadyExists" when the
		// category already exists. Treat that as success.
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict {
			return name, nil
		}
		return "", fmt.Errorf("outlook: create category %q: %w", name, err)
	}
	if out.DisplayName == "" {
		return name, nil
	}
	return out.DisplayName, nil
}

// findCategoryByName looks up an existing master category. Returns
// ("", nil) on cache miss.
func (p *LabelProvider) findCategoryByName(ctx context.Context, email, name string) (string, error) {
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/outlook/masterCategories",
		p.baseURL, url.PathEscape(email))
	var list outlookCategoryList
	if err := p.do(ctx, http.MethodGet, endpoint, nil, &list); err != nil {
		return "", fmt.Errorf("outlook: list categories: %w", err)
	}
	for _, c := range list.Value {
		if strings.EqualFold(c.DisplayName, name) {
			return c.DisplayName, nil
		}
	}
	return "", nil
}

// ApplyLabel sets the named category on the message. Because the
// Graph API replaces the entire `categories` array on PATCH, we first
// GET the current value and then PATCH with the union.
func (p *LabelProvider) ApplyLabel(ctx context.Context, email, messageID, labelID string) error {
	if email == "" || messageID == "" {
		return errors.New("outlook: email and message_id are required")
	}
	cats, err := p.getMessageCategories(ctx, email, messageID)
	if err != nil {
		return err
	}
	updated := mergeCategory(cats, labelID, addOp)
	return p.patchMessageCategories(ctx, email, messageID, updated)
}

// RemoveLabel drops the named category from the message.
func (p *LabelProvider) RemoveLabel(ctx context.Context, email, messageID, labelID string) error {
	if email == "" || messageID == "" {
		return errors.New("outlook: email and message_id are required")
	}
	cats, err := p.getMessageCategories(ctx, email, messageID)
	if err != nil {
		return err
	}
	updated := mergeCategory(cats, labelID, removeOp)
	return p.patchMessageCategories(ctx, email, messageID, updated)
}

type messageEnvelope struct {
	Categories []string `json:"categories"`
}

func (p *LabelProvider) getMessageCategories(ctx context.Context, email, messageID string) ([]string, error) {
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages/%s?$select=categories",
		p.baseURL, url.PathEscape(email), url.PathEscape(messageID))
	var env messageEnvelope
	if err := p.do(ctx, http.MethodGet, endpoint, nil, &env); err != nil {
		return nil, fmt.Errorf("outlook: get message categories: %w", err)
	}
	return env.Categories, nil
}

func (p *LabelProvider) patchMessageCategories(ctx context.Context, email, messageID string, categories []string) error {
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages/%s",
		p.baseURL, url.PathEscape(email), url.PathEscape(messageID))
	// Use an empty slice (not nil) so JSON encodes as `[]` when the
	// caller drops the last category — sending `null` here would be
	// rejected by Graph.
	if categories == nil {
		categories = []string{}
	}
	return p.do(ctx, http.MethodPatch, endpoint, messageEnvelope{Categories: categories}, nil)
}

// op identifies the merge mode used by mergeCategory.
type op int

const (
	addOp op = iota
	removeOp
)

// mergeCategory adds or removes name from the existing categories,
// preserving order and case while deduplicating case-insensitively.
func mergeCategory(existing []string, name string, mode op) []string {
	seen := make(map[string]struct{}, len(existing)+1)
	out := make([]string, 0, len(existing)+1)
	for _, c := range existing {
		k := strings.ToLower(c)
		if mode == removeOp && strings.EqualFold(c, name) {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, c)
	}
	if mode == addOp {
		k := strings.ToLower(name)
		if _, ok := seen[k]; !ok {
			out = append(out, name)
		}
	}
	return out
}

// mapPreset maps the abstract label colour to one of the 25 Outlook
// preset values (`preset0` … `preset24`). The action package already
// chose a preset per tier; we use that directly and fall back to
// preset0 (yellow) when the caller did not supply one.
func mapPreset(c action.LabelColor) string {
	if c.OutlookPreset != "" {
		return c.OutlookPreset
	}
	return "preset0"
}

// do executes an authenticated request and decodes the JSON response
// into out when out != nil. Non-2xx responses are turned into a typed
// error containing the response body.
func (p *LabelProvider) do(ctx context.Context, method, endpoint string, in, out any) error {
	var bodyReader io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	tok, err := p.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("acquire token: %w", err)
	}
	if tok == "" {
		return errors.New("outlook: empty bearer token")
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		return fmt.Errorf("read body: %w", rerr)
	}
	if resp.StatusCode/100 != 2 {
		return &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
			Endpoint:   endpoint,
		}
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// APIError captures a non-2xx Graph response.
type APIError struct {
	StatusCode int
	Body       string
	Endpoint   string
}

// Error renders a compact form including the endpoint for fast
// triage.
func (e *APIError) Error() string {
	return fmt.Sprintf("outlook: %d %s: %s", e.StatusCode, e.Endpoint, truncate(e.Body, 256))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
