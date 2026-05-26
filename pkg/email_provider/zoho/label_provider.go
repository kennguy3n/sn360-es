package zoho

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// LabelProvider implements action.LabelProvider against the Zoho Mail
// REST tag API.
//
// Zoho's tag model differs from Gmail labels in that tags are
// org-scoped, not per-mailbox: they live on /api/organization/{org}/tags
// and are attached to messages via /api/accounts/{acct}/messages/tag.
// The implementation creates the tag once at org level and then
// attaches it on each ApplyLabel call.
type LabelProvider struct {
	client *Client
}

// Config wires the LabelProvider — kept aligned with Gmail/Outlook
// shape so wire code is symmetric.
type Config struct {
	Client *Client
}

// New constructs a Zoho LabelProvider.
func New(cfg Config) (*LabelProvider, error) {
	if cfg.Client == nil {
		return nil, errors.New("zoho: label provider requires a Client")
	}
	return &LabelProvider{client: cfg.Client}, nil
}

// Kind reports the provider identity.
func (p *LabelProvider) Kind() action.LabelProviderKind { return action.LabelProviderZoho }

// zohoTag is the wire shape returned by /organization/{org}/tags.
type zohoTag struct {
	TagID      string `json:"tagId"`
	TagName    string `json:"tagName"`
	NameSpace  string `json:"nameSpace,omitempty"`
	Color      string `json:"color,omitempty"`
	UsageCount int    `json:"usageCount,omitempty"`
}

type zohoTagList struct {
	Data []zohoTag `json:"data"`
}

// EnsureLabel creates the org-scoped tag if it does not already
// exist. The returned ID is Zoho's tagId, which is the value
// /messages/tag expects.
func (p *LabelProvider) EnsureLabel(ctx context.Context, email, name string, color action.LabelColor) (string, error) {
	if email == "" || name == "" {
		return "", errors.New("zoho: email and tag name are required")
	}
	if existing, err := p.findTagByName(ctx, name); err != nil {
		return "", err
	} else if existing != "" {
		return existing, nil
	}
	endpoint := fmt.Sprintf("%s/organization/%s/tags",
		p.client.baseURL, url.PathEscape(p.client.orgID))
	body := map[string]any{
		"tagName": name,
		"color":   mapZohoColor(color),
	}
	var resp struct {
		Data zohoTag `json:"data"`
	}
	if err := p.client.do(ctx, http.MethodPost, endpoint, body, &resp); err != nil {
		// Zoho returns 409 / a "tag already exists" error when the
		// tag is registered by another caller between findTagByName
		// and Post. Recover by re-listing.
		if existing, lerr := p.findTagByName(ctx, name); lerr == nil && existing != "" {
			return existing, nil
		}
		return "", fmt.Errorf("zoho: create tag %q: %w", name, err)
	}
	if resp.Data.TagID == "" {
		return "", fmt.Errorf("zoho: create tag %q: missing tag id in response", name)
	}
	return resp.Data.TagID, nil
}

// findTagByName looks up an existing tag id by display name (case
// insensitive). Returns ("", nil) on cache miss.
func (p *LabelProvider) findTagByName(ctx context.Context, name string) (string, error) {
	endpoint := fmt.Sprintf("%s/organization/%s/tags?limit=200&index=1",
		p.client.baseURL, url.PathEscape(p.client.orgID))
	var list zohoTagList
	if err := p.client.do(ctx, http.MethodGet, endpoint, nil, &list); err != nil {
		return "", fmt.Errorf("zoho: list tags: %w", err)
	}
	for _, t := range list.Data {
		if strings.EqualFold(t.TagName, name) {
			return t.TagID, nil
		}
	}
	return "", nil
}

// ApplyLabel attaches the tag to the given message. Zoho's tag
// attachment endpoint expects the per-account base URL — the message
// id alone is not enough because tags live on /accounts/{acct}.
func (p *LabelProvider) ApplyLabel(ctx context.Context, email, messageID, labelID string) error {
	if email == "" || messageID == "" || labelID == "" {
		return errors.New("zoho: email, message_id and label_id are required")
	}
	accountID, err := p.accountIDForEmail(ctx, email)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/accounts/%s/messages/tag/%s",
		p.client.baseURL, url.PathEscape(accountID), url.PathEscape(labelID))
	body := map[string]any{
		"mode":       "add",
		"messageId":  []string{messageID},
	}
	return p.client.do(ctx, http.MethodPost, endpoint, body, nil)
}

// RemoveLabel detaches the tag from the given message.
func (p *LabelProvider) RemoveLabel(ctx context.Context, email, messageID, labelID string) error {
	if email == "" || messageID == "" || labelID == "" {
		return errors.New("zoho: email, message_id and label_id are required")
	}
	accountID, err := p.accountIDForEmail(ctx, email)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/accounts/%s/messages/tag/%s",
		p.client.baseURL, url.PathEscape(accountID), url.PathEscape(labelID))
	body := map[string]any{
		"mode":       "remove",
		"messageId":  []string{messageID},
	}
	return p.client.do(ctx, http.MethodPost, endpoint, body, nil)
}

// mapZohoColor projects the abstract LabelColor onto one of Zoho's
// named palette values. Falls back to a neutral grey when no preset
// is supplied by the caller.
func mapZohoColor(c action.LabelColor) string {
	// Zoho expects an RGB hex string with a leading "#". When the
	// caller supplied a Background colour we pass it through; the
	// Outlook preset / Gmail-flavoured fallbacks are not used here.
	if c.Background != "" {
		return c.Background
	}
	return "#7a7a7a"
}

// accountIDForEmail resolves a mailbox email address to its Zoho
// account ID. Zoho's tag-apply endpoint needs the account id rather
// than the email so we look it up via the directory client.
func (p *LabelProvider) accountIDForEmail(ctx context.Context, email string) (string, error) {
	dir, err := NewDirectoryClient(DirectoryClientConfig{Client: p.client})
	if err != nil {
		return "", err
	}
	users, err := dir.ListUsers(ctx, "")
	if err != nil {
		return "", fmt.Errorf("zoho: resolve account for %s: %w", email, err)
	}
	target := strings.ToLower(strings.TrimSpace(email))
	for _, u := range users {
		if u.Email == target {
			return u.ID, nil
		}
		for _, a := range u.Aliases {
			if a == target {
				return u.ID, nil
			}
		}
	}
	return "", fmt.Errorf("zoho: no account found for %s", email)
}

// Compile-time interface check.
var _ action.LabelProvider = (*LabelProvider)(nil)
