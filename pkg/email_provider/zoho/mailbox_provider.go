package zoho

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
)

// MailboxProviderConfig wires the Zoho-side MailboxProvider used by
// the ingestion poller.
type MailboxProviderConfig struct {
	Client   *Client
	TenantID string
	// InboxFolder is the per-account folder name to poll. Defaults
	// to "Inbox". Zoho folder names are case-insensitive in the
	// Mail UI but the API is case-sensitive — operators wanting to
	// poll a non-default folder (e.g. "Filtered") set this here.
	InboxFolder string
}

// MailboxProvider implements ingestion.MailboxProvider on top of the
// Zoho Mail REST API.
//
// Per-message fetch is a two-step flow:
//
//  1. GET /api/accounts/{accountId}/messages/view?folderId={inbox}
//     returns a paginated list of message envelopes (message-id,
//     subject, from, received-time).
//  2. GET /api/accounts/{accountId}/folders/{folderId}/messages/{id}/content
//     returns the full body (HTML or plain text).
//
// We fetch step 1 once per cycle then concurrently dispatch step 2
// up to BatchSize messages.
type MailboxProvider struct {
	client      *Client
	tenantID    string
	inboxFolder string
}

// NewMailboxProvider validates the config and returns a ready-to-use
// MailboxProvider.
func NewMailboxProvider(cfg MailboxProviderConfig) (*MailboxProvider, error) {
	if cfg.Client == nil {
		return nil, errors.New("zoho: mailbox provider requires a Client")
	}
	if strings.TrimSpace(cfg.TenantID) == "" {
		return nil, errors.New("zoho: mailbox provider requires a tenant id")
	}
	folder := strings.TrimSpace(cfg.InboxFolder)
	if folder == "" {
		folder = "Inbox"
	}
	return &MailboxProvider{
		client:      cfg.Client,
		tenantID:    cfg.TenantID,
		inboxFolder: folder,
	}, nil
}

// Kind implements ingestion.MailboxProvider.
func (p *MailboxProvider) Kind() string { return "zoho" }

// ListMailboxes enumerates every user in the configured Zoho
// organisation and returns one Mailbox per primary email address. It
// mirrors the Outlook provider's enumeration semantics so the poller
// loops over the same shape regardless of provider.
func (p *MailboxProvider) ListMailboxes(ctx context.Context, tenantID string) ([]ingestion.Mailbox, error) {
	if tenantID == "" {
		tenantID = p.tenantID
	}
	dir, err := NewDirectoryClient(DirectoryClientConfig{Client: p.client})
	if err != nil {
		return nil, fmt.Errorf("zoho: mailbox enumeration: %w", err)
	}
	users, err := dir.ListUsers(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("zoho: list users for mailboxes: %w", err)
	}
	out := make([]ingestion.Mailbox, 0, len(users))
	for _, u := range users {
		if u.IsSuspended || u.Email == "" {
			continue
		}
		out = append(out, ingestion.Mailbox{
			TenantID: tenantID,
			Address:  u.Email,
			UserID:   u.ID,
		})
	}
	return out, nil
}

// zohoMessageHeader is the wire shape of the message-view list entry.
type zohoMessageHeader struct {
	MessageID    string `json:"messageId"`
	FolderID     string `json:"folderId"`
	Subject      string `json:"subject"`
	Sender       string `json:"sender"`
	FromAddress  string `json:"fromAddress"`
	ToAddress    string `json:"toAddress"`
	CcAddress    string `json:"ccAddress"`
	Summary      string `json:"summary"`
	ReceivedTime string `json:"receivedTime"`
	HasAttach    string `json:"hasAttachment"`
	HTMLBody     string `json:"htmlBody,omitempty"`
}

// zohoMessageDetail is the shape returned by the per-message content
// endpoint when called with includeBlockContent=true.
type zohoMessageDetail struct {
	Content     string            `json:"content"`
	HTMLContent string            `json:"htmlContent"`
	Headers     map[string]string `json:"headers"`
}

// FetchNew retrieves messages received after `since` for one mailbox.
func (p *MailboxProvider) FetchNew(ctx context.Context, mailbox ingestion.Mailbox, since time.Time, limit int) ([]ingestion.RawEmail, error) {
	if mailbox.UserID == "" && mailbox.Address == "" {
		return nil, errors.New("zoho: fetch requires a mailbox user id or address")
	}
	if limit <= 0 {
		limit = 50
	}
	accountID := mailbox.UserID
	if accountID == "" {
		accountID = mailbox.Address
	}
	// Step 1: list message headers in the Inbox folder.
	q := url.Values{}
	q.Set("folder", p.inboxFolder)
	q.Set("limit", fmt.Sprintf("%d", limit))
	q.Set("start", "1")
	q.Set("sortby", "date")
	q.Set("sortorder", "false") // descending
	endpoint := fmt.Sprintf("%s/accounts/%s/messages/view?%s",
		p.client.baseURL, url.PathEscape(accountID), q.Encode())
	var list struct {
		Data []zohoMessageHeader `json:"data"`
	}
	if err := p.client.do(ctx, http.MethodGet, endpoint, nil, &list); err != nil {
		return nil, fmt.Errorf("zoho: list messages: %w", err)
	}
	if len(list.Data) == 0 {
		return nil, nil
	}
	out := make([]ingestion.RawEmail, 0, len(list.Data))
	for _, h := range list.Data {
		received, err := parseZohoTime(h.ReceivedTime)
		if err != nil {
			// Skip messages with unparseable timestamps rather than
			// failing the whole fetch — the next cycle will re-list.
			continue
		}
		if !since.IsZero() && !received.After(since) {
			continue
		}
		detail, derr := p.fetchMessageDetail(ctx, accountID, h.FolderID, h.MessageID)
		if derr != nil {
			return nil, fmt.Errorf("zoho: fetch message %s: %w", h.MessageID, derr)
		}
		raw := ingestion.RawEmail{
			ProviderMessageID: h.MessageID,
			TenantID:          mailbox.TenantID,
			Mailbox:           mailbox.Address,
			Sender:            firstNonEmpty(h.FromAddress, h.Sender),
			Subject:           h.Subject,
			ReceivedAt:        received,
			Headers:           map[string]string{},
		}
		raw.Recipients = splitAddresses(h.ToAddress)
		raw.CC = splitAddresses(h.CcAddress)
		if detail.HTMLContent != "" {
			raw.HTMLBody = detail.HTMLContent
			raw.Body = h.Summary
		} else {
			raw.Body = detail.Content
		}
		for k, v := range detail.Headers {
			raw.Headers[k] = v
		}
		if h.HasAttach == "true" && raw.Headers["Content-Type"] == "" {
			raw.Headers["Content-Type"] = "multipart/mixed"
		}
		out = append(out, raw)
	}
	return out, nil
}

// fetchMessageDetail invokes the per-message content endpoint and
// returns a Zoho message detail object.
func (p *MailboxProvider) fetchMessageDetail(ctx context.Context, accountID, folderID, messageID string) (zohoMessageDetail, error) {
	endpoint := fmt.Sprintf("%s/accounts/%s/folders/%s/messages/%s/content?mode=full",
		p.client.baseURL, url.PathEscape(accountID), url.PathEscape(folderID), url.PathEscape(messageID))
	var resp struct {
		Data zohoMessageDetail `json:"data"`
	}
	if err := p.client.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return zohoMessageDetail{}, err
	}
	return resp.Data, nil
}

// parseZohoTime parses Zoho's millisecond-epoch timestamp string into
// a time.Time. Zoho APIs return receivedTime as a numeric string of
// milliseconds since epoch.
func parseZohoTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("empty time")
	}
	// All-digit fast path: milliseconds since epoch.
	allDigit := true
	for _, r := range s {
		if r < '0' || r > '9' {
			allDigit = false
			break
		}
	}
	if allDigit {
		ms, err := parseInt64(s)
		if err != nil {
			return time.Time{}, err
		}
		return time.UnixMilli(ms).UTC(), nil
	}
	// Fall back to RFC3339 for endpoints that return ISO timestamps.
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("zoho: parse time %q: %w", s, err)
}

func parseInt64(s string) (int64, error) {
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("zoho: non-digit in time %q", s)
		}
		n = n*10 + int64(r-'0')
	}
	return n, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// splitAddresses splits a Zoho comma-or-semicolon-delimited recipient
// string into a slice. Whitespace is trimmed; empty entries are
// dropped.
func splitAddresses(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	// Zoho mixes commas and semicolons depending on locale.
	normalized := strings.ReplaceAll(s, ";", ",")
	parts := strings.Split(normalized, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Compile-time check.
var _ ingestion.MailboxProvider = (*MailboxProvider)(nil)
