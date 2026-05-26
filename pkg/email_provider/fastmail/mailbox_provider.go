package fastmail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
)

// MailboxProvider implements ingestion.MailboxProvider for Fastmail
// over JMAP.
//
// JMAP exposes mailboxes as first-class objects (RFC 8621 §2). For
// SN360-ES we poll the "Inbox" role mailbox by default; FetchNew
// uses Email/query with a `receivedAt` after filter and a Email/get
// back-reference so the list + body fetch happens in one round trip.
type MailboxProvider struct {
	client *Client
	// inboxRole is the JMAP mailbox role to poll. Defaults to
	// "inbox" — operators wanting to poll a different role (e.g.
	// "archive") set this explicitly.
	inboxRole string
}

// MailboxProviderConfig wires the MailboxProvider.
type MailboxProviderConfig struct {
	Client    *Client
	InboxRole string
}

// NewMailboxProvider returns a ready-to-use MailboxProvider.
func NewMailboxProvider(cfg MailboxProviderConfig) (*MailboxProvider, error) {
	if cfg.Client == nil {
		return nil, errors.New("fastmail: mailbox provider requires a Client")
	}
	role := strings.ToLower(strings.TrimSpace(cfg.InboxRole))
	if role == "" {
		role = "inbox"
	}
	return &MailboxProvider{client: cfg.Client, inboxRole: role}, nil
}

// Kind implements ingestion.MailboxProvider.
func (p *MailboxProvider) Kind() string { return "fastmail" }

// jmapMailbox is the subset of JMAP Mailbox we consume.
type jmapMailbox struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	ParentID   string `json:"parentId,omitempty"`
	TotalEmail int    `json:"totalEmails,omitempty"`
}

// ListMailboxes returns one Mailbox per identity (RFC 8621 Identity).
// Fastmail is single-tenant so we surface every Identity address as
// a pollable mailbox.
func (p *MailboxProvider) ListMailboxes(ctx context.Context, tenantID string) ([]ingestion.Mailbox, error) {
	if tenantID == "" {
		tenantID = p.client.accountID
		if tenantID == "" {
			if _, err := p.client.Session(ctx); err != nil {
				return nil, err
			}
			tenantID = p.client.accountID
		}
	}
	dir, err := NewDirectoryClient(DirectoryClientConfig{Client: p.client})
	if err != nil {
		return nil, fmt.Errorf("fastmail: mailbox enumeration: %w", err)
	}
	users, err := dir.ListUsers(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("fastmail: list mailboxes: %w", err)
	}
	out := make([]ingestion.Mailbox, 0, len(users))
	for _, u := range users {
		out = append(out, ingestion.Mailbox{
			TenantID: tenantID,
			Address:  u.Email,
			UserID:   u.ID,
		})
	}
	return out, nil
}

// jmapEmail is the subset of JMAP Email we consume. RFC 8621 §4.
type jmapEmail struct {
	ID         string             `json:"id"`
	ThreadID   string             `json:"threadId"`
	MailboxIDs map[string]bool    `json:"mailboxIds"`
	From       []jmapEmailAddress `json:"from"`
	To         []jmapEmailAddress `json:"to"`
	CC         []jmapEmailAddress `json:"cc"`
	Subject    string             `json:"subject"`
	ReceivedAt string             `json:"receivedAt"`
	BodyValues map[string]struct {
		Value       string `json:"value"`
		IsTruncated bool   `json:"isTruncated"`
	} `json:"bodyValues"`
	TextBody []struct {
		PartID string `json:"partId"`
		Type   string `json:"type"`
	} `json:"textBody"`
	HTMLBody []struct {
		PartID string `json:"partId"`
		Type   string `json:"type"`
	} `json:"htmlBody"`
	Headers []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"headers"`
}

type jmapEmailAddress struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// FetchNew uses Email/query + Email/get back-reference to fetch new
// messages in a single round trip. The `receivedAt` filter is
// inclusive of the requested time; we add a nanosecond to convert it
// to the strict ">" semantics the poller expects.
func (p *MailboxProvider) FetchNew(ctx context.Context, mailbox ingestion.Mailbox, since time.Time, limit int) ([]ingestion.RawEmail, error) {
	if limit <= 0 {
		limit = 50
	}
	inboxID, err := p.inboxIDForAccount(ctx)
	if err != nil {
		return nil, err
	}
	filter := map[string]any{
		"inMailbox": inboxID,
	}
	if !since.IsZero() {
		filter["after"] = since.UTC().Add(time.Nanosecond).Format(time.RFC3339)
	}
	queryArgs := map[string]any{
		"accountId":       p.client.accountID,
		"filter":          filter,
		"sort":            []map[string]any{{"property": "receivedAt", "isAscending": true}},
		"limit":           limit,
		"collapseThreads": false,
	}
	getArgs := map[string]any{
		"accountId":           p.client.accountID,
		"#ids":                map[string]string{"resultOf": "0", "name": "Email/query", "path": "/ids"},
		"properties":          []string{"id", "threadId", "mailboxIds", "from", "to", "cc", "subject", "receivedAt", "bodyValues", "textBody", "htmlBody", "headers"},
		"fetchTextBodyValues": true,
		"fetchHTMLBodyValues": true,
		"maxBodyValueBytes":   1 << 20,
	}
	resps, err := p.client.InvokeBatch(ctx, []MethodCall{
		{Name: "Email/query", Args: queryArgs, CallID: "0"},
		{Name: "Email/get", Args: getArgs, CallID: "1"},
	})
	if err != nil {
		return nil, fmt.Errorf("fastmail: fetch new: %w", err)
	}
	if len(resps) < 2 {
		return nil, fmt.Errorf("fastmail: fetch new: expected 2 responses, got %d", len(resps))
	}
	var getResp struct {
		List []jmapEmail `json:"list"`
	}
	if err := json.Unmarshal(resps[1].Args, &getResp); err != nil {
		return nil, fmt.Errorf("fastmail: decode email/get: %w", err)
	}
	out := make([]ingestion.RawEmail, 0, len(getResp.List))
	for _, e := range getResp.List {
		received, err := time.Parse(time.RFC3339, e.ReceivedAt)
		if err != nil {
			continue
		}
		raw := ingestion.RawEmail{
			ProviderMessageID: e.ID,
			TenantID:          mailbox.TenantID,
			Mailbox:           mailbox.Address,
			Subject:           e.Subject,
			ReceivedAt:        received,
			Headers:           map[string]string{},
		}
		if len(e.From) > 0 {
			raw.Sender = e.From[0].Email
		}
		for _, addr := range e.To {
			raw.Recipients = append(raw.Recipients, addr.Email)
		}
		for _, addr := range e.CC {
			raw.CC = append(raw.CC, addr.Email)
		}
		// Prefer HTML body when present.
		if len(e.HTMLBody) > 0 {
			partID := e.HTMLBody[0].PartID
			if val, ok := e.BodyValues[partID]; ok {
				raw.HTMLBody = val.Value
			}
		}
		if len(e.TextBody) > 0 {
			partID := e.TextBody[0].PartID
			if val, ok := e.BodyValues[partID]; ok {
				raw.Body = val.Value
			}
		}
		for _, h := range e.Headers {
			raw.Headers[h.Name] = h.Value
		}
		out = append(out, raw)
	}
	return out, nil
}

// inboxIDForAccount resolves the mailbox ID for the configured inbox
// role. JMAP guarantees there's at most one mailbox per role per
// account.
func (p *MailboxProvider) inboxIDForAccount(ctx context.Context) (string, error) {
	args := map[string]any{
		"accountId":  p.client.accountID,
		"properties": []string{"id", "name", "role"},
	}
	resp, err := p.client.Invoke(ctx, "Mailbox/get", args)
	if err != nil {
		return "", fmt.Errorf("fastmail: mailbox/get: %w", err)
	}
	var decoded struct {
		List []jmapMailbox `json:"list"`
	}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return "", fmt.Errorf("fastmail: decode mailbox/get: %w", err)
	}
	for _, m := range decoded.List {
		if strings.EqualFold(m.Role, p.inboxRole) {
			return m.ID, nil
		}
	}
	return "", fmt.Errorf("fastmail: no mailbox with role %q found", p.inboxRole)
}

// Compile-time interface check.
var _ ingestion.MailboxProvider = (*MailboxProvider)(nil)
