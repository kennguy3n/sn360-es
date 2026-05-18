package gmail

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
)

// MailboxProviderConfig wires the Gmail-side MailboxProvider used by
// the ingestion poller.
type MailboxProviderConfig struct {
	// BaseURL overrides the Gmail REST base. Default is the public
	// endpoint at https://gmail.googleapis.com.
	BaseURL string
	// AdminBaseURL overrides the Admin SDK Directory API base used
	// for ListMailboxes. Defaults to https://admin.googleapis.com.
	AdminBaseURL string
	// HTTPClient is the transport. Default is http.DefaultClient
	// with a 30s timeout.
	HTTPClient *http.Client
	// TokenSource is the bearer token issuer for the Gmail API.
	// Required.
	TokenSource TokenSource
	// AdminTokenSource is the bearer token issuer for the Admin
	// SDK. Optional; when nil, ListMailboxes returns
	// ManualMailboxes (see below).
	AdminTokenSource TokenSource
	// CustomerID is the Google Workspace customer identifier. The
	// special value "my_customer" works for delegated admins.
	// Required when AdminTokenSource is set.
	CustomerID string
	// Domain narrows ListMailboxes to a single Google Workspace
	// domain. Optional.
	Domain string
	// TenantID is the tenant identifier propagated into every
	// returned RawEmail and Mailbox. Required.
	TenantID string
	// ManualMailboxes is the static list of mailbox addresses used
	// when AdminTokenSource is nil. Useful for single-mailbox
	// deployments and tests that don't have Admin SDK delegation.
	ManualMailboxes []string
}

// MailboxProvider implements ingestion.MailboxProvider on top of the
// Gmail REST API and (optionally) the Admin SDK Directory API.
type MailboxProvider struct {
	baseURL      string
	adminBaseURL string
	http         *http.Client
	tokens       TokenSource
	adminTokens  TokenSource
	customerID   string
	domain       string
	tenantID     string
	manual       []string
}

// NewMailboxProvider validates the config and returns a ready-to-use
// MailboxProvider. TokenSource and TenantID are required. If
// AdminTokenSource is not set, callers must populate
// ManualMailboxes; otherwise ListMailboxes returns an empty slice
// (which the poller treats as "no mailboxes, skip provider").
func NewMailboxProvider(cfg MailboxProviderConfig) (*MailboxProvider, error) {
	if cfg.TokenSource == nil {
		return nil, errors.New("gmail: mailbox provider requires a token source")
	}
	if strings.TrimSpace(cfg.TenantID) == "" {
		return nil, errors.New("gmail: mailbox provider requires a tenant id")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://gmail.googleapis.com"
	}
	adminBase := strings.TrimRight(cfg.AdminBaseURL, "/")
	if adminBase == "" {
		adminBase = "https://admin.googleapis.com"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	customer := cfg.CustomerID
	if customer == "" {
		customer = "my_customer"
	}
	return &MailboxProvider{
		baseURL:      base,
		adminBaseURL: adminBase,
		http:         client,
		tokens:       cfg.TokenSource,
		adminTokens:  cfg.AdminTokenSource,
		customerID:   customer,
		domain:       cfg.Domain,
		tenantID:     cfg.TenantID,
		manual:       cfg.ManualMailboxes,
	}, nil
}

// Kind implements ingestion.MailboxProvider.
func (p *MailboxProvider) Kind() string { return "gmail" }

// adminUser is the subset of the Admin SDK user object the poller
// needs. Documented at https://developers.google.com/admin-sdk/directory/reference/rest/v1/users.
type adminUser struct {
	PrimaryEmail string `json:"primaryEmail"`
	Suspended    bool   `json:"suspended"`
	Archived     bool   `json:"archived"`
	ID           string `json:"id"`
}

type adminUserList struct {
	Users         []adminUser `json:"users"`
	NextPageToken string      `json:"nextPageToken,omitempty"`
}

// ListMailboxes enumerates Workspace users via the Admin SDK
// Directory API. When no admin token source is configured the
// manual mailbox list from the config is returned instead.
func (p *MailboxProvider) ListMailboxes(ctx context.Context, tenantID string) ([]ingestion.Mailbox, error) {
	if tenantID == "" {
		tenantID = p.tenantID
	}
	if p.adminTokens == nil {
		return p.manualList(tenantID), nil
	}
	var out []ingestion.Mailbox
	page := ""
	for {
		endpoint := fmt.Sprintf("%s/admin/directory/v1/users", p.adminBaseURL)
		q := url.Values{}
		if p.domain != "" {
			q.Set("domain", p.domain)
		} else {
			q.Set("customer", p.customerID)
		}
		q.Set("maxResults", "200")
		q.Set("query", "isSuspended=false")
		if page != "" {
			q.Set("pageToken", page)
		}
		endpoint = endpoint + "?" + q.Encode()

		var list adminUserList
		if err := p.doToken(ctx, http.MethodGet, endpoint, nil, &list, p.adminTokens); err != nil {
			return nil, fmt.Errorf("gmail: admin users.list: %w", err)
		}
		for _, u := range list.Users {
			if u.Suspended || u.Archived || u.PrimaryEmail == "" {
				continue
			}
			out = append(out, ingestion.Mailbox{
				TenantID: tenantID,
				Address:  strings.ToLower(u.PrimaryEmail),
				UserID:   u.ID,
			})
		}
		if list.NextPageToken == "" {
			break
		}
		page = list.NextPageToken
	}
	if len(out) == 0 {
		return p.manualList(tenantID), nil
	}
	return out, nil
}

func (p *MailboxProvider) manualList(tenantID string) []ingestion.Mailbox {
	if len(p.manual) == 0 {
		return nil
	}
	out := make([]ingestion.Mailbox, 0, len(p.manual))
	for _, addr := range p.manual {
		addr = strings.TrimSpace(strings.ToLower(addr))
		if addr == "" {
			continue
		}
		out = append(out, ingestion.Mailbox{TenantID: tenantID, Address: addr})
	}
	return out
}

// gmailMessageList is the wire shape for users.messages.list.
type gmailMessageList struct {
	Messages []struct {
		ID       string `json:"id"`
		ThreadID string `json:"threadId,omitempty"`
	} `json:"messages,omitempty"`
	NextPageToken string `json:"nextPageToken,omitempty"`
}

// gmailMessage is the subset of users.messages.get we consume.
type gmailMessage struct {
	ID           string             `json:"id"`
	ThreadID     string             `json:"threadId,omitempty"`
	InternalDate string             `json:"internalDate,omitempty"`
	Payload      gmailMessagePayload `json:"payload"`
}

type gmailMessagePayload struct {
	MimeType string                `json:"mimeType,omitempty"`
	Headers  []gmailMessageHeader  `json:"headers,omitempty"`
	Body     gmailMessagePart      `json:"body,omitempty"`
	Parts    []gmailMessagePayload `json:"parts,omitempty"`
}

type gmailMessageHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type gmailMessagePart struct {
	Size int    `json:"size,omitempty"`
	Data string `json:"data,omitempty"`
}

// FetchNew retrieves messages received after `since` for one
// mailbox. The Gmail query language supports `after:` with seconds
// since epoch; we apply that filter to the list endpoint and then
// hydrate each result with users.messages.get(format=full).
func (p *MailboxProvider) FetchNew(ctx context.Context, mailbox ingestion.Mailbox, since time.Time, limit int) ([]ingestion.RawEmail, error) {
	if mailbox.Address == "" {
		return nil, errors.New("gmail: fetch requires a mailbox address")
	}
	if limit <= 0 {
		limit = 50
	}
	q := url.Values{}
	q.Set("maxResults", strconv.Itoa(limit))
	if !since.IsZero() {
		q.Set("q", "after:"+strconv.FormatInt(since.UTC().Unix(), 10))
	}
	listEndpoint := fmt.Sprintf("%s/gmail/v1/users/%s/messages?%s",
		p.baseURL, url.PathEscape(mailbox.Address), q.Encode())
	var list gmailMessageList
	if err := p.do(ctx, http.MethodGet, listEndpoint, nil, &list); err != nil {
		return nil, fmt.Errorf("gmail: list messages: %w", err)
	}
	if len(list.Messages) == 0 {
		return nil, nil
	}
	out := make([]ingestion.RawEmail, 0, len(list.Messages))
	for _, ref := range list.Messages {
		msgEndpoint := fmt.Sprintf("%s/gmail/v1/users/%s/messages/%s?format=full",
			p.baseURL, url.PathEscape(mailbox.Address), url.PathEscape(ref.ID))
		var msg gmailMessage
		if err := p.do(ctx, http.MethodGet, msgEndpoint, nil, &msg); err != nil {
			return nil, fmt.Errorf("gmail: get message %q: %w", ref.ID, err)
		}
		raw := p.toRawEmail(mailbox, msg)
		// Defensive: don't re-emit messages whose timestamp is at
		// or before the checkpoint. Gmail's `after:` query is
		// inclusive of the second so the same message can show
		// up twice across consecutive polls.
		if !since.IsZero() && !raw.ReceivedAt.After(since) {
			continue
		}
		out = append(out, raw)
	}
	return out, nil
}

// toRawEmail flattens a Gmail message into the ingestion.RawEmail
// shape consumed by the normalizer.
func (p *MailboxProvider) toRawEmail(mailbox ingestion.Mailbox, msg gmailMessage) ingestion.RawEmail {
	raw := ingestion.RawEmail{
		ProviderMessageID: msg.ID,
		TenantID:          mailbox.TenantID,
		Mailbox:           mailbox.Address,
		Headers:           map[string]string{},
	}
	for _, h := range msg.Payload.Headers {
		switch strings.ToLower(h.Name) {
		case "from":
			raw.Sender = h.Value
		case "to":
			raw.Recipients = splitAddresses(h.Value)
		case "cc":
			raw.CC = splitAddresses(h.Value)
		case "subject":
			raw.Subject = h.Value
		}
		raw.Headers[h.Name] = h.Value
	}
	textBody, htmlBody := extractBodies(msg.Payload)
	raw.Body = textBody
	raw.HTMLBody = htmlBody
	if msg.InternalDate != "" {
		if ms, err := strconv.ParseInt(msg.InternalDate, 10, 64); err == nil {
			raw.ReceivedAt = time.Unix(0, ms*int64(time.Millisecond)).UTC()
		}
	}
	return raw
}

// extractBodies walks the MIME tree and returns (text/plain,
// text/html) bodies as decoded UTF-8 strings. Encrypted parts are
// skipped; empty payloads yield "".
func extractBodies(part gmailMessagePayload) (string, string) {
	var textBody, htmlBody string
	var walk func(p gmailMessagePayload)
	walk = func(p gmailMessagePayload) {
		mt := strings.ToLower(p.MimeType)
		switch {
		case mt == "text/plain" && p.Body.Data != "" && textBody == "":
			textBody = decodeURLSafeBase64(p.Body.Data)
		case mt == "text/html" && p.Body.Data != "" && htmlBody == "":
			htmlBody = decodeURLSafeBase64(p.Body.Data)
		}
		for _, child := range p.Parts {
			walk(child)
		}
	}
	walk(part)
	return textBody, htmlBody
}

func decodeURLSafeBase64(data string) string {
	// Gmail uses URL-safe base64 without padding.
	b, err := base64.URLEncoding.DecodeString(addBase64Padding(data))
	if err != nil {
		// Fall back to standard base64; some clients add padding
		// even on the URL-safe path.
		if b2, err2 := base64.StdEncoding.DecodeString(addBase64Padding(data)); err2 == nil {
			return string(b2)
		}
		return ""
	}
	return string(b)
}

func addBase64Padding(s string) string {
	if rem := len(s) % 4; rem != 0 {
		return s + strings.Repeat("=", 4-rem)
	}
	return s
}

// splitAddresses turns a comma-separated address header into a list
// of trimmed addresses. RFC 5322 group syntax is not normalised
// here; the normalizer is responsible for further cleaning.
func splitAddresses(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// doToken is the variant of `do` that lets us swap the token source
// (Admin SDK vs Gmail API).
func (p *MailboxProvider) doToken(ctx context.Context, method, endpoint string, in, out any, source TokenSource) error {
	if source == nil {
		return errors.New("gmail: token source not configured")
	}
	old := p.tokens
	p.tokens = source
	defer func() { p.tokens = old }()
	return p.do(ctx, method, endpoint, in, out)
}

// do reuses the same minimal HTTP plumbing as the LabelProvider so
// MailboxProvider stays self-contained.
func (p *MailboxProvider) do(ctx context.Context, method, endpoint string, in, out any) error {
	lp := &LabelProvider{
		baseURL: p.baseURL,
		http:    p.http,
		tokens:  p.tokens,
	}
	return lp.do(ctx, method, endpoint, in, out)
}
