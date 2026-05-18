package outlook

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

// MailboxProviderConfig wires the Outlook-side MailboxProvider used
// by the ingestion poller.
type MailboxProviderConfig struct {
	// BaseURL overrides the Microsoft Graph base URL. Default is
	// https://graph.microsoft.com/v1.0.
	BaseURL string
	// HTTPClient is the transport. Default is http.DefaultClient
	// with a 30s timeout.
	HTTPClient *http.Client
	// TokenSource issues bearer tokens. Required.
	TokenSource TokenSource
	// TenantID is the tenant identifier propagated into every
	// returned RawEmail and Mailbox. Required.
	TenantID string
	// ManualMailboxes is the static list of mailbox addresses used
	// when no admin-level enumeration is available. Useful for
	// single-mailbox deployments and tests.
	ManualMailboxes []string
	// EnumerateUsers controls whether ListMailboxes calls the
	// Graph /users endpoint to discover mailboxes. When false the
	// manual list is returned as-is.
	EnumerateUsers bool
}

// MailboxProvider implements ingestion.MailboxProvider on top of the
// Microsoft Graph API.
type MailboxProvider struct {
	baseURL    string
	http       *http.Client
	tokens     TokenSource
	tenantID   string
	manual     []string
	enumerate  bool
}

// NewMailboxProvider validates the config and returns a ready-to-use
// MailboxProvider. TokenSource and TenantID are required.
func NewMailboxProvider(cfg MailboxProviderConfig) (*MailboxProvider, error) {
	if cfg.TokenSource == nil {
		return nil, errors.New("outlook: mailbox provider requires a token source")
	}
	if strings.TrimSpace(cfg.TenantID) == "" {
		return nil, errors.New("outlook: mailbox provider requires a tenant id")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://graph.microsoft.com/v1.0"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &MailboxProvider{
		baseURL:   base,
		http:      client,
		tokens:    cfg.TokenSource,
		tenantID:  cfg.TenantID,
		manual:    cfg.ManualMailboxes,
		enumerate: cfg.EnumerateUsers,
	}, nil
}

// Kind implements ingestion.MailboxProvider.
func (p *MailboxProvider) Kind() string { return "outlook" }

// graphUser is the subset of the Graph user object we consume.
type graphUser struct {
	ID                string `json:"id"`
	Mail              string `json:"mail,omitempty"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
	AccountEnabled    bool   `json:"accountEnabled"`
}

type graphUserList struct {
	Value    []graphUser `json:"value"`
	NextLink string      `json:"@odata.nextLink,omitempty"`
}

// ListMailboxes enumerates mailboxes via the Graph /users endpoint
// when EnumerateUsers is true. Otherwise the manual mailbox list is
// returned as-is.
func (p *MailboxProvider) ListMailboxes(ctx context.Context, tenantID string) ([]ingestion.Mailbox, error) {
	if tenantID == "" {
		tenantID = p.tenantID
	}
	if !p.enumerate {
		return p.manualList(tenantID), nil
	}
	var out []ingestion.Mailbox
	endpoint := fmt.Sprintf("%s/users?$select=id,mail,userPrincipalName,accountEnabled&$top=200",
		p.baseURL)
	for endpoint != "" {
		var list graphUserList
		if err := p.do(ctx, http.MethodGet, endpoint, nil, &list); err != nil {
			return nil, fmt.Errorf("outlook: graph users.list: %w", err)
		}
		for _, u := range list.Value {
			if !u.AccountEnabled {
				continue
			}
			addr := u.Mail
			if addr == "" {
				addr = u.UserPrincipalName
			}
			if addr == "" {
				continue
			}
			out = append(out, ingestion.Mailbox{
				TenantID: tenantID,
				Address:  strings.ToLower(addr),
				UserID:   u.ID,
			})
		}
		endpoint = list.NextLink
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

// graphMessageList is the wire shape for /users/{id}/messages.
type graphMessageList struct {
	Value    []graphMessage `json:"value"`
	NextLink string         `json:"@odata.nextLink,omitempty"`
}

// graphMessage is the subset of the Graph message resource we
// consume. The fields mirror https://learn.microsoft.com/graph/api/resources/message.
type graphMessage struct {
	ID                  string         `json:"id"`
	Subject             string         `json:"subject,omitempty"`
	Body                graphItemBody  `json:"body"`
	BodyPreview         string         `json:"bodyPreview,omitempty"`
	ReceivedDateTime    time.Time      `json:"receivedDateTime"`
	From                graphRecipient `json:"from"`
	ToRecipients        []graphRecipient `json:"toRecipients,omitempty"`
	CcRecipients        []graphRecipient `json:"ccRecipients,omitempty"`
	InternetMessageHeaders []graphHeader `json:"internetMessageHeaders,omitempty"`
	HasAttachments      bool           `json:"hasAttachments,omitempty"`
}

type graphItemBody struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

type graphRecipient struct {
	EmailAddress graphEmailAddress `json:"emailAddress"`
}

type graphEmailAddress struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
}

type graphHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// FetchNew retrieves messages received after `since` for one
// mailbox. We rely on Graph's $filter to do the cursor check
// server-side which is cheaper than client-side pagination.
func (p *MailboxProvider) FetchNew(ctx context.Context, mailbox ingestion.Mailbox, since time.Time, limit int) ([]ingestion.RawEmail, error) {
	if mailbox.Address == "" {
		return nil, errors.New("outlook: fetch requires a mailbox address")
	}
	if limit <= 0 {
		limit = 50
	}
	mboxID := mailbox.UserID
	if mboxID == "" {
		mboxID = mailbox.Address
	}
	q := url.Values{}
	q.Set("$top", fmt.Sprintf("%d", limit))
	q.Set("$orderby", "receivedDateTime asc")
	if !since.IsZero() {
		q.Set("$filter", fmt.Sprintf("receivedDateTime gt %s", since.UTC().Format(time.RFC3339)))
	}
	q.Set("$select", "id,subject,body,bodyPreview,receivedDateTime,from,toRecipients,ccRecipients,hasAttachments,internetMessageHeaders")
	endpoint := fmt.Sprintf("%s/users/%s/messages?%s",
		p.baseURL, url.PathEscape(mboxID), q.Encode())
	var list graphMessageList
	if err := p.do(ctx, http.MethodGet, endpoint, nil, &list); err != nil {
		return nil, fmt.Errorf("outlook: list messages: %w", err)
	}
	if len(list.Value) == 0 {
		return nil, nil
	}
	out := make([]ingestion.RawEmail, 0, len(list.Value))
	for _, m := range list.Value {
		raw := p.toRawEmail(mailbox, m)
		if !since.IsZero() && !raw.ReceivedAt.After(since) {
			continue
		}
		out = append(out, raw)
	}
	return out, nil
}

// toRawEmail flattens a Graph message into the ingestion.RawEmail
// shape.
func (p *MailboxProvider) toRawEmail(mailbox ingestion.Mailbox, m graphMessage) ingestion.RawEmail {
	raw := ingestion.RawEmail{
		ProviderMessageID: m.ID,
		TenantID:          mailbox.TenantID,
		Mailbox:           mailbox.Address,
		Sender:            m.From.EmailAddress.Address,
		Subject:           m.Subject,
		ReceivedAt:        m.ReceivedDateTime,
		Headers:           map[string]string{},
	}
	for _, r := range m.ToRecipients {
		if r.EmailAddress.Address != "" {
			raw.Recipients = append(raw.Recipients, r.EmailAddress.Address)
		}
	}
	for _, r := range m.CcRecipients {
		if r.EmailAddress.Address != "" {
			raw.CC = append(raw.CC, r.EmailAddress.Address)
		}
	}
	// Graph returns the body in either text/html or text/plain
	// depending on the message and the $select projection. Treat
	// both consistently — the normalizer is responsible for HTML
	// stripping.
	switch strings.ToLower(m.Body.ContentType) {
	case "html":
		raw.HTMLBody = m.Body.Content
		raw.Body = m.BodyPreview
	default:
		raw.Body = m.Body.Content
		if raw.Body == "" {
			raw.Body = m.BodyPreview
		}
	}
	for _, h := range m.InternetMessageHeaders {
		raw.Headers[h.Name] = h.Value
	}
	if m.HasAttachments {
		ct := raw.Headers["Content-Type"]
		if ct == "" {
			raw.Headers["Content-Type"] = "multipart/mixed"
		}
	}
	return raw
}

// do reuses the LabelProvider HTTP plumbing so MailboxProvider stays
// self-contained.
func (p *MailboxProvider) do(ctx context.Context, method, endpoint string, in, out any) error {
	lp := &LabelProvider{
		baseURL: p.baseURL,
		http:    p.http,
		tokens:  p.tokens,
	}
	return lp.do(ctx, method, endpoint, in, out)
}
