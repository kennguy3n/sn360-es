package workmail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
)

// MailboxProvider implements ingestion.MailboxProvider for Amazon
// WorkMail. Mailbox enumeration uses the WorkMail JSON API (ListUsers)
// while per-mailbox fetching uses EWS (FindItem + GetItem) with
// ExchangeImpersonation to act on behalf of the mailbox owner.
type MailboxProvider struct {
	client     *Client
	ews        *EWSClient
	tenantID   string
	pollFolder string
}

// MailboxProviderConfig wires MailboxProvider.
type MailboxProviderConfig struct {
	Client   *Client
	EWS      *EWSClient
	TenantID string
	// PollFolder is the EWS distinguished folder id to poll
	// ("inbox" by default).
	PollFolder string
}

// NewMailboxProvider validates the config and returns a usable
// MailboxProvider.
func NewMailboxProvider(cfg MailboxProviderConfig) (*MailboxProvider, error) {
	if cfg.Client == nil {
		return nil, errors.New("workmail: mailbox provider requires a Client")
	}
	if cfg.EWS == nil {
		return nil, errors.New("workmail: mailbox provider requires an EWSClient")
	}
	if strings.TrimSpace(cfg.TenantID) == "" {
		return nil, errors.New("workmail: mailbox provider requires a tenant id")
	}
	folder := strings.ToLower(strings.TrimSpace(cfg.PollFolder))
	if folder == "" {
		folder = "inbox"
	}
	return &MailboxProvider{client: cfg.Client, ews: cfg.EWS, tenantID: cfg.TenantID, pollFolder: folder}, nil
}

// Kind implements ingestion.MailboxProvider.
func (p *MailboxProvider) Kind() string { return "workmail" }

// ListMailboxes enumerates WorkMail users and yields one Mailbox per
// ENABLED user. Suspended / deleted users are skipped at the provider
// layer so the poller doesn't waste an EWS round-trip on them.
func (p *MailboxProvider) ListMailboxes(ctx context.Context, tenantID string) ([]ingestion.Mailbox, error) {
	if tenantID == "" {
		tenantID = p.tenantID
	}
	dir, err := NewDirectoryClient(DirectoryClientConfig{Client: p.client})
	if err != nil {
		return nil, err
	}
	users, err := dir.ListUsers(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("workmail: enumerate mailboxes: %w", err)
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

// FetchNew uses EWS FindItem with an item:DateTimeReceived restriction,
// then issues a single GetItem per matching id to fetch the body.
func (p *MailboxProvider) FetchNew(ctx context.Context, mailbox ingestion.Mailbox, since time.Time, limit int) ([]ingestion.RawEmail, error) {
	if mailbox.Address == "" {
		return nil, errors.New("workmail: mailbox address is required")
	}
	if limit <= 0 {
		limit = 50
	}
	items, err := p.ews.FindItems(ctx, mailbox.Address, p.pollFolder, since, limit)
	if err != nil {
		return nil, fmt.Errorf("workmail: find items: %w", err)
	}
	out := make([]ingestion.RawEmail, 0, len(items))
	for _, it := range items {
		body, gerr := p.ews.GetItem(ctx, mailbox.Address, it.ID)
		if gerr != nil {
			return nil, fmt.Errorf("workmail: get item %s: %w", it.ID, gerr)
		}
		raw := ingestion.RawEmail{
			ProviderMessageID: it.ID,
			TenantID:          mailbox.TenantID,
			Mailbox:           mailbox.Address,
			Subject:           it.Subject,
			Sender:            it.From,
			Recipients:        append([]string{}, it.To...),
			CC:                append([]string{}, it.Cc...),
			ReceivedAt:        it.DateReceived,
			Headers:           map[string]string{},
		}
		if strings.EqualFold(body.BodyType, "HTML") {
			raw.HTMLBody = body.Content
		} else {
			raw.Body = body.Content
		}
		out = append(out, raw)
	}
	return out, nil
}

// Compile-time interface check.
var _ ingestion.MailboxProvider = (*MailboxProvider)(nil)
