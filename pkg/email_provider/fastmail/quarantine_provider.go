package fastmail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// QuarantineProvider implements action.QuarantineProvider for
// Fastmail. The hidden quarantine mailbox is a normal JMAP Mailbox
// named action.QuarantineLabelName; messages are moved by replacing
// their mailboxIds via Email/set.
//
// Body stubbing uses the same upload/import/destroy pattern as the
// BannerInjector because JMAP Email bodies are immutable.
type QuarantineProvider struct {
	client *Client
	inj    *BannerInjector

	mu       sync.Mutex
	cachedID string
	inboxID  string
}

// QuarantineProviderConfig wires the QuarantineProvider.
type QuarantineProviderConfig struct {
	Client *Client
}

// NewQuarantineProvider validates the config and returns the provider.
func NewQuarantineProvider(cfg QuarantineProviderConfig) (*QuarantineProvider, error) {
	if cfg.Client == nil {
		return nil, errors.New("fastmail: quarantine provider requires a Client")
	}
	inj, err := NewBannerInjector(BannerInjectorConfig{Client: cfg.Client})
	if err != nil {
		return nil, err
	}
	return &QuarantineProvider{client: cfg.Client, inj: inj}, nil
}

// Kind reports the provider identity.
func (q *QuarantineProvider) Kind() action.LabelProviderKind { return action.LabelProviderFastmail }

// EnsureQuarantineLabel creates (or resolves) the hidden quarantine
// mailbox. Returns the JMAP mailboxId.
func (q *QuarantineProvider) EnsureQuarantineLabel(ctx context.Context, email string) (string, error) {
	q.mu.Lock()
	if q.cachedID != "" {
		q.mu.Unlock()
		return q.cachedID, nil
	}
	q.mu.Unlock()
	id, err := q.resolveOrCreate(ctx, action.QuarantineLabelName)
	if err != nil {
		return "", err
	}
	q.mu.Lock()
	q.cachedID = id
	q.mu.Unlock()
	return id, nil
}

// resolveOrCreate looks up a mailbox by name and creates it when
// missing.
func (q *QuarantineProvider) resolveOrCreate(ctx context.Context, name string) (string, error) {
	args := map[string]any{
		"accountId":  q.client.accountID,
		"properties": []string{"id", "name", "role"},
	}
	resp, err := q.client.Invoke(ctx, "Mailbox/get", args)
	if err != nil {
		return "", fmt.Errorf("fastmail: list mailboxes: %w", err)
	}
	var decoded struct {
		List []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Role string `json:"role"`
		} `json:"list"`
	}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return "", fmt.Errorf("fastmail: decode mailbox/get: %w", err)
	}
	for _, m := range decoded.List {
		if strings.EqualFold(m.Name, name) {
			return m.ID, nil
		}
	}
	createArgs := map[string]any{
		"accountId": q.client.accountID,
		"create": map[string]any{
			"new": map[string]any{
				"name": name,
				"role": nil,
			},
		},
	}
	createResp, err := q.client.Invoke(ctx, "Mailbox/set", createArgs)
	if err != nil {
		return "", err
	}
	var cd struct {
		Created map[string]struct {
			ID string `json:"id"`
		} `json:"created"`
	}
	if err := json.Unmarshal(createResp, &cd); err != nil {
		return "", fmt.Errorf("fastmail: decode mailbox/set: %w", err)
	}
	c, ok := cd.Created["new"]
	if !ok {
		return "", errors.New("fastmail: mailbox/set returned no created entry")
	}
	return c.ID, nil
}

// MoveToQuarantine replaces the message's mailboxIds with the
// quarantine mailbox and rewrites the body to the stub.
func (q *QuarantineProvider) MoveToQuarantine(ctx context.Context, email, messageID, quarantineLabelID, stubBody string) error {
	if err := q.replaceMailboxes(ctx, messageID, []string{quarantineLabelID}); err != nil {
		return fmt.Errorf("fastmail: move to quarantine: %w", err)
	}
	if stubBody == "" {
		return nil
	}
	// Rewrite the body with a banner-style stub. We use the same
	// upload/import/destroy dance.
	bw, err := NewBodyRewriter(q.inj)
	if err != nil {
		return err
	}
	if err := bw.WriteBody(ctx, email, messageID, "<html><body>"+htmlEscape(stubBody)+"</body></html>"); err != nil {
		return fmt.Errorf("fastmail: stub body: %w", err)
	}
	return nil
}

// RestoreFromQuarantine moves the message back to Inbox and rewrites
// the body to restoredBody (or a short release receipt when empty).
func (q *QuarantineProvider) RestoreFromQuarantine(ctx context.Context, email, messageID, quarantineLabelID, restoredBody string) error {
	inboxID, err := q.resolveInbox(ctx)
	if err != nil {
		return err
	}
	if err := q.replaceMailboxes(ctx, messageID, []string{inboxID}); err != nil {
		return fmt.Errorf("fastmail: restore move: %w", err)
	}
	if restoredBody == "" {
		restoredBody = "<p>This message was released from SN360 quarantine.</p>"
	}
	bw, err := NewBodyRewriter(q.inj)
	if err != nil {
		return err
	}
	if err := bw.WriteBody(ctx, email, messageID, restoredBody); err != nil {
		return fmt.Errorf("fastmail: restored body: %w", err)
	}
	return nil
}

// resolveInbox returns the JMAP mailboxId for the role "inbox".
func (q *QuarantineProvider) resolveInbox(ctx context.Context) (string, error) {
	q.mu.Lock()
	if q.inboxID != "" {
		q.mu.Unlock()
		return q.inboxID, nil
	}
	q.mu.Unlock()
	args := map[string]any{
		"accountId":  q.client.accountID,
		"properties": []string{"id", "role"},
	}
	resp, err := q.client.Invoke(ctx, "Mailbox/get", args)
	if err != nil {
		return "", err
	}
	var decoded struct {
		List []struct {
			ID   string `json:"id"`
			Role string `json:"role"`
		} `json:"list"`
	}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return "", err
	}
	for _, m := range decoded.List {
		if strings.EqualFold(m.Role, "inbox") {
			q.mu.Lock()
			q.inboxID = m.ID
			q.mu.Unlock()
			return m.ID, nil
		}
	}
	return "", errors.New("fastmail: inbox mailbox not found")
}

// replaceMailboxes sets the message's mailboxIds to exactly the given
// list (i.e. removing it from every mailbox not in the list).
func (q *QuarantineProvider) replaceMailboxes(ctx context.Context, messageID string, mailboxIDs []string) error {
	mb := make(map[string]bool, len(mailboxIDs))
	for _, id := range mailboxIDs {
		mb[id] = true
	}
	args := map[string]any{
		"accountId": q.client.accountID,
		"update": map[string]any{
			messageID: map[string]any{
				"mailboxIds": mb,
			},
		},
	}
	resp, err := q.client.Invoke(ctx, "Email/set", args)
	if err != nil {
		return err
	}
	var decoded struct {
		NotUpdated map[string]json.RawMessage `json:"notUpdated"`
	}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return fmt.Errorf("fastmail: decode email/set: %w", err)
	}
	if len(decoded.NotUpdated) > 0 {
		for id, raw := range decoded.NotUpdated {
			return fmt.Errorf("fastmail: update %s failed: %s", id, string(raw))
		}
	}
	return nil
}

// Compile-time interface check.
var _ action.QuarantineProvider = (*QuarantineProvider)(nil)
