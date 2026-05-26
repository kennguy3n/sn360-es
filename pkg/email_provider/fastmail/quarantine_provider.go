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
	inj, err := NewBannerInjector(BannerInjectorConfig(cfg))
	if err != nil {
		return nil, err
	}
	return &QuarantineProvider{client: cfg.Client, inj: inj}, nil
}

// Kind reports the provider identity.
func (q *QuarantineProvider) Kind() action.LabelProviderKind { return action.LabelProviderFastmail }

// EnsureQuarantineLabel creates (or resolves) the hidden quarantine
// mailbox. Returns the JMAP mailboxId.
func (q *QuarantineProvider) EnsureQuarantineLabel(ctx context.Context, _ string) (string, error) {
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

// MoveToQuarantine places the message in the quarantine mailbox with
// a body stub in a single pass.
//
// JMAP email bodies are immutable, so rewriting the body necessarily
// destroys the original message and imports a new one. Doing the
// mailbox-move and the body-rewrite as two separate steps (the
// previous implementation) left a window where the destroy succeeded
// against the original id but the caller's QuarantineRecord still
// referenced that destroyed id — making release impossible.
//
// We now do a single fetchRaw → splice stub HTML → upload → import
// (with the quarantine mailbox as the only target) → destroy
// original. The newly-imported message lives only in the quarantine
// mailbox with the stub body, and we return its id so the caller
// persists a valid reference.
//
// When stubBody is empty we keep the original message intact and
// only flip the mailboxIds; the id stays stable and we return it
// unchanged.
func (q *QuarantineProvider) MoveToQuarantine(ctx context.Context, _, messageID, quarantineLabelID, stubBody string) (string, error) {
	if stubBody == "" {
		if err := q.replaceMailboxes(ctx, messageID, []string{quarantineLabelID}); err != nil {
			return "", fmt.Errorf("fastmail: move to quarantine: %w", err)
		}
		return messageID, nil
	}
	stubHTML := "<html><body>" + htmlEscape(stubBody) + "</body></html>"
	newID, err := q.rewriteIntoMailbox(ctx, messageID, quarantineLabelID, stubHTML)
	if err != nil {
		return newID, fmt.Errorf("fastmail: quarantine rewrite: %w", err)
	}
	return newID, nil
}

// RestoreFromQuarantine moves the message back to Inbox and rewrites
// the body to restoredBody (or a short release receipt when empty).
// Uses the same single-pass pattern as MoveToQuarantine to keep the
// returned id pointing at the message that actually exists.
func (q *QuarantineProvider) RestoreFromQuarantine(ctx context.Context, _, messageID, _, restoredBody string) (string, error) {
	inboxID, err := q.resolveInbox(ctx)
	if err != nil {
		return "", err
	}
	if restoredBody == "" {
		restoredBody = "<p>This message was released from SN360 quarantine.</p>"
	}
	newID, err := q.rewriteIntoMailbox(ctx, messageID, inboxID, restoredBody)
	if err != nil {
		return newID, fmt.Errorf("fastmail: restore rewrite: %w", err)
	}
	return newID, nil
}

// rewriteIntoMailbox performs the atomic body-rewrite + reparent
// flow used by both MoveToQuarantine and RestoreFromQuarantine.
//
// On success the original message is destroyed and the returned id
// references the new message in destMailboxID. The new message
// inherits the original message's JMAP keywords (so SEEN/FLAGGED
// state is preserved) but its mailbox set is reduced to
// {destMailboxID} regardless of what the source had — quarantine
// must hide the message from every other folder, and release must
// land it cleanly in the inbox.
//
// On partial failure (import succeeded but destroy failed) the new
// id is returned together with the error so the caller can persist
// it for a subsequent retry — at worst the original remains as a
// duplicate in its old location until the destroy retries clean it
// up.
func (q *QuarantineProvider) rewriteIntoMailbox(ctx context.Context, messageID, destMailboxID, htmlBody string) (string, error) {
	raw, _, keywords, err := q.inj.fetchRaw(ctx, messageID)
	if err != nil {
		return "", fmt.Errorf("fetch raw: %w", err)
	}
	mutated, err := replaceHTMLBody(raw, []byte(htmlBody))
	if err != nil {
		return "", fmt.Errorf("replace body: %w", err)
	}
	blobID, err := q.inj.upload(ctx, mutated)
	if err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}
	newID, err := q.inj.importBlob(ctx, blobID, map[string]bool{destMailboxID: true}, keywords)
	if err != nil {
		return "", fmt.Errorf("import: %w", err)
	}
	if newID == "" {
		return "", errors.New("import returned no new id")
	}
	if err := q.inj.destroy(ctx, messageID); err != nil {
		// Import already produced a new message in the target
		// mailbox; surface the new id alongside the error so the
		// caller's record points at the message that exists.
		return newID, fmt.Errorf("destroy original: %w", err)
	}
	return newID, nil
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
