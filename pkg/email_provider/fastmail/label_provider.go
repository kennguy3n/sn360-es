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

// LabelProvider implements action.LabelProvider for Fastmail. In
// JMAP, mailboxes serve as both folders and labels — a message can
// live in multiple mailboxes simultaneously (RFC 8621 §2). We
// represent SN360 tier labels as dedicated mailboxes under the
// account root.
type LabelProvider struct {
	client *Client

	mu        sync.Mutex
	cache     map[string]string // name → mailboxId
	cacheInit bool
}

// LabelProviderConfig wires the LabelProvider.
type LabelProviderConfig struct {
	Client *Client
}

// NewLabelProvider validates the config and returns the provider.
func NewLabelProvider(cfg LabelProviderConfig) (*LabelProvider, error) {
	if cfg.Client == nil {
		return nil, errors.New("fastmail: label provider requires a Client")
	}
	return &LabelProvider{client: cfg.Client, cache: make(map[string]string)}, nil
}

// Kind reports the provider identity.
func (p *LabelProvider) Kind() action.LabelProviderKind { return action.LabelProviderFastmail }

// EnsureLabel creates the mailbox if it doesn't already exist. The
// returned ID is the JMAP mailboxId.
//
// The email argument is ignored: JMAP labels are account-scoped, not
// per-mailbox like Gmail. Color is also ignored — Fastmail's UI
// derives mailbox colors from its own settings.
func (p *LabelProvider) EnsureLabel(ctx context.Context, _, name string, _ action.LabelColor) (string, error) {
	if name == "" {
		return "", errors.New("fastmail: label name is required")
	}
	if err := p.warmCache(ctx); err != nil {
		return "", err
	}
	p.mu.Lock()
	if id, ok := p.cache[strings.ToLower(name)]; ok {
		p.mu.Unlock()
		return id, nil
	}
	p.mu.Unlock()
	id, err := p.createLabel(ctx, name)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.cache[strings.ToLower(name)] = id
	p.mu.Unlock()
	return id, nil
}

// ApplyLabel adds the mailboxId to the message's mailboxIds set.
func (p *LabelProvider) ApplyLabel(ctx context.Context, _, messageID, labelID string) error {
	if messageID == "" || labelID == "" {
		return errors.New("fastmail: message_id and label_id are required")
	}
	patch := map[string]any{
		"accountId": p.client.accountID,
		"update": map[string]any{
			messageID: map[string]any{
				"mailboxIds/" + labelID: true,
			},
		},
	}
	return p.invokeSet(ctx, "Email/set", patch)
}

// RemoveLabel removes the mailboxId from the message's mailboxIds.
func (p *LabelProvider) RemoveLabel(ctx context.Context, _, messageID, labelID string) error {
	if messageID == "" || labelID == "" {
		return errors.New("fastmail: message_id and label_id are required")
	}
	patch := map[string]any{
		"accountId": p.client.accountID,
		"update": map[string]any{
			messageID: map[string]any{
				"mailboxIds/" + labelID: nil,
			},
		},
	}
	return p.invokeSet(ctx, "Email/set", patch)
}

// invokeSet runs a JMAP /set method and surfaces JMAP-level errors
// from `notUpdated` / `notCreated` as Go errors.
func (p *LabelProvider) invokeSet(ctx context.Context, method string, args any) error {
	resp, err := p.client.Invoke(ctx, method, args)
	if err != nil {
		return err
	}
	var decoded struct {
		NotUpdated map[string]json.RawMessage `json:"notUpdated"`
		NotCreated map[string]json.RawMessage `json:"notCreated"`
	}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return fmt.Errorf("fastmail: decode %s: %w", method, err)
	}
	if len(decoded.NotCreated) > 0 {
		for id, raw := range decoded.NotCreated {
			return fmt.Errorf("fastmail: %s create %s failed: %s", method, id, string(raw))
		}
	}
	if len(decoded.NotUpdated) > 0 {
		for id, raw := range decoded.NotUpdated {
			return fmt.Errorf("fastmail: %s update %s failed: %s", method, id, string(raw))
		}
	}
	return nil
}

// createLabel creates a JMAP Mailbox with the given name and returns
// its mailbox ID.
func (p *LabelProvider) createLabel(ctx context.Context, name string) (string, error) {
	args := map[string]any{
		"accountId": p.client.accountID,
		"create": map[string]any{
			"new": map[string]any{
				"name": name,
				"role": nil,
			},
		},
	}
	resp, err := p.client.Invoke(ctx, "Mailbox/set", args)
	if err != nil {
		return "", err
	}
	var decoded struct {
		Created map[string]struct {
			ID string `json:"id"`
		} `json:"created"`
		NotCreated map[string]json.RawMessage `json:"notCreated"`
	}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return "", fmt.Errorf("fastmail: decode mailbox/set: %w", err)
	}
	if len(decoded.NotCreated) > 0 {
		for id, raw := range decoded.NotCreated {
			return "", fmt.Errorf("fastmail: mailbox/set create %s failed: %s", id, string(raw))
		}
	}
	created, ok := decoded.Created["new"]
	if !ok || created.ID == "" {
		return "", errors.New("fastmail: mailbox/set returned no id")
	}
	return created.ID, nil
}

// warmCache populates the name→id map from Mailbox/get on the first
// call.
func (p *LabelProvider) warmCache(ctx context.Context) error {
	p.mu.Lock()
	if p.cacheInit {
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()
	args := map[string]any{
		"accountId":  p.client.accountID,
		"properties": []string{"id", "name", "role"},
	}
	resp, err := p.client.Invoke(ctx, "Mailbox/get", args)
	if err != nil {
		return fmt.Errorf("fastmail: warm mailbox cache: %w", err)
	}
	var decoded struct {
		List []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"list"`
	}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return fmt.Errorf("fastmail: decode mailbox/get: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range decoded.List {
		p.cache[strings.ToLower(m.Name)] = m.ID
	}
	p.cacheInit = true
	return nil
}

// Compile-time interface check.
var _ action.LabelProvider = (*LabelProvider)(nil)
