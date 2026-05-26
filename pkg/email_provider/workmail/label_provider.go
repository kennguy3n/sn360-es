package workmail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// LabelProvider implements action.LabelProvider for Amazon WorkMail.
// WorkMail uses the Exchange "Categories" model — strings that
// decorate a message and are visible to the user via the Outlook
// category UI. We treat the SN360 tier names as category strings.
//
// EWS UpdateItem with FieldURI item:Categories sets the full
// category list, so applying or removing a label is a read-modify-
// write (we fetch the message's current categories, add/remove ours,
// and set the merged list).
type LabelProvider struct {
	ews *EWSClient

	cacheMu sync.Mutex
	known   map[string]struct{} // category names we've returned IDs for
}

// LabelProviderConfig wires LabelProvider.
type LabelProviderConfig struct {
	EWS *EWSClient
}

// NewLabelProvider validates the config and returns the provider.
func NewLabelProvider(cfg LabelProviderConfig) (*LabelProvider, error) {
	if cfg.EWS == nil {
		return nil, errors.New("workmail: label provider requires an EWSClient")
	}
	return &LabelProvider{ews: cfg.EWS, known: make(map[string]struct{})}, nil
}

// Kind reports the provider identity.
func (p *LabelProvider) Kind() action.LabelProviderKind { return action.LabelProviderWorkmail }

// EnsureLabel records the category name. Categories in Exchange are
// free-form strings; there is no provider-side create call required.
// We return the name as the label id so ApplyLabel / RemoveLabel can
// round-trip it.
func (p *LabelProvider) EnsureLabel(ctx context.Context, email, name string, color action.LabelColor) (string, error) {
	_ = ctx
	_ = email
	_ = color
	if name == "" {
		return "", errors.New("workmail: label name is required")
	}
	p.cacheMu.Lock()
	p.known[name] = struct{}{}
	p.cacheMu.Unlock()
	return name, nil
}

// ApplyLabel adds the category to the message's category list.
func (p *LabelProvider) ApplyLabel(ctx context.Context, email, messageID, labelID string) error {
	if email == "" || messageID == "" || labelID == "" {
		return errors.New("workmail: email, message_id and label_id are required")
	}
	current, err := p.currentCategories(ctx, email, messageID)
	if err != nil {
		return err
	}
	if containsCI(current, labelID) {
		return nil // already set; nothing to do
	}
	updated := append(current, labelID)
	if err := p.ews.UpdateCategories(ctx, email, messageID, updated); err != nil {
		return fmt.Errorf("workmail: apply category: %w", err)
	}
	return nil
}

// RemoveLabel drops the category from the message's category list.
func (p *LabelProvider) RemoveLabel(ctx context.Context, email, messageID, labelID string) error {
	if email == "" || messageID == "" || labelID == "" {
		return errors.New("workmail: email, message_id and label_id are required")
	}
	current, err := p.currentCategories(ctx, email, messageID)
	if err != nil {
		return err
	}
	filtered := current[:0]
	for _, c := range current {
		if !strings.EqualFold(c, labelID) {
			filtered = append(filtered, c)
		}
	}
	if len(filtered) == len(current) {
		return nil // not present
	}
	if err := p.ews.UpdateCategories(ctx, email, messageID, filtered); err != nil {
		return fmt.Errorf("workmail: remove category: %w", err)
	}
	return nil
}

// currentCategories fetches the message's current category list via
// EWS GetItem with the item:Categories property requested.
func (p *LabelProvider) currentCategories(ctx context.Context, email, messageID string) ([]string, error) {
	body := fmt.Sprintf(`
    <m:GetItem>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Categories"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:ItemIds>
        <t:ItemId Id="%s"/>
      </m:ItemIds>
    </m:GetItem>`, xmlEscape(messageID))
	respBody, err := p.ews.Invoke(ctx, email, body)
	if err != nil {
		return nil, fmt.Errorf("workmail: get categories: %w", err)
	}
	return parseCategories(respBody)
}

func containsCI(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

// Compile-time interface check.
var _ action.LabelProvider = (*LabelProvider)(nil)
