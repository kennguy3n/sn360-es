package gmail

import (
	"context"
	"errors"
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// QuarantineProvider implements action.QuarantineProvider for Gmail.
// It builds on the LabelProvider to ensure the "SN360 / Blocked"
// label exists, attach it to the offending message, and strip the
// INBOX label so the message disappears from the user's primary
// view. Restore re-attaches INBOX and removes the quarantine label.
//
// Gmail's API does not natively support hidden folders, so we lean
// on `messageListVisibility: hide` (set when the label is created)
// to keep the SN360 / Blocked entry out of the sidebar. Body
// rewriting is the responsibility of the BannerInjector and is
// invoked separately by the quarantine action handler — keeping
// the provider scoped to the label-move concern keeps each
// operation independently retryable.
type QuarantineProvider struct {
	labels *LabelProvider
}

// QuarantineProviderConfig wires the provider.
type QuarantineProviderConfig struct {
	Labels *LabelProvider
}

// NewQuarantineProvider constructs the Gmail quarantine provider.
func NewQuarantineProvider(cfg QuarantineProviderConfig) (*QuarantineProvider, error) {
	if cfg.Labels == nil {
		return nil, errors.New("gmail quarantine: label provider is required")
	}
	return &QuarantineProvider{labels: cfg.Labels}, nil
}

// Kind returns action.LabelProviderGmail.
func (p *QuarantineProvider) Kind() action.LabelProviderKind {
	return action.LabelProviderGmail
}

// EnsureQuarantineLabel creates the "SN360 / Blocked" label in the
// mailbox (idempotent on the server side) and returns its ID.
func (p *QuarantineProvider) EnsureQuarantineLabel(ctx context.Context, email string) (string, error) {
	id, err := p.labels.EnsureLabel(ctx, email, action.QuarantineLabelName, action.LabelColor{
		Background: "#000000",
		Foreground: "#ffffff",
	})
	if err != nil {
		return "", fmt.Errorf("ensure quarantine label: %w", err)
	}
	return id, nil
}

// MoveToQuarantine attaches the quarantine label and removes INBOX
// in a single modify call. stubBody is accepted (and ignored) here
// — Gmail body rewriting requires the shadow-copy pattern and is
// driven by the action handler through the BannerInjector. Keeping
// the contract aligned with the QuarantineProvider interface
// preserves provider substitutability.
func (p *QuarantineProvider) MoveToQuarantine(ctx context.Context, email, messageID, quarantineLabelID, _ string) error {
	if err := p.labels.modify(ctx, email, messageID, gmailModifyRequest{
		AddLabelIDs:    []string{quarantineLabelID},
		RemoveLabelIDs: []string{"INBOX"},
	}); err != nil {
		return fmt.Errorf("apply quarantine label: %w", err)
	}
	return nil
}

// RestoreFromQuarantine re-attaches INBOX and removes the quarantine
// label.
func (p *QuarantineProvider) RestoreFromQuarantine(ctx context.Context, email, messageID, quarantineLabelID, _ string) error {
	if err := p.labels.modify(ctx, email, messageID, gmailModifyRequest{
		AddLabelIDs:    []string{"INBOX"},
		RemoveLabelIDs: []string{quarantineLabelID},
	}); err != nil {
		return fmt.Errorf("remove quarantine label: %w", err)
	}
	return nil
}
