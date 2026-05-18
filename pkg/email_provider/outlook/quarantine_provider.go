package outlook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// QuarantineProvider implements action.QuarantineProvider for
// Microsoft 365 / Exchange Online.
//
// Outlook has no "label" object the way Gmail does — categories are
// just strings on the message. To quarantine a message we therefore
// (a) ensure the SN360 / Blocked master category exists, (b) attach
// it to the message via the standard categories PATCH path, and
// (c) move the message into the "Junk Email" well-known folder so it
// drops out of the inbox view. RestoreFromQuarantine performs the
// inverse: move back to Inbox + remove the category.
//
// The category name doubles as the quarantine label ID returned to
// the action.QuarantineService; downstream code keys quarantine
// records by tenant + pseudo-message-id, so a stable, human-readable
// id is fine.
type QuarantineProvider struct {
	labels *LabelProvider
}

// QuarantineProviderConfig wires the provider.
type QuarantineProviderConfig struct {
	Labels *LabelProvider
}

// NewQuarantineProvider constructs the Outlook quarantine provider.
func NewQuarantineProvider(cfg QuarantineProviderConfig) (*QuarantineProvider, error) {
	if cfg.Labels == nil {
		return nil, errors.New("outlook quarantine: label provider is required")
	}
	return &QuarantineProvider{labels: cfg.Labels}, nil
}

// Kind reports the provider identity used by the action layer.
func (p *QuarantineProvider) Kind() action.LabelProviderKind {
	return action.LabelProviderOutlook
}

// EnsureQuarantineLabel creates the master category that backs the
// SN360 quarantine flow. Returns the category name (which is what
// Graph treats as the identifier for `categories` patching).
func (p *QuarantineProvider) EnsureQuarantineLabel(ctx context.Context, email string) (string, error) {
	name, err := p.labels.EnsureLabel(ctx, email, action.QuarantineLabelName, action.LabelColor{
		OutlookPreset: "preset5", // dark grey — visually distinct from tier labels
	})
	if err != nil {
		return "", fmt.Errorf("ensure quarantine category: %w", err)
	}
	return name, nil
}

// MoveToQuarantine attaches the quarantine category and moves the
// message into the user's "Junk Email" folder so it drops out of the
// primary inbox. stubBody is ignored at this layer — body rewriting
// is handled by the BannerInjector through a separate code path.
func (p *QuarantineProvider) MoveToQuarantine(ctx context.Context, email, messageID, quarantineLabelID, _ string) error {
	if err := p.labels.ApplyLabel(ctx, email, messageID, quarantineLabelID); err != nil {
		return fmt.Errorf("apply quarantine category: %w", err)
	}
	if err := p.moveTo(ctx, email, messageID, "junkemail"); err != nil {
		return fmt.Errorf("move to junk: %w", err)
	}
	return nil
}

// RestoreFromQuarantine removes the quarantine category and moves the
// message back into the inbox.
func (p *QuarantineProvider) RestoreFromQuarantine(ctx context.Context, email, messageID, quarantineLabelID, _ string) error {
	if err := p.labels.RemoveLabel(ctx, email, messageID, quarantineLabelID); err != nil {
		return fmt.Errorf("remove quarantine category: %w", err)
	}
	if err := p.moveTo(ctx, email, messageID, "inbox"); err != nil {
		return fmt.Errorf("move to inbox: %w", err)
	}
	return nil
}

// moveTo invokes Graph's well-known folder move endpoint. The
// `destinationId` accepts the well-known names ("inbox",
// "junkemail", "archive", ...) without translation.
func (p *QuarantineProvider) moveTo(ctx context.Context, email, messageID, destination string) error {
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages/%s/move",
		p.labels.baseURL, url.PathEscape(email), url.PathEscape(messageID))
	body := struct {
		DestinationID string `json:"destinationId"`
	}{DestinationID: destination}
	return p.labels.do(ctx, http.MethodPost, endpoint, body, nil)
}
