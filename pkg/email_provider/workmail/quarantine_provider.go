package workmail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// QuarantineProvider implements action.QuarantineProvider for
// WorkMail using EWS CreateFolder + MoveItem. The hidden quarantine
// folder lives under msgfolderroot (NOT the Junk Email folder — see
// the Outlook provider docstring for the same rationale).
type QuarantineProvider struct {
	ews *EWSClient

	mu          sync.Mutex
	folderCache map[string]string // email → folder id
}

// QuarantineProviderConfig wires QuarantineProvider.
type QuarantineProviderConfig struct {
	EWS *EWSClient
}

// NewQuarantineProvider validates the config and returns the provider.
func NewQuarantineProvider(cfg QuarantineProviderConfig) (*QuarantineProvider, error) {
	if cfg.EWS == nil {
		return nil, errors.New("workmail: quarantine provider requires an EWSClient")
	}
	return &QuarantineProvider{ews: cfg.EWS, folderCache: make(map[string]string)}, nil
}

// Kind reports the provider identity.
func (q *QuarantineProvider) Kind() action.LabelProviderKind { return action.LabelProviderWorkmail }

// EnsureQuarantineLabel creates or resolves the hidden quarantine
// folder under msgfolderroot. Returns its EWS FolderId.
func (q *QuarantineProvider) EnsureQuarantineLabel(ctx context.Context, email string) (string, error) {
	if email == "" {
		return "", errors.New("workmail: email is required")
	}
	q.mu.Lock()
	if id, ok := q.folderCache[email]; ok {
		q.mu.Unlock()
		return id, nil
	}
	q.mu.Unlock()
	id, err := q.ews.FindFolder(ctx, email, "msgfolderroot", action.QuarantineLabelName)
	if err != nil {
		return "", err
	}
	if id == "" {
		created, cerr := q.ews.CreateFolder(ctx, email, "msgfolderroot", action.QuarantineLabelName)
		if cerr != nil {
			return "", fmt.Errorf("workmail: create quarantine folder: %w", cerr)
		}
		id = created
	}
	q.mu.Lock()
	q.folderCache[email] = id
	q.mu.Unlock()
	return id, nil
}

// MoveToQuarantine moves the message into the hidden folder and
// rewrites its body to the stub.
func (q *QuarantineProvider) MoveToQuarantine(ctx context.Context, email, messageID, quarantineLabelID, stubBody string) error {
	if err := q.ews.MoveItem(ctx, email, messageID, quarantineLabelID); err != nil {
		return fmt.Errorf("workmail: move to quarantine: %w", err)
	}
	if strings.TrimSpace(stubBody) == "" {
		return nil
	}
	stub := EWSMessageBody{BodyType: "HTML", Content: "<html><body>" + htmlEscape(stubBody) + "</body></html>"}
	if err := q.ews.UpdateBody(ctx, email, messageID, stub); err != nil {
		return fmt.Errorf("workmail: stub body: %w", err)
	}
	return nil
}

// RestoreFromQuarantine moves the message back to Inbox and updates
// its body to restoredBody (or a release receipt when empty).
func (q *QuarantineProvider) RestoreFromQuarantine(ctx context.Context, email, messageID, quarantineLabelID, restoredBody string) error {
	if err := q.ews.MoveItemToDistinguished(ctx, email, messageID, "inbox"); err != nil {
		return fmt.Errorf("workmail: restore move: %w", err)
	}
	if strings.TrimSpace(restoredBody) == "" {
		restoredBody = "<p>This message was released from SN360 quarantine.</p>"
	}
	if err := q.ews.UpdateBody(ctx, email, messageID, EWSMessageBody{BodyType: "HTML", Content: restoredBody}); err != nil {
		return fmt.Errorf("workmail: restored body: %w", err)
	}
	return nil
}

// Compile-time interface check.
var _ action.QuarantineProvider = (*QuarantineProvider)(nil)
