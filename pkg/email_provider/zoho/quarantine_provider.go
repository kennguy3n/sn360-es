package zoho

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// QuarantineProvider implements action.QuarantineProvider for Zoho
// Mail. The provider creates a hidden "SN360 / Blocked" folder via
// the per-account folder API and moves messages into it via
// /accounts/{acct}/messages/move.
type QuarantineProvider struct {
	client *Client

	// folderCache memoises (email → folderID) lookups so the
	// quarantine loop doesn't re-walk the directory and folder
	// list on every message.
	folderMu    sync.Mutex
	folderCache map[string]string
}

// QuarantineProviderConfig wires the QuarantineProvider.
type QuarantineProviderConfig struct {
	Client *Client
}

// NewQuarantineProvider validates the config and returns the provider.
func NewQuarantineProvider(cfg QuarantineProviderConfig) (*QuarantineProvider, error) {
	if cfg.Client == nil {
		return nil, errors.New("zoho: quarantine provider requires a Client")
	}
	return &QuarantineProvider{client: cfg.Client, folderCache: make(map[string]string)}, nil
}

// Kind reports the provider identity for the quarantine service.
func (q *QuarantineProvider) Kind() action.LabelProviderKind { return action.LabelProviderZoho }

// zohoFolder is the wire shape for folder list/create.
type zohoFolder struct {
	FolderID   string `json:"folderId"`
	FolderName string `json:"folderName"`
	FolderType string `json:"folderType"`
	IsHidden   bool   `json:"isHidden,omitempty"`
}

// EnsureQuarantineLabel resolves (or creates) the hidden quarantine
// folder for the given mailbox and returns its folderId.
func (q *QuarantineProvider) EnsureQuarantineLabel(ctx context.Context, email string) (string, error) {
	if email == "" {
		return "", errors.New("zoho: email is required")
	}
	q.folderMu.Lock()
	if cached, ok := q.folderCache[email]; ok {
		q.folderMu.Unlock()
		return cached, nil
	}
	q.folderMu.Unlock()

	accountID, err := q.accountIDForEmail(ctx, email)
	if err != nil {
		return "", err
	}

	// Step 1: list existing folders and check for SN360 / Blocked.
	listEndpoint := fmt.Sprintf("%s/accounts/%s/folders",
		q.client.baseURL, url.PathEscape(accountID))
	var listResp struct {
		Data []zohoFolder `json:"data"`
	}
	if err := q.client.do(ctx, http.MethodGet, listEndpoint, nil, &listResp); err != nil {
		return "", fmt.Errorf("zoho: list folders: %w", err)
	}
	for _, f := range listResp.Data {
		if strings.EqualFold(f.FolderName, action.QuarantineLabelName) {
			q.folderMu.Lock()
			q.folderCache[email] = f.FolderID
			q.folderMu.Unlock()
			return f.FolderID, nil
		}
	}

	// Step 2: create the hidden folder.
	createBody := map[string]any{
		"folderName": action.QuarantineLabelName,
		"isHidden":   true,
	}
	var createResp struct {
		Data zohoFolder `json:"data"`
	}
	if err := q.client.do(ctx, http.MethodPost, listEndpoint, createBody, &createResp); err != nil {
		return "", fmt.Errorf("zoho: create quarantine folder: %w", err)
	}
	if createResp.Data.FolderID == "" {
		return "", errors.New("zoho: create folder response missing folderId")
	}
	q.folderMu.Lock()
	q.folderCache[email] = createResp.Data.FolderID
	q.folderMu.Unlock()
	return createResp.Data.FolderID, nil
}

// MoveToQuarantine moves messageID into the hidden quarantine folder
// and replaces the body with the stub. The body rewrite is best
// effort: Zoho may reject the edit on already-quarantined messages,
// in which case the move alone is sufficient to hide the message.
func (q *QuarantineProvider) MoveToQuarantine(ctx context.Context, email, messageID, quarantineLabelID, stubBody string) (string, error) {
	accountID, err := q.accountIDForEmail(ctx, email)
	if err != nil {
		return "", err
	}
	if err := q.moveMessage(ctx, accountID, messageID, quarantineLabelID); err != nil {
		return "", fmt.Errorf("zoho: move to quarantine: %w", err)
	}
	if stubBody == "" {
		return messageID, nil
	}
	inj, err := NewBannerInjector(BannerInjectorConfig{Client: q.client})
	if err != nil {
		return messageID, err
	}
	// Wrap the stub in a minimal HTML document so it renders
	// identically to the Fastmail and WorkMail quarantine stubs.
	// Without the wrapper Zoho's web UI sometimes renders the
	// escaped text as a plain string rather than an HTML body.
	body := zohoBody{HTML: "<html><body>" + htmlEscape(stubBody) + "</body></html>", IsHTML: true}
	if err := inj.writeBody(ctx, accountID, messageID, body); err != nil {
		// Surface the write error — operators want to know when the
		// stub couldn't be applied, but the message is already
		// moved so the user can't see it anyway. Zoho's PUT
		// /messages endpoint updates the body in place and does
		// NOT reissue the message id, so the original id remains
		// valid for the caller's quarantine record.
		return messageID, fmt.Errorf("zoho: apply quarantine stub: %w", err)
	}
	return messageID, nil
}

// RestoreFromQuarantine moves the message back to Inbox and replaces
// the stub with the supplied restoredBody (or a short receipt when
// empty).
func (q *QuarantineProvider) RestoreFromQuarantine(ctx context.Context, email, messageID, _, restoredBody string) (string, error) {
	accountID, err := q.accountIDForEmail(ctx, email)
	if err != nil {
		return "", err
	}
	// Resolve the Inbox folder ID — Zoho doesn't accept folder
	// names in the move endpoint, only numeric folderIds.
	listEndpoint := fmt.Sprintf("%s/accounts/%s/folders",
		q.client.baseURL, url.PathEscape(accountID))
	var listResp struct {
		Data []zohoFolder `json:"data"`
	}
	if err := q.client.do(ctx, http.MethodGet, listEndpoint, nil, &listResp); err != nil {
		return "", fmt.Errorf("zoho: list folders for restore: %w", err)
	}
	var inboxID string
	for _, f := range listResp.Data {
		if strings.EqualFold(f.FolderType, "Inbox") || strings.EqualFold(f.FolderName, "Inbox") {
			inboxID = f.FolderID
			break
		}
	}
	if inboxID == "" {
		return "", errors.New("zoho: inbox folder not found for restore")
	}
	if err := q.moveMessage(ctx, accountID, messageID, inboxID); err != nil {
		return "", fmt.Errorf("zoho: restore move: %w", err)
	}
	if restoredBody == "" {
		restoredBody = "<p>This message was released from SN360 quarantine.</p>"
	}
	inj, err := NewBannerInjector(BannerInjectorConfig{Client: q.client})
	if err != nil {
		return messageID, err
	}
	body := zohoBody{HTML: restoredBody, IsHTML: true}
	if err := inj.writeBody(ctx, accountID, messageID, body); err != nil {
		return messageID, fmt.Errorf("zoho: apply restore body: %w", err)
	}
	// Zoho's PUT-based body rewrite is in place — the message id
	// is stable across move + body update.
	return messageID, nil
}

// moveMessage drives /accounts/{acct}/messages/move.
func (q *QuarantineProvider) moveMessage(ctx context.Context, accountID, messageID, destFolderID string) error {
	endpoint := fmt.Sprintf("%s/accounts/%s/messages",
		q.client.baseURL, url.PathEscape(accountID))
	body := map[string]any{
		"mode":         "move",
		"messageId":    []string{messageID},
		"destFolderId": destFolderID,
	}
	return q.client.do(ctx, http.MethodPut, endpoint, body, nil)
}

// accountIDForEmail mirrors the LabelProvider helper — delegates to
// the per-Client account-id cache.
func (q *QuarantineProvider) accountIDForEmail(ctx context.Context, email string) (string, error) {
	return q.client.ResolveAccountID(ctx, email)
}

// Compile-time interface check.
var _ action.QuarantineProvider = (*QuarantineProvider)(nil)
