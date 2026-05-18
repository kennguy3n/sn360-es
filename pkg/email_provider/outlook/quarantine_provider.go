package outlook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// QuarantineFolderName is the display name of the per-mailbox child
// folder that SN360 creates and moves quarantined messages into. We
// deliberately do NOT use the "junkemail" well-known folder because
// Exchange Online tenants frequently configure aggressive Junk Email
// policies (e.g. auto-purge after N days) which would silently
// destroy messages SN360 is holding for admin review. A dedicated
// folder isolates SN360 from tenant-side retention policy.
const QuarantineFolderName = "SN360 / Quarantined"

// defaultFolderCacheMax bounds the in-memory cache that maps mailbox
// email -> Graph folder id. The cache only holds string -> string
// entries (~200 bytes each), so 16384 entries cap memory at ~4 MB —
// well above the largest realistic single-tenant footprint while
// preventing a runaway tenant from exhausting memory if the binary
// is reused across many tenants in a long-running deployment. When
// the cap is hit, the first entry encountered during map iteration
// (Go-randomised, so effectively random eviction) is dropped to make
// room. Random eviction is acceptable here because cache misses are
// cheap — they trigger a single Graph round-trip that recovers the
// id via the create-then-list flow in ensureQuarantineFolder.
const defaultFolderCacheMax = 16384

// QuarantineProvider implements action.QuarantineProvider for
// Microsoft 365 / Exchange Online.
//
// Outlook has no "label" object the way Gmail does — categories are
// just strings on the message. To quarantine a message we therefore
// (a) ensure the SN360 / Blocked master category exists, (b) attach
// it to the message via the standard categories PATCH path, and
// (c) move the message into a dedicated SN360 child folder (created
// once per mailbox under the inbox) so it drops out of the primary
// inbox view but remains exempt from Junk Email retention policies.
// RestoreFromQuarantine performs the inverse: move back to Inbox +
// remove the category.
//
// The category name doubles as the quarantine label ID returned to
// the action.QuarantineService; downstream code keys quarantine
// records by tenant + pseudo-message-id, so a stable, human-readable
// id is fine.
type QuarantineProvider struct {
	labels *LabelProvider

	folderMu       sync.Mutex
	folderIDCache  map[string]string // email -> folder id
	folderCacheMax int               // 0 = use defaultFolderCacheMax
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
	return &QuarantineProvider{
		labels:        cfg.Labels,
		folderIDCache: make(map[string]string),
	}, nil
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
// message into the per-mailbox SN360 quarantine child folder so it
// drops out of the primary inbox without being subject to Junk Email
// retention policies. stubBody is ignored at this layer — body
// rewriting is handled by the BannerInjector through a separate code
// path.
//
// The folder-id lookup is cache-backed (see ensureQuarantineFolder)
// so the steady-state hot path is a single Graph round-trip. If an
// admin manually deletes the SN360 quarantine folder out of band,
// the cached id will be stale and Graph returns 404 on /move; we
// invalidate the cache and re-run ensureQuarantineFolder once,
// which transparently recreates the folder. Bounded to a single
// retry to avoid masking a genuine "message-not-found" 404 (which
// would still surface after the second failed attempt).
func (p *QuarantineProvider) MoveToQuarantine(ctx context.Context, email, messageID, quarantineLabelID, _ string) error {
	if err := p.labels.ApplyLabel(ctx, email, messageID, quarantineLabelID); err != nil {
		return fmt.Errorf("apply quarantine category: %w", err)
	}
	folderID, err := p.ensureQuarantineFolder(ctx, email)
	if err != nil {
		return fmt.Errorf("ensure quarantine folder: %w", err)
	}
	err = p.moveTo(ctx, email, messageID, folderID)
	if err == nil {
		return nil
	}
	// Stale-cache recovery: a 404 on /move with a folder id we
	// just looked up is almost always the folder having been
	// admin-deleted between cache fill and call. Re-create and
	// retry once. Any other error — including a 404 on the
	// retry — surfaces normally.
	if !is404(err) {
		return fmt.Errorf("move to quarantine folder: %w", err)
	}
	p.invalidateFolderID(email)
	folderID, err = p.ensureQuarantineFolder(ctx, email)
	if err != nil {
		return fmt.Errorf("recreate quarantine folder after stale-cache 404: %w", err)
	}
	if err := p.moveTo(ctx, email, messageID, folderID); err != nil {
		return fmt.Errorf("move to quarantine folder (retry after stale-cache 404): %w", err)
	}
	return nil
}

// is404 reports whether the error is an *APIError carrying a 404
// status. Used by MoveToQuarantine to distinguish the
// folder-deleted recovery path from genuine errors.
func is404(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// invalidateFolderID drops the cached folder id for `email` so the
// next ensureQuarantineFolder call re-runs the create-then-list
// recovery flow. Safe to call when the entry is already absent.
func (p *QuarantineProvider) invalidateFolderID(email string) {
	p.folderMu.Lock()
	defer p.folderMu.Unlock()
	delete(p.folderIDCache, email)
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

// moveTo invokes Graph's folder move endpoint. The `destinationId`
// accepts both well-known folder names ("inbox", "archive", ...) and
// concrete folder ids returned by /mailFolders.
func (p *QuarantineProvider) moveTo(ctx context.Context, email, messageID, destination string) error {
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages/%s/move",
		p.labels.baseURL, url.PathEscape(email), url.PathEscape(messageID))
	body := struct {
		DestinationID string `json:"destinationId"`
	}{DestinationID: destination}
	return p.labels.do(ctx, http.MethodPost, endpoint, body, nil)
}

// graphFolder is the subset of microsoft.graph.mailFolder the
// quarantine provider needs.
type graphFolder struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// ensureQuarantineFolder returns the id of the per-mailbox child
// folder under the inbox that backs the SN360 quarantine. Folder
// creation is best-effort idempotent: when a folder with the target
// name already exists Graph returns 409, which we recover by listing
// children and matching on DisplayName. The id is cached per email
// for the lifetime of the process so steady-state has no folder
// lookups.
func (p *QuarantineProvider) ensureQuarantineFolder(ctx context.Context, email string) (string, error) {
	p.folderMu.Lock()
	if id, ok := p.folderIDCache[email]; ok {
		p.folderMu.Unlock()
		return id, nil
	}
	p.folderMu.Unlock()

	// Try to create first.
	create := fmt.Sprintf("%s/v1.0/users/%s/mailFolders/inbox/childFolders",
		p.labels.baseURL, url.PathEscape(email))
	body := struct {
		DisplayName string `json:"displayName"`
	}{DisplayName: QuarantineFolderName}
	var created graphFolder
	err := p.labels.do(ctx, http.MethodPost, create, body, &created)
	if err == nil && created.ID != "" {
		p.cacheFolderID(email, created.ID)
		return created.ID, nil
	}
	// Fall back to listing existing child folders and matching by
	// name — this is the recovery path when the folder already
	// exists (409 from Graph).
	list := fmt.Sprintf("%s/v1.0/users/%s/mailFolders/inbox/childFolders?$top=200",
		p.labels.baseURL, url.PathEscape(email))
	var page struct {
		Value []graphFolder `json:"value"`
	}
	if lerr := p.labels.do(ctx, http.MethodGet, list, nil, &page); lerr != nil {
		// Surface the original creation error when the list call
		// also fails; otherwise downstream debugging is harder.
		if err != nil {
			return "", fmt.Errorf("create quarantine folder failed (%v); list fallback also failed: %w", err, lerr)
		}
		return "", fmt.Errorf("list quarantine folder candidates: %w", lerr)
	}
	for _, f := range page.Value {
		if f.DisplayName == QuarantineFolderName && f.ID != "" {
			p.cacheFolderID(email, f.ID)
			return f.ID, nil
		}
	}
	if err != nil {
		return "", fmt.Errorf("create quarantine folder: %w", err)
	}
	return "", fmt.Errorf("quarantine folder not found after create+list")
}

// cacheFolderID stores email -> folder id and enforces the size cap.
// When the cap is reached we drop a single map entry (Go-randomised
// iteration order makes this effectively random eviction) to make
// room for the new mapping. Random eviction is acceptable because
// cache misses are cheap — see the comment on defaultFolderCacheMax.
func (p *QuarantineProvider) cacheFolderID(email, id string) {
	p.folderMu.Lock()
	defer p.folderMu.Unlock()
	max := p.folderCacheMax
	if max <= 0 {
		max = defaultFolderCacheMax
	}
	if _, exists := p.folderIDCache[email]; !exists && len(p.folderIDCache) >= max {
		for k := range p.folderIDCache {
			delete(p.folderIDCache, k)
			break
		}
	}
	p.folderIDCache[email] = id
}
