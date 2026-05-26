// Package action contains the post-evaluation actions that SN360-ES
// applies to a message: rendering banners, applying provider labels,
// rewriting URLs, and posting one-click feedback actions back to the
// pipeline. This file implements the tier-aware label applier.
package action

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// LabelProviderKind identifies the upstream mail provider. The label
// applier branches on this value so each provider can use its native
// label / category model.
type LabelProviderKind string

const (
	LabelProviderGmail    LabelProviderKind = "gmail"
	LabelProviderOutlook  LabelProviderKind = "outlook"
	LabelProviderZoho     LabelProviderKind = "zoho"
	LabelProviderFastmail LabelProviderKind = "fastmail"
	LabelProviderWorkmail LabelProviderKind = "workmail"
)

// LabelCache is the minimal contract the label applier needs from
// Redis: idempotent storage of provider-side label / category IDs so
// repeated runs do not re-create the same label.
type LabelCache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
}

// LabelProvider is the per-provider integration the applier delegates
// to. Implementations live in `pkg/email_provider/*` (gws / o365) and
// translate the abstract requests into Gmail labels.create or Outlook
// outlookCategories.add calls.
type LabelProvider interface {
	// Kind reports which provider this implementation targets.
	Kind() LabelProviderKind
	// EnsureLabel creates the label/category in the user's mailbox if
	// it does not already exist and returns its provider-side ID. It
	// MUST be idempotent.
	EnsureLabel(ctx context.Context, email, name string, color LabelColor) (id string, err error)
	// ApplyLabel attaches labelID to the message identified by
	// messageID in the user's mailbox.
	ApplyLabel(ctx context.Context, email, messageID, labelID string) error
	// RemoveLabel detaches labelID from messageID.
	RemoveLabel(ctx context.Context, email, messageID, labelID string) error
}

// LabelApplyRequest is the input to LabelApplier.Apply.
type LabelApplyRequest struct {
	Tenant          string
	Provider        LabelProviderKind
	Email           string
	MessageID       string
	NewTier         constant.Tier
	PreviousTier    constant.Tier // empty / Trusted when not transitioning
	PrimaryCategory constant.Category
}

// LabelApplyResult records what the applier actually did. It is
// returned to the caller for audit logging and metrics.
type LabelApplyResult struct {
	AppliedLabelID  string
	AppliedLabel    string
	RemovedLabelIDs []string
	SubCategoryID   string
}

// LabelApplier applies tier and category labels to messages in their
// native provider. Construction is per-process; per-tenant state lives
// in the LabelCache.
type LabelApplier struct {
	logger    *slog.Logger
	providers map[LabelProviderKind]LabelProvider
	cache     LabelCache
	// ensureMu serialises concurrent ensure-label calls for the same
	// cache key so we don't make duplicate provider calls under
	// load (e.g. a fan-out of 50 evaluations for the same tenant /
	// mailbox).
	ensureMu sync.Mutex
}

// NewLabelApplier wires up the applier. providers must contain entries
// for every LabelProviderKind the caller intends to use; missing
// entries cause Apply to return an error.
func NewLabelApplier(logger *slog.Logger, cache LabelCache, providers ...LabelProvider) *LabelApplier {
	if logger == nil {
		logger = slog.Default()
	}
	m := make(map[LabelProviderKind]LabelProvider, len(providers))
	for _, p := range providers {
		if p == nil {
			continue
		}
		m[p.Kind()] = p
	}
	return &LabelApplier{logger: logger, providers: m, cache: cache}
}

// Apply ensures the tier label exists in the user's mailbox, attaches
// it to the message, and removes any other SN360 tier labels that
// were previously applied. When primaryCategory triggers a tier sub-
// label (e.g. "SN360 / Warning / Lookalike"), that label is created
// and applied as well.
func (a *LabelApplier) Apply(ctx context.Context, req LabelApplyRequest) (LabelApplyResult, error) {
	res := LabelApplyResult{}
	if req.Tenant == "" || req.Email == "" || req.MessageID == "" {
		return res, errors.New("label_applier: tenant, email and message_id are required")
	}
	if !req.NewTier.Valid() {
		return res, fmt.Errorf("label_applier: invalid tier %q", req.NewTier)
	}
	prov, ok := a.providers[req.Provider]
	if !ok {
		return res, fmt.Errorf("label_applier: no provider registered for %q", req.Provider)
	}

	// 1. Ensure the new tier label exists.
	tierLabel := req.NewTier.LabelName()
	tierID, err := a.ensureLabel(ctx, prov, req, tierLabel, ColorFor(req.NewTier))
	if err != nil {
		return res, fmt.Errorf("ensure tier label: %w", err)
	}
	res.AppliedLabelID = tierID
	res.AppliedLabel = tierLabel

	// 2. Apply the new tier label to the message.
	if err := prov.ApplyLabel(ctx, req.Email, req.MessageID, tierID); err != nil {
		return res, fmt.Errorf("apply tier label: %w", err)
	}

	// 3. Remove any previous tier label that no longer applies. The
	// applier is monotonic per message: only one tier label may be
	// attached at any time.
	for _, other := range constant.AllTiers {
		if other == req.NewTier {
			continue
		}
		key := cacheKey(req.Provider, req.Tenant, req.Email, other)
		id, err := a.cache.Get(ctx, key)
		if err != nil || id == "" {
			continue
		}
		if err := prov.RemoveLabel(ctx, req.Email, req.MessageID, id); err != nil {
			// Best-effort: log and continue. A stale label is a UX
			// issue, not a correctness issue.
			a.logger.WarnContext(ctx, "label_applier: remove previous tier label",
				slog.String("tenant", req.Tenant),
				slog.String("tier", string(other)),
				slog.Any("error", err))
			continue
		}
		res.RemovedLabelIDs = append(res.RemovedLabelIDs, id)
	}

	// 4. Apply an optional category sub-label, lazily created.
	if req.PrimaryCategory != "" && req.PrimaryCategory.Valid() && !req.PrimaryCategory.IsBenign() {
		subName := tierLabel + " / " + categoryShortName(req.PrimaryCategory)
		subID, err := a.ensureLabel(ctx, prov, req, subName, ColorFor(req.NewTier))
		if err != nil {
			// Sub-labels are best-effort; do not fail the whole
			// apply if one cannot be created.
			a.logger.WarnContext(ctx, "label_applier: ensure sub-label",
				slog.String("sub", subName),
				slog.Any("error", err))
		} else {
			if err := prov.ApplyLabel(ctx, req.Email, req.MessageID, subID); err != nil {
				a.logger.WarnContext(ctx, "label_applier: apply sub-label",
					slog.String("sub", subName),
					slog.Any("error", err))
			} else {
				res.SubCategoryID = subID
			}
		}
	}
	return res, nil
}

// ensureLabel returns the provider-side ID for the named label,
// creating it (via prov.EnsureLabel) and caching the ID if necessary.
// It is safe to call concurrently for the same key.
func (a *LabelApplier) ensureLabel(ctx context.Context, prov LabelProvider, req LabelApplyRequest, name string, color LabelColor) (string, error) {
	key := cacheKeyNamed(req.Provider, req.Tenant, req.Email, name)
	if id, err := a.cache.Get(ctx, key); err == nil && id != "" {
		return id, nil
	}
	a.ensureMu.Lock()
	defer a.ensureMu.Unlock()
	// Double-check inside the lock: another goroutine may have
	// raced ahead while we were waiting.
	if id, err := a.cache.Get(ctx, key); err == nil && id != "" {
		return id, nil
	}
	id, err := prov.EnsureLabel(ctx, req.Email, name, color)
	if err != nil {
		return "", err
	}
	if err := a.cache.Set(ctx, key, id, 30*24*time.Hour); err != nil {
		// Cache miss is recoverable; log and continue.
		a.logger.WarnContext(ctx, "label_applier: cache set",
			slog.String("key", key),
			slog.Any("error", err))
	}
	return id, nil
}

// cacheKey returns the Redis key for a tier label ID.
//
// Format: `{provider}:{tenant}:{email}:label:{tier}`. The format
// mirrors ARCHITECTURE.md Section 8.4.
func cacheKey(p LabelProviderKind, tenant, email string, tier constant.Tier) string {
	return fmt.Sprintf("%s:%s:%s:label:%s", p, tenant, email, tier)
}

func cacheKeyNamed(p LabelProviderKind, tenant, email, name string) string {
	return fmt.Sprintf("%s:%s:%s:labelname:%s", p, tenant, email, name)
}

// categoryShortName trims the SN360-internal category code into a
// user-friendly suffix. e.g. CategoryLookalikeDomain → "Lookalike".
func categoryShortName(c constant.Category) string {
	s := string(c)
	// Strip common prefix groups to keep the sub-label short.
	for _, p := range []string{"LIKELY_", "SUSPICIOUS_", "FIRST_CONTACT_", "BEC_"} {
		s = strings.TrimPrefix(s, p)
	}
	// Title-case each underscore-separated word.
	parts := strings.Split(strings.ToLower(s), "_")
	for i, w := range parts {
		if w == "" {
			continue
		}
		parts[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(parts, " ")
}
