// Copyright 2024-2026 SN360. All rights reserved.
// Use of this source code is governed by the proprietary license
// that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/escalation"
)

// bannerReopener is the cmd-side implementation of
// escalation.BannerReopener.
//
// It looks up the provider-side delivery context recorded by
// handleActionBanner (provider, delivered_message_id,
// delivered_email), composes a re-injection request with the
// "Updated by SOC analyst" reason, drives the same
// providerRegistry the original injection used, and stamps
// banner_state.reopened_at on success.
//
// The reopener is intentionally narrow: it does NOT re-render
// the full banner via the BannerRenderer, because the renderer's
// input (tier, primary, secondary, sender auth chip) is not
// recoverable from the producer-side IncidentResolved payload.
// Instead, it emits a self-contained "updated reason" notice
// HTML fragment that the provider's InjectBanner overlays the
// same way it overlays the automated banner. The HTML mirrors
// the renderer's accessibility conventions (role=alert,
// aria-live=polite, lang attr).
type bannerReopener struct {
	logger    *slog.Logger
	banners   repository.BannerStateRepository
	providers *providerRegistry
}

// newBannerReopener constructs the reopener. providers may be
// nil — the reopener degrades to a "log + skip" path so unit
// tests that don't wire the provider registry can still
// exercise the resolver. banners is required because the
// reopen invariant lives there.
func newBannerReopener(logger *slog.Logger, banners repository.BannerStateRepository, providers *providerRegistry) (*bannerReopener, error) {
	if banners == nil {
		return nil, errors.New("banner_reopener: banner_state repository required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &bannerReopener{
		logger:    logger,
		banners:   banners,
		providers: providers,
	}, nil
}

// ReopenBanner implements escalation.BannerReopener.
//
// reopenMessageID is the producer-stamped pseudonymised id
// (the same value the resolver derives from the IncidentResolved
// EmailLink). The reopener looks up the stored banner_state row
// to recover the plaintext provider message-id + recipient
// mailbox; if neither is present the reopen is a no-op
// (because there's no way to target the provider call without
// them). The pseudo IS NOT used as the provider-side MessageID
// because providers don't accept opaque pseudonyms.
func (b *bannerReopener) ReopenBanner(ctx context.Context, tenantID, reopenMessageID, reason string) error {
	if tenantID == "" {
		return errors.New("banner_reopener: tenant_id required")
	}
	if reopenMessageID == "" {
		return errors.New("banner_reopener: message_id required")
	}
	if reason == "" {
		return errors.New("banner_reopener: reason required")
	}
	// Look up the original delivery context.
	bs, err := b.banners.Get(ctx, tenantID, []byte(reopenMessageID))
	if err != nil {
		// If we can't read the state, we can't reopen
		// safely. Resolver upstream guards against
		// ErrNotFound before calling us, but surface
		// other errors so JetStream retries.
		return fmt.Errorf("banner_reopener: load banner_state: %w", err)
	}
	if bs.DeliveredAt == nil {
		// Defence-in-depth: the resolver already gates on
		// this. A row with delivered_at == NULL means the
		// banner was attempted but never delivered to the
		// recipient — silently skip the reopen.
		b.logger.DebugContext(ctx, "banner_reopener: skip — delivered_at nil",
			slog.String("tenant_id", tenantID))
		return nil
	}
	providerKind := action.LabelProviderKind(bs.Provider)
	deliveredMessageID := bs.DeliveredMessageID
	deliveredEmail := bs.DeliveredEmail
	if providerKind == "" || deliveredMessageID == "" || deliveredEmail == "" {
		// Legacy row from before MarkDelivered started
		// stamping the provider / message_id / email
		// columns. Without the recipient and provider
		// handle, there's no way to push the update;
		// stamp the reopen audit metadata and return.
		b.logger.WarnContext(ctx, "banner_reopener: legacy banner_state row — provider context missing",
			slog.String("tenant_id", tenantID),
			slog.String("provider", bs.Provider),
			slog.Bool("has_delivered_message_id", deliveredMessageID != ""),
			slog.Bool("has_delivered_email", deliveredEmail != ""))
		if err := b.banners.MarkReopened(ctx, tenantID, []byte(reopenMessageID), time.Now().UTC(), reason); err != nil {
			return fmt.Errorf("banner_reopener: MarkReopened (legacy path): %w", err)
		}
		return nil
	}
	if b.providers == nil {
		// No real injector registry wired (unit tests).
		// Still stamp banner_state.reopened_at so the
		// audit trail records the reopen attempt.
		b.logger.DebugContext(ctx, "banner_reopener: no provider registry — recording reopen only",
			slog.String("tenant_id", tenantID))
		return b.banners.MarkReopened(ctx, tenantID, []byte(reopenMessageID), time.Now().UTC(), reason)
	}
	inj := b.providers.bannerInjectorFor(tenantID, providerKind)
	if inj == nil {
		return fmt.Errorf("banner_reopener: no injector for tenant=%s provider=%q", tenantID, providerKind)
	}
	htmlBytes := renderReopenBanner(reason)
	if err := inj.InjectBanner(ctx, action.BannerInjectRequest{
		Tenant:    tenantID,
		Provider:  providerKind,
		Email:     deliveredEmail,
		MessageID: deliveredMessageID,
		HTML:      htmlBytes,
	}); err != nil {
		return fmt.Errorf("banner_reopener: InjectBanner: %w", err)
	}
	return b.banners.MarkReopened(ctx, tenantID, []byte(reopenMessageID), time.Now().UTC(), reason)
}

// renderReopenBanner produces the HTML fragment shown to the
// recipient when the resolver flips a verdict to malicious.
// The fragment is intentionally self-contained: no external
// CSS, no JS, no remote images. The styling mirrors the
// BannerRenderer's blocked-tier palette so the visual cue
// matches the user's mental model of "this is now considered
// dangerous".
//
// The reason is HTML-escaped because it may contain analyst
// notes (free-form text typed by a human). The escape is
// applied via html.EscapeString — the same primitive the
// renderer uses for its templated strings.
func renderReopenBanner(reason string) []byte {
	safe := html.EscapeString(strings.TrimSpace(reason))
	// Inline styling mirrors banner_renderer.go's blocked
	// tier palette (deep-red background, white text). The
	// .sn360-reopen-banner class name is unique to this
	// path so deployment surfaces (e.g. mailbox CSS
	// linters) can suppress / instrument it independently.
	const tpl = `<div class="sn360-reopen-banner" role="alert" aria-live="polite" ` +
		`style="background:#8b0000;color:#fff;padding:12px 16px;` +
		`font-family:Arial,Helvetica,sans-serif;font-size:14px;` +
		`border-left:4px solid #5b0000;margin:0 0 12px 0;">` +
		`<strong>SN360 — Updated by SOC analyst</strong><br>%s</div>`
	return []byte(fmt.Sprintf(tpl, safe))
}

// compile-time assertion that bannerReopener satisfies
// escalation.BannerReopener. Catches signature drift between
// the consumer adapter and the resolver-side contract at
// build time.
var _ escalation.BannerReopener = (*bannerReopener)(nil)
