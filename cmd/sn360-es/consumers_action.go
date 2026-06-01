package main

// This file holds the action-domain consumer handlers split out of
// consumers.go. All subscription orchestration (StartConsumers /
// StopConsumers / trackSub) remains there.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/bridge"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// actionLabelEnvelope is the wire format published by
// handleIngestionAction on `es.action.label`.
type actionLabelEnvelope struct {
	TenantID      string            `json:"tenant_id"`
	MessageID     string            `json:"message_id"`
	CorrelationID string            `json:"correlation_id"`
	Tier          constant.Tier     `json:"tier"`
	Primary       constant.Category `json:"primary"`
	Email         string            `json:"email"`
}

// actionBannerEnvelope is the wire format published by
// handleIngestionAction on `es.action.banner`.
type actionBannerEnvelope struct {
	TenantID      string        `json:"tenant_id"`
	MessageID     string        `json:"message_id"`
	CorrelationID string        `json:"correlation_id"`
	Tier          constant.Tier `json:"tier"`
	HTML          string        `json:"html"`
	Email         string        `json:"email"`
}

// actionURLRewriteEnvelope is the wire format published by
// handleIngestionAction on `es.action.url_rewrite`.
type actionURLRewriteEnvelope struct {
	TenantID      string        `json:"tenant_id"`
	MessageID     string        `json:"message_id"`
	CorrelationID string        `json:"correlation_id"`
	Tier          constant.Tier `json:"tier"`
	Email         string        `json:"email"`
}

// actionQuarantineEnvelope is the wire format published by
// handleIngestionAction on `es.action.quarantine`.
type actionQuarantineEnvelope struct {
	TenantID      string            `json:"tenant_id"`
	MessageID     string            `json:"message_id"`
	CorrelationID string            `json:"correlation_id"`
	Tier          constant.Tier     `json:"tier"`
	Primary       constant.Category `json:"primary"`
	Score         int               `json:"score"`
	Email         string            `json:"email"`
	// Tier2Malicious is the privacy-safe "tier-2 SLM classified
	// this as malicious" bit derived at evaluation time. It is
	// emitted by handleIngestionAction (this file, below) from
	// res.Tier2.IsMalicious() and persisted onto the
	// QuarantineRecord so the WS-3a self-release flow can refuse
	// recipient-driven release on tier-2 malicious verdicts
	// without re-evaluating. Defaults to false (omitempty) for
	// backward compatibility with envelopes minted before WS-3a.
	Tier2Malicious bool `json:"tier2_malicious,omitempty"`
}

// handleActionLabel applies the tier (and optional category) native
// label via the provider-aware LabelApplier.
func (a *application) handleActionLabel(ctx context.Context, msg events.Message) error {
	if a.labelApplier == nil || a.providers == nil {
		return nil
	}
	var env actionLabelEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.label unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.TenantID == "" || env.MessageID == "" || env.Email == "" {
		a.logger.DebugContext(ctx, "sn360-es: action.label missing identifiers",
			slog.String("tenant_id", env.TenantID),
			slog.String("message_id", env.MessageID),
			slog.Bool("has_email", env.Email != ""))
		return nil
	}
	kind := a.providers.resolveKind(env.TenantID)
	if kind == "" {
		a.logger.DebugContext(ctx, "sn360-es: action.label: no provider registered",
			slog.String("tenant_id", env.TenantID))
		return nil
	}
	res, err := a.labelApplier.Apply(ctx, action.LabelApplyRequest{
		Tenant:          env.TenantID,
		Provider:        kind,
		Email:           env.Email,
		MessageID:       env.MessageID,
		NewTier:         env.Tier,
		PrimaryCategory: env.Primary,
	})
	if err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.label: applier failed",
			slog.String("tenant_id", env.TenantID),
			slog.String("provider", string(kind)),
			slog.Any("error", err))
		return nil
	}
	a.logger.DebugContext(ctx, "sn360-es: action.label applied",
		slog.String("tenant_id", env.TenantID),
		slog.String("provider", string(kind)),
		slog.String("tier", string(env.Tier)),
		slog.Bool("category_applied", res.SubCategoryID != ""))
	return nil
}

// handleActionBanner splices the pre-rendered banner HTML into the
// recipient's mailbox.
func (a *application) handleActionBanner(ctx context.Context, msg events.Message) error {
	if a.providers == nil {
		return nil
	}
	var env actionBannerEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.banner unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.TenantID == "" || env.MessageID == "" || env.HTML == "" || env.Email == "" {
		return nil
	}
	kind := a.providers.resolveKind(env.TenantID)
	if kind == "" {
		return nil
	}
	inj := a.providers.bannerInjectorFor(env.TenantID, kind)
	if inj == nil {
		return nil
	}
	if err := inj.InjectBanner(ctx, action.BannerInjectRequest{
		Tenant:    env.TenantID,
		Provider:  kind,
		Email:     env.Email,
		MessageID: env.MessageID,
		HTML:      []byte(env.HTML),
	}); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.banner: inject failed",
			slog.String("tenant_id", env.TenantID),
			slog.String("provider", string(kind)),
			slog.Any("error", err))
		return nil
	}
	a.logger.DebugContext(ctx, "sn360-es: action.banner injected",
		slog.String("tenant_id", env.TenantID),
		slog.String("provider", string(kind)),
		slog.Int("html_bytes", len(env.HTML)))

	// Stamp banner_state for the WS-5A.6 reopen path.
	// `delivered_at` is the WS-5A.6 reopen gate; without
	// this stamp the resolver would skip the reopen even
	// after a successful injection. The message_id_hash is
	// the same raw-bytes-of-plaintext-message-id convention
	// consumers_evaluate.go uses when it writes
	// evaluation_results.message_id_hash; both call sites
	// must stay in lockstep so the resolver's lookup keys
	// agree.
	if a.repos != nil && a.repos.BannerStates != nil {
		if err := a.repos.BannerStates.MarkDelivered(ctx, repository.MarkDeliveredInput{
			TenantID:           env.TenantID,
			MessageIDHash:      []byte(env.MessageID),
			At:                 time.Now().UTC(),
			Reason:             "automated banner injection",
			Provider:           string(kind),
			DeliveredMessageID: env.MessageID,
			DeliveredEmail:     env.Email,
		}); err != nil {
			// Non-fatal: the banner was delivered, just
			// the WS-5A.6 reopen gate can't be updated.
			// Ops can still see the original banner
			// landed via the DEBUG log above.
			a.logger.WarnContext(ctx, "sn360-es: action.banner: banner_state stamp failed (non-fatal)",
				slog.String("tenant_id", env.TenantID),
				slog.Any("error", err))
		}
	}
	return nil
}

// handleActionURLRewrite rewrites URLs in the message body.
func (a *application) handleActionURLRewrite(ctx context.Context, msg events.Message) error {
	if a.urlRewriter == nil {
		return nil
	}
	var env actionURLRewriteEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.url_rewrite unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.TenantID == "" || env.MessageID == "" || env.Email == "" {
		return nil
	}
	if a.providers == nil {
		return nil
	}

	kind := a.providers.resolveKind(env.TenantID)
	if kind == "" {
		a.logger.DebugContext(ctx, "sn360-es: action.url_rewrite: no provider registered",
			slog.String("tenant_id", env.TenantID))
		return nil
	}

	bw := a.providers.bodyRewriterFor(env.TenantID, kind)
	if bw == nil {
		a.logger.DebugContext(ctx, "sn360-es: action.url_rewrite: no body rewriter for provider",
			slog.String("tenant_id", env.TenantID),
			slog.String("provider", string(kind)))
		return nil
	}

	svc := &action.URLRewriteService{
		Rewriter: a.urlRewriter,
		Logger:   a.logger,
	}
	if err := svc.RewriteBody(ctx, bw, action.BodyRewriteRequest{
		Tenant:    env.TenantID,
		Provider:  kind,
		Email:     env.Email,
		MessageID: env.MessageID,
	}, string(env.Tier)); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.url_rewrite failed",
			slog.String("tenant_id", env.TenantID),
			slog.String("provider", string(kind)),
			slog.Any("error", err))
		return nil
	}
	return nil
}

// handleActionQuarantine moves a Blocked-tier message into the
// hidden quarantine label.
func (a *application) handleActionQuarantine(ctx context.Context, msg events.Message) error {
	if a.quarantineSvc == nil || a.providers == nil {
		return nil
	}
	var env actionQuarantineEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.quarantine unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.TenantID == "" || env.MessageID == "" || env.Email == "" {
		return nil
	}
	if env.Tier != constant.TierBlocked {
		return nil
	}
	kind := a.providers.resolveKind(env.TenantID)
	if kind == "" {
		return nil
	}
	if _, err := a.quarantineSvc.Quarantine(ctx, action.QuarantineRequest{
		Tenant:               env.TenantID,
		PseudonymizedMessage: env.MessageID,
		Provider:             kind,
		Email:                env.Email,
		MessageID:            env.MessageID,
		Tier:                 env.Tier,
		Primary:              env.Primary,
		Tier2Malicious:       env.Tier2Malicious,
	}); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.quarantine: quarantine failed",
			slog.String("tenant_id", env.TenantID),
			slog.String("provider", string(kind)),
			slog.Any("error", err))
		return nil
	}
	a.logger.InfoContext(ctx, "sn360-es: action.quarantine applied",
		slog.String("tenant_id", env.TenantID),
		slog.String("provider", string(kind)),
		slog.String("primary", string(env.Primary)),
		slog.Int("score", env.Score))

	// WS-5A.1: fan the quarantine apply event out to the
	// sn360-security-platform SOC so the platform's correlation
	// engine and OpenSearch indexer see the quarantine action on
	// the same `sn360.events.email.<tid>.quarantine` subject the
	// rest of the platform consumes. The bridge no-ops when
	// PLATFORM_NATS_ENABLED=false so this call costs nothing in
	// standalone deployments.
	if a.platformBridge != nil {
		if perr := a.platformBridge.PublishQuarantine(ctx, bridge.QuarantineEvent{
			TenantID:      env.TenantID,
			MessageID:     env.MessageID,
			CorrelationID: env.CorrelationID,
			Action:        bridge.QuarantineActionApplied,
			Tier:          env.Tier,
			Primary:       env.Primary,
			Score:         env.Score,
			Recipient:     env.Email,
		}); perr != nil {
			a.logger.WarnContext(ctx, "sn360-es: action.quarantine: platform bridge publish failed",
				slog.String("tenant_id", env.TenantID),
				slog.Any("error", perr))
		}
	}
	return nil
}

// handleIngestionAction renders the banner, rewrites risky URLs, and
// triggers a quarantine reference for Blocked verdicts.
func (a *application) handleIngestionAction(ctx context.Context, msg events.Message) error {
	var res dto.EvaluateResult
	if err := json.Unmarshal(msg.Data(), &res); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: evaluate.result unmarshal failed in ingestion-action",
			slog.Any("error", err))
		return nil
	}
	if res.MessageID == "" || res.TenantID == "" {
		return nil
	}

	// 1. Banner
	if a.bannerRenderer != nil && res.Tier.Valid() && res.Tier != constant.TierTrusted {
		locale := a.cfg.Banner.DefaultLocale
		if locale == "" {
			locale = "en"
		}
		input := action.BannerInput{
			Tier:        res.Tier,
			Primary:     res.Primary,
			Secondary:   res.Secondary,
			ReasonCodes: res.ReasonCodes,
			Locale:      locale,
			Degraded:    res.Degraded,
		}
		if a.jwtIssuer != nil {
			if tok, terr := a.jwtIssuer.Issue(res.TenantID, res.MessageID, privacy.IssueOptions{
				Tier: string(res.Tier),
			}); terr == nil {
				input.ActionToken = tok
			} else {
				a.logger.WarnContext(ctx, "sn360-es: ingestion-action: issue banner token failed",
					slog.String("tenant_id", res.TenantID),
					slog.Any("error", terr))
			}
		}
		if html, rerr := a.bannerRenderer.Render(input); rerr != nil {
			a.logger.WarnContext(ctx, "sn360-es: ingestion-action: banner render failed",
				slog.String("tenant_id", res.TenantID),
				slog.String("message_id", res.MessageID),
				slog.Any("error", rerr))
		} else {
			bannerEvt := map[string]any{
				"tenant_id":      res.TenantID,
				"message_id":     res.MessageID,
				"correlation_id": res.CorrelationID,
				"tier":           res.Tier,
				"html":           string(html),
				"email":          res.Recipient,
			}
			if blob, merr := json.Marshal(bannerEvt); merr == nil {
				if perr := a.eventBus.Publish(ctx, "es.action.banner", blob,
					events.WithTenantID(res.TenantID),
					events.WithCorrelationID(res.CorrelationID),
					events.WithEventType("action.banner"),
					events.WithTraceContext(ctx),
				); perr != nil {
					a.logger.WarnContext(ctx, "sn360-es: ingestion-action: publish banner failed",
						slog.Any("error", perr))
				}
			}
		}
	}

	// 2. URL rewriting
	if a.urlRewriter != nil && (res.Tier == constant.TierBlocked || res.Tier == constant.TierHighRisk) {
		signal := map[string]any{
			"tenant_id":      res.TenantID,
			"message_id":     res.MessageID,
			"correlation_id": res.CorrelationID,
			"tier":           res.Tier,
			"email":          res.Recipient,
		}
		if blob, merr := json.Marshal(signal); merr == nil {
			if perr := a.eventBus.Publish(ctx, "es.action.url_rewrite", blob,
				events.WithTenantID(res.TenantID),
				events.WithCorrelationID(res.CorrelationID),
				events.WithEventType("action.url_rewrite"),
				events.WithTraceContext(ctx),
			); perr != nil {
				a.logger.WarnContext(ctx, "sn360-es: ingestion-action: publish url_rewrite signal failed",
					slog.Any("error", perr))
			}
		}
	}

	// 3. Quarantine
	if res.Tier == constant.TierBlocked {
		// Capture the privacy-safe "tier-2 said malicious" bit
		// at publish time so the downstream quarantine consumer
		// can persist it onto the QuarantineRecord without
		// re-deriving from the full Tier2Outcome (which is not
		// included on the wire envelope to keep the bus payload
		// PII-minimal). When Tier 2 did not run (Tier2 == nil)
		// the bit is false; the WS-3a self-release service
		// treats a false bit on a legacy record as "unknown
		// malicious" — it does not block on absence, so this
		// degrades correctly when Tier 2 is degraded/unavailable.
		tier2Malicious := res.Tier2 != nil && res.Tier2.IsMalicious()
		signal := map[string]any{
			"tenant_id":       res.TenantID,
			"message_id":      res.MessageID,
			"correlation_id":  res.CorrelationID,
			"tier":            res.Tier,
			"primary":         res.Primary,
			"score":           res.Score,
			"email":           res.Recipient,
			"tier2_malicious": tier2Malicious,
		}
		if blob, merr := json.Marshal(signal); merr == nil {
			if perr := a.eventBus.Publish(ctx, "es.action.quarantine", blob,
				events.WithTenantID(res.TenantID),
				events.WithCorrelationID(res.CorrelationID),
				events.WithEventType("action.quarantine"),
				events.WithTraceContext(ctx),
			); perr != nil {
				a.logger.WarnContext(ctx, "sn360-es: ingestion-action: publish quarantine signal failed",
					slog.Any("error", perr))
			}
		}
	}

	// 4. Native label
	if res.Tier.Valid() && res.Tier != constant.TierTrusted {
		signal := map[string]any{
			"tenant_id":      res.TenantID,
			"message_id":     res.MessageID,
			"correlation_id": res.CorrelationID,
			"tier":           res.Tier,
			"primary":        res.Primary,
			"email":          res.Recipient,
		}
		if blob, merr := json.Marshal(signal); merr == nil {
			if perr := a.eventBus.Publish(ctx, "es.action.label", blob,
				events.WithTenantID(res.TenantID),
				events.WithCorrelationID(res.CorrelationID),
				events.WithEventType("action.label"),
				events.WithTraceContext(ctx),
			); perr != nil {
				a.logger.WarnContext(ctx, "sn360-es: ingestion-action: publish label signal failed",
					slog.Any("error", perr))
			}
		}
	}

	// 5. WS-5A.1 — fan terminal verdicts out to the
	// sn360-security-platform SOC after the local action signals
	// have been published. The bridge gates itself on tier
	// (Blocked / HighRisk only) and no-ops when
	// PLATFORM_NATS_ENABLED=false so this call costs nothing in
	// standalone deployments.
	if a.platformBridge != nil {
		if perr := a.platformBridge.PublishEvaluation(ctx, &res); perr != nil {
			a.logger.WarnContext(ctx, "sn360-es: ingestion-action: platform bridge publish failed",
				slog.String("tenant_id", res.TenantID),
				slog.String("tier", string(res.Tier)),
				slog.Any("error", perr))
		}
	}

	return nil
}

// quarantineReleaseEnvelope is the wire format for the release flow.
type quarantineReleaseEnvelope struct {
	TenantID             string `json:"tenant_id"`
	PseudonymizedMessage string `json:"pseudonymized_message_id"`
	RequestedBy          string `json:"requested_by,omitempty"`
	RestoredBody         string `json:"restored_body,omitempty"`
	CorrelationID        string `json:"correlation_id,omitempty"`
}

// handleQuarantineRelease calls ReleaseService.Release.
func (a *application) handleQuarantineRelease(ctx context.Context, msg events.Message) error {
	if a.releaseSvc == nil {
		return nil
	}
	var env quarantineReleaseEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: quarantine.release unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.TenantID == "" || env.PseudonymizedMessage == "" {
		return nil
	}
	if _, err := a.releaseSvc.Release(ctx, action.ReleaseRequest{
		TenantID:             env.TenantID,
		PseudonymizedMessage: env.PseudonymizedMessage,
		RequestedBy:          env.RequestedBy,
		RestoredBody:         env.RestoredBody,
		CorrelationID:        env.CorrelationID,
	}); err != nil {
		return fmt.Errorf("quarantine.release: %w", err)
	}

	// WS-5A.1: close the bi-directional quarantine lifecycle loop
	// to the platform SOC. The platform's correlation engine and
	// OpenSearch indexer pair this release event (via MessageID)
	// with the original `.quarantine.applied` event so the SOC UI
	// can show the full lifecycle (apply -> release) without
	// re-querying sn360-es. Tier / Primary / Score are not on the
	// release envelope by design — the platform joins on MessageID
	// to retrieve the original verdict metadata. Bridge no-ops
	// when PLATFORM_NATS_ENABLED=false so this call costs nothing
	// in standalone deployments.
	if a.platformBridge != nil {
		if perr := a.platformBridge.PublishQuarantine(ctx, bridge.QuarantineEvent{
			TenantID:      env.TenantID,
			MessageID:     env.PseudonymizedMessage,
			CorrelationID: env.CorrelationID,
			Action:        bridge.QuarantineActionReleased,
			RequestedBy:   env.RequestedBy,
		}); perr != nil {
			a.logger.WarnContext(ctx, "sn360-es: quarantine.release: platform bridge publish failed",
				slog.String("tenant_id", env.TenantID),
				slog.Any("error", perr))
		}
	}
	return nil
}
