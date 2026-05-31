package main

// This file holds the action-domain consumer handlers split out of
// consumers.go. All subscription orchestration (StartConsumers /
// StopConsumers / trackSub) remains there.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/action"
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
				// Banner tokens are consumed by recipients (the
				// end users) when they click Report Phishing /
				// Mark Safe / Trust Sender. The path
				// /v1/banner/action bypasses the platform JWT
				// middleware (see defaultAuthSkipPaths) so the
				// role is mostly informational on the wire
				// today, but stamping RoleEndUser keeps the
				// token self-describing for any future audit
				// or transitional gate.
				Role: privacy.RoleEndUser,
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
		signal := map[string]any{
			"tenant_id":      res.TenantID,
			"message_id":     res.MessageID,
			"correlation_id": res.CorrelationID,
			"tier":           res.Tier,
			"primary":        res.Primary,
			"score":          res.Score,
			"email":          res.Recipient,
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
	return nil
}
