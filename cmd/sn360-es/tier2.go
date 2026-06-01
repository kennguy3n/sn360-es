package main

import (
	"errors"
	"log/slog"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/pkg/inference/slm"
)

// buildTier2Client constructs the Tier 2 (SLM) client used by the
// evaluator. The shape is:
//
//  1. Deployment default: cfg.AI.Provider (env TIER2_PROVIDER) is
//     looked up in the slm registry and constructed via slm.New
//     with cfg.AI's URL / APIKey / Model / Timeout / MaxTokens /
//     Temperature / ProviderOpts. Default provider is
//     "ternarybonsai", which preserves the historical Tier 2 HTTP
//     client behaviour bit-for-bit (same wire format, same prompt
//     template, same JSON verdict parser).
//
//  2. Per-tenant overrides: a slm.Router wraps the default and
//     consults app.tenantScoringConfig.LoadTenantTier2Provider for
//     each request. When the tenant has tier2_provider set in
//     score_engine, the Router constructs the named provider with
//     the same deployment-default connection config (URL, APIKey,
//     timeouts, opts) and caches the resulting client for the
//     lifetime of the process. Override resolution failures fall
//     back to the deployment default — a typo in score_engine
//     never blocks Tier 2 evaluation.
//
// Returns nil when AI is not configured at all (AI_URL empty), in
// which case the evaluator skips Tier 2 escalation entirely. Any
// construction error logs at warn and degrades to nil so a
// misconfigured deployment still serves Tier 0 / Tier 1 / Rspamd
// verdicts.
func buildTier2Client(app *application, cfg *config.Config, logger *slog.Logger) evaluate.Tier2Client {
	if cfg.AI.URL == "" {
		logger.Info("sn360-es: AI_URL not configured; tier2 LLM client disabled")
		return nil
	}

	providerName := cfg.AI.Provider
	defaultProviderCfg := buildDefaultTier2ProviderConfig(cfg)
	defaultProviderCfg.Name = providerName

	defaultClient, err := slm.New(defaultProviderCfg)
	if err != nil {
		// Specifically log the "unknown provider" path with the
		// full registered set so operators can tell at a glance
		// whether they typo'd TIER2_PROVIDER vs. forgot to add a
		// new factory to pkg/inference/slm/all.
		if errors.Is(err, slm.ErrProviderNotRegistered) {
			logger.Warn("sn360-es: tier2 provider not registered; evaluator will skip LLM escalation",
				slog.String("provider", providerName),
				slog.Any("registered", slm.Registered()))
			return nil
		}
		logger.Warn("sn360-es: tier2 default client init failed; evaluator will skip LLM escalation",
			slog.String("provider", providerName),
			slog.String("url", cfg.AI.URL),
			slog.Any("error", err))
		return nil
	}

	// Router wires per-tenant overrides on top of the default. We
	// only attach a loader when app.tenantScoringConfig is wired
	// (score_engine repo is present); otherwise every tenant goes
	// through Default which is the historical behaviour.
	routerCfg := slm.RouterConfig{
		Default: defaultClient,
		Logger:  logger,
	}
	if app.tenantScoringConfig != nil {
		routerCfg.Loader = app.tenantScoringConfig
		routerCfg.ResolveConfig = func(name string) (slm.ProviderConfig, error) {
			// Per-tenant overrides reuse the deployment-default
			// connection config (URL / APIKey / timeouts /
			// ProviderOpts) and only swap the provider name —
			// the override is a "use a different SLM model on
			// the same hardware" knob, not a "talk to a
			// different endpoint" knob. Adding per-tenant URLs
			// would require its own column (and a credential
			// rotation story); not in scope for WS-4c.
			pc := buildDefaultTier2ProviderConfig(cfg)
			pc.Name = name
			return pc, nil
		}
	}
	router, err := slm.NewRouter(routerCfg)
	if err != nil {
		logger.Warn("sn360-es: tier2 router init failed; falling back to default client without per-tenant override",
			slog.Any("error", err))
		return defaultClient
	}
	// Wire adapter -> router invalidation so a write that calls
	// adapter.Invalidate (today: tuning writes via
	// postgresConfigStore.invalidate; in the future: any admin
	// endpoint that updates score_engine.tier2_provider) also clears
	// the Router's per-tenant client cache. Without this hook the
	// Router would keep returning the previously-constructed
	// override client after the underlying provider name flipped.
	// The hook is installed only when both an adapter and a Loader
	// are wired — without the Loader the Router has no per-tenant
	// cache anyway.
	if app.tenantScoringConfig != nil && routerCfg.Loader != nil {
		app.tenantScoringConfig.SetOnInvalidate(router.Invalidate)
	}
	logger.Info("sn360-es: tier2 client wired",
		slog.String("provider", providerName),
		slog.String("url", cfg.AI.URL),
		slog.Bool("per_tenant_override_enabled", routerCfg.Loader != nil))
	return router
}

// buildDefaultTier2ProviderConfig translates the deployment-wide AI
// config into the provider-agnostic slm.ProviderConfig. The Name
// field is left blank — callers fill it in for either the default
// provider or the per-tenant override at construction time.
func buildDefaultTier2ProviderConfig(cfg *config.Config) slm.ProviderConfig {
	return slm.ProviderConfig{
		URL:          cfg.AI.URL,
		APIKey:       cfg.AI.APIKey,
		Model:        cfg.AI.Model,
		Timeout:      cfg.AI.Timeout,
		MaxTokens:    cfg.AI.MaxTokens,
		Temperature:  cfg.AI.Temperature,
		ProviderOpts: cfg.AI.ProviderOpts,
	}
}

// Compile-time guard so refactors that change the
// TenantProviderLoader contract surface immediately on the cmd-
// package build instead of waiting for a runtime evaluation. The
// concrete *tenantScoringConfigAdapter must always satisfy
// slm.TenantProviderLoader.
var _ slm.TenantProviderLoader = (*tenantScoringConfigAdapter)(nil)
