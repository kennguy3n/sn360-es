package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/gmail"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/outlook"
)

// providerKey uniquely identifies a per-tenant provider client. The
// kind discriminator keeps tenants that have both Gmail and Outlook
// configured (e.g. while migrating) from colliding on the tenant ID
// alone.
type providerKey struct {
	tenant string
	kind   action.LabelProviderKind
}

// providerEntry bundles every per-tenant provider client we need to
// service `es.action.*` events. We keep them grouped because the
// label applier, banner injector, URL writer and quarantine mover all
// need to share a token source — separating them out would force
// each consumer to maintain its own copy of the OAuth state.
type providerEntry struct {
	kind               action.LabelProviderKind
	labelProvider      action.LabelProvider
	quarantineProvider action.QuarantineProvider
	gmailBanner        *gmail.BannerInjector   // nil for Outlook
	outlookBanner      *outlook.BannerInjector // nil for Gmail
}

// providerRegistry holds the per-tenant provider clients used by the
// action consumers. It is populated at boot from configuration; in
// future PRs it will also be mutated at runtime by the onboarding
// agent. All accessors are safe for concurrent use.
//
// Today the binary supports a single GWS tenant and a single O365
// tenant; the registry key is the tenant_id from configuration. When
// either set of credentials is absent the corresponding entry stays
// nil and consumers degrade to a logging mode.
type providerRegistry struct {
	mu      sync.RWMutex
	entries map[providerKey]*providerEntry

	// fallbackInjector receives banner-inject requests when no
	// real provider matches; it logs and records so dev mode + the
	// degraded-binary case still produce visible output.
	fallbackInjector action.BannerInjector
}

func newProviderRegistry(logger *slog.Logger) *providerRegistry {
	return &providerRegistry{
		entries:          make(map[providerKey]*providerEntry),
		fallbackInjector: action.NewLoggingBannerInjector(logger),
	}
}

// register attaches an entry to the registry for the given tenant +
// kind. Subsequent calls overwrite the previous entry, which mirrors
// the eventual "onboarding overwrite" path.
func (r *providerRegistry) register(tenant string, e *providerEntry) {
	if e == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[providerKey{tenant: tenant, kind: e.kind}] = e
}

// labelProviders flattens the registered providers into the slice the
// action.LabelApplier expects. Empty when no providers are registered.
func (r *providerRegistry) labelProviders() []action.LabelProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]action.LabelProvider, 0, len(r.entries))
	for _, e := range r.entries {
		if e.labelProvider != nil {
			out = append(out, e.labelProvider)
		}
	}
	return out
}

// quarantineProviders returns the QuarantineProvider implementations
// registered in the registry. Used by main.go to wire the
// provider-aware action.QuarantineService.
func (r *providerRegistry) quarantineProviders() []action.QuarantineProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]action.QuarantineProvider, 0, len(r.entries))
	for _, e := range r.entries {
		if e.quarantineProvider != nil {
			out = append(out, e.quarantineProvider)
		}
	}
	return out
}

// bannerInjectorFor returns the banner injector matching the
// (tenant, kind) tuple. When no real injector is configured the
// fallback (logging) injector is returned so consumers can call
// InjectBanner unconditionally.
func (r *providerRegistry) bannerInjectorFor(tenant string, kind action.LabelProviderKind) action.BannerInjector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.entries[providerKey{tenant: tenant, kind: kind}]; ok {
		switch kind {
		case action.LabelProviderGmail:
			if e.gmailBanner != nil {
				return e.gmailBanner
			}
		case action.LabelProviderOutlook:
			if e.outlookBanner != nil {
				return e.outlookBanner
			}
		}
	}
	return r.fallbackInjector
}

// resolveKind picks the provider kind for a tenant when the consumer
// only knows the tenant ID. Prefers Gmail when both kinds are
// registered (matches the historical default in nges-ingestion-svc).
func (r *providerRegistry) resolveKind(tenant string) action.LabelProviderKind {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.entries[providerKey{tenant: tenant, kind: action.LabelProviderGmail}]; ok {
		return action.LabelProviderGmail
	}
	if _, ok := r.entries[providerKey{tenant: tenant, kind: action.LabelProviderOutlook}]; ok {
		return action.LabelProviderOutlook
	}
	return ""
}

// hasAny reports whether the registry contains any tenant. Used by
// readiness probes and the consumer wiring to decide whether to
// activate provider-bound paths.
func (r *providerRegistry) hasAny() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries) > 0
}

// lookup returns the entry registered for the given tenant. Prefers
// Gmail when both kinds are registered (mirrors resolveKind). Returns
// nil when no entry matches — callers should treat this as a
// best-effort skip.
func (r *providerRegistry) lookup(tenant string) *providerEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.entries[providerKey{tenant: tenant, kind: action.LabelProviderGmail}]; ok {
		return e
	}
	if e, ok := r.entries[providerKey{tenant: tenant, kind: action.LabelProviderOutlook}]; ok {
		return e
	}
	return nil
}

// snapshot returns a copy of the registry contents for observability.
// Keys are flattened into "tenant:kind" strings so the result is
// trivially loggable.
func (r *providerRegistry) snapshot() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for k := range r.entries {
		out = append(out, k.tenant+":"+string(k.kind))
	}
	return out
}

// buildProviderRegistry inspects the configured credentials and
// constructs the registry. Returns an empty (but non-nil) registry
// when neither provider is configured so callers can use it
// unconditionally.
//
// The tenant binding is taken from cfg.Banner.DefaultTenant — the
// same value the rest of the binary uses as the "single-tenant" key
// when not running in multi-tenant mode. In a future iteration this
// will be supplanted by the onboarding pipeline registering tenants
// dynamically.
func buildProviderRegistry(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*providerRegistry, error) {
	reg := newProviderRegistry(logger)
	tenant := defaultProviderTenant(cfg)

	if cfg.GWS.HasGmail() {
		entry, err := buildGmailEntry(ctx, cfg, logger)
		if err != nil {
			logger.Warn("sn360-es: gmail provider init failed", slog.Any("error", err))
		} else {
			reg.register(tenant, entry)
			logger.Info("sn360-es: gmail provider registered",
				slog.String("tenant", tenant),
				slog.String("delegated_admin", cfg.GWS.DelegatedAdmin))
		}
	}

	if cfg.O365.HasOutlook() {
		entry, err := buildOutlookEntry(ctx, cfg, logger)
		if err != nil {
			logger.Warn("sn360-es: outlook provider init failed", slog.Any("error", err))
		} else {
			reg.register(tenant, entry)
			logger.Info("sn360-es: outlook provider registered",
				slog.String("tenant", tenant),
				slog.String("ms_tenant", cfg.O365.TenantID))
		}
	}

	if !reg.hasAny() {
		logger.Info("sn360-es: no email providers configured; action consumers will run in degraded mode")
	}
	return reg, nil
}

// defaultProviderTenant returns the tenant ID to bind provider
// credentials to at boot. The single-tenant deployments key by the
// configured GWS domain (when Gmail is wired) or the O365 tenant ID
// (when Outlook is wired); when neither is present we fall back to
// "default" so the registry has *some* key. Multi-tenant deployments
// will plug a real tenant resolver in via the onboarding agent in a
// later PR.
func defaultProviderTenant(cfg *config.Config) string {
	if d := strings.TrimSpace(cfg.GWS.Domain); d != "" {
		return d
	}
	if t := strings.TrimSpace(cfg.O365.TenantID); t != "" {
		return t
	}
	return "default"
}

// buildGmailEntry constructs the Gmail label provider + banner
// injector against the configured service-account JSON. The same
// token source backs both clients so we only need one OAuth round
// trip per refresh window.
func buildGmailEntry(_ context.Context, cfg *config.Config, logger *slog.Logger) (*providerEntry, error) {
	sa, err := gmail.LoadServiceAccount(cfg.GWS.ServiceAccountJSON)
	if err != nil {
		return nil, fmt.Errorf("load service account: %w", err)
	}
	tokens, err := gmail.NewJWTBearerSource(gmail.JWTBearerConfig{
		ServiceAccount:   sa,
		ImpersonatedUser: cfg.GWS.DelegatedAdmin,
	})
	if err != nil {
		return nil, fmt.Errorf("token source: %w", err)
	}
	label, err := gmail.New(gmail.Config{
		BaseURL:     cfg.GWS.BaseURL,
		TokenSource: tokens,
	})
	if err != nil {
		return nil, fmt.Errorf("label provider: %w", err)
	}
	banner, err := gmail.NewBannerInjector(gmail.BannerInjectorConfig{
		BaseURL:     cfg.GWS.BaseURL,
		TokenSource: tokens,
	})
	if err != nil {
		return nil, fmt.Errorf("banner injector: %w", err)
	}
	quarantine, err := gmail.NewQuarantineProvider(gmail.QuarantineProviderConfig{Labels: label})
	if err != nil {
		return nil, fmt.Errorf("quarantine provider: %w", err)
	}
	if logger != nil {
		logger.Debug("sn360-es: gmail provider wired",
			slog.String("base_url", cfg.GWS.BaseURL))
	}
	return &providerEntry{
		kind:               action.LabelProviderGmail,
		labelProvider:      label,
		quarantineProvider: quarantine,
		gmailBanner:        banner,
	}, nil
}

// buildOutlookEntry constructs the Outlook label provider + banner
// injector via the client-credentials OAuth flow. Same shared token
// source for the same reason as Gmail.
func buildOutlookEntry(_ context.Context, cfg *config.Config, logger *slog.Logger) (*providerEntry, error) {
	tokens, err := outlook.NewClientCredentialsSource(outlook.ClientCredentialsConfig{
		TenantID:     cfg.O365.TenantID,
		ClientID:     cfg.O365.ClientID,
		ClientSecret: cfg.O365.ClientSecret,
		TokenURL:     cfg.O365.TokenURL,
	})
	if err != nil {
		return nil, fmt.Errorf("token source: %w", err)
	}
	label, err := outlook.New(outlook.Config{
		BaseURL:     cfg.O365.BaseURL,
		TokenSource: tokens,
	})
	if err != nil {
		return nil, fmt.Errorf("label provider: %w", err)
	}
	banner, err := outlook.NewBannerInjector(outlook.BannerInjectorConfig{
		BaseURL:     cfg.O365.BaseURL,
		TokenSource: tokens,
	})
	if err != nil {
		return nil, fmt.Errorf("banner injector: %w", err)
	}
	quarantine, err := outlook.NewQuarantineProvider(outlook.QuarantineProviderConfig{Labels: label})
	if err != nil {
		return nil, fmt.Errorf("quarantine provider: %w", err)
	}
	if logger != nil {
		logger.Debug("sn360-es: outlook provider wired",
			slog.String("base_url", cfg.O365.BaseURL))
	}
	return &providerEntry{
		kind:               action.LabelProviderOutlook,
		labelProvider:      label,
		quarantineProvider: quarantine,
		outlookBanner:      banner,
	}, nil
}

// ErrNoProvider is returned by the consumer helpers when no provider
// is registered for the (tenant, kind) tuple. Consumers treat it as a
// best-effort skip rather than a hard failure.
var ErrNoProvider = errors.New("provider registry: no entry for tenant")
