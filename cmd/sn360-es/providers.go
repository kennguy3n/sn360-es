package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/onboarding"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/fastmail"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/gmail"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/outlook"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/workmail"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/zoho"
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
	// bannerInjector is the per-provider BannerInjector implementation.
	// Stored as the generic action.BannerInjector interface so the
	// registry doesn't need a typed field per provider.
	bannerInjector action.BannerInjector
	bodyRewriter   action.BodyRewriter // nil when no rewriter configured
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
	if e, ok := r.entries[providerKey{tenant: tenant, kind: kind}]; ok && e.bannerInjector != nil {
		return e.bannerInjector
	}
	return r.fallbackInjector
}

// bodyRewriterFor returns the BodyRewriter matching the (tenant, kind)
// tuple. Returns nil when no rewriter is configured.
func (r *providerRegistry) bodyRewriterFor(tenant string, kind action.LabelProviderKind) action.BodyRewriter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.entries[providerKey{tenant: tenant, kind: kind}]; ok && e.bodyRewriter != nil {
		return e.bodyRewriter
	}
	return nil
}

// resolveKind picks the provider kind for a tenant when the consumer
// only knows the tenant ID. Prefers Gmail when both kinds are
// registered (matches the historical default in nges-ingestion-svc).
func (r *providerRegistry) resolveKind(tenant string) action.LabelProviderKind {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, k := range []action.LabelProviderKind{
		action.LabelProviderGmail,
		action.LabelProviderOutlook,
		action.LabelProviderZoho,
		action.LabelProviderFastmail,
		action.LabelProviderWorkmail,
	} {
		if _, ok := r.entries[providerKey{tenant: tenant, kind: k}]; ok {
			return k
		}
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
	for _, k := range []action.LabelProviderKind{
		action.LabelProviderGmail,
		action.LabelProviderOutlook,
		action.LabelProviderZoho,
		action.LabelProviderFastmail,
		action.LabelProviderWorkmail,
	} {
		if e, ok := r.entries[providerKey{tenant: tenant, kind: k}]; ok {
			return e
		}
	}
	return nil
}

// buildProviderRegistry inspects the configured credentials and
// constructs the registry. Returns an empty (but non-nil) registry
// when neither provider is configured so callers can use it
// unconditionally.
//
// Each provider entry is keyed under the tenant identifier that the
// matching MailboxProvider will emit on every polled message:
// `cfg.GWS.Domain` for Gmail, `cfg.O365.TenantID` for Outlook. This
// matters when both stacks are configured simultaneously — using a
// single "default" key for both would cause the action consumers'
// `resolveKind(env.TenantID)` lookup to miss for whichever provider
// was registered second.
//
// The HasGmail / HasOutlook predicates already require Domain /
// TenantID respectively, so by the time we reach the registration
// step the tenant key is guaranteed to be the same value the matching
// MailboxProvider will publish. Without that invariant the registry
// could register an entry under "default" that no flow ever reaches.
// See config.GWS.HasGmail for the supporting predicate.
//
// Per-entry construction failures are recoverable: we log a warning
// and leave that entry unregistered so the binary still boots with
// the other provider (or empty registry → logging-only consumers).
// The function therefore intentionally returns no error — there is
// no aggregate failure mode that should fail the whole boot. An
// earlier signature returned (reg, error) with a dead caller branch;
// dropped to match the actual behaviour and avoid the misleading
// "may fail" reading at the call site.
func buildProviderRegistry(ctx context.Context, cfg *config.Config, logger *slog.Logger) *providerRegistry {
	reg := newProviderRegistry(logger)

	if cfg.GWS.HasGmail() {
		tenant := gmailProviderTenant(cfg)
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
		tenant := outlookProviderTenant(cfg)
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

	if cfg.Zoho.HasZoho() {
		tenant := zohoProviderTenant(cfg)
		entry, err := buildZohoEntry(ctx, cfg, logger)
		if err != nil {
			logger.Warn("sn360-es: zoho provider init failed", slog.Any("error", err))
		} else {
			reg.register(tenant, entry)
			logger.Info("sn360-es: zoho provider registered",
				slog.String("tenant", tenant),
				slog.String("data_center", cfg.Zoho.DataCenter))
		}
	}

	if cfg.Fastmail.HasFastmail() {
		tenant := fastmailProviderTenant(cfg)
		entry, err := buildFastmailEntry(ctx, cfg, logger)
		if err != nil {
			logger.Warn("sn360-es: fastmail provider init failed", slog.Any("error", err))
		} else {
			reg.register(tenant, entry)
			logger.Info("sn360-es: fastmail provider registered",
				slog.String("tenant", tenant),
				slog.String("account_id", cfg.Fastmail.AccountID))
		}
	}

	if cfg.WorkMail.HasWorkMail() {
		tenant := workmailProviderTenant(cfg)
		entry, err := buildWorkmailEntry(ctx, cfg, logger)
		if err != nil {
			logger.Warn("sn360-es: workmail provider init failed", slog.Any("error", err))
		} else {
			reg.register(tenant, entry)
			logger.Info("sn360-es: workmail provider registered",
				slog.String("tenant", tenant),
				slog.String("region", cfg.WorkMail.Region))
		}
	}

	if !reg.hasAny() {
		logger.Info("sn360-es: no email providers configured; action consumers will run in degraded mode")
	}
	return reg
}

// gmailProviderTenant returns the registry key for the Gmail entry.
// It must match the TenantID that buildMailboxProviders gives to the
// Gmail MailboxProvider (today: cfg.GWS.Domain). cfg.GWS.HasGmail()
// is the only caller-side gate for invoking this helper and it
// requires Domain to be non-empty, so we can return it verbatim
// without a fallback — if Domain were empty, the buildGmailEntry
// branch in buildProviderRegistry would never run. Whitespace
// normalisation lives in config.Load, so this helper is a direct
// passthrough — keeping it as a named function makes the registry
// key vs. MailboxProvider TenantID invariant grep-able from a
// single site.
func gmailProviderTenant(cfg *config.Config) string {
	return cfg.GWS.Domain
}

// outlookProviderTenant returns the registry key for the Outlook
// entry. Same invariant as gmailProviderTenant: cfg.O365.HasOutlook
// requires TenantID to be non-empty and config.Load trims it, so
// the helper is a direct passthrough — no fallback needed because
// the caller-side HasOutlook() gate guarantees a non-empty value.
func outlookProviderTenant(cfg *config.Config) string {
	return cfg.O365.TenantID
}

// zohoProviderTenant returns the registry key for the Zoho entry.
// HasZoho requires OrgID to be non-empty; we prefer the operator-set
// Domain when present so the registry key matches the tenant id the
// Zoho MailboxProvider emits, falling back to OrgID otherwise.
func zohoProviderTenant(cfg *config.Config) string {
	if cfg.Zoho.Domain != "" {
		return cfg.Zoho.Domain
	}
	return cfg.Zoho.OrgID
}

// fastmailProviderTenant returns the registry key for the Fastmail
// entry. AccountID is required by HasFastmail() so the value is
// always available.
func fastmailProviderTenant(cfg *config.Config) string {
	return cfg.Fastmail.AccountID
}

// workmailProviderTenant returns the registry key for the WorkMail
// entry. OrganizationID is required by HasWorkMail() so the value is
// always available.
func workmailProviderTenant(cfg *config.Config) string {
	return cfg.WorkMail.OrganizationID
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
		bannerInjector:     banner,
		bodyRewriter:       gmail.NewBodyRewriter(banner),
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
		bannerInjector:     banner,
		bodyRewriter:       outlook.NewBodyRewriter(banner),
	}, nil
}

// ErrNoProvider is returned by the consumer helpers when no provider
// is registered for the (tenant, kind) tuple. Consumers treat it as a
// best-effort skip rather than a hard failure.
var ErrNoProvider = errors.New("provider registry: no entry for tenant")

// providerRegistrarAdapter implements onboarding.ProviderRegistrar by
// constructing Gmail/Outlook provider entries from OAuth tokens and
// registering them in the runtime registry.
type providerRegistrarAdapter struct {
	registry *providerRegistry
	svc      *onboarding.Service
	cfg      *config.Config
	logger   *slog.Logger
}

// RegisterFromToken implements onboarding.ProviderRegistrar. The
// `token` parameter is intentionally unused: the runtime provider for
// Microsoft is wired via the onboarding service's refresh-aware
// TokenFor method (so the stored token is always the source of
// truth), and the Google branch ignores tokens entirely because GWS
// runs through service-account delegation.
func (a *providerRegistrarAdapter) RegisterFromToken(ctx context.Context, tenantID string, provider onboarding.ProviderType, _ onboarding.Token) error {
	switch provider {
	case onboarding.ProviderGoogle:
		// GWS uses domain-wide-delegation via a service account, not
		// per-user OAuth tokens. The static boot-time registration
		// covers all GWS tenants. The consent-flow token is persisted
		// for audit/revocation but not used as a runtime provider.
		a.logger.Info("provider-registrar: GWS token stored; runtime uses service-account delegation",
			slog.String("tenant_id", tenantID))
		return nil
	case onboarding.ProviderMicrosoft:
		entry, err := buildOutlookEntryFromToken(ctx, a.cfg, tenantID, a.svc, a.logger)
		if err != nil {
			return fmt.Errorf("provider-registrar: build outlook entry: %w", err)
		}
		a.registry.register(tenantID, entry)
		a.logger.Info("provider-registrar: outlook provider registered from token",
			slog.String("tenant_id", tenantID))
		return nil
	case onboarding.ProviderZoho:
		entry, err := buildZohoEntryFromToken(ctx, a.cfg, tenantID, a.svc, a.logger)
		if err != nil {
			return fmt.Errorf("provider-registrar: build zoho entry: %w", err)
		}
		a.registry.register(tenantID, entry)
		a.logger.Info("provider-registrar: zoho provider registered from token",
			slog.String("tenant_id", tenantID))
		return nil
	case onboarding.ProviderFastmail:
		// Fastmail uses static API tokens, not OAuth. The static
		// boot-time registration in buildProviderRegistry covers the
		// configured Fastmail account; per-tenant onboarding tokens
		// have no semantics for Fastmail.
		a.logger.Info("provider-registrar: fastmail uses static API token; runtime path is boot-time registration",
			slog.String("tenant_id", tenantID))
		return nil
	case onboarding.ProviderWorkmail:
		// WorkMail uses AWS IAM credentials, not OAuth. Same
		// behaviour as Fastmail: boot-time registration is the
		// only runtime path.
		a.logger.Info("provider-registrar: workmail uses AWS IAM credentials; runtime path is boot-time registration",
			slog.String("tenant_id", tenantID))
		return nil
	default:
		return fmt.Errorf("provider-registrar: unknown provider %q", provider)
	}
}

// buildOutlookEntryFromToken constructs a providerEntry with a
// refreshing token source backed by the onboarding service's
// TokenFor method. Each call to Token() loads the current token
// from the encrypted store and transparently refreshes it when
// expired, so the provider entry never goes stale.
func buildOutlookEntryFromToken(_ context.Context, cfg *config.Config, tenantID string, svc *onboarding.Service, logger *slog.Logger) (*providerEntry, error) {
	tokens := outlook.TokenSourceFunc(func(ctx context.Context) (string, error) {
		tok, err := svc.TokenFor(ctx, tenantID, onboarding.ProviderMicrosoft)
		if err != nil {
			return "", fmt.Errorf("outlook token refresh: %w", err)
		}
		return tok.AccessToken, nil
	})
	baseURL := cfg.O365.BaseURL
	label, err := outlook.New(outlook.Config{
		BaseURL:     baseURL,
		TokenSource: tokens,
	})
	if err != nil {
		return nil, fmt.Errorf("label provider: %w", err)
	}
	banner, err := outlook.NewBannerInjector(outlook.BannerInjectorConfig{
		BaseURL:     baseURL,
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
		logger.Debug("sn360-es: outlook provider wired from token",
			slog.String("base_url", baseURL))
	}
	return &providerEntry{
		kind:               action.LabelProviderOutlook,
		labelProvider:      label,
		quarantineProvider: quarantine,
		bannerInjector:     banner,
		bodyRewriter:       outlook.NewBodyRewriter(banner),
	}, nil
}

// buildZohoEntry constructs the Zoho label provider + banner injector
// + quarantine provider using the configured OAuth refresh-token. All
// providers share a single token source so refresh roundtrips are
// amortised across them.
func buildZohoEntry(_ context.Context, cfg *config.Config, logger *slog.Logger) (*providerEntry, error) {
	tokens, err := zoho.NewRefreshTokenSource(zoho.RefreshTokenConfig{
		ClientID:     cfg.Zoho.ClientID,
		ClientSecret: cfg.Zoho.ClientSecret,
		RefreshToken: cfg.Zoho.RefreshToken,
		AccountsURL:  cfg.Zoho.AccountsURL,
		DataCenter:   cfg.Zoho.DataCenter,
	})
	if err != nil {
		return nil, fmt.Errorf("token source: %w", err)
	}
	client, err := zoho.NewClient(zoho.ClientConfig{
		TokenSource: tokens,
		BaseURL:     cfg.Zoho.BaseURL,
		DataCenter:  cfg.Zoho.DataCenter,
		OrgID:       cfg.Zoho.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("zoho client: %w", err)
	}
	label, err := zoho.New(zoho.Config{Client: client})
	if err != nil {
		return nil, fmt.Errorf("label provider: %w", err)
	}
	banner, err := zoho.NewBannerInjector(zoho.BannerInjectorConfig{Client: client})
	if err != nil {
		return nil, fmt.Errorf("banner injector: %w", err)
	}
	body, err := zoho.NewBodyRewriter(banner)
	if err != nil {
		return nil, fmt.Errorf("body rewriter: %w", err)
	}
	quarantine, err := zoho.NewQuarantineProvider(zoho.QuarantineProviderConfig{Client: client})
	if err != nil {
		return nil, fmt.Errorf("quarantine provider: %w", err)
	}
	if logger != nil {
		logger.Debug("sn360-es: zoho provider wired",
			slog.String("data_center", cfg.Zoho.DataCenter),
			slog.String("org_id", cfg.Zoho.OrgID))
	}
	return &providerEntry{
		kind:               action.LabelProviderZoho,
		labelProvider:      label,
		quarantineProvider: quarantine,
		bannerInjector:     banner,
		bodyRewriter:       body,
	}, nil
}

// buildZohoEntryFromToken constructs a Zoho providerEntry whose
// token source loads the refresh token via the onboarding service's
// TokenFor method on every call, so per-tenant tokens stored in the
// encrypted token store remain the source of truth.
func buildZohoEntryFromToken(_ context.Context, cfg *config.Config, tenantID string, svc *onboarding.Service, logger *slog.Logger) (*providerEntry, error) {
	tokens := zoho.TokenSourceFunc(func(ctx context.Context) (string, error) {
		tok, err := svc.TokenFor(ctx, tenantID, onboarding.ProviderZoho)
		if err != nil {
			return "", fmt.Errorf("zoho token refresh: %w", err)
		}
		return tok.AccessToken, nil
	})
	client, err := zoho.NewClient(zoho.ClientConfig{
		TokenSource: tokens,
		BaseURL:     cfg.Zoho.BaseURL,
		DataCenter:  cfg.Zoho.DataCenter,
		OrgID:       cfg.Zoho.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("zoho client: %w", err)
	}
	label, err := zoho.New(zoho.Config{Client: client})
	if err != nil {
		return nil, fmt.Errorf("label provider: %w", err)
	}
	banner, err := zoho.NewBannerInjector(zoho.BannerInjectorConfig{Client: client})
	if err != nil {
		return nil, fmt.Errorf("banner injector: %w", err)
	}
	body, err := zoho.NewBodyRewriter(banner)
	if err != nil {
		return nil, fmt.Errorf("body rewriter: %w", err)
	}
	quarantine, err := zoho.NewQuarantineProvider(zoho.QuarantineProviderConfig{Client: client})
	if err != nil {
		return nil, fmt.Errorf("quarantine provider: %w", err)
	}
	if logger != nil {
		logger.Debug("sn360-es: zoho provider wired from token",
			slog.String("tenant_id", tenantID))
	}
	return &providerEntry{
		kind:               action.LabelProviderZoho,
		labelProvider:      label,
		quarantineProvider: quarantine,
		bannerInjector:     banner,
		bodyRewriter:       body,
	}, nil
}

// buildFastmailEntry constructs the Fastmail provider stack. Fastmail
// uses a static API token (app-specific password with JMAP scope) so
// the token source is a simple StaticTokenSource. The same Client is
// shared by every provider in the entry — JMAP method calls are
// idempotent so the shared session cache adds no contention.
func buildFastmailEntry(_ context.Context, cfg *config.Config, logger *slog.Logger) (*providerEntry, error) {
	tokens := fastmail.StaticTokenSource{APIToken: cfg.Fastmail.APIToken}
	client, err := fastmail.NewClient(fastmail.ClientConfig{
		TokenSource: tokens,
		BaseURL:     cfg.Fastmail.BaseURL,
		AccountID:   cfg.Fastmail.AccountID,
	})
	if err != nil {
		return nil, fmt.Errorf("fastmail client: %w", err)
	}
	label, err := fastmail.NewLabelProvider(fastmail.LabelProviderConfig{Client: client})
	if err != nil {
		return nil, fmt.Errorf("label provider: %w", err)
	}
	banner, err := fastmail.NewBannerInjector(fastmail.BannerInjectorConfig{Client: client})
	if err != nil {
		return nil, fmt.Errorf("banner injector: %w", err)
	}
	body, err := fastmail.NewBodyRewriter(banner)
	if err != nil {
		return nil, fmt.Errorf("body rewriter: %w", err)
	}
	quarantine, err := fastmail.NewQuarantineProvider(fastmail.QuarantineProviderConfig{Client: client})
	if err != nil {
		return nil, fmt.Errorf("quarantine provider: %w", err)
	}
	if logger != nil {
		logger.Debug("sn360-es: fastmail provider wired",
			slog.String("account_id", cfg.Fastmail.AccountID))
	}
	return &providerEntry{
		kind:               action.LabelProviderFastmail,
		labelProvider:      label,
		quarantineProvider: quarantine,
		bannerInjector:     banner,
		bodyRewriter:       body,
	}, nil
}

// buildWorkmailEntry constructs the WorkMail provider stack. WorkMail
// uses AWS IAM credentials (static via config, or the standard env
// chain) signed with SigV4. The same Signer backs both the JSON API
// client and the EWS client because WorkMail's IAM scope covers both.
func buildWorkmailEntry(_ context.Context, cfg *config.Config, logger *slog.Logger) (*providerEntry, error) {
	creds := workmail.ChainedCredentials{
		Providers: []workmail.CredentialsProvider{
			workmail.StaticCredentials{Credentials: workmail.Credentials{
				AccessKeyID:     cfg.WorkMail.AccessKeyID,
				SecretAccessKey: cfg.WorkMail.SecretAccessKey,
			}},
			workmail.EnvCredentials{},
		},
	}
	signer, err := workmail.NewSigner(workmail.SignerConfig{
		Region:      cfg.WorkMail.Region,
		Service:     "workmail",
		Credentials: creds,
	})
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	client, err := workmail.NewClient(workmail.ClientConfig{
		Signer: signer,
		Region: cfg.WorkMail.Region,
		OrgID:  cfg.WorkMail.OrganizationID,
	})
	if err != nil {
		return nil, fmt.Errorf("workmail client: %w", err)
	}
	ews, err := workmail.NewEWSClient(workmail.EWSClientConfig{
		Signer:   signer,
		Endpoint: cfg.WorkMail.EWSBaseURL,
		Region:   cfg.WorkMail.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("ews client: %w", err)
	}
	label, err := workmail.NewLabelProvider(workmail.LabelProviderConfig{EWS: ews})
	if err != nil {
		return nil, fmt.Errorf("label provider: %w", err)
	}
	banner, err := workmail.NewBannerInjector(workmail.BannerInjectorConfig{EWS: ews})
	if err != nil {
		return nil, fmt.Errorf("banner injector: %w", err)
	}
	body, err := workmail.NewBodyRewriter(ews)
	if err != nil {
		return nil, fmt.Errorf("body rewriter: %w", err)
	}
	quarantine, err := workmail.NewQuarantineProvider(workmail.QuarantineProviderConfig{EWS: ews})
	if err != nil {
		return nil, fmt.Errorf("quarantine provider: %w", err)
	}
	_ = client // future use: SDK calls outside the directory client
	if logger != nil {
		logger.Debug("sn360-es: workmail provider wired",
			slog.String("region", cfg.WorkMail.Region),
			slog.String("org_id", cfg.WorkMail.OrganizationID))
	}
	return &providerEntry{
		kind:               action.LabelProviderWorkmail,
		labelProvider:      label,
		quarantineProvider: quarantine,
		bannerInjector:     banner,
		bodyRewriter:       body,
	}, nil
}
