package slm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// TenantProviderLoader resolves a per-tenant override for the Tier 2
// provider name. Implementations look the value up from durable
// storage (e.g. the score_engine table) and are responsible for
// their own caching policy — the Router caches the constructed
// Client per tenant, not the lookup result.
//
// LoadTenantTier2Provider returns ("", nil) when the tenant has no
// override configured — that is the steady-state expectation for
// most tenants, who run on the deployment default. A non-nil error
// is logged at warn and the Router falls back to the default, so a
// transient DB blip never blocks evaluation.
type TenantProviderLoader interface {
	LoadTenantTier2Provider(ctx context.Context, tenantID string) (string, error)
}

// RouterConfig bundles the inputs to NewRouter. Both Default and
// (Loader + ResolveConfig) are independently optional: a Router with
// only Default behaves identically to "use the deployment default
// for every tenant", a Router with no Default at all returns an
// error from Evaluate when called for an unknown tenant (so a
// misconfigured boot fails loudly instead of silently disabling
// Tier 2).
type RouterConfig struct {
	// Default is the deployment-wide Tier 2 client. Used for every
	// tenant that does not have an override. Nil disables the
	// default path; in that case Loader MUST resolve every tenant
	// that ever reaches the Router.
	Default Client

	// Loader resolves per-tenant overrides. Nil disables per-tenant
	// override resolution entirely — every request goes to Default.
	Loader TenantProviderLoader

	// ResolveConfig builds a ProviderConfig from a provider name at
	// override-construction time. It is called at most once per
	// (tenant, provider) pair — the result is wrapped in a Client
	// via slm.New and cached for the lifetime of the Router. Nil
	// disables override construction even when Loader returns a
	// name, which is useful in tests where you want to assert
	// "Loader was consulted" without standing up real providers.
	ResolveConfig func(providerName string) (ProviderConfig, error)

	// Logger receives override / fallback events at info level.
	// Defaults to slog.Default when nil.
	Logger *slog.Logger
}

// Router implements Client by dispatching to a per-tenant Client
// resolved through Loader + ResolveConfig and cached for the
// lifetime of the Router. When the tenant has no override or the
// override fails to construct, Router falls back to Default.
//
// The cache is intentionally simple: a sync.Map keyed by tenant ID
// holding a routerEntry. There is no TTL — provider changes
// require a process restart (or an explicit cache invalidation
// call, which we add when the operational need is real). Tier 2
// providers are heavyweight HTTP clients with their own connection
// pools; re-creating one per request would dominate the Tier 2
// latency budget and is the wrong default.
//
// Router is safe for concurrent use across many goroutines.
type Router struct {
	defaultClient Client
	loader        TenantProviderLoader
	resolveCfg    func(providerName string) (ProviderConfig, error)
	log           *slog.Logger

	// cache holds *routerEntry per tenant. A successful resolve
	// populates entry.client; a failed resolve populates entry.err
	// so subsequent requests for the same tenant short-circuit
	// without retrying the (presumed-still-broken) construction.
	cache sync.Map
}

// routerEntry is the cached resolution result for one tenant.
// Exactly one of (client, fellThroughToDefault) is meaningful; err
// is non-nil only when construction failed and we want subsequent
// requests for the same tenant to surface the same failure mode
// rather than papering over it with the default.
type routerEntry struct {
	client               Client
	fellThroughToDefault bool
	overrideProviderName string
	constructionError    error
}

// NewRouter validates cfg and returns a ready-to-use router. The
// caller is responsible for ensuring slm.New can succeed for every
// provider name the Loader might return — typically by blank-
// importing pkg/inference/slm/all in main.
func NewRouter(cfg RouterConfig) (*Router, error) {
	if cfg.Default == nil && cfg.Loader == nil {
		return nil, errors.New("slm.NewRouter: at least one of Default or Loader must be set")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Router{
		defaultClient: cfg.Default,
		loader:        cfg.Loader,
		resolveCfg:    cfg.ResolveConfig,
		log:           cfg.Logger,
	}, nil
}

// Evaluate dispatches to the per-tenant client when one is cached
// or resolvable, and to the default client otherwise. Returns an
// error only when neither path is usable (no default and no
// resolved override).
func (r *Router) Evaluate(ctx context.Context, req dto.EvaluateRequest, hint dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	client := r.resolve(ctx, req.TenantID)
	if client == nil {
		return dto.Tier2Outcome{}, fmt.Errorf("slm.Router: no Tier 2 client available for tenant %q", req.TenantID)
	}
	return client.Evaluate(ctx, req, hint)
}

// resolve returns the Client to use for tenantID, or nil if no
// client is available. The lookup is:
//  1. Cache hit → return cached client (or default if cached entry
//     fell through).
//  2. Loader is nil OR tenantID is empty → return default.
//  3. Loader returns an empty / error → log + cache default
//     fall-through → return default.
//  4. Loader returns a name → ResolveConfig + slm.New; on success
//     cache + return that client; on failure log + cache default
//     fall-through + return default.
func (r *Router) resolve(ctx context.Context, tenantID string) Client {
	if tenantID == "" || r.loader == nil {
		return r.defaultClient
	}
	if cached, ok := r.cache.Load(tenantID); ok {
		entry := cached.(*routerEntry)
		if entry.fellThroughToDefault {
			return r.defaultClient
		}
		return entry.client
	}

	name, err := r.loader.LoadTenantTier2Provider(ctx, tenantID)
	if err != nil {
		// Transient loader failures must NOT be cached — the next
		// evaluation should retry the lookup. A persistent error
		// will keep falling through to the default until the DB
		// recovers.
		r.log.WarnContext(ctx, "slm.Router: tenant provider lookup failed; using deployment default",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err))
		return r.defaultClient
	}
	if name == "" {
		// "No override configured" is the steady state for most
		// tenants — cache so we never re-query the DB for the
		// same tenant.
		r.cache.Store(tenantID, &routerEntry{fellThroughToDefault: true})
		return r.defaultClient
	}

	if r.resolveCfg == nil {
		// Loader returned a name but the Router has no way to
		// construct it. Cache the fallback so we don't keep
		// trying.
		r.log.WarnContext(ctx, "slm.Router: tenant override resolved but ResolveConfig is nil; using deployment default",
			slog.String("tenant_id", tenantID),
			slog.String("override", name))
		r.cache.Store(tenantID, &routerEntry{fellThroughToDefault: true, overrideProviderName: name})
		return r.defaultClient
	}

	providerCfg, err := r.resolveCfg(name)
	if err != nil {
		r.log.WarnContext(ctx, "slm.Router: ResolveConfig failed; using deployment default",
			slog.String("tenant_id", tenantID),
			slog.String("override", name),
			slog.Any("error", err))
		r.cache.Store(tenantID, &routerEntry{
			fellThroughToDefault: true,
			overrideProviderName: name,
			constructionError:    err,
		})
		return r.defaultClient
	}
	providerCfg.Name = name

	client, err := New(providerCfg)
	if err != nil {
		r.log.WarnContext(ctx, "slm.Router: slm.New failed for tenant override; using deployment default",
			slog.String("tenant_id", tenantID),
			slog.String("override", name),
			slog.Any("error", err))
		r.cache.Store(tenantID, &routerEntry{
			fellThroughToDefault: true,
			overrideProviderName: name,
			constructionError:    err,
		})
		return r.defaultClient
	}

	r.log.InfoContext(ctx, "slm.Router: tenant override resolved",
		slog.String("tenant_id", tenantID),
		slog.String("override", name))

	// LoadOrStore protects against the race where two goroutines
	// resolve the same tenant simultaneously. Only one entry
	// wins; the loser's client is dropped (no leaked
	// goroutines — providers hold only an http.Client which the
	// runtime GCs).
	entry := &routerEntry{client: client, overrideProviderName: name}
	actual, _ := r.cache.LoadOrStore(tenantID, entry)
	winner := actual.(*routerEntry)
	if winner.fellThroughToDefault {
		return r.defaultClient
	}
	return winner.client
}

// Invalidate evicts the cached entry for tenantID so the next
// Evaluate re-resolves through the loader. Used by control-plane
// callers (e.g. when the tuning agent updates a tenant's
// tier2_provider) to propagate changes without a restart. Calling
// with an empty tenantID is a no-op.
func (r *Router) Invalidate(tenantID string) {
	if tenantID == "" {
		return
	}
	r.cache.Delete(tenantID)
}

// InvalidateAll evicts every cached entry. Operationally rare —
// reserved for global provider-config changes (e.g. an admin
// updates the deployment default's URL) where the safest action
// is to drop every per-tenant cache and re-resolve.
func (r *Router) InvalidateAll() {
	r.cache.Range(func(k, _ any) bool {
		r.cache.Delete(k)
		return true
	})
}

// Default returns the underlying deployment-default Client. Mainly
// useful for the Tier 2 fallback wrapper, which needs the raw
// primary to wrap with a circuit breaker — handing it the Router
// would re-enter per-tenant dispatch and double-count the cache.
func (r *Router) Default() Client {
	return r.defaultClient
}
