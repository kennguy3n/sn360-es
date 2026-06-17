package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/handler"
	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/pkg/intel"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
	storageredis "github.com/kennguy3n/sn360-es/pkg/storage/redis"
)

// buildMux constructs the HTTP routing tree. Handlers from
// internal/handler are wired here so future routes have one obvious
// place to register.
func buildMux(app *application) (http.Handler, error) {
	if app == nil {
		return nil, errors.New("buildMux: app is required")
	}
	logger := app.logger
	mux := http.NewServeMux()

	checkers := buildHealthCheckers(app)
	health := handler.NewHealthHandler(handler.HealthConfig{Logger: logger, Checkers: checkers})
	mux.HandleFunc("/healthz", health.Liveness)
	mux.HandleFunc("/readyz", health.Readiness)

	mux.Handle("/metrics", app.metrics.HTTPHandler())

	docs, err := handler.NewDocsHandler()
	if err != nil {
		return nil, fmt.Errorf("docs handler: %w", err)
	}
	mux.HandleFunc("/docs", docs.ServeSwaggerUI)
	mux.HandleFunc("/docs/", docs.ServeSwaggerUI)
	mux.HandleFunc("/openapi.yaml", docs.ServeOpenAPI)

	// Business routes are mounted only for roles that should
	// serve HTTP traffic. Consumer / worker pods still expose
	// /healthz, /readyz, /metrics, /docs (mounted above) so
	// kubelet probes, Prometheus scrapes, and operators reading
	// the spec all work — but they refuse the request-time
	// /v1/* surface. This is what fixes the noisy-neighbour
	// failure mode the review identified: a slow Tier-2 SLM
	// call on a consumer pod can no longer stall HTTP request
	// handling on the same process.
	if !app.cfg.Role.ServesAPI() {
		logger.Info("sn360-es: HTTP business routes disabled by role",
			slog.String("role", string(app.cfg.Role)))
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		return mux, nil
	}

	// Banner-action / feedback.
	bannerAction := handler.NewBannerActionHandler(logger, app.feedbackSvc)
	mux.Handle("/v1/banner/action", bannerAction)

	// Dashboard summary.
	dashboardH := handler.NewDashboardHandler(logger, app.dashboardGen)
	mux.Handle("/v1/dashboard/summary", dashboardH)

	// Education micro-lessons.
	educationH := handler.NewEducationHandler(logger, app.microLessonSvc)
	mux.Handle("/v1/education/lesson/", educationH)

	// Education campaign analytics.
	educationAnalyticsH := handler.NewEducationAnalyticsHandler(logger, app.educationAnalytic)
	mux.Handle("/v1/education/analytics", educationAnalyticsH)

	// Predict (pre-send + pre-open).
	predictH := handler.NewPredictHandler(logger, app.recipientSvc, app.openSvc)
	mux.HandleFunc("/v1/predict/recipient", predictH.ServeRecipient)
	mux.HandleFunc("/v1/predict/open", predictH.ServeOpen)

	// Quarantine release. The handler dispatches on the token's
	// `scp` claim: the legacy scp="banner_action" (or unset)
	// scope routes to the SOC-operator ReleaseService; the WS-3a
	// scp="quarantine_release" scope routes to the recipient
	// self-service coordinator. selfReleaseSvc may be nil in
	// deployments without a durable audit / policy repository;
	// the handler refuses self-release tokens with a uniform
	// 401 in that case so no audit-less code path is reachable.
	//
	// The endpoint sits in defaultAuthSkipPaths() because the
	// recipient JWT lives in the POST body, not the
	// Authorization header — JWTAuth middleware cannot decode
	// it. That also means the TenantConnBinder middleware
	// (which depends on JWTAuth's tenant_id ctx value) is
	// bypassed, so the handler is the only place that can
	// activate Postgres RLS for the new self-release path. The
	// `quarantineTenantBinder(app)` helper returns a real
	// adapter when pgDB != nil (production), nil otherwise (in-
	// memory / dev runs); the handler treats a nil binder as a
	// valid no-op so unit tests with the in-memory repository
	// continue to work unchanged.
	if app.jwtIssuer != nil {
		if qh, qerr := handler.NewQuarantineHandler(logger, app.jwtIssuer, app.releaseSvc, app.selfReleaseSvc, quarantineTenantBinder(app)); qerr == nil {
			mux.Handle("/v1/quarantine/release", qh)
		} else {
			logger.Warn("sn360-es: quarantine handler init failed", slog.Any("error", qerr))
		}
	}

	// Escalation tickets.
	escalationH := handler.NewEscalationHandler(logger, app.escalationSvc)
	mux.HandleFunc("/v1/escalation/resolve", escalationH.ServeResolve)
	mux.HandleFunc("/v1/escalation/", escalationH.ServeGet)

	// WS-3b investigation API. Both routes always register; the
	// handler renders 503 if app.investigationSvc is nil so the
	// readiness signal matches the wiring state rather than
	// silently 404-ing on a wired-but-unbacked deployment.
	investigationH := handler.NewInvestigationHandler(logger, app.investigationSvc)
	mux.HandleFunc("/v1/investigation/message/", investigationH.ServeMessage)
	mux.HandleFunc("/v1/investigation/sender/", investigationH.ServeSender)

	// Threat-intel feed admin API (WS-5B.3). Gated on
	// scp="admin_api" inside the handler; if the intel store
	// failed to wire (e.g. Postgres down at boot) the handler
	// still mounts and renders 503 so operators see a clear
	// readiness signal rather than a 404.
	//
	// app.intelJob is a *worker.IntelJob (concrete pointer). When
	// the intel worker is disabled (WORKER_INTEL_ENABLED=false, the
	// default) it stays nil. Passing a typed-nil pointer to a
	// parameter typed as the IntelFeedRefresher interface produces
	// a non-nil interface value carrying a nil dynamic value, which
	// the handler's `h.refresher == nil` guard does not catch and
	// would panic on the first /refresh call. Convert the pointer
	// to an interface explicitly so a nil refresher stays a nil
	// interface (and the handler renders 501 instead).
	var intelRefresher handler.IntelFeedRefresher
	if app.intelJob != nil {
		intelRefresher = app.intelJob
	}
	// intel.DefaultRegistry is populated by the init() blocks in
	// each pkg/intel/<provider> sub-package, which the main
	// binary loads via the anonymous imports in wire_intel.go.
	// Providers() is the canonical list of registered keys (sorted)
	// and matches the Postgres CHECK constraint + OpenAPI enum.
	// Wiring it here turns the admin API into the single point of
	// validation so MemoryIntelStore (dev/test) rejects the same
	// inputs Postgres would reject in production.
	intelH := handler.NewIntelFeedsHandler(logger, app.intelStore, intelRefresher).
		WithProviders(intel.DefaultRegistry.Providers())
	mux.HandleFunc("/v1/intel/feeds", intelH.ServeFeeds)
	mux.HandleFunc("/v1/intel/feeds/", intelH.ServeFeeds)
	mux.HandleFunc("/v1/intel/indicators", intelH.ServeIndicators)

	// Interstitial click handler. Only registered when the URL
	// rewriter is configured; the handler unconditionally calls into
	// the rewriter and would panic on a nil dereference otherwise.
	if app.urlRewriter != nil {
		// Time-of-click recheck: reuse the same cache-fronted
		// threat-intel checker the Tier 0 gate uses so a URL added
		// to a feed after delivery is blocked when clicked. When the
		// intel store is absent (dev configs) the handler degrades to
		// a pass-through redirect.
		var threatIntel handler.ThreatIntel
		if app.tiChecker != nil {
			threatIntel = interstitialThreatIntel{
				checker: app.tiChecker,
				logger:  logger.With(slog.String("component", "interstitial_ti")),
			}
		}
		interstitialH := handler.NewInterstitialHandler(logger, app.urlRewriter, threatIntel, nil, handler.InterstitialConfig{})
		mux.Handle("/l/", interstitialH)
	}

	// Push-notification webhook (Gmail Pub/Sub + Microsoft Graph).
	//
	// The route is only mounted when BOTH the PushManager and the
	// PushSignatureVerifier wired up successfully. The handler
	// validates the signature on every request before invoking the
	// manager, so a misconfigured verifier would fail-closed at the
	// handler — but we still gate at wiring time to keep the
	// public surface area honest: /v1/push/ is only advertised
	// when push ingestion is genuinely ready.
	if app.pushManager != nil && app.pushSignatureVerifier != nil {
		pushH := &handler.PushWebhookHandler{
			Manager:           app.pushManager,
			Logger:            logger,
			SignatureVerifier: app.pushSignatureVerifier,
		}
		mux.Handle("/v1/push/", pushH)
	}

	// Onboarding OAuth consent flow.
	if app.onboardingSvc != nil {
		adapter := &onboardingServiceAdapter{
			svc:   app.onboardingSvc,
			repos: app.repos,
		}
		onboardingH := handler.NewOnboardingHandler(logger, adapter)
		mux.HandleFunc("/v1/onboarding/start", onboardingH.ServeStart)
		mux.HandleFunc("/v1/onboarding/callback", onboardingH.ServeCallback)
		mux.HandleFunc("/v1/onboarding/status", onboardingH.ServeStatus)
		mux.HandleFunc("/v1/onboarding/revoke", onboardingH.ServeRevoke)
	}

	// GWS setup wizard — always registered so tenants can check
	// configuration status even before onboarding is complete.
	wizardH := handler.NewOnboardingWizardHandler(logger, &gwsSetupChecker{
		cfg:    app.cfg,
		logger: logger,
	})
	mux.HandleFunc("/v1/onboarding/gws-setup-status", wizardH.ServeGWSSetupStatus)

	// Vendor management CRUD.
	if app.repos != nil && app.repos.Vendors != nil {
		vendorH := handler.NewVendorHandler(logger, app.repos.Vendors)
		mux.HandleFunc("/v1/vendors", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				vendorH.ServeList(w, r)
			case http.MethodPost:
				vendorH.ServeCreate(w, r)
			default:
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			}
		})
		mux.HandleFunc("/v1/vendors/", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodDelete:
				vendorH.ServeDelete(w, r)
			case strings.HasSuffix(r.URL.Path, "/approve"):
				vendorH.ServeApprove(w, r)
			case strings.HasSuffix(r.URL.Path, "/revoke"):
				vendorH.ServeRevoke(w, r)
			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"not found"}`))
			}
		})
	}

	if app.repos != nil && app.repos.OrgGraphs != nil {
		orgGraphH := handler.NewOrgGraphHandler(logger, app.repos.OrgGraphs)
		mux.Handle("/v1/org-graph", orgGraphH)
	}

	// WS-5B.2 — per-tenant standalone webhook sinks. Registered
	// only when the repository + encryptor are wired. The handler
	// itself does tenant-bound authz against the JWT's tid claim;
	// RequireAdmin enforces the role gate so JWTAuth's tenant
	// binding and the role check fail closed in lock-step.
	if app.repos != nil && app.repos.WebhookSinks != nil && app.encryptor != nil {
		whH, whErr := handler.NewWebhookSinksHandler(
			logger,
			app.repos.WebhookSinks,
			app.encryptor,
			app.webhookDispatcher,
		)
		if whErr != nil {
			logger.Warn("sn360-es: webhook sinks handler init failed", slog.Any("error", whErr))
		} else {
			mux.Handle("/v1/tenants/", middleware.RequireAdmin(whH))
		}
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("http: unmatched route", slog.String("path", r.URL.Path))
		w.WriteHeader(http.StatusNotFound)
	})
	return mux, nil
}

// wrapMiddleware applies the standard middleware chain. Order matters:
// the outermost wrapper runs first.
//
//	telemetry  →  request-id  →  request-logger  →  CORS  →  rate-limit  →  JWT-auth  →  tenant-conn  →  mux
//
// Telemetry runs first so it captures total latency including auth
// rejections and rate-limit denials. Request-ID sits between
// telemetry and the request logger so every log line — including the
// one emitted by the logger middleware itself — carries the
// correlation ID, while still being inside telemetry so metric
// labels can stay low-cardinality and unaffected by it. Rate
// limiting sits OUTSIDE JWT auth so we can shed load before doing
// the expensive token-verify work — an attacker hammering us with
// garbage Bearer tokens still gets cut off at the limiter.
//
// The tenant-conn binder sits BETWEEN JWT and the mux because it
// depends on JWT having put the verified tenant_id on the request
// context. The binder acquires a *sql.Conn, runs `SELECT
// set_config('sn360.tenant_id', $1, false)` on it, attaches the
// pinned conn to the request ctx, and defers a release on response
// completion. That binding is what activates the Postgres Row-Level
// Security policy installed in
// `migrations/0018_row_level_security.up.sql`: without it, every
// handler would acquire a fresh pool conn with no GUC and the
// policy would deterministically return zero rows.
func wrapMiddleware(mux http.Handler, app *application) (http.Handler, error) {
	logger := app.logger
	var h = mux

	// Tenant-conn binder: only wired when a real Postgres pool is
	// available. Wraps the mux first so it sits *inside* JWT —
	// JWT injects tenant_id into ctx, the binder reads it, the
	// mux handlers see a ctx with both tenant_id AND a pinned
	// conn whose session GUC is set to that tenant.
	if app.pgDB != nil {
		// WS-7a: forward the shared tenantBinder's
		// RegionalDB + Resolver into the per-mux binder so
		// HTTP and NATS entrypoints route through identical
		// region-resolution logic. Either / both fields stay
		// nil in single-region deployments and the binder
		// falls back to the pgDB.WithTenant single-pool code
		// path -- the existing single-region default.
		var regional *postgres.RegionalDB
		var resolver middleware.RegionResolver
		if app.tenantBinder != nil {
			regional = app.regional
			resolver = app.tenantBinder.Resolver()
		}
		binder, berr := middleware.NewTenantConnBinder(h, middleware.TenantConnConfig{
			DB:        app.pgDB,
			Regional:  regional,
			Resolver:  resolver,
			Logger:    logger,
			SkipPaths: defaultAuthSkipPaths(),
		})
		if berr != nil {
			return nil, fmt.Errorf("wrap middleware: %w", berr)
		}
		h = binder
	}

	// JWT auth: optional. Skipped when no issuer is configured (dev
	// runs with no banner secret).
	// Dual-issuer: mount the middleware when EITHER the primary
	// banner-token issuer OR the iam-core JWKS issuer is configured.
	// A deployment may run iam-core-only (no banner secret) and still
	// needs authenticated routes.
	if app.jwtIssuer != nil || app.cfg.IAMCore.JWKSEndpoint != "" {
		h = middleware.NewJWTAuth(h, middleware.JWTAuthConfig{
			Issuer:         app.jwtIssuer,
			SkipPaths:      defaultAuthSkipPaths(),
			IAMCoreJWKSURL: app.cfg.IAMCore.JWKSEndpoint,
			IAMCoreIssuer:  app.cfg.IAMCore.Issuer,
		})
	}

	routeTemplates := defaultRouteTemplates()
	knownExactRoutes := defaultKnownExactRoutes()

	// Per-IP token-bucket rate limiter. The /healthz, /readyz,
	// /metrics and /docs paths bypass the limiter so liveness probes
	// and Prometheus scrapes never get 429'd. The limiter shares
	// app.metrics so 429 counts surface alongside other HTTP
	// telemetry.
	if app.cfg.RateLimit.Enabled {
		// Parsing trusted-proxy CIDRs here (not in config.Load)
		// keeps boot-time fatal errors next to the wiring that
		// actually relies on them. An empty / unset value yields a
		// nil slice, which the middleware interprets as the secure
		// default: bucket on r.RemoteAddr only, ignore XFF.
		trusted, perr := middleware.ParseTrustedProxies(app.cfg.RateLimit.TrustedProxies)
		if perr != nil {
			return nil, fmt.Errorf("rate-limit trusted proxies: %w", perr)
		}
		// Resolve the store backend. "memory" (default) keeps the
		// existing per-replica behaviour; "redis" shares token
		// state across every replica that points at the same
		// Redis — required for the documented rate to actually
		// hold cluster-wide.
		var (
			store         middleware.BucketStore
			fallbackStore middleware.BucketStore
		)
		switch app.cfg.RateLimit.Backend {
		case "redis":
			if app.redis == nil {
				return nil, errors.New("rate-limit: RATE_LIMIT_BACKEND=redis requires Redis to be configured")
			}
			bucketStore, berr := storageredis.NewRateBucketStore(
				context.Background(), app.redis, storageredis.RateBucketConfig{
					KeyPrefix: app.cfg.RateLimit.RedisKeyPrefix,
					TTL:       app.cfg.RateLimit.RedisTTL,
				})
			if berr != nil {
				return nil, fmt.Errorf("rate-limit: build redis bucket store: %w", berr)
			}
			adapter, aerr := middleware.NewRedisBucketStore(middleware.RedisBucketStoreConfig{
				Store:   bucketStore,
				Timeout: app.cfg.RateLimit.RedisTimeout,
			})
			if aerr != nil {
				return nil, fmt.Errorf("rate-limit: wire redis bucket store: %w", aerr)
			}
			store = adapter
			if app.cfg.RateLimit.FallbackToMemory {
				// Per-replica memory store gives the
				// limiter a soft-fall path under Redis
				// hard-down: counting degrades from
				// cluster-wide to per-replica (less
				// correct, still safe) instead of fail-
				// open or fail-closed.
				fallbackStore = middleware.NewMemoryBucketStore()
			}
		default:
			// store stays nil; NewRateLimiter builds the
			// default in-process memory store.
		}

		failureMode := middleware.FailureModeOpen
		if app.cfg.RateLimit.FailureMode == "closed" {
			failureMode = middleware.FailureModeClosed
		}

		rl := middleware.NewRateLimiter(h, middleware.RateLimitConfig{
			Rate:                app.cfg.RateLimit.Rate,
			Burst:               app.cfg.RateLimit.Burst,
			Store:               store, // nil => in-process memory
			FailureMode:         failureMode,
			FailureModeFallback: fallbackStore,
			Logger:              logger,
			OnStoreError: func(err error, clientKey string) {
				// Bucket-store error metrics are emitted
				// here (and only here) so the Redis path
				// can be alerted on without the limiter
				// itself having to know about Prometheus.
				if app.metrics != nil {
					app.metrics.RateLimitStoreErrorsTotal.WithLabelValues(app.cfg.RateLimit.Backend).Inc()
				}
				logger.Warn("http: rate-limit store error",
					slog.String("backend", app.cfg.RateLimit.Backend),
					slog.String("client_key", clientKey),
					slog.Any("error", err),
				)
			},
			CleanupInterval: app.cfg.RateLimit.CleanupInterval,
			IdleTTL:         app.cfg.RateLimit.IdleTTL,
			TrustedProxies:  trusted, // boot-time-validated, may be nil
			SkipPaths:       defaultRateLimitSkipPaths(),
			OnLimited: func(ip, path string) {
				if app.metrics != nil {
					// Bucket the path into a bounded set
					// before stamping it on a Prometheus
					// label. Attackers spraying random URLs
					// would otherwise explode the
					// http_rate_limited_total series count;
					// see Devin Review self-audit / the
					// rationale on Metrics.RateLimitedTotal.
					route := rateLimitRouteLabel(path, routeTemplates, knownExactRoutes)
					app.metrics.RateLimitedTotal.WithLabelValues(route).Inc()
				}
				logger.Debug("http: rate limit exceeded",
					slog.String("ip", ip),
					slog.String("path", path),
				)
			},
		})
		app.closers = append(app.closers, func() error {
			rl.Stop()
			return nil
		})
		h = rl
	}

	// CORS. The override argument is left nil so NewCORSFromConfig
	// reads from app.cfg.CORS.AllowedOrigins.
	h = middleware.NewCORSFromConfig(h, *app.cfg, nil)

	// Request logging.
	h = middleware.NewRequestLogger(h, middleware.RequestLoggerConfig{Logger: logger})

	// Correlation ID: resolved from X-Correlation-ID or generated as
	// a fresh UUID, attached to the request context, and echoed back
	// on the response so callers can correlate logs across the hop.
	// Sits outside the request logger so every emitted log entry
	// carries the ID, but inside telemetry so high-cardinality IDs
	// never reach Prometheus labels.
	h = middleware.NewRequestID(h)

	// Telemetry (counters + latency histograms).
	h = middleware.NewTelemetry(h, middleware.TelemetryConfig{
		Metrics:       app.metrics,
		RoutePatterns: routeTemplates,
	})

	return h, nil
}

// defaultRouteTemplates lists the high-cardinality route prefixes the
// HTTP layer collapses into stable Prometheus labels. Shared by the
// telemetry middleware and the rate-limit metrics callback so
// http_requests_total and http_rate_limited_total stay consistent.
func defaultRouteTemplates() []middleware.RoutePattern {
	return []middleware.RoutePattern{
		{Prefix: "/v1/escalation/", Label: "/v1/escalation/:id"},
		{Prefix: "/l/", Label: "/l/:token"},
		{Prefix: "/v1/education/lesson/", Label: "/v1/education/lesson/:id"},
		{Prefix: "/v1/vendors/", Label: "/v1/vendors/:id"},
		{Prefix: "/v1/push/", Label: "/v1/push/:provider/:tenant"},
		// WS-3b investigation API — pseudo_id and sender_hash are
		// high-cardinality (one per message / per sender), so both
		// need stable Prometheus labels here. Without this the
		// telemetry middleware would emit a unique
		// http_requests_total{path="..."} time-series per probed
		// hash, blowing up Prometheus head series.
		{Prefix: "/v1/investigation/message/", Label: "/v1/investigation/message/:pseudo_id"},
		{Prefix: "/v1/investigation/sender/", Label: "/v1/investigation/sender/:sender_hash"},
		// WS-5B.2 webhook-sinks API — every URL under
		// /v1/tenants/<tenant_uuid>/webhook-sinks[/<sink_uuid>[/test]]
		// carries TWO high-cardinality path segments (tenant + sink
		// IDs), each grown by every customer admin who creates a
		// sink. Without collapsing here, telemetry.normaliseRoute
		// would emit a fresh http_requests_total time-series per
		// (tenant, sink, method, status) tuple — exactly the
		// unbounded-series shape the WS-3b investigation routes
		// above guard against. The label only captures the parent
		// collection (sub-resources /<id> and /<id>/test still hash
		// onto the same series); the `method` label preserves the
		// list/create/get/update/delete/test distinction, which is
		// what dashboards actually care about. The handler itself
		// is mounted at the broad /v1/tenants/ prefix so any future
		// /v1/tenants/<tid>/<other-resource> additions also fall
		// under this label until they get their own entry.
		{Prefix: "/v1/tenants/", Label: "/v1/tenants/:tenant_id/webhook-sinks"},
	}
}

// defaultKnownExactRoutes is the bounded allowlist of literal paths
// the rate-limit callback uses to label legitimate-but-unmatched
// routes (i.e. paths registered on the mux that have no path
// parameters). Anything outside this set + the route templates is
// reported under the "/other" label so attacker traffic spraying
// random URLs cannot drive Prometheus series count up unbounded.
func defaultKnownExactRoutes() map[string]struct{} {
	return map[string]struct{}{
		"/v1/banner/action":               {},
		"/v1/dashboard/summary":           {},
		"/v1/education/analytics":         {},
		"/v1/predict/recipient":           {},
		"/v1/predict/open":                {},
		"/v1/quarantine/release":          {},
		"/v1/escalation/resolve":          {},
		"/v1/onboarding/start":            {},
		"/v1/onboarding/callback":         {},
		"/v1/onboarding/status":           {},
		"/v1/onboarding/revoke":           {},
		"/v1/onboarding/gws-setup-status": {},
		"/v1/vendors":                     {},
		"/v1/org-graph":                   {},
	}
}

// rateLimitRouteLabel maps an arbitrary request path onto the bounded
// label set used by the http_rate_limited_total Prometheus counter.
//
// Priority order: known exact path → route-template match → "/other".
//
// The known-exact allowlist is checked FIRST so endpoints whose
// stable form happens to look like the bare prefix of a parameterized
// sibling (e.g. POST /v1/escalation/resolve versus GET
// /v1/escalation/<id>, GET /v1/vendors versus GET /v1/vendors/<id>)
// keep their authoritative label instead of being silently collapsed
// onto the parameterized template.
func rateLimitRouteLabel(path string, patterns []middleware.RoutePattern, knownExact map[string]struct{}) string {
	if _, ok := knownExact[path]; ok {
		return path
	}
	if label, ok := middleware.NormaliseRoute(patterns, path); ok {
		return label
	}
	return "/other"
}

// defaultRateLimitSkipPaths returns the paths that bypass the rate
// limiter entirely. These are mostly probes and docs the operator
// always needs to be able to hit.
//
// /v1/push/ is also skipped because push-webhook callbacks from
// Google Pub/Sub and Microsoft Graph all originate from a small
// pool of provider-owned IPs and, behind a load balancer without
// RATE_LIMIT_TRUSTED_PROXIES configured, would share a single
// token bucket keyed on the LB's IP. During a Pub/Sub batch
// fan-out or a Graph notification burst, legitimate callbacks
// would 429 and force the provider into its exponential retry
// schedule — Gmail Pub/Sub retries up to 7 days with backoff,
// Graph retries 4 times over ~10 minutes — visibly delaying email
// ingestion and inflating provider error metrics.
//
// Skipping rate-limiting on /v1/push/ is safe because the handler
// is closed-by-default and provider-authenticated:
//   - Google Pub/Sub callbacks must carry a valid OIDC bearer
//     whose `aud` matches PushGoogleAudience and whose `iss` is
//     accounts.google.com (verified by buildPushSignatureVerifier
//     via JWKS).
//   - Microsoft Graph callbacks must carry a clientState that
//     constant-time-matches PushMicrosoftClientStateSecret.
//   - If either verifier is unwired (missing secret), the push
//     manager itself is never registered and the route 404s.
//
// An unauthenticated DoS would therefore still be rejected at the
// signature-verification layer (cheap), and the upstream JetStream
// publisher applies its own backpressure for the authenticated path.
func defaultRateLimitSkipPaths() []string {
	return []string{
		"/healthz",
		"/readyz",
		"/metrics",
		"/docs",
		"/docs/",
		"/openapi.yaml",
		"/v1/push/",
	}
}

// defaultAuthSkipPaths returns the paths that bypass JWT auth.
//
// /v1/push/ is included because push-webhook callbacks authenticate
// using a provider-specific scheme (Google Pub/Sub OIDC bearer for
// Gmail, Microsoft Graph clientState for Outlook) verified inside
// the PushWebhookHandler itself — not a Bearer JWT issued by us.
// The handler still fails-closed without the verifier wired.
func defaultAuthSkipPaths() []string {
	return []string{
		"/healthz",
		"/readyz",
		"/metrics",
		"/docs",
		"/docs/",
		"/openapi.yaml",
		"/l/",
		"/v1/banner/action",
		"/v1/quarantine/release",
		"/v1/education/lesson/",
		"/v1/onboarding/callback",
		"/v1/push/",
	}
}
