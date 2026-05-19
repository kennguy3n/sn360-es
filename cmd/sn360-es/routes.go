package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/handler"
	"github.com/kennguy3n/sn360-es/internal/middleware"
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

	// Banner-action / feedback.
	bannerAction := handler.NewBannerActionHandler(logger, app.feedbackSvc)
	mux.Handle("/v1/banner/action", bannerAction)

	// Dashboard summary.
	dashboardH := handler.NewDashboardHandler(logger, app.dashboardGen)
	mux.Handle("/v1/dashboard/summary", dashboardH)

	// Education micro-lessons.
	educationH := handler.NewEducationHandler(logger, app.microLessonSvc)
	mux.Handle("/v1/education/lesson/", educationH)

	// Predict (pre-send + pre-open).
	predictH := handler.NewPredictHandler(logger, app.recipientSvc, app.openSvc)
	mux.HandleFunc("/v1/predict/recipient", predictH.ServeRecipient)
	mux.HandleFunc("/v1/predict/open", predictH.ServeOpen)

	// Quarantine release.
	if app.jwtIssuer != nil {
		if qh, qerr := handler.NewQuarantineHandler(logger, app.jwtIssuer, app.releaseSvc); qerr == nil {
			mux.Handle("/v1/quarantine/release", qh)
		} else {
			logger.Warn("sn360-es: quarantine handler init failed", slog.Any("error", qerr))
		}
	}

	// Escalation tickets.
	escalationH := handler.NewEscalationHandler(logger, app.escalationSvc)
	mux.HandleFunc("/v1/escalation/resolve", escalationH.ServeResolve)
	mux.HandleFunc("/v1/escalation/", escalationH.ServeGet)

	// Interstitial click handler. Only registered when the URL
	// rewriter is configured; the handler unconditionally calls into
	// the rewriter and would panic on a nil dereference otherwise.
	if app.urlRewriter != nil {
		interstitialH := handler.NewInterstitialHandler(logger, app.urlRewriter, nil, nil, handler.InterstitialConfig{})
		mux.Handle("/l/", interstitialH)
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

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("http: unmatched route", slog.String("path", r.URL.Path))
		w.WriteHeader(http.StatusNotFound)
	})
	return mux, nil
}

// wrapMiddleware applies the standard middleware chain. Order matters:
// the outermost wrapper runs first.
//
//	telemetry  →  request-logger  →  CORS  →  rate-limit  →  JWT-auth  →  mux
//
// Telemetry runs first so it captures total latency including auth
// rejections and rate-limit denials. Rate limiting sits OUTSIDE JWT
// auth so we can shed load before doing the expensive token-verify
// work — an attacker hammering us with garbage Bearer tokens still
// gets cut off at the limiter.
func wrapMiddleware(mux http.Handler, app *application) (http.Handler, error) {
	logger := app.logger
	var h http.Handler = mux

	// JWT auth: optional. Skipped when no issuer is configured (dev
	// runs with no banner secret).
	if app.jwtIssuer != nil {
		h = middleware.NewJWTAuth(h, middleware.JWTAuthConfig{
			Issuer:    app.jwtIssuer,
			SkipPaths: defaultAuthSkipPaths(),
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
		rl := middleware.NewRateLimiter(h, middleware.RateLimitConfig{
			Rate:            app.cfg.RateLimit.Rate,
			Burst:           app.cfg.RateLimit.Burst,
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
		"/v1/banner/action":                  {},
		"/v1/dashboard/summary":              {},
		"/v1/predict/recipient":              {},
		"/v1/predict/open":                   {},
		"/v1/quarantine/release":             {},
		"/v1/escalation/resolve":             {},
		"/v1/onboarding/start":               {},
		"/v1/onboarding/callback":            {},
		"/v1/onboarding/status":              {},
		"/v1/onboarding/revoke":              {},
		"/v1/onboarding/gws-setup-status":    {},
		"/v1/vendors":                        {},
		"/v1/org-graph":                      {},
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
func defaultRateLimitSkipPaths() []string {
	return []string{
		"/healthz",
		"/readyz",
		"/metrics",
		"/docs",
		"/docs/",
		"/openapi.yaml",
	}
}

// defaultAuthSkipPaths returns the paths that bypass JWT auth.
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
	}
}
