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
//	telemetry  →  request-logger  →  CORS  →  JWT-auth  →  mux
//
// Telemetry runs first so it captures total latency including auth
// rejections. JWT auth sits closest to the mux so request logging
// covers 401s.
func wrapMiddleware(mux http.Handler, app *application) http.Handler {
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

	// CORS. The override argument is left nil so NewCORSFromConfig
	// reads from app.cfg.CORS.AllowedOrigins.
	h = middleware.NewCORSFromConfig(h, *app.cfg, nil)

	// Request logging.
	h = middleware.NewRequestLogger(h, middleware.RequestLoggerConfig{Logger: logger})

	// Telemetry (counters + latency histograms).
	h = middleware.NewTelemetry(h, middleware.TelemetryConfig{
		Metrics: app.metrics,
		RoutePatterns: []middleware.RoutePattern{
			{Prefix: "/v1/escalation/", Label: "/v1/escalation/:id"},
			{Prefix: "/l/", Label: "/l/:token"},
		},
	})

	return h
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
