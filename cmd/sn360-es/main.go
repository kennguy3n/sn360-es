// Command sn360-es is the service entrypoint that boots configuration,
// connects to NATS / Redis / PostgreSQL, and runs the HTTP server alongside
// any configured event-bus listeners.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/handler"
	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/internal/service/cache"
	"github.com/kennguy3n/sn360-es/internal/service/dashboard"
	"github.com/kennguy3n/sn360-es/internal/service/education"
	"github.com/kennguy3n/sn360-es/internal/service/predict"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/events/bus"
	natsbus "github.com/kennguy3n/sn360-es/pkg/events/nats"
	redisbus "github.com/kennguy3n/sn360-es/pkg/events/redis"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
	"github.com/kennguy3n/sn360-es/pkg/storage/redis"
	"github.com/kennguy3n/sn360-es/pkg/telemetry"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sn360-es: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.MustLoad()
	logger := newLogger(&cfg)
	logger.Info("sn360-es: starting",
		slog.String("app", cfg.AppName),
		slog.String("env", string(cfg.Environment)),
		slog.String("event_bus", string(cfg.EventBus)))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	app, err := newApplication(ctx, &cfg, logger)
	if err != nil {
		return err
	}
	defer app.Close(logger)

	mux, err := buildMux(app)
	if err != nil {
		return fmt.Errorf("build mux: %w", err)
	}

	httpHandler := wrapMiddleware(mux, app)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTP.Port),
		Handler:           httpHandler,
		ReadHeaderTimeout: cfg.HTTP.ReadTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
	}

	if cerr := app.StartConsumers(ctx); cerr != nil {
		// Critical subscription failures bubble up here. Tear down
		// any partially-wired subscriptions before returning so the
		// bus close (via app.Close) does not race in-flight handlers.
		app.StopConsumers(logger)
		return fmt.Errorf("start consumers: %w", cerr)
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("sn360-es: http server listening", slog.Int("port", cfg.HTTP.Port))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("sn360-es: shutdown signal received")
	case err := <-serveErr:
		return fmt.Errorf("http server: %w", err)
	}

	// Close subscriptions before shutting down the bus so in-flight
	// messages can ack cleanly.
	app.StopConsumers(logger)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("sn360-es: http shutdown error", slog.Any("error", err))
	}
	return nil
}

// application bundles every wired dependency so handlers, middleware,
// and consumers can read from a single composition root. Each field is
// optional from the perspective of unit tests; handlers gracefully
// return 503 when their service is nil so a partial wiring still
// produces a navigable mux.
type application struct {
	cfg     *config.Config
	logger  *slog.Logger
	metrics *telemetry.Metrics

	eventBus events.EventService
	pgDB     *postgres.DB
	redis    *redis.Client
	repos    *repository.Registry

	// Privacy + caches.
	jwtIssuer   *privacy.JWTIssuer
	aiCache     *cache.AICache
	rspamdCache *cache.RspamdCache

	// HTTP-facing services.
	bannerRenderer *action.BannerRenderer
	feedbackSvc    *action.FeedbackService
	releaseSvc     *action.ReleaseService
	urlRewriter    *action.URLRewriter
	microLessonSvc *education.MicroLessonService
	simulationEng  *education.SimulationEngine
	dashboardGen   *dashboard.DashboardGenerator
	recipientSvc   *predict.RecipientService
	openSvc        *predict.OpenService
	escalationSvc  *agent.EscalationService

	// Lifecycle.
	subs    []events.Subscription
	subsMu  sync.Mutex
	closers []func() error
	dlqProc *service.DLQProcessor
}

// newApplication wires every component the binary needs. Required
// pieces (event bus) hard-fail; optional pieces (postgres, redis, JWT
// secret) log warnings and leave their consumers in a degraded mode so
// the binary still answers /healthz and the routes that do not require
// the missing dependency.
func newApplication(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*application, error) {
	app := &application{cfg: cfg, logger: logger, metrics: telemetry.DefaultMetrics()}

	// Event bus is required. The factory understands "memory" so unit
	// tests and offline dev runs do not need a broker.
	eventBus, err := bus.New(ctx, factoryConfigFromAppConfig(cfg), logger)
	if err != nil {
		return nil, fmt.Errorf("event bus: %w", err)
	}
	app.eventBus = eventBus
	app.closers = append(app.closers, func() error {
		return bus.CloseWithTimeout(eventBus, 5*time.Second)
	})

	// Postgres is optional but strongly preferred. When it cannot be
	// reached we log and continue so the binary still answers
	// /healthz, /metrics, and the auth-token endpoints.
	if cfg.Postgres.Host != "" && cfg.Postgres.Database != "" {
		pgDB, perr := postgres.Open(ctx, postgres.Config{
			Host:            cfg.Postgres.Host,
			Port:            cfg.Postgres.Port,
			User:            cfg.Postgres.User,
			Password:        cfg.Postgres.Password,
			Database:        cfg.Postgres.Database,
			SSLMode:         cfg.Postgres.SSLMode,
			MaxOpenConns:    cfg.Postgres.MaxOpenConns,
			MaxIdleConns:    cfg.Postgres.MaxIdleConns,
			ConnMaxLifetime: cfg.Postgres.ConnMaxLifetime,
		})
		if perr != nil {
			logger.Warn("sn360-es: postgres unavailable; continuing without repository layer",
				slog.Any("error", perr))
		} else {
			app.pgDB = pgDB
			app.repos = repository.NewPostgresRegistry(pgDB)
			app.closers = append(app.closers, pgDB.Close)
		}
	} else {
		logger.Info("sn360-es: postgres not configured; repository layer disabled")
	}

	// Redis is required for the AI/Rspamd verdict caches and for the
	// URL-rewriter pre-image store. Same degraded-mode behaviour as
	// Postgres.
	if cfg.Redis.Addr != "" {
		redisClient, rerr := redis.New(ctx, redis.Config{
			Addr:         cfg.Redis.Addr,
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			PoolSize:     cfg.Redis.PoolSize,
			MinIdleConns: cfg.Redis.MinIdleConns,
			DialTimeout:  cfg.Redis.DialTimeout,
			ReadTimeout:  cfg.Redis.ReadTimeout,
			WriteTimeout: cfg.Redis.WriteTimeout,
		})
		if rerr != nil {
			logger.Warn("sn360-es: redis unavailable; verdict caches disabled",
				slog.Any("error", rerr))
		} else {
			app.redis = redisClient
			app.closers = append(app.closers, redisClient.Close)
			if c, cerr := cache.NewAICache(redisClient, cache.AICacheConfig{}); cerr == nil {
				app.aiCache = c
			} else {
				logger.Warn("sn360-es: ai cache init failed", slog.Any("error", cerr))
			}
			if c, cerr := cache.NewRspamdCache(redisClient, cache.RspamdCacheConfig{}); cerr == nil {
				app.rspamdCache = c
			} else {
				logger.Warn("sn360-es: rspamd cache init failed", slog.Any("error", cerr))
			}
		}
	} else {
		logger.Info("sn360-es: redis not configured; verdict caches disabled")
	}

	// JWT issuer underpins the banner-action, quarantine-release, and
	// interstitial flows. The privacy.NewJWTIssuer constructor
	// enforces the minimum-length invariant; we only need to skip
	// the call when the operator left the secret empty.
	if cfg.Banner.TokenSecret != "" {
		ttl := cfg.Banner.TokenTTL
		if ttl <= 0 {
			ttl = 30 * 24 * time.Hour
		}
		issuer, jerr := privacy.NewJWTIssuer(privacy.JWTConfig{
			Secret: []byte(cfg.Banner.TokenSecret),
			Issuer: "sn360-es",
			TTL:    ttl,
		})
		if jerr != nil {
			logger.Warn("sn360-es: jwt issuer init failed", slog.Any("error", jerr))
		} else {
			app.jwtIssuer = issuer
		}
	} else {
		logger.Info("sn360-es: banner token secret not configured; signed-action flows disabled")
	}

	// Banner renderer (HTML templates). Always wireable — uses
	// embedded i18n catalogs.
	if catalog, cerr := action.DefaultBannerCatalog(); cerr == nil {
		if renderer, rerr := action.NewBannerRenderer(catalog); rerr == nil {
			app.bannerRenderer = renderer
		} else {
			logger.Warn("sn360-es: banner renderer init failed", slog.Any("error", rerr))
		}
	} else {
		logger.Warn("sn360-es: banner i18n catalog load failed", slog.Any("error", cerr))
	}

	// Feedback service consumes verified action tokens. ReEvaluator
	// is nil here because the synchronous evaluator path lives in
	// management-svc; the asynchronous consumer below republishes
	// feedback for downstream re-evaluation.
	if app.jwtIssuer != nil {
		app.feedbackSvc = action.NewFeedbackService(logger, app.jwtIssuer, eventBus, nil)
	}

	// Release service for /v1/quarantine/release. The synchronous
	// quarantine + re-evaluator are not wired in this binary yet; the
	// release service still publishes audit events through the bus.
	if rsvc, rerr := action.NewReleaseService(action.ReleaseConfig{
		Logger:    logger,
		Publisher: eventBus,
	}); rerr == nil {
		app.releaseSvc = rsvc
	} else {
		logger.Warn("sn360-es: release service init failed", slog.Any("error", rerr))
	}

	// URL rewriter for outbound mail. Skipped when Redis is missing
	// (pre-image store) or when the JWT issuer is absent (no token).
	if app.jwtIssuer != nil && app.redis != nil {
		urlEncryptor, eerr := buildURLEncryptor(cfg, logger)
		if eerr != nil {
			logger.Warn("sn360-es: url rewriter disabled — encryptor init failed",
				slog.Any("error", eerr))
		} else {
			rewriter, rerr := action.NewURLRewriter(
				logger, app.jwtIssuer,
				redisURLStore{client: app.redis},
				urlEncryptor,
				action.URLRewriterConfig{BaseURL: cfg.URLRewrite.Base},
			)
			if rerr == nil {
				app.urlRewriter = rewriter
			} else {
				logger.Warn("sn360-es: url rewriter init failed", slog.Any("error", rerr))
			}
		}
	}

	// Micro-lesson service. The default lesson store ships embedded
	// catalogs so the service is always wireable.
	if store, serr := education.DefaultLessonStore(); serr == nil {
		svc, lerr := education.NewMicroLessonService(education.MicroLessonConfig{
			Store:     store,
			Publisher: eventBus,
			Logger:    logger,
		})
		if lerr == nil {
			app.microLessonSvc = svc
		} else {
			logger.Warn("sn360-es: micro-lesson service init failed", slog.Any("error", lerr))
		}
	} else {
		logger.Warn("sn360-es: lesson catalog load failed", slog.Any("error", serr))
	}

	// Simulation engine — memory-backed store + embedded templates.
	// The sender stays nil so dry-run campaigns remain testable; real
	// send-out only happens once a provider sender is wired.
	if eng, eerr := education.NewSimulationEngine(education.EngineConfig{
		Store:     education.NewMemoryCampaignStore(),
		Templates: education.NewTemplateLibrary(),
		Publisher: eventBus,
		Logger:    logger,
	}); eerr == nil {
		app.simulationEng = eng
	} else {
		logger.Warn("sn360-es: simulation engine init failed", slog.Any("error", eerr))
	}

	// Recipient + Open predict services. Both depend only on optional
	// look-ups so they are always wireable.
	app.recipientSvc = predict.NewRecipientService(predict.RecipientServiceConfig{})
	app.openSvc = predict.NewOpenService(predict.OpenServiceConfig{})

	// Escalation service uses the in-memory ticket store by default;
	// production wires a Postgres-backed implementation through the
	// repository registry once the management API merges.
	if esc, eerr := agent.NewEscalationService(agent.EscalationServiceConfig{
		Publisher: escalationPublisherAdapter{bus: eventBus},
		Store:     agent.NewMemoryTicketStore(),
		Logger:    logger,
	}); eerr == nil {
		app.escalationSvc = esc
	} else {
		logger.Warn("sn360-es: escalation service init failed", slog.Any("error", eerr))
	}

	// Dashboard generator. The MetricsSource is backed by Postgres
	// when the management schema is reachable; without it the
	// generator stays nil and the /v1/dashboard handler responds 503
	// (the contract documented in README "Project Status"). The
	// narrative slot is intentionally left nil so the generator falls
	// back to the deterministic narrative — wiring the support agent
	// here would couple it to the LLM tier, which is optional.
	if app.pgDB != nil {
		src, serr := dashboard.NewPostgresSource(app.pgDB)
		if serr != nil {
			logger.Warn("sn360-es: dashboard metrics source init failed",
				slog.Any("error", serr))
		} else if gen, gerr := dashboard.NewDashboardGenerator(dashboard.DashboardGeneratorConfig{
			Source: src,
			Logger: logger,
		}); gerr != nil {
			logger.Warn("sn360-es: dashboard generator init failed",
				slog.Any("error", gerr))
		} else {
			app.dashboardGen = gen
		}
	} else {
		logger.Info("sn360-es: dashboard generator disabled (postgres not configured)")
	}

	return app, nil
}

// Close runs every registered closer in reverse order. Errors are
// logged but never returned — shutdown should always make progress.
func (a *application) Close(logger *slog.Logger) {
	for i := len(a.closers) - 1; i >= 0; i-- {
		if err := a.closers[i](); err != nil {
			logger.Warn("sn360-es: closer error", slog.Any("error", err))
		}
	}
}

// StartConsumers subscribes to the event subjects this binary handles.
// All subscriptions are tracked so StopConsumers can drain them in
// reverse order before the bus closes.
//
// Subscriptions are classified as critical or best-effort:
//
//   - critical: their dependent service is fully wired and we cannot
//     deliver the documented behaviour without them. A critical
//     subscription failure is returned as an error so the binary
//     fails fast instead of pretending to be healthy.
//   - best-effort: their dependent service is missing or the
//     subscription is purely opportunistic (e.g. DLQ log-only). We
//     log a warning and continue.
//
// In practice the management-persist consumer is critical when the
// repository layer is wired, and the education-trigger consumer is
// critical when the micro-lesson service is wired. The DLQ processor
// is always best-effort.
func (a *application) StartConsumers(ctx context.Context) error {
	if a.eventBus == nil {
		return nil
	}

	var critErrs []error

	// es.evaluate.result → persist to the management Postgres layer.
	if a.repos != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.evaluate.result", a.handleEvaluateResult,
			events.WithDurable("management-persist"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe evaluate.result (management-persist) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("management-persist: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.evaluate.result → trigger contextual micro-lessons.
	if a.microLessonSvc != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.evaluate.result", a.handleEducationTrigger,
			events.WithDurable("education-trigger"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe evaluate.result (education-trigger) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("education-trigger: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// DLQ processor — best-effort. It watches the canonical DLQ
	// subjects and logs each failed message; without it the system
	// still functions, the operator just loses the structured failed-
	// message signal.
	dlq, derr := service.NewDLQProcessor(service.DLQProcessorConfig{
		Bus: a.eventBus,
		// Default to log-only so the processor never silently
		// retries messages that the operator has not opted into.
		Decider: service.DeciderFunc(func(_ context.Context, _ events.Message) service.Decision {
			return service.Decision{Action: service.ActionLogOnly, Reason: "default"}
		}),
		Republisher: a.eventBus,
		Logger:      a.logger,
	})
	if derr != nil {
		a.logger.Warn("sn360-es: dlq processor init failed", slog.Any("error", derr))
	} else if serr := dlq.Start(ctx); serr != nil {
		a.logger.Warn("sn360-es: dlq processor start failed", slog.Any("error", serr))
	} else {
		a.dlqProc = dlq
	}

	if len(critErrs) > 0 {
		return fmt.Errorf("sn360-es: critical consumer subscriptions failed: %w",
			errors.Join(critErrs...))
	}
	return nil
}

// StopConsumers closes every subscription previously registered and
// stops the DLQ processor. Errors are logged but never returned.
func (a *application) StopConsumers(logger *slog.Logger) {
	if a.dlqProc != nil {
		if err := a.dlqProc.Stop(); err != nil {
			logger.Warn("sn360-es: dlq processor stop error", slog.Any("error", err))
		}
		a.dlqProc = nil
	}
	a.subsMu.Lock()
	subs := a.subs
	a.subs = nil
	a.subsMu.Unlock()
	for i := len(subs) - 1; i >= 0; i-- {
		if err := subs[i].Close(); err != nil {
			logger.Warn("sn360-es: subscription close error", slog.Any("error", err))
		}
	}
}

func (a *application) trackSub(sub events.Subscription) {
	a.subsMu.Lock()
	a.subs = append(a.subs, sub)
	a.subsMu.Unlock()
}

func (a *application) handleEvaluateResult(ctx context.Context, msg events.Message) error {
	if a.repos == nil {
		return nil
	}
	var res dto.EvaluateResult
	if err := json.Unmarshal(msg.Data(), &res); err != nil {
		a.logger.Warn("sn360-es: evaluate.result unmarshal failed", slog.Any("error", err))
		return nil // poison message; drop rather than redeliver
	}
	row := evaluateResultRow(res, msg)
	if err := a.repos.EvaluationResults.Create(ctx, row); err != nil {
		return fmt.Errorf("persist evaluate.result: %w", err)
	}
	return nil
}

// handleEducationTrigger fans evaluation results out to the
// micro-lesson trigger subject so the resilience scorer can credit
// engagement when the user later reads the lesson. The actual
// HTTP-served lesson is fetched on demand by the email banner via
// /v1/education/lesson/{category}.
func (a *application) handleEducationTrigger(ctx context.Context, msg events.Message) error {
	if a.eventBus == nil {
		return nil
	}
	var res dto.EvaluateResult
	if err := json.Unmarshal(msg.Data(), &res); err != nil {
		return nil
	}
	if !triggersLesson(res) {
		return nil
	}
	trigger := map[string]string{
		"tenant_id": res.TenantID,
		"category":  string(res.Primary),
		"tier":      string(res.Tier),
	}
	data, err := json.Marshal(trigger)
	if err != nil {
		return nil
	}
	opts := []events.PublishOption{
		events.WithTenantID(res.TenantID),
		events.WithCorrelationID(res.CorrelationID),
	}
	if err := a.eventBus.Publish(ctx, "es.education.trigger", data, opts...); err != nil {
		// Best-effort fan-out: we deliberately swallow the error so
		// a transient bus failure does not redeliver the original
		// es.evaluate.result message (the persist consumer has
		// already handled it, redelivery would double-write).
		// Log at Error with the correlation/tenant ids so the
		// silent drop is loud in observability.
		a.logger.ErrorContext(ctx, "sn360-es: education trigger publish failed; lesson trigger dropped",
			slog.String("tenant_id", res.TenantID),
			slog.String("correlation_id", res.CorrelationID),
			slog.String("tier", string(res.Tier)),
			slog.String("category", string(res.Primary)),
			slog.Any("error", err),
		)
	}
	return nil
}

// buildMux constructs the HTTP routing tree. Handlers from
// internal/handler are wired here so future routes have one obvious
// place to register.
func buildMux(app *application) (http.Handler, error) {
	if app == nil {
		return nil, errors.New("buildMux: app is required")
	}
	logger := app.logger
	mux := http.NewServeMux()

	checkers := []handler.HealthChecker{
		handler.HealthCheckerFunc{N: "event_bus", F: func(ctx context.Context) error {
			if app.eventBus == nil {
				return errors.New("event bus not configured")
			}
			// Health is the canonical side-effect-free liveness
			// probe; for NATS it round-trips AccountInfo, for
			// Redis it PINGs. Publishing on every readiness probe
			// would emit messages to a stream that may or may not
			// exist and is the wrong shape for a k8s probe.
			return app.eventBus.Health(ctx)
		}},
	}
	if app.pgDB != nil {
		pg := app.pgDB
		checkers = append(checkers, handler.HealthCheckerFunc{N: "postgres", F: func(ctx context.Context) error {
			return pg.PingContext(ctx)
		}})
	}
	if app.redis != nil {
		raw := app.redis.Raw()
		checkers = append(checkers, handler.HealthCheckerFunc{N: "redis", F: func(ctx context.Context) error {
			return raw.Ping(ctx).Err()
		}})
	}
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
	// reads from app.cfg.CORS.AllowedOrigins (CORS_ALLOWED_ORIGINS
	// env var) and falls back to wildcard in dev / empty in prod.
	h = middleware.NewCORSFromConfig(h, *app.cfg, nil)

	// Request logging — the logger is already wrapped with the log
	// sanitizer so PII never reaches the structured log stream.
	h = middleware.NewRequestLogger(h, middleware.RequestLoggerConfig{Logger: logger})

	// Telemetry (counters + latency histograms; tracing optional).
	// The route patterns collapse parameterised paths so Prometheus
	// does not see one series per ticket id / signed URL token. Add
	// new patterns here when introducing routes with path params.
	h = middleware.NewTelemetry(h, middleware.TelemetryConfig{
		Metrics: app.metrics,
		RoutePatterns: []middleware.RoutePattern{
			{Prefix: "/v1/escalation/", Label: "/v1/escalation/:id"},
			{Prefix: "/l/", Label: "/l/:token"},
		},
	})

	return h
}

func defaultAuthSkipPaths() []string {
	return []string{
		"/healthz",
		"/readyz",
		"/metrics",
		"/docs",
		"/docs/",
		"/openapi.yaml",
		// Public click handler — auth happens inside via the
		// short-lived URL token, not via Bearer.
		"/l/",
		// Banner-action / quarantine-release / interstitial flows
		// authenticate through their own signed tokens.
		"/v1/banner/action",
		"/v1/quarantine/release",
	}
}

// triggersLesson reports whether the evaluation tier warrants a
// contextual micro-lesson. Anything below Warning is too low signal
// to interrupt the user with a lesson.
func triggersLesson(res dto.EvaluateResult) bool {
	switch res.Tier {
	case constant.TierWarning, constant.TierHighRisk, constant.TierBlocked:
		return true
	}
	return false
}

// evaluateResultRow projects a DTO into the repository row shape. The
// repository layer is the authoritative persistence shape, so this
// function intentionally drops fields that are scoped to the bus envelope
// (delivery counts, ack tokens, etc.).
func evaluateResultRow(res dto.EvaluateResult, msg events.Message) *repository.EvaluationResult {
	tenantID := res.TenantID
	correlationID := res.CorrelationID
	if msg != nil {
		headers := msg.Headers()
		if v := headers[events.HeaderTenantID]; v != "" {
			tenantID = v
		}
		if v := headers[events.HeaderCorrelationID]; v != "" {
			correlationID = v
		}
	}
	secondary := make([]string, 0, len(res.Secondary))
	for _, c := range res.Secondary {
		secondary = append(secondary, string(c))
	}
	reasons := append([]string(nil), res.ReasonCodes...)
	evaluatedAt := res.EvaluatedAt
	if evaluatedAt.IsZero() {
		evaluatedAt = time.Now().UTC()
	}
	return &repository.EvaluationResult{
		TenantID:      tenantID,
		MessageIDHash: []byte(res.MessageID),
		CorrelationID: correlationID,
		Score:         res.Score,
		Tier:          string(res.Tier),
		Primary:       string(res.Primary),
		Secondary:     secondary,
		ReasonCodes:   reasons,
		Degraded:      res.Degraded,
		EvaluatedAt:   evaluatedAt,
	}
}

// redisURLStore adapts our redis.Client to the action.URLStore
// interface — the rewriter only needs Get/Set/TTL helpers.
type redisURLStore struct{ client *redis.Client }

func (s redisURLStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return s.client.Set(ctx, key, value, ttl)
}

func (s redisURLStore) Get(ctx context.Context, key string) (string, bool, error) {
	return s.client.Get(ctx, key)
}

// passthroughEncryptor is a last-resort URLEncryptor that returns the
// input unchanged. It is used only when the operator has explicitly
// disabled KMS (AWS_KMS_USE_MOCK=false + empty AWS_KMS_MASTER_KEY_ID)
// — buildURLEncryptor logs a loud warning in that case so the
// pre-image store going plaintext in Redis is never silent.
type passthroughEncryptor struct{}

func (passthroughEncryptor) Encrypt(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}

func (passthroughEncryptor) Decrypt(_ context.Context, _ string, ciphertext []byte) ([]byte, error) {
	return append([]byte(nil), ciphertext...), nil
}

// buildURLEncryptor returns the action.URLEncryptor the URL rewriter
// should use to wrap pre-images before writing them to Redis. The
// selection ladder is:
//
//  1. cfg.AWS.KMSUseMock=true (the default for non-prod) — build a
//     privacy.MockKMS and wrap it in privacy.NewEncryptor. The mock
//     KMS is AES-256-GCM in-process and produces real ciphertext, so
//     Redis values are encrypted at rest even in dev.
//  2. cfg.AWS.KMSUseMock=false and cfg.AWS.KMSMasterKeyID set — in
//     production this branch should be wired to a real AWS KMS
//     client. We do not have one in-repo today, so we fall back to a
//     deterministic MockKMS seeded with the master-key-id and log a
//     warning so the gap is visible.
//  3. cfg.AWS.KMSUseMock=false and KMSMasterKeyID empty — operator
//     has explicitly opted out of envelope encryption. We log a loud
//     warning and return passthroughEncryptor so the rewriter still
//     functions in tightly controlled environments (e.g. internal
//     test rigs where the pre-image store is not sensitive).
func buildURLEncryptor(cfg *config.Config, logger *slog.Logger) (action.URLEncryptor, error) {
	if cfg == nil {
		return nil, errors.New("buildURLEncryptor: nil config")
	}
	if cfg.AWS.KMSUseMock {
		var rootKey []byte
		if seed := strings.TrimSpace(cfg.AWS.KMSMockKeyHex); seed != "" {
			decoded, derr := hex.DecodeString(seed)
			if derr == nil && len(decoded) == 32 {
				rootKey = decoded
			} else {
				logger.Warn("sn360-es: AWS_KMS_MOCK_KEY_HEX is not 32 hex bytes; using random root key",
					slog.Int("seed_len", len(decoded)),
					slog.Any("error", derr),
				)
			}
		}
		kms, err := privacy.NewMockKMS(rootKey)
		if err != nil {
			return nil, fmt.Errorf("buildURLEncryptor: mock KMS: %w", err)
		}
		enc, err := privacy.NewEncryptor(privacy.EncryptorConfig{KMS: kms})
		if err != nil {
			return nil, fmt.Errorf("buildURLEncryptor: encryptor: %w", err)
		}
		logger.Info("sn360-es: url rewriter using mock KMS encryptor (envelope encryption in-process)")
		return enc, nil
	}
	if strings.TrimSpace(cfg.AWS.KMSMasterKeyID) != "" {
		// Real AWS KMS client wiring belongs here. Until that is
		// added, fall back to a MockKMS seeded so the key-id is
		// stable across restarts in the same deployment.
		rootKey := derivedRootKey(cfg.AWS.KMSMasterKeyID)
		kms, err := privacy.NewMockKMS(rootKey)
		if err != nil {
			return nil, fmt.Errorf("buildURLEncryptor: derived KMS: %w", err)
		}
		enc, err := privacy.NewEncryptor(privacy.EncryptorConfig{KMS: kms})
		if err != nil {
			return nil, fmt.Errorf("buildURLEncryptor: encryptor: %w", err)
		}
		logger.Warn("sn360-es: url rewriter using derived-from-key-id mock KMS — wire a real AWS KMS client for production",
			slog.String("master_key_id", cfg.AWS.KMSMasterKeyID),
		)
		return enc, nil
	}
	logger.Warn("sn360-es: url rewriter falling back to passthrough encryptor — URL pre-images will be stored UNENCRYPTED in Redis. Set AWS_KMS_USE_MOCK=true or AWS_KMS_MASTER_KEY_ID to fix.")
	return passthroughEncryptor{}, nil
}

// derivedRootKey expands an arbitrary key-id string into a 32-byte
// AES-256 root key for the mock KMS. SHA-256 keeps the mapping
// deterministic so two processes started with the same master key id
// share the same MockKMS root key (within a single deployment).
func derivedRootKey(id string) []byte {
	sum := sha256.Sum256([]byte("sn360-es:mock-kms:" + id))
	return sum[:]
}

// escalationPublisherAdapter narrows events.EventService down to the
// (Publish-only) shape the escalation service requires.
type escalationPublisherAdapter struct{ bus events.EventService }

func (a escalationPublisherAdapter) Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	if a.bus == nil {
		return nil
	}
	return a.bus.Publish(ctx, subject, data, opts...)
}

func factoryConfigFromAppConfig(cfg *config.Config) bus.Config {
	return bus.Config{
		Type:   bus.Type(cfg.EventBus),
		Source: cfg.AppName,
		NATS: natsbus.Config{
			URL:                  cfg.NATS.URL,
			Name:                 cfg.AppName,
			User:                 cfg.NATS.User,
			Password:             cfg.NATS.Password,
			Token:                cfg.NATS.Token,
			CredsFile:            cfg.NATS.CredsFile,
			TLSCAFile:            cfg.NATS.TLSCAFile,
			TLSCertFile:          cfg.NATS.TLSCertFile,
			TLSKeyFile:           cfg.NATS.TLSKeyFile,
			TLSInsecure:          cfg.NATS.TLSInsecure,
			ReconnectWait:        cfg.NATS.ReconnectWait,
			MaxReconnects:        cfg.NATS.MaxReconnects,
			RequestTimeout:       cfg.NATS.RequestTimeout,
			PublishRetryAttempts: cfg.NATS.PublishRetryAttempts,
			PublishRetryDelay:    cfg.NATS.PublishRetryDelay,
			DedupWindow:          cfg.NATS.DedupWindow,
			Replicas:             cfg.NATS.Replicas,
			Storage:              cfg.NATS.Storage,
			FetchBatchSize:       cfg.NATS.FetchBatchSize,
			FetchMaxWait:         cfg.NATS.FetchMaxWait,
		},
		Redis: redisbus.Config{
			Addr:           cfg.Redis.Addr,
			DB:             cfg.Redis.DB,
			Password:       cfg.Redis.Password,
			PoolSize:       cfg.Redis.PoolSize,
			ReadBlock:      cfg.Redis.ConsumerBlock,
			FetchBatchSize: cfg.Redis.FetchBatchSize,
		},
	}
}

func newLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Log.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	var h slog.Handler
	if cfg.Log.Format == "text" {
		h = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	} else {
		h = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	return slog.New(middleware.NewLogSanitizer(h, privacy.NewSanitizer()))
}
