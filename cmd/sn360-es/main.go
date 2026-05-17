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
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/internal/service/predict"
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
	"github.com/kennguy3n/sn360-es/internal/service/tier1"
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
	bannerRenderer    *action.BannerRenderer
	feedbackSvc       *action.FeedbackService
	releaseSvc        *action.ReleaseService
	urlRewriter       *action.URLRewriter
	microLessonSvc    *education.MicroLessonService
	simulationEng     *education.SimulationEngine
	simulationTracker *education.SimulationTracker
	dashboardGen      *dashboard.DashboardGenerator
	recipientSvc      *predict.RecipientService
	openSvc           *predict.OpenService
	escalationSvc     *agent.EscalationService

	// Evaluation pipeline. Tier 0 is always wireable (pure CPU); the
	// other clients are optional and stay nil when their endpoints are
	// unconfigured or unreachable. The evaluator itself is constructed
	// even in fully-degraded mode so the consumer wiring stays uniform
	// — its markDegraded path handles a nil Tier 1 / Tier 2 / Rspamd
	// at runtime.
	tier0Gate    *tier0.Gate
	tier1Raw     *tier1.Client
	tier1Client  evaluate.Tier1Client
	tier2Client  evaluate.Tier2Client
	rspamdClient evaluate.RspamdClient
	evaluator    *evaluate.Evaluator
	batchOrch    *evaluate.BatchOrchestrator

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

	// Quarantine service + release service for /v1/quarantine/release.
	//
	// The quarantine service needs a store (redis if available, in-memory
	// fallback so tests + dev still work) and an encryptor (the same
	// envelope-encryption ladder we use for the URL pre-image store).
	// Provider implementations (Gmail, O365) live elsewhere and are
	// wired in by deployment-specific binaries; when no providers are
	// registered, the service still serves LookupReference / persist
	// paths but Release() rejects with "no provider registered".
	if qencryptor, eerr := buildURLEncryptor(cfg, logger); eerr != nil {
		logger.Warn("sn360-es: quarantine encryptor init failed", slog.Any("error", eerr))
	} else {
		qstore := newQuarantineStore(app.redis)
		qsvc, qerr := action.NewQuarantineService(action.QuarantineConfig{
			Logger:    logger,
			Store:     qstore,
			Encryptor: qencryptor,
			Publisher: eventBus,
		})
		if qerr != nil {
			logger.Warn("sn360-es: quarantine service init failed", slog.Any("error", qerr))
		} else {
			// Reevaluator looks up the most recent evaluation_result
			// for (tenant, pseudo_message_id). The repository layer is
			// the source of truth for the latest verdict; the
			// asynchronous evaluator updates it whenever a fresh
			// scoring pass completes. When no repos are wired we fall
			// back to a conservative "still blocked" verdict so the
			// release flow does not accidentally restore messages
			// without re-checking them.
			reevaluator := newLatestVerdictReevaluator(app.repos, logger)
			rsvc, rerr := action.NewReleaseService(action.ReleaseConfig{
				Logger:      logger,
				Quarantine:  qsvc,
				Reevaluator: reevaluator,
				Publisher:   eventBus,
			})
			if rerr == nil {
				app.releaseSvc = rsvc
			} else {
				logger.Warn("sn360-es: release service init failed", slog.Any("error", rerr))
			}
		}
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

	// Simulation tracker — memory-backed InteractionStore so the
	// es.education.simulation.result consumer has somewhere to land
	// interactions until a Postgres-backed store is wired. Publisher
	// is intentionally nil here because the tracker writes the same
	// `es.education.simulation.result` subject the consumer is reading
	// from; re-publishing would cause an infinite loop.
	if tracker, terr := education.NewSimulationTracker(education.TrackerConfig{
		Store:  education.NewMemoryInteractionStore(),
		Logger: logger,
	}); terr == nil {
		app.simulationTracker = tracker
	} else {
		logger.Warn("sn360-es: simulation tracker init failed", slog.Any("error", terr))
	}

	// Recipient + Open predict services. Both depend only on optional
	// look-ups so they are always wireable.
	app.recipientSvc = predict.NewRecipientService(predict.RecipientServiceConfig{})
	app.openSvc = predict.NewOpenService(predict.OpenServiceConfig{})

	// Escalation service. Tickets land in escalation_tickets when a
	// Postgres connection is available so the dashboard FalseRates
	// aggregate has rows to count; otherwise the in-memory store keeps
	// the HTTP path working in dev / test.
	var ticketStore agent.TicketStore
	if app.pgDB != nil {
		ticketStore = agent.NewPostgresTicketStore(app.pgDB)
	} else {
		ticketStore = agent.NewMemoryTicketStore()
	}
	if esc, eerr := agent.NewEscalationService(agent.EscalationServiceConfig{
		Publisher: escalationPublisherAdapter{bus: eventBus},
		Store:     ticketStore,
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
		cfg := dashboard.PostgresSourceConfig{}
		if app.repos != nil && app.repos.FeedbackEvents != nil {
			cfg.Feedback = feedbackCountsAdapter{repo: app.repos.FeedbackEvents}
		}
		src, serr := dashboard.NewPostgresSourceWithConfig(app.pgDB, cfg)
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

	// Evaluation pipeline.
	//
	// Tier 0 is pure-CPU and has no external dependencies, so we always
	// wire it. Tier 1, Tier 2, and Rspamd each require an external
	// service; failure to reach any of them is non-fatal — the
	// evaluator's markDegraded path keeps verdicts flowing with
	// reduced signal. We still construct the evaluator unconditionally
	// so the consumer wiring in StartConsumers can treat it as the
	// single entry point.
	app.tier0Gate = tier0.NewGate(tier0.GateConfig{
		SkipInternal:         cfg.Tier0.SkipInternal,
		SkipVendor:           cfg.Tier0.SkipVendor,
		SkipRecurring:        cfg.Tier0.SkipRecurring,
		HighVolumeRspamdOnly: cfg.Tier0.HighVolumeRspamdOnly,
	}, nil)

	if cfg.Tier1.URL != "" {
		t1, err := tier1.New(tier1.Config{
			URL:          cfg.Tier1.URL,
			Timeout:      cfg.Tier1.Timeout,
			MaxBatchSize: cfg.Tier1.BatchSize,
		})
		if err != nil {
			logger.Warn("sn360-es: tier1 client init failed; evaluator will run in degraded mode",
				slog.String("url", cfg.Tier1.URL),
				slog.Any("error", err))
		} else {
			app.tier1Raw = t1
			app.tier1Client = evaluate.NewTier1Adapter(t1, tier1.Thresholds{
				PassBelow: cfg.Tier1.PassThreshold,
				FlagAbove: cfg.Tier1.FlagThreshold,
			})
		}
	} else {
		logger.Info("sn360-es: TIER1_URL not configured; tier1 encoder client disabled")
	}

	if cfg.AI.URL != "" {
		t2, err := evaluate.NewTier2HTTPClient(evaluate.Tier2HTTPConfig{
			URL:     cfg.AI.URL,
			APIKey:  cfg.AI.APIKey,
			Timeout: cfg.AI.Timeout,
		})
		if err != nil {
			logger.Warn("sn360-es: tier2 client init failed; evaluator will skip LLM escalation",
				slog.String("url", cfg.AI.URL),
				slog.Any("error", err))
		} else {
			app.tier2Client = t2
		}
	} else {
		logger.Info("sn360-es: AI_URL not configured; tier2 LLM client disabled")
	}

	if cfg.Rspamd.URL != "" {
		rs, err := evaluate.NewRspamdHTTPClient(evaluate.RspamdHTTPConfig{
			URL:      cfg.Rspamd.URL,
			Password: cfg.Rspamd.Password,
			Timeout:  cfg.Rspamd.Timeout,
		})
		if err != nil {
			logger.Warn("sn360-es: rspamd client init failed; evaluator will skip heuristic scoring",
				slog.String("url", cfg.Rspamd.URL),
				slog.Any("error", err))
		} else {
			app.rspamdClient = rs
		}
	} else {
		logger.Info("sn360-es: RSPAMD_URL not configured; rspamd client disabled")
	}

	tierDecider, derr := action.NewTierDecider(action.TierThresholds{
		Blocked:           cfg.Score.Blocked,
		HighRisk:          cfg.Score.HighRisk,
		Warning:           cfg.Score.Warning,
		Caution:           cfg.Score.Caution,
		Informational:     cfg.Score.Info,
		FirstContactFloor: constant.TierInformational,
	})
	if derr != nil {
		return nil, fmt.Errorf("tier decider: %w", derr)
	}

	app.evaluator = evaluate.NewEvaluator(evaluate.Config{
		Tier0:              app.tier0Gate,
		Tier1:              app.tier1Client,
		Tier2:              app.tier2Client,
		Rspamd:             app.rspamdClient,
		Categorizer:        evaluate.NewRuleCategorizer(),
		TierDecider:        tierDeciderAdapter{decider: tierDecider},
		Weights:            evaluate.DefaultWeights(),
		Tier1PassThreshold: cfg.Tier1.PassThreshold,
		Tier1FlagThreshold: cfg.Tier1.FlagThreshold,
		Tier1Timeout:       cfg.Tier1.Timeout,
		Tier2Timeout:       cfg.AI.Timeout,
		RspamdTimeout:      cfg.Rspamd.Timeout,
		Logger:             logger,
		Observer:           app.metrics.PipelineObserver(),
	})

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

	// es.action.feedback.> → persist each verified banner click into
	// feedback_events (migration 0002) so the dashboard FeedbackStats
	// aggregate has rows to count. Critical only when both the
	// repository layer and the feedback service are wired; in dev or
	// when Postgres is missing the dashboard surfaces zero counts and
	// the bus messages flow through unblocked.
	if a.repos != nil && a.repos.FeedbackEvents != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.feedback.>", a.handleFeedbackPersist,
			events.WithDurable("feedback-persist"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe action.feedback (feedback-persist) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("feedback-persist: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.evaluate.request → the multi-tier detection pipeline.
	// This is the documented entry point for the evaluation flow
	// (ARCHITECTURE.md §2): ingestion-svc publishes one
	// EvaluateRequest per discovered message, this consumer fans it
	// through Tier 0 → Tier 1 → Tier 2 → Rspamd via the evaluator,
	// and publishes the resulting EvaluateResult on
	// `es.evaluate.result` for the persist + action consumers to
	// pick up. The evaluator is constructed unconditionally so this
	// subscription is always critical when wired.
	if a.evaluator != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.evaluate.request", a.handleEvaluateRequest,
			events.WithDurable("evaluate-svc"),
			events.WithMaxDeliver(5))
		if err != nil {
			a.logger.Error("sn360-es: subscribe evaluate.request (evaluate-svc) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("evaluate-svc: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.evaluate.result → ingestion-action chain: render the banner,
	// apply the native tier label, rewrite URLs for risky tiers, and
	// quarantine on Blocked. Each step is best-effort; their failures
	// must not block the others or block re-delivery, so we always
	// return nil from the handler. Critical when at least one of the
	// downstream services is wired.
	if a.bannerRenderer != nil || a.urlRewriter != nil || a.releaseSvc != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.evaluate.result", a.handleIngestionAction,
			events.WithDurable("ingestion-action"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe evaluate.result (ingestion-action) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("ingestion-action: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.education.simulation.send → dispatch a campaign through the
	// SimulationEngine. The engine itself is always wired (memory
	// store + embedded templates), so subscription failure is
	// critical: a silent skip would let send requests pile up in the
	// stream.
	if a.simulationEng != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.education.simulation.send", a.handleSimulationSend,
			events.WithDurable("education-sim"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe education.simulation.send (education-sim) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("education-sim: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.education.simulation.result → record per-user interaction
	// outcomes (delivered / opened / clicked / submitted / reported /
	// ignored) into the SimulationTracker so Aggregate() returns
	// up-to-date counts for the dashboard. Best-effort: a missing
	// tracker means we just skip persistence; the stream is
	// independent of the engine path that originally published the
	// interaction.
	if a.simulationTracker != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.education.simulation.result", a.handleSimulationResult,
			events.WithDurable("education-sim-track"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Warn("sn360-es: subscribe education.simulation.result (education-sim-track) failed",
				slog.Any("error", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.onboarding.> → onboarding-side effects (label-applier seed,
	// vendor allowlist warm-up, audit). Until a DirectoryClient is
	// wired the agent itself is not constructed, so this consumer
	// runs in observe-only mode: it logs the event and continues so
	// downstream services that depend on the onboarding stream (e.g.
	// the future user-store hydrator) can still consume the same
	// subject without a separate subscription.
	sub, err := a.eventBus.Subscribe(ctx, "es.onboarding.>", a.handleOnboarding,
		events.WithDurable("ingestion-onboard"),
		events.WithMaxDeliver(3))
	if err != nil {
		a.logger.Warn("sn360-es: subscribe onboarding (ingestion-onboard) failed",
			slog.Any("error", err))
	} else {
		a.trackSub(sub)
	}

	// es.action.quarantine.release → user (or AI agent) released a
	// quarantined message. Calls the ReleaseService which re-attaches
	// the original body in the provider mailbox and publishes the
	// outcome on `es.action.quarantine.release.result`. Critical when
	// the release service is wired.
	if a.releaseSvc != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.quarantine.release", a.handleQuarantineRelease,
			events.WithDurable("quarantine-release"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe quarantine.release (quarantine-release) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("quarantine-release: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.action.escalation.> → fan escalation events (created /
	// resolved) into the EscalationService. Critical when the
	// service is wired.
	if a.escalationSvc != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.escalation.>", a.handleEscalation,
			events.WithDurable("escalation"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe escalation (escalation) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("escalation: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// Optional Tier 1 batch orchestrator. Pulls EvaluateRequest
	// messages in batches of up to BatchSize from `es.evaluate.request`,
	// runs Tier 0 in-process, packs the survivors into a single batched
	// Tier 1 HTTP call, escalates ambiguous verdicts through the full
	// evaluator, and publishes verdicts on the action subject. Only
	// runs when explicitly opted-in via TIER1_BATCH_ENABLED — the
	// per-message consumer above remains the default path.
	if a.batchOrch != nil {
		a.batchOrch.Start(ctx)
		a.logger.Info("sn360-es: tier1 batch orchestrator started")
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

// handleFeedbackPersist writes each verified banner click into the
// feedback_events table so the dashboard FeedbackStats aggregate has
// rows to count. The handler is keyed by subject suffix (the action)
// so a single subscription on `es.action.feedback.>` covers all three
// action types. We deliberately drop malformed payloads (poison
// messages) so the bus does not redeliver them forever.
func (a *application) handleFeedbackPersist(ctx context.Context, msg events.Message) error {
	if a.repos == nil || a.repos.FeedbackEvents == nil {
		return nil
	}
	var evt action.FeedbackEvent
	if err := json.Unmarshal(msg.Data(), &evt); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.feedback unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if evt.TenantID == "" || evt.PseudonymizedMessage == "" || !evt.Action.Valid() {
		a.logger.WarnContext(ctx, "sn360-es: action.feedback missing required fields",
			slog.String("tenant_id", evt.TenantID),
			slog.String("action", string(evt.Action)))
		return nil
	}
	occurred := evt.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	row := &repository.FeedbackEvent{
		TenantID:        evt.TenantID,
		PseudoMessageID: evt.PseudonymizedMessage,
		Action:          string(evt.Action),
		Tier:            evt.Tier,
		CorrelationID:   evt.CorrelationID,
		OccurredAt:      occurred,
	}
	if err := a.repos.FeedbackEvents.Create(ctx, row); err != nil {
		return fmt.Errorf("persist action.feedback: %w", err)
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

// handleEvaluateRequest fans an es.evaluate.request payload through
// the multi-tier evaluator and publishes the verdict on
// `es.evaluate.result`. Malformed payloads (poison messages) are
// dropped — returning nil tells the bus not to redeliver them. Real
// evaluator errors propagate so the bus can retry up to MaxDeliver,
// then DLQ.
func (a *application) handleEvaluateRequest(ctx context.Context, msg events.Message) error {
	if a.evaluator == nil || a.eventBus == nil {
		return nil
	}
	var req dto.EvaluateRequest
	if err := json.Unmarshal(msg.Data(), &req); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: evaluate.request unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if req.MessageID == "" || req.TenantID == "" {
		a.logger.WarnContext(ctx, "sn360-es: evaluate.request missing identifiers",
			slog.String("tenant_id", req.TenantID),
			slog.String("message_id", req.MessageID))
		return nil
	}
	result, err := a.evaluator.Evaluate(ctx, req)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}
	if result.MessageID == "" {
		result.MessageID = req.MessageID
	}
	if result.TenantID == "" {
		result.TenantID = req.TenantID
	}
	if result.CorrelationID == "" {
		result.CorrelationID = req.CorrelationID
	}
	if result.EvaluatedAt.IsZero() {
		result.EvaluatedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(result)
	if err != nil {
		a.logger.WarnContext(ctx, "sn360-es: evaluate.result marshal failed",
			slog.Any("error", err))
		return nil
	}
	if err := a.eventBus.Publish(ctx, "es.evaluate.result", payload,
		events.WithCorrelationID(req.CorrelationID),
		events.WithTenantID(req.TenantID),
		events.WithEventType("evaluate.result"),
	); err != nil {
		return fmt.Errorf("publish evaluate.result: %w", err)
	}
	return nil
}

// handleIngestionAction renders the banner, rewrites risky URLs, and
// triggers a quarantine reference for Blocked verdicts. Each step is
// best-effort: a per-step failure is logged but does not abort the
// chain and does not return an error (so the message is not
// redelivered just because one provider call timed out). Native label
// application is wired separately once a LabelProvider is registered
// (Group D); until then the chain operates without the label step.
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

	// 1. Banner — only renders into bytes; the actual provider-side
	// injection happens in ingestion-svc, which subscribes to the
	// `es.action.banner` subject. We publish the rendered HTML so the
	// downstream injector does not have to know about templates.
	if a.bannerRenderer != nil && res.Tier.Valid() && res.Tier != constant.TierTrusted {
		input := action.BannerInput{
			Tier:        res.Tier,
			Primary:     res.Primary,
			Secondary:   res.Secondary,
			ReasonCodes: res.ReasonCodes,
			Locale:      "en",
		}
		// ActionToken is required for tiers that allow Mark Safe; we
		// only synthesise one when the JWT issuer is wired. The
		// action is left as "mark_safe" so the banner CTA matches
		// the canonical FeedbackAction value enforced by the banner
		// handler.
		if input.Tier.AllowsMarkSafe() && a.jwtIssuer != nil {
			if tok, terr := a.jwtIssuer.Issue(res.TenantID, res.MessageID, privacy.IssueOptions{
				Tier:   string(res.Tier),
				Action: string(action.FeedbackMarkSafe),
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
			}
			if blob, merr := json.Marshal(bannerEvt); merr == nil {
				if perr := a.eventBus.Publish(ctx, "es.action.banner", blob,
					events.WithTenantID(res.TenantID),
					events.WithCorrelationID(res.CorrelationID),
					events.WithEventType("action.banner"),
				); perr != nil {
					a.logger.WarnContext(ctx, "sn360-es: ingestion-action: publish banner failed",
						slog.Any("error", perr))
				}
			}
		}
	}

	// 2. URL rewriting — rewriter takes the result's reason codes and
	// extracts the URLs from the body in the live ingestion path. The
	// rewriter exposes a per-URL Rewrite() call rather than a result-
	// level helper, so the ingestion-svc itself owns the per-URL fan-
	// out. We publish a signal here so the downstream service knows it
	// should rewrite the message body for this tier.
	if a.urlRewriter != nil && (res.Tier == constant.TierBlocked || res.Tier == constant.TierHighRisk) {
		signal := map[string]any{
			"tenant_id":      res.TenantID,
			"message_id":     res.MessageID,
			"correlation_id": res.CorrelationID,
			"tier":           res.Tier,
		}
		if blob, merr := json.Marshal(signal); merr == nil {
			if perr := a.eventBus.Publish(ctx, "es.action.url_rewrite", blob,
				events.WithTenantID(res.TenantID),
				events.WithCorrelationID(res.CorrelationID),
				events.WithEventType("action.url_rewrite"),
			); perr != nil {
				a.logger.WarnContext(ctx, "sn360-es: ingestion-action: publish url_rewrite signal failed",
					slog.Any("error", perr))
			}
		}
	}

	// 3. Quarantine — only when the verdict is Blocked. The actual
	// provider-side replacement happens in ingestion-svc; here we
	// publish a signal carrying the verdict so the downstream
	// quarantine consumer can pull the provider client off the
	// tenant context and act.
	if res.Tier == constant.TierBlocked {
		signal := map[string]any{
			"tenant_id":      res.TenantID,
			"message_id":     res.MessageID,
			"correlation_id": res.CorrelationID,
			"tier":           res.Tier,
			"primary":        res.Primary,
			"score":          res.Score,
		}
		if blob, merr := json.Marshal(signal); merr == nil {
			if perr := a.eventBus.Publish(ctx, "es.action.quarantine", blob,
				events.WithTenantID(res.TenantID),
				events.WithCorrelationID(res.CorrelationID),
				events.WithEventType("action.quarantine"),
			); perr != nil {
				a.logger.WarnContext(ctx, "sn360-es: ingestion-action: publish quarantine signal failed",
					slog.Any("error", perr))
			}
		}
	}

	// 4. Native label — publish a typed signal so the provider-aware
	// label applier (wired in Group D) can pick it up. We use the
	// canonical `es.action.label` subject documented in
	// ARCHITECTURE.md §8.4.
	if res.Tier.Valid() && res.Tier != constant.TierTrusted {
		signal := map[string]any{
			"tenant_id":      res.TenantID,
			"message_id":     res.MessageID,
			"correlation_id": res.CorrelationID,
			"tier":           res.Tier,
			"primary":        res.Primary,
		}
		if blob, merr := json.Marshal(signal); merr == nil {
			if perr := a.eventBus.Publish(ctx, "es.action.label", blob,
				events.WithTenantID(res.TenantID),
				events.WithCorrelationID(res.CorrelationID),
				events.WithEventType("action.label"),
			); perr != nil {
				a.logger.WarnContext(ctx, "sn360-es: ingestion-action: publish label signal failed",
					slog.Any("error", perr))
			}
		}
	}

	return nil
}

// simulationSendEnvelope is the wire format expected on
// `es.education.simulation.send`. It carries the campaign ID and the
// target list assembled by the management service.
type simulationSendEnvelope struct {
	CampaignID string                          `json:"campaign_id"`
	Targets    []simulationSendTargetEnvelope  `json:"targets"`
	Params     map[string]string               `json:"params,omitempty"`
}

type simulationSendTargetEnvelope struct {
	UserHash     string `json:"user_hash"`
	MailboxAlias string `json:"mailbox_alias"`
	DisplayName  string `json:"display_name,omitempty"`
}

// handleSimulationSend dispatches a campaign through SimulationEngine.
// Malformed payloads are dropped; downstream errors propagate so the
// bus can retry.
func (a *application) handleSimulationSend(ctx context.Context, msg events.Message) error {
	if a.simulationEng == nil {
		return nil
	}
	var env simulationSendEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.send unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.CampaignID == "" {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.send missing campaign_id")
		return nil
	}
	targets := make([]education.SimulationTarget, 0, len(env.Targets))
	for _, t := range env.Targets {
		if t.UserHash == "" || t.MailboxAlias == "" {
			continue
		}
		targets = append(targets, education.SimulationTarget{
			UserHash:     t.UserHash,
			MailboxAlias: t.MailboxAlias,
			DisplayName:  t.DisplayName,
		})
	}
	if _, err := a.simulationEng.SendSimulation(ctx, env.CampaignID, targets, env.Params); err != nil {
		return fmt.Errorf("simulation.send: %w", err)
	}
	return nil
}

// handleSimulationResult records an interaction event published by
// the engine (or by the click-tracking endpoint) into the tracker so
// Aggregate() returns up-to-date counts. We deliberately do not
// re-publish from inside the handler — that would loop on the same
// subject we are reading from.
func (a *application) handleSimulationResult(ctx context.Context, msg events.Message) error {
	if a.simulationTracker == nil {
		return nil
	}
	var interaction dto.UserInteraction
	if err := json.Unmarshal(msg.Data(), &interaction); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.result unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if interaction.CampaignID == "" || interaction.UserHash == "" || !interaction.Action.Valid() {
		return nil
	}
	if _, err := a.simulationTracker.RecordInteraction(ctx,
		interaction.CampaignID, interaction.UserHash, interaction.Action); err != nil {
		return fmt.Errorf("simulation.result: %w", err)
	}
	return nil
}

// handleOnboarding dispatches by subject suffix. Until an
// OnboardingAgent (which needs a DirectoryClient) is wired the handler
// runs in observe-only mode: it logs the event so operators can
// confirm the stream is live, and returns nil so the bus does not
// redeliver. The conditional inside is intentionally permissive — new
// suffixes can be added without touching the subscription.
func (a *application) handleOnboarding(ctx context.Context, msg events.Message) error {
	subject := msg.Subject()
	switch {
	case strings.HasSuffix(subject, ".user.created"),
		strings.HasSuffix(subject, ".user.deleted"),
		strings.HasSuffix(subject, ".tenant.created"),
		strings.HasSuffix(subject, ".vendor.seeded"):
		a.logger.InfoContext(ctx, "sn360-es: onboarding event received",
			slog.String("subject", subject),
			slog.Int("bytes", len(msg.Data())))
	default:
		a.logger.DebugContext(ctx, "sn360-es: onboarding event ignored (unknown suffix)",
			slog.String("subject", subject))
	}
	return nil
}

// quarantineReleaseEnvelope is the wire format for the user- or
// agent-driven release flow. The fields mirror the HTTP handler's
// request body so the same struct can travel over either transport.
type quarantineReleaseEnvelope struct {
	TenantID             string `json:"tenant_id"`
	PseudonymizedMessage string `json:"pseudonymized_message_id"`
	RequestedBy          string `json:"requested_by,omitempty"`
	RestoredBody         string `json:"restored_body,omitempty"`
}

// handleQuarantineRelease calls ReleaseService.Release; the service
// itself publishes the outcome on
// `es.action.quarantine.release.result`, so we only need to surface
// real errors here.
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
	}); err != nil {
		return fmt.Errorf("quarantine.release: %w", err)
	}
	return nil
}

// escalationCreateEnvelope and escalationResolveEnvelope are the wire
// formats for the two escalation subjects. They keep the JSON
// independent of the internal DTO so future schema changes don't
// require coordinated bus migrations.
type escalationCreateEnvelope struct {
	TenantID string                 `json:"tenant_id"`
	Incident dto.EscalationIncident `json:"incident"`
}

type escalationResolveEnvelope struct {
	TicketID     string                 `json:"ticket_id"`
	ResolverHash string                 `json:"resolver_hash"`
	Outcome      dto.EscalationOutcome  `json:"outcome"`
	Notes        string                 `json:"notes,omitempty"`
}

// handleEscalation dispatches by subject suffix between Escalate (for
// `*.created`) and ResolveEscalation (for `*.resolved`).
func (a *application) handleEscalation(ctx context.Context, msg events.Message) error {
	if a.escalationSvc == nil {
		return nil
	}
	subject := msg.Subject()
	switch {
	case strings.HasSuffix(subject, ".created"):
		var env escalationCreateEnvelope
		if err := json.Unmarshal(msg.Data(), &env); err != nil {
			a.logger.WarnContext(ctx, "sn360-es: escalation.created unmarshal failed",
				slog.Any("error", err))
			return nil
		}
		if env.TenantID == "" {
			return nil
		}
		if _, err := a.escalationSvc.Escalate(ctx, env.TenantID, env.Incident); err != nil {
			return fmt.Errorf("escalation.created: %w", err)
		}
	case strings.HasSuffix(subject, ".resolved"):
		var env escalationResolveEnvelope
		if err := json.Unmarshal(msg.Data(), &env); err != nil {
			a.logger.WarnContext(ctx, "sn360-es: escalation.resolved unmarshal failed",
				slog.Any("error", err))
			return nil
		}
		if env.TicketID == "" {
			return nil
		}
		if _, err := a.escalationSvc.ResolveEscalation(ctx, env.TicketID, env.ResolverHash, env.Outcome, env.Notes); err != nil {
			return fmt.Errorf("escalation.resolved: %w", err)
		}
	default:
		a.logger.DebugContext(ctx, "sn360-es: escalation event ignored (unknown suffix)",
			slog.String("subject", subject))
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
	if app.tier1Raw != nil {
		t1 := app.tier1Raw
		checkers = append(checkers, handler.HealthCheckerFunc{N: "tier1_encoder", F: func(ctx context.Context) error {
			return t1.Health(ctx)
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
		// Education lessons are linked from the email banner's
		// "Learn more" affordance; the click reaches an end user
		// who does not carry a Bearer JWT. The lesson handler
		// only returns static localised copy, so skipping auth
		// here is safe — no tenant scoping is needed.
		"/v1/education/lesson/",
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

// redisQuarantineStore adapts redis.Client to action.QuarantineStore.
// The quarantine service writes hex-encoded encrypted records keyed by
// QuarantineKey(tenant, pseudo_message_id).
type redisQuarantineStore struct{ client *redis.Client }

func (s redisQuarantineStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return s.client.Set(ctx, key, value, ttl)
}

func (s redisQuarantineStore) Get(ctx context.Context, key string) (string, bool, error) {
	return s.client.Get(ctx, key)
}

func (s redisQuarantineStore) Del(ctx context.Context, keys ...string) error {
	return s.client.Del(ctx, keys...)
}

// memoryQuarantineStore is the in-memory fallback used when Redis is
// not configured. It is goroutine-safe and respects the TTL parameter
// so dev / unit-test behaviour matches the redis path.
type memoryQuarantineStore struct {
	mu   sync.Mutex
	rows map[string]memoryQuarantineEntry
}

type memoryQuarantineEntry struct {
	value   string
	expires time.Time
}

func newMemoryQuarantineStore() *memoryQuarantineStore {
	return &memoryQuarantineStore{rows: map[string]memoryQuarantineEntry{}}
}

func (m *memoryQuarantineStore) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var expires time.Time
	if ttl > 0 {
		expires = time.Now().Add(ttl)
	}
	m.rows[key] = memoryQuarantineEntry{value: value, expires: expires}
	return nil
}

func (m *memoryQuarantineStore) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.rows[key]
	if !ok {
		return "", false, nil
	}
	if !entry.expires.IsZero() && time.Now().After(entry.expires) {
		delete(m.rows, key)
		return "", false, nil
	}
	return entry.value, true, nil
}

func (m *memoryQuarantineStore) Del(_ context.Context, keys ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		delete(m.rows, k)
	}
	return nil
}

// newQuarantineStore returns redisQuarantineStore when a Redis client
// is available; otherwise the in-memory fallback so QuarantineService
// still satisfies its non-nil-store invariant.
func newQuarantineStore(client *redis.Client) action.QuarantineStore {
	if client != nil {
		return redisQuarantineStore{client: client}
	}
	return newMemoryQuarantineStore()
}

// latestVerdictReevaluator implements action.QuarantineReevaluator by
// reading the most recent evaluation_result for the (tenant,
// pseudo_message_id) tuple from the repository. The asynchronous
// evaluator updates the row every time it scores a message, so this
// adapter always returns the freshest verdict the management plane
// has produced. When no repository or no row is available we return
// a conservative "still blocked" verdict so the release flow does
// not accidentally restore a message we no longer know anything
// about.
type latestVerdictReevaluator struct {
	repo   repository.EvaluationResultRepository
	logger *slog.Logger
}

func newLatestVerdictReevaluator(repos *repository.Registry, logger *slog.Logger) *latestVerdictReevaluator {
	var r repository.EvaluationResultRepository
	if repos != nil {
		r = repos.EvaluationResults
	}
	return &latestVerdictReevaluator{repo: r, logger: logger}
}

// Reevaluate satisfies action.QuarantineReevaluator. It looks the
// pseudonymised message up by hash; the management evaluator hashes
// raw message-ids the same way (the privacy-safe hash IS the
// pseudonymised id), so a single byte cast bridges them. We do not
// re-run the tier 0/1/2 pipeline here — doing so would couple the
// release endpoint to the evaluator's import graph for no benefit;
// the latest verdict on file is the authoritative source.
func (r *latestVerdictReevaluator) Reevaluate(ctx context.Context, tenantID, pseudoMessageID string) (dto.EvaluateResult, error) {
	if r.repo == nil {
		if r.logger != nil {
			r.logger.WarnContext(ctx,
				"release: no evaluation_results repo; returning conservative still-blocked verdict",
				slog.String("tenant_id", tenantID),
			)
		}
		return dto.EvaluateResult{
			TenantID:  tenantID,
			MessageID: pseudoMessageID,
			Tier:      constant.TierBlocked,
		}, nil
	}
	row, err := r.repo.GetByMessageHash(ctx, tenantID, []byte(pseudoMessageID))
	if errors.Is(err, repository.ErrNotFound) {
		// No row means we have not re-scored the message since it
		// was quarantined. Refuse the release to be safe.
		return dto.EvaluateResult{
			TenantID:  tenantID,
			MessageID: pseudoMessageID,
			Tier:      constant.TierBlocked,
		}, nil
	}
	if err != nil {
		return dto.EvaluateResult{}, fmt.Errorf("reevaluator: lookup verdict: %w", err)
	}
	secondary := make([]constant.Category, 0, len(row.Secondary))
	for _, c := range row.Secondary {
		secondary = append(secondary, constant.Category(c))
	}
	return dto.EvaluateResult{
		TenantID:      row.TenantID,
		MessageID:     pseudoMessageID,
		CorrelationID: row.CorrelationID,
		Score:         row.Score,
		Tier:          constant.Tier(row.Tier),
		Primary:       constant.Category(row.Primary),
		Secondary:     secondary,
		ReasonCodes:   append([]string(nil), row.ReasonCodes...),
		Degraded:      row.Degraded,
		EvaluatedAt:   row.EvaluatedAt,
	}, nil
}

// feedbackCountsAdapter bridges repository.FeedbackEventRepository to
// the dashboard.FeedbackCountsReader contract so the dashboard package
// does not need to import the repository package directly.
type feedbackCountsAdapter struct {
	repo repository.FeedbackEventRepository
}

func (a feedbackCountsAdapter) Counts(ctx context.Context, tenantID string, start, end time.Time) (dashboard.FeedbackCounts, error) {
	counts, err := a.repo.Counts(ctx, tenantID, start, end)
	if err != nil {
		return dashboard.FeedbackCounts{}, err
	}
	return dashboard.FeedbackCounts{
		ReportedPhishing: counts.ReportedPhishing,
		MarkedSafe:       counts.MarkedSafe,
		TrustedSender:    counts.TrustedSender,
	}, nil
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

// tierDeciderAdapter bridges the production *action.TierDecider — whose
// Decide method consumes a full dto.EvaluateResult — to the evaluate
// package's TierDecider interface, which takes (score, primary,
// signals). The decider only reads Score and Primary from the
// EvaluateResult; the signals argument is passed through unchanged for
// future tenant-specific overrides. This mirrors the deciderAdapter
// used in the accuracy / bench harness so production and harness wire
// to the same threshold logic.
type tierDeciderAdapter struct{ decider *action.TierDecider }

func (a tierDeciderAdapter) Decide(score int, primary constant.Category, _ dto.RiskSignals) constant.Tier {
	if a.decider == nil {
		return constant.TierInformational
	}
	return a.decider.Decide(dto.EvaluateResult{Score: score, Primary: primary})
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
