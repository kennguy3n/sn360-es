// Command sn360-es is the service entrypoint that boots configuration,
// connects to NATS / Redis / PostgreSQL, and runs the HTTP server alongside
// any configured event-bus listeners.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	"sync/atomic"
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
	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
	"github.com/kennguy3n/sn360-es/internal/service/onboarding"
	"github.com/kennguy3n/sn360-es/internal/service/predict"
	"github.com/kennguy3n/sn360-es/internal/service/relationship"
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
	"github.com/kennguy3n/sn360-es/internal/service/tier1"
	"github.com/kennguy3n/sn360-es/internal/service/worker"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/gmail"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/outlook"
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

	// Background workers: poller + periodic runners. Each respects
	// context cancellation so SIGTERM cleanly stops the lot. Errors
	// from Run() are logged but do not bubble up because a missed
	// cycle on a recurring worker is recoverable on the next tick.
	app.StartBackground(ctx)

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

	// Shut down the HTTP server so no new requests are accepted.
	// In-flight handlers run to completion before Shutdown returns,
	// so any bgWG.Add(1) calls from HTTP handlers (e.g. AgentBridge
	// post-consent trigger) are guaranteed to execute before we
	// reach WaitBackground below.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("sn360-es: http shutdown error", slog.Any("error", err))
	}

	// Belt-and-suspenders: set draining after HTTP shutdown so any
	// future non-HTTP paths that call bgWG.Add also get rejected.
	app.draining.Store(true)

	// Drain background goroutines (poller, periodic workers, label
	// cache janitor, in-flight onboarding) AFTER the HTTP server
	// and consumers are both shut down. No new bgWG.Add(1) calls
	// can arrive, so Wait() is safe.
	app.WaitBackground()

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

	// Provider-side action machinery. Populated from GWS / O365
	// credentials in newApplication. When no credentials are
	// configured the registry is non-nil but empty and the action
	// consumers below degrade to logging fallbacks.
	providers     *providerRegistry
	labelApplier  *action.LabelApplier
	quarantineSvc *action.QuarantineService

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

	// Ingestion polling. Populated when at least one mailbox
	// provider is configured; the poller publishes
	// `es.evaluate.request` on the bus so this binary's evaluator
	// consumer (or a peer replica's batch orchestrator) picks the
	// messages up.
	poller *ingestion.Poller

	// Periodic workers. Each runner drives one Job on its declared
	// interval; nil when the underlying dependency (postgres, the
	// relationship aggregator, etc.) is missing. Run() starts them
	// after the consumers come online.
	relationshipRunner *worker.Runner
	vendorRunner       *worker.Runner
	cleanupRunner      *worker.Runner

	// AI agents. The onboarding agent fires on directory discovery,
	// the tuning agent runs on a schedule, the support agent
	// services in-product queries. All three are optional — they
	// degrade gracefully when their inputs (directory client, repos)
	// are not wired.
	onboardAgent  *agent.OnboardingAgent
	tuningAgent   *agent.TuningAgent
	supportAgent  *agent.SupportAgent
	onboardingSvc *onboarding.Service

	// In-process caches that own a janitor goroutine. We keep a
	// typed reference (separate from the action.LabelCache interface
	// stored on labelApplier) so StartBackground can run the janitor
	// and tests can stop it deterministically.
	memLabelCache *memoryLabelCache

	// Lifecycle.
	subs    []events.Subscription
	subsMu  sync.Mutex
	closers []func() error
	dlqProc *service.DLQProcessor

	// bgWG tracks every goroutine started by StartBackground so the
	// shutdown sequence can wait for them to drain before the
	// process exits. Each goroutine MUST `defer a.bgWG.Done()` and
	// the matching `a.bgWG.Add(1)` MUST run on the calling
	// goroutine (not inside the spawned one) to avoid a Wait race.
	bgWG     sync.WaitGroup
	draining atomic.Bool
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
	// An SMTP sender is wired when SMTP_HOST + SMTP_FROM are
	// configured; otherwise the engine stays in dry-run mode (renders
	// templates and publishes interactions without actually mailing).
	var simSender education.SimulationSender
	if cfg.SMTP.Host != "" && cfg.SMTP.From != "" {
		smtpSender, serr := education.NewSMTPSender(education.SMTPConfig{
			Host:       cfg.SMTP.Host,
			Port:       cfg.SMTP.Port,
			User:       cfg.SMTP.User,
			Password:   cfg.SMTP.Password,
			From:       cfg.SMTP.From,
			StartTLS:   cfg.SMTP.StartTLS,
			Timeout:    cfg.SMTP.Timeout,
			SkipVerify: cfg.SMTP.SkipVerify,
		})
		if serr != nil {
			logger.Warn("sn360-es: smtp simulation sender init failed", slog.Any("error", serr))
		} else {
			simSender = smtpSender
		}
	}
	if eng, eerr := education.NewSimulationEngine(education.EngineConfig{
		Store:     education.NewMemoryCampaignStore(),
		Templates: education.NewTemplateLibrary(),
		Sender:    simSender,
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

	// Share a single Categorizer + the shared TierDecider adapter +
	// the same Weights value between the per-message evaluator and
	// the optional batch orchestrator so both paths produce
	// byte-identical categorisation, tiering, and score scale for
	// the same Tier 1 input. The rule categorizer is stateless today,
	// but sharing the instance keeps the wiring honest if a future
	// implementation gains tenant-scoped caches or metrics that
	// should not be duplicated.
	//
	// Sharing invariant: the variables below MUST be passed
	// unchanged to *both* evaluate.NewEvaluator and
	// evaluate.NewBatchOrchestrator. Score() applies the weights
	// before the categoriser / tier decider see it, so any
	// divergence (e.g. one path constructing its own
	// DefaultWeights() instance, the other reading the config
	// override) would silently send the same message into different
	// TierDecider bands depending on which consumer happened to
	// handle it. The batch and per-message paths regression-test
	// the shared-score contract — keep them in lockstep.
	categorizer := evaluate.NewRuleCategorizer()
	tierDeciderAdapt := tierDeciderAdapter{decider: tierDecider}
	weights := evaluate.DefaultWeights()

	app.evaluator = evaluate.NewEvaluator(evaluate.Config{
		Tier0:              app.tier0Gate,
		Tier1:              app.tier1Client,
		Tier2:              app.tier2Client,
		Rspamd:             app.rspamdClient,
		Categorizer:        categorizer,
		TierDecider:        tierDeciderAdapt,
		Weights:            weights,
		Tier1PassThreshold: cfg.Tier1.PassThreshold,
		Tier1FlagThreshold: cfg.Tier1.FlagThreshold,
		Tier1Timeout:       cfg.Tier1.Timeout,
		Tier2Timeout:       cfg.AI.Timeout,
		RspamdTimeout:      cfg.Rspamd.Timeout,
		Logger:             logger,
		Observer:           app.metrics.PipelineObserver(),
	})

	// Optional Tier 1 batch orchestrator. When enabled it pulls
	// es.evaluate.request in batches, runs Tier 0 in-process, batches
	// the Tier 1 HTTP call, and escalates "escalate" verdicts through
	// the full evaluator. Requires NATS JetStream (it uses pull-fetch)
	// and a wired Tier 1 client; degrades to "skip" when either is
	// missing so single-message consumer (handleEvaluateRequest) still
	// covers the path.
	if cfg.Tier1.BatchEnabled {
		switch {
		case app.tier1Raw == nil:
			logger.Warn("sn360-es: TIER1_BATCH_ENABLED set but tier1 client unavailable; batch orchestrator disabled")
		default:
			natsSvc, ok := app.eventBus.(*natsbus.Service)
			if !ok {
				logger.Warn("sn360-es: TIER1_BATCH_ENABLED set but event bus is not NATS; batch orchestrator disabled",
					slog.String("event_bus", string(cfg.EventBus)))
			} else {
				orch, oerr := evaluate.NewBatchOrchestrator(evaluate.BatchOrchestratorConfig{
					JS:        natsSvc.Client(),
					BatchSize: cfg.Tier1.BatchSize,
					Tier0:     tier0BatchAdapter{gate: app.tier0Gate},
					Tier1:     app.tier1Raw,
					Thresholds: tier1.Thresholds{
						PassBelow: cfg.Tier1.PassThreshold,
						FlagAbove: cfg.Tier1.FlagThreshold,
					},
					Fallback: fallbackEvaluatorAdapter{eval: app.evaluator},
					// Pass Categorizer + TierDecider + Weights so the
					// batch path can populate Primary + Tier + a weighted
					// Score on the pass / flag verdicts that skip
					// Fallback. Without these the verdicts would publish
					// to es.evaluate.result with an empty Tier (and the
					// raw Tier 1 score), and handleIngestionAction
					// (Tier.Valid() guard) would silently drop every
					// banner / label / URL-rewrite / quarantine signal
					// for batch-emitted threats. We pass the *same*
					// Categorizer / TierDecider / Weights instances
					// constructed above for the per-message evaluator so
					// both paths produce byte-identical categorisation
					// output for the same Tier 1 input.
					Categorizer: categorizer,
					TierDecider: tierDeciderAdapt,
					Weights:     weights,
					Sink:        app.eventBus,
					// Match the per-message handler's output subject so the
					// management-persist / education-trigger / ingestion-action
					// consumers receive batch-produced verdicts the same way
					// they receive single-message ones. The package default
					// is now also "es.evaluate.result"; setting it
					// explicitly here makes the intent obvious at the wiring
					// site even though it duplicates the default.
					ResultSubject: "es.evaluate.result",
					Logger:        logger,
				})
				if oerr != nil {
					logger.Warn("sn360-es: tier1 batch orchestrator init failed; falling back to single-message consumer",
						slog.Any("error", oerr))
				} else {
					app.batchOrch = orch
					logger.Info("sn360-es: tier1 batch orchestrator wired",
						slog.Int("batch_size", cfg.Tier1.BatchSize))
				}
			}
		}
	}

	// Provider registry — looks up authenticated Gmail / Outlook
	// clients per tenant. When neither GWS nor O365 credentials are
	// configured the registry is non-nil but empty; the action
	// consumers below skip when no provider is registered. We build
	// the registry before the label applier and quarantine service
	// so they can pick up its providers. Per-entry construction
	// failures are recovered inside buildProviderRegistry (logged
	// and skipped) so this call cannot return an error — see the
	// docstring there for the rationale.
	app.providers = buildProviderRegistry(ctx, cfg, logger)

	// Label applier — picks up every LabelProvider in the registry
	// and applies tier / category labels to messages. The applier
	// requires a label cache to remember provider-side label IDs
	// across runs; we use Redis when available and an in-memory
	// fallback otherwise so tests + dev still work.
	if app.providers != nil && app.providers.hasAny() {
		labelCache, memCache := newLabelCache(app.redis)
		// memCache is non-nil only on the in-process path; stash it
		// so StartBackground can run its janitor goroutine and stop
		// the map from growing without bound.
		app.memLabelCache = memCache
		app.labelApplier = action.NewLabelApplier(logger, labelCache, app.providers.labelProviders()...)
	}

	// Provider-aware quarantine service. The HTTP release path
	// builds its own QuarantineService without provider clients (so
	// /v1/quarantine/release works in dev). Here we construct a
	// second instance wired to real Gmail / Outlook quarantine
	// providers so the es.action.quarantine consumer can actually
	// move Blocked-tier messages out of the inbox. Only constructed
	// when at least one provider is registered.
	if qencryptor, eerr := buildURLEncryptor(cfg, logger); eerr == nil && app.providers != nil && app.providers.hasAny() {
		qstore := newQuarantineStore(app.redis)
		qsvc, qerr := action.NewQuarantineService(action.QuarantineConfig{
			Logger:    logger,
			Providers: app.providers.quarantineProviders(),
			Store:     qstore,
			Encryptor: qencryptor,
			Publisher: eventBus,
		})
		if qerr == nil {
			app.quarantineSvc = qsvc
		} else {
			logger.Warn("sn360-es: provider-aware quarantine service init failed",
				slog.Any("error", qerr))
		}
	}

	// Ingestion poller — wakes mailboxes, normalizes messages, and
	// publishes `es.evaluate.request` on the bus. Only constructed
	// when at least one MailboxProvider is configured. The
	// checkpoint store + distributed lock factory are Redis-backed;
	// when Redis is absent the poller still runs (per-mailbox
	// locks are no-ops, checkpoints reset on restart), so dev mode
	// keeps working.
	app.poller = buildPoller(ctx, cfg, logger, app)

	// Periodic workers.
	app.relationshipRunner, app.vendorRunner, app.cleanupRunner = buildWorkers(cfg, logger, app)

	// AI agents. Wiring is best-effort: each agent skips when its
	// inputs are missing. The onboarding + support agents publish
	// follow-up events on the bus; the tuning agent persists
	// updated weights/thresholds via the repository layer.
	app.onboardAgent, app.tuningAgent, app.supportAgent = buildAgents(cfg, logger, app)

	// Onboarding service — the OAuth consent + post-consent discovery
	// flow. Only constructed when both state secret and callback URL are
	// configured so dev-mode binaries stay bootable without onboarding
	// credentials. The AgentBridge depends on onboardAgent, which is why
	// this block sits after buildAgents.
	if cfg.Onboarding.StateSecret != "" && cfg.Onboarding.CallbackURL != "" {
		obSvc, obErr := buildOnboardingService(cfg, logger, app)
		if obErr != nil {
			logger.Warn("sn360-es: onboarding service init failed", slog.Any("error", obErr))
		} else {
			app.onboardingSvc = obSvc
			logger.Info("sn360-es: onboarding service wired",
				slog.String("callback_url", cfg.Onboarding.CallbackURL))
		}
	} else {
		logger.Info("sn360-es: onboarding service disabled (ONBOARDING_STATE_SECRET or ONBOARDING_CALLBACK_URL not set)")
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
	// pick up.
	//
	// Mutually exclusive with the Tier 1 batch orchestrator: both
	// would otherwise compete for messages on the same WorkQueue
	// stream with different wire formats (the batch path expects a
	// BatchMessage envelope; the per-message path expects a flat
	// EvaluateRequest), causing JetStream to split messages across
	// consumers and produce verdicts with empty IDs. When batch is
	// active the orchestrator owns the subject end-to-end.
	if a.evaluator != nil && a.batchOrch == nil {
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

	// es.action.label → apply tier + category native labels via the
	// provider-aware LabelApplier. Critical only when a label
	// applier is wired; without one the consumer would no-op so we
	// keep the subscription itself best-effort.
	if a.labelApplier != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.label", a.handleActionLabel,
			events.WithDurable("action-label"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Warn("sn360-es: subscribe action.label (action-label) failed",
				slog.Any("error", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.action.banner → inject pre-rendered banner HTML into the
	// recipient's mailbox via Gmail's shadow-copy or Outlook's
	// PATCH.
	if a.providers != nil && a.providers.hasAny() {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.banner", a.handleActionBanner,
			events.WithDurable("action-banner"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Warn("sn360-es: subscribe action.banner (action-banner) failed",
				slog.Any("error", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.action.url_rewrite → log + observe for now. Full
	// body-rewrite implementation is deferred until the provider
	// body abstraction generalises across Gmail's shadow-copy and
	// Outlook's PATCH paths (see handleActionURLRewrite docstring).
	if a.urlRewriter != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.url_rewrite", a.handleActionURLRewrite,
			events.WithDurable("action-url-rewrite"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Warn("sn360-es: subscribe action.url_rewrite (action-url-rewrite) failed",
				slog.Any("error", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.action.quarantine → move Blocked-tier messages into the
	// hidden quarantine label / folder via the provider-aware
	// QuarantineService.
	if a.quarantineSvc != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.quarantine", a.handleActionQuarantine,
			events.WithDurable("action-quarantine"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Warn("sn360-es: subscribe action.quarantine (action-quarantine) failed",
				slog.Any("error", err))
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
	if a.batchOrch != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.batchOrch.Stop(stopCtx); err != nil {
			logger.Warn("sn360-es: tier1 batch orchestrator stop error", slog.Any("error", err))
		}
		a.batchOrch = nil
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
	// Backfill the routing / identity envelope fields the request
	// carries so downstream consumers on `es.evaluate.result` see
	// the same envelope regardless of which producer (per-message
	// here, or BatchOrchestrator.processOnce) emitted the verdict.
	// In particular, the Recipient backfill keeps the downstream
	// action consumers (label / banner / url_rewrite / quarantine)
	// from silently no-op'ing on the empty-email guard. The shared
	// helper lives in `internal/dto` so the two producers cannot
	// drift apart.
	dto.BackfillRoutingFields(&result, req)
	payload, err := json.Marshal(result)
	if err != nil {
		a.logger.WarnContext(ctx, "sn360-es: evaluate.result marshal failed",
			slog.Any("error", err))
		return nil
	}
	// Carry the canonical message-id header in addition to tenant /
	// correlation / event-type so per-message and batch verdicts
	// (BatchOrchestrator.publishResult) share an identical header
	// envelope on `es.evaluate.result`. Any bus middleware that keys
	// off `message-id` (tracing, replay tooling) would otherwise see
	// the header only on batch-emitted verdicts.
	if err := a.eventBus.Publish(ctx, "es.evaluate.result", payload,
		events.WithMessageID(result.MessageID),
		events.WithCorrelationID(req.CorrelationID),
		events.WithTenantID(req.TenantID),
		events.WithEventType("evaluate.result"),
	); err != nil {
		return fmt.Errorf("publish evaluate.result: %w", err)
	}
	return nil
}

// actionLabelEnvelope is the wire format published by
// handleIngestionAction on `es.action.label`. The fields are kept
// in sync with the map[string]any literal that publishes the
// signal so any future addition there must be reflected here.
type actionLabelEnvelope struct {
	TenantID      string            `json:"tenant_id"`
	MessageID     string            `json:"message_id"`
	CorrelationID string            `json:"correlation_id"`
	Tier          constant.Tier     `json:"tier"`
	Primary       constant.Category `json:"primary"`
	Email         string            `json:"email"`
}

// actionBannerEnvelope is the wire format published by
// handleIngestionAction on `es.action.banner`. HTML is the
// pre-rendered banner ready to be spliced into the body.
type actionBannerEnvelope struct {
	TenantID      string        `json:"tenant_id"`
	MessageID     string        `json:"message_id"`
	CorrelationID string        `json:"correlation_id"`
	Tier          constant.Tier `json:"tier"`
	HTML          string        `json:"html"`
	Email         string        `json:"email"`
}

// actionURLRewriteEnvelope is the wire format published by
// handleIngestionAction on `es.action.url_rewrite`. The consumer
// owns the per-URL fan-out.
type actionURLRewriteEnvelope struct {
	TenantID      string        `json:"tenant_id"`
	MessageID     string        `json:"message_id"`
	CorrelationID string        `json:"correlation_id"`
	Tier          constant.Tier `json:"tier"`
	Email         string        `json:"email"`
}

// actionQuarantineEnvelope is the wire format published by
// handleIngestionAction on `es.action.quarantine`. Carries the
// score and primary category so the consumer can persist them
// alongside the encrypted reference.
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
// label via the provider-aware LabelApplier. Best-effort: a missing
// provider or label-applier means we log and skip; the message is
// not re-delivered.
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
// recipient's mailbox via the provider-specific injector (Gmail's
// shadow-copy, Outlook's PATCH).
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

// handleActionURLRewrite rewrites URLs in the message body via the
// provider-specific BodyRewriter (Gmail shadow-copy, Outlook PATCH).
// When no BodyRewriter is configured for the tenant the handler logs
// the signal and returns without error so the consumer never blocks.
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
// hidden quarantine label and persists an encrypted reference. The
// caller's signal must include the recipient email so the provider
// can address the mailbox; everything else is sourced from the
// signal payload.
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
		// Skip non-Blocked signals — the publisher guards against
		// this but a defensive check here keeps replays safe.
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
		// Banner locale comes from the operator-configured default
		// (BANNER_DEFAULT_LOCALE). The HTTP banner-render path uses the
		// same value; we deliberately re-use it here so verdicts
		// reaching ingestion-action through the bus produce identical
		// banner HTML to those rendered synchronously by the HTTP
		// handler. Per-request locale overrides aren't surfaced on
		// dto.EvaluateResult today; if they ever need to be, the
		// override should land on the result type so both paths can
		// honour it without diverging.
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
			// Propagate the evaluator's degraded signal so the
			// rendered banner carries the `sn360-degraded` CSS
			// class (verified by
			// TestBannerRendererInjectsDegradedNotice). The
			// evaluator sets this in evaluator.go::markDegraded
			// when Tier 1 / Tier 2 / Rspamd was unavailable at
			// scoring time; dropping it here would hide that the
			// verdict ran with reduced inputs, even though the
			// renderer template explicitly renders a notice.
			Degraded: res.Degraded,
		}
		// Mint an ActionToken so the banner CTAs (Report Phishing
		// always; Mark Safe / Trust Sender on AllowsMarkSafe tiers)
		// carry a usable JWT for posting feedback. The token is
		// emitted with an *empty* Action claim so the same value
		// works for any of the three FeedbackAction strings the user
		// might click: feedback.FeedbackService.Process only rejects
		// the request when claims.Action is non-empty AND mismatches
		// the request action (internal/service/action/feedback.go).
		// Binding the token to a single action would have made the
		// other two buttons in the banner unusable — the template
		// shares one token across all three anchor tags. We mint a
		// token for any non-Trusted tier (not just AllowsMarkSafe)
		// so Report Phishing keeps working on HighRisk and Blocked
		// banners, where reporting matters most.
		//
		// In deployments without a feedback-token issuer the banner
		// renderer suppresses the interactive CTAs and still emits
		// the informational body, so the banner is published either
		// way (see banner_renderer.go BannerInput.ActionToken).
		if a.jwtIssuer != nil {
			if tok, terr := a.jwtIssuer.Issue(res.TenantID, res.MessageID, privacy.IssueOptions{
				Tier: string(res.Tier),
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
			"email":          res.Recipient,
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
			"email":          res.Recipient,
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
			"email":          res.Recipient,
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
	CampaignID string                         `json:"campaign_id"`
	Targets    []simulationSendTargetEnvelope `json:"targets"`
	Params     map[string]string              `json:"params,omitempty"`
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
	// Empty target list at the wire boundary is treated as a malformed
	// publish and dropped here rather than handed to SendSimulation.
	// The engine's contract on zero-target campaigns is not part of
	// the bus envelope schema (it varies by provider), so we surface
	// the issue at the consumer where the operator can correlate it
	// with the publishing service. Returning nil acks the message so
	// the bus does not redeliver a payload the upstream will not
	// have re-populated.
	if len(env.Targets) == 0 {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.send dropped: empty targets",
			slog.String("campaign_id", env.CampaignID))
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
	// Warn when the envelope carried targets but the per-target
	// filter dropped every one of them. Without this signal a
	// misconfigured management-service publisher (e.g. omitting
	// user_hash or mailbox_alias) shows up as silent no-ops with no
	// hint that simulations were enqueued at all.
	if len(env.Targets) > 0 && len(targets) == 0 {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.send filter dropped all targets",
			slog.String("campaign_id", env.CampaignID),
			slog.Int("raw_targets", len(env.Targets)))
		return nil
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
	case strings.HasSuffix(subject, ".tenant.created"):
		if a.onboardAgent != nil {
			var env struct {
				TenantID string `json:"tenant_id"`
				Provider string `json:"provider"`
			}
			if err := json.Unmarshal(msg.Data(), &env); err != nil {
				a.logger.WarnContext(ctx, "sn360-es: onboarding.tenant.created unmarshal failed",
					slog.Any("error", err))
				return nil
			}
			if env.TenantID == "" {
				return nil
			}
			p := agent.Provider(env.Provider)
			if !p.Valid() || p == agent.ProviderUnknown {
				a.logger.WarnContext(ctx, "sn360-es: onboarding.tenant.created unknown provider, skipping",
					slog.String("tenant_id", env.TenantID),
					slog.String("provider", env.Provider))
				return nil
			}
			tctx := agent.TenantContext{
				TenantID:  env.TenantID,
				Provider:  p,
				StartedAt: time.Now().UTC(),
			}
			if a.draining.Load() {
				a.logger.WarnContext(ctx, "sn360-es: onboarding.tenant.created rejected (draining)",
					slog.String("tenant_id", env.TenantID))
				return nil
			}
			a.bgWG.Add(1)
			go func() {
				defer a.bgWG.Done()
				bgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
				defer cancel()
				if _, err := a.onboardAgent.Onboard(bgCtx, tctx); err != nil {
					a.logger.Error("sn360-es: onboarding agent failed",
						slog.String("tenant_id", env.TenantID),
						slog.Any("error", err))
				}
			}()
		} else {
			a.logger.InfoContext(ctx, "sn360-es: onboarding event received (agent not wired)",
				slog.String("subject", subject))
		}
	case strings.HasSuffix(subject, ".user.created"),
		strings.HasSuffix(subject, ".user.deleted"),
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
	// CorrelationID propagates upstream tracing through the release
	// flow. ReleaseService.publishOutcome forwards it onto the
	// `es.action.quarantine.release` event so an operator can join
	// the original evaluation to the eventual release outcome.
	CorrelationID string `json:"correlation_id,omitempty"`
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
		CorrelationID:        env.CorrelationID,
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
	TicketID     string                `json:"ticket_id"`
	ResolverHash string                `json:"resolver_hash"`
	Outcome      dto.EscalationOutcome `json:"outcome"`
	Notes        string                `json:"notes,omitempty"`
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
	// Informational checkers for the components wired by the
	// 2026-05-18 plan. These never error (they never fail readiness)
	// — they exist so operators can see whether the provider
	// registry, the poller, and the periodic workers were
	// constructed when they look at /readyz. Anything actually
	// broken (e.g. Redis lock acquisition failures) surfaces through
	// the metrics + structured logs.
	if app.providers != nil {
		reg := app.providers
		checkers = append(checkers, handler.HealthCheckerFunc{N: "provider_registry", F: func(_ context.Context) error {
			if !reg.hasAny() {
				logger.Debug("readyz: provider registry has no tenants registered")
			}
			return nil
		}})
	}
	if app.poller != nil {
		checkers = append(checkers, handler.HealthCheckerFunc{N: "ingestion_poller", F: func(_ context.Context) error {
			return nil
		}})
	}
	if app.relationshipRunner != nil {
		checkers = append(checkers, handler.HealthCheckerFunc{N: "worker_relationship", F: func(_ context.Context) error {
			return nil
		}})
	}
	if app.vendorRunner != nil {
		checkers = append(checkers, handler.HealthCheckerFunc{N: "worker_vendor", F: func(_ context.Context) error {
			return nil
		}})
	}
	if app.cleanupRunner != nil {
		checkers = append(checkers, handler.HealthCheckerFunc{N: "worker_cleanup", F: func(_ context.Context) error {
			return nil
		}})
	}
	if app.tuningAgent != nil {
		checkers = append(checkers, handler.HealthCheckerFunc{N: "agent_tuning", F: func(_ context.Context) error {
			return nil
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
		// OAuth callback is hit by the IdP redirect — the browser
		// will not carry a Bearer JWT.
		"/v1/onboarding/callback",
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

// redisLabelCache adapts redis.Client to action.LabelCache.
type redisLabelCache struct{ client *redis.Client }

func (c redisLabelCache) Get(ctx context.Context, key string) (string, error) {
	v, ok, err := c.client.Get(ctx, key)
	if err != nil || !ok {
		return "", err
	}
	return v, nil
}

func (c redisLabelCache) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return c.client.Set(ctx, key, value, ttl)
}

// memoryLabelCache is the in-process fallback when Redis is not
// configured. Goroutine-safe; respects the supplied TTL.
//
// Expired entries are evicted lazily on Get and proactively by the
// janitor goroutine started via runJanitor(ctx). Without the
// janitor, keys that are written once and never read again would
// linger forever — Set overwrites the slot but does not sweep peers,
// so a long-running process can accumulate unbounded entries.
type memoryLabelCache struct {
	mu      sync.Mutex
	entries map[string]memoryLabelEntry
}

type memoryLabelEntry struct {
	value     string
	expiresAt time.Time
}

// memoryLabelCacheJanitorInterval is how often the janitor sweeps
// expired entries. Five minutes balances "bound memory growth" with
// "do not wake up frequently on idle deployments".
const memoryLabelCacheJanitorInterval = 5 * time.Minute

func newMemoryLabelCache() *memoryLabelCache {
	return &memoryLabelCache{entries: make(map[string]memoryLabelEntry)}
}

func (c *memoryLabelCache) Get(_ context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return "", nil
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		delete(c.entries, key)
		return "", nil
	}
	return e.value, nil
}

func (c *memoryLabelCache) Set(_ context.Context, key, value string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := time.Time{}
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	c.entries[key] = memoryLabelEntry{value: value, expiresAt: exp}
	return nil
}

// sweepExpired removes every entry whose TTL has passed. Returns the
// number of entries evicted so the caller can log it.
func (c *memoryLabelCache) sweepExpired(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for k, e := range c.entries {
		if e.expiresAt.IsZero() {
			continue
		}
		if now.After(e.expiresAt) {
			delete(c.entries, k)
			removed++
		}
	}
	return removed
}

// runJanitor evicts expired entries on a fixed cadence until ctx is
// cancelled. It is intentionally blocking so callers can wrap it in
// a tracked goroutine (see application.StartBackground).
func (c *memoryLabelCache) runJanitor(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = memoryLabelCacheJanitorInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if n := c.sweepExpired(now); n > 0 && logger != nil {
				logger.Debug("sn360-es: memoryLabelCache janitor swept entries",
					slog.Int("evicted", n))
			}
		}
	}
}

// newLabelCache picks the redis-backed adapter when redis is wired,
// otherwise it falls back to the in-memory implementation. Both
// satisfy action.LabelCache so the applier wiring is identical.
//
// When the in-memory cache is selected the returned *memoryLabelCache
// is also returned so the caller can wire its janitor goroutine —
// this avoids unbounded growth in long-running deployments that have
// not configured Redis. The second return value is nil for the redis
// path because the redis server enforces TTL eviction itself.
func newLabelCache(r *redis.Client) (action.LabelCache, *memoryLabelCache) {
	if r != nil {
		return redisLabelCache{client: r}, nil
	}
	mem := newMemoryLabelCache()
	return mem, mem
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

// tier0BatchAdapter adapts tier0.Gate to the evaluate.Tier0BatchGate
// interface used by BatchOrchestrator. The orchestrator wants a single
// call that says "did Tier 0 short-circuit, and if so, here is the
// final result"; the underlying gate returns a richer Tier0Outcome
// with Bypass/SkipML/RspamdOnly flags. The adapter only short-circuits
// on Bypass (the case where the gate has a forced category and the
// whole pipeline can be skipped). SkipML/RspamdOnly hits fall through
// to Tier 1 so the orchestrator's escalation path still runs them
// through the full evaluator if needed.
type tier0BatchAdapter struct{ gate *tier0.Gate }

func (a tier0BatchAdapter) Apply(req dto.EvaluateRequest, signals dto.RiskSignals) (dto.EvaluateResult, bool) {
	if a.gate == nil {
		return dto.EvaluateResult{}, false
	}
	// The batch envelope carries Signals alongside the request, but the
	// gate reads from req.Signals. Splice the batch signals onto the
	// request so the gate sees the same view the single-message path
	// would after unmarshalling.
	req.Signals = signals
	out := a.gate.Apply(req)
	if !out.Bypass {
		return dto.EvaluateResult{}, false
	}
	res := dto.EvaluateResult{
		TenantID:      req.TenantID,
		MessageID:     req.MessageID,
		CorrelationID: req.CorrelationID,
		EvaluatedAt:   time.Now().UTC(),
		Primary:       out.ForcedCategory,
		Tier:          evaluate.ForcedTierFor(out.ForcedCategory),
		Tier0:         &out,
	}
	if out.Reason != "" {
		res.ReasonCodes = append(res.ReasonCodes, out.Reason)
	}
	return res, true
}

// fallbackEvaluatorAdapter adapts *evaluate.Evaluator (which exposes
// Evaluate(ctx, req)) to evaluate.MessageEvaluator (which expects
// Evaluate(ctx, req, signals)). The evaluator reads signals from
// req.Signals internally; the adapter splices the batch signals into
// the request before delegating.
type fallbackEvaluatorAdapter struct{ eval *evaluate.Evaluator }

func (a fallbackEvaluatorAdapter) Evaluate(ctx context.Context, req dto.EvaluateRequest, signals dto.RiskSignals) (dto.EvaluateResult, error) {
	if a.eval == nil {
		return dto.EvaluateResult{}, errors.New("evaluate: fallback evaluator unavailable")
	}
	req.Signals = signals
	return a.eval.Evaluate(ctx, req)
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

// ---------------------------------------------------------------------
// Ingestion poller wiring.
// ---------------------------------------------------------------------

// buildPoller constructs the ingestion poller from the configured
// mailbox providers. When ingestion is disabled or no providers are
// wired the function returns nil — Run() then simply skips the
// goroutine.
func buildPoller(ctx context.Context, cfg *config.Config, logger *slog.Logger, app *application) *ingestion.Poller {
	if !cfg.Ingestion.Enabled {
		logger.Info("sn360-es: ingestion polling disabled via config")
		return nil
	}

	providers := buildMailboxProviders(ctx, cfg, logger)
	if len(providers) == 0 {
		logger.Info("sn360-es: ingestion polling skipped; no mailbox providers configured")
		return nil
	}

	// Checkpoint store — Redis-backed in production; nil in
	// fall-back mode (the poller still runs, it just re-fetches
	// from the lookback window on every restart).
	var checkpoint ingestion.CheckpointStore
	if app.redis != nil {
		store, cerr := ingestion.NewCheckpointStore(app.redis, "", 0)
		if cerr != nil {
			logger.Warn("sn360-es: ingestion checkpoint store init failed; running stateless",
				slog.Any("error", cerr))
		} else {
			checkpoint = store
		}
	}

	// Lock factory — Redis-backed in production; nil in dev so
	// the poller does not deadlock against a missing Redis.
	var lockFactory ingestion.LockFactory
	if app.redis != nil {
		lockTTL := cfg.Ingestion.LockTTL
		if lockTTL <= 0 {
			lockTTL = 3 * cfg.Ingestion.Interval / 2
			if lockTTL <= 0 {
				lockTTL = 45 * time.Second
			}
		}
		client := app.redis
		lockFactory = func(key string) ingestion.DistributedLock {
			lock, lerr := redis.NewDistributedLock(client, key, lockTTL)
			if lerr != nil {
				logger.Warn("sn360-es: ingestion lock init failed; running unlocked",
					slog.String("key", key), slog.Any("error", lerr))
				return ingestion.NoopLock{}
			}
			return ingestionLockAdapter{lock: lock}
		}
	}

	p, err := ingestion.New(ingestion.PollerConfig{
		Providers:          providers,
		Publisher:          app.eventBus,
		Logger:             logger,
		Normalizer:         ingestion.NewDefaultNormalizer(),
		Checkpoint:         checkpoint,
		Locks:              lockFactory,
		Interval:           cfg.Ingestion.Interval,
		BatchSize:          cfg.Ingestion.BatchSize,
		Concurrency:        cfg.Ingestion.Concurrency,
		LookbackOnFirstRun: cfg.Ingestion.InitialBackfill,
	})
	if err != nil {
		logger.Warn("sn360-es: ingestion poller init failed; polling disabled",
			slog.Any("error", err))
		return nil
	}
	logger.Info("sn360-es: ingestion poller wired",
		slog.Int("providers", len(providers)),
		slog.Duration("interval", cfg.Ingestion.Interval))
	return p
}

// buildMailboxProviders inspects the GWS / O365 configuration and
// returns the matching MailboxProvider implementations. Returns an
// empty slice when neither provider is configured.
func buildMailboxProviders(ctx context.Context, cfg *config.Config, logger *slog.Logger) []ingestion.MailboxProvider {
	out := make([]ingestion.MailboxProvider, 0, 2)
	if cfg.GWS.HasGmail() {
		sa, err := gmail.LoadServiceAccount(cfg.GWS.ServiceAccountJSON)
		if err != nil {
			logger.Warn("sn360-es: gmail mailbox provider init failed (service account)",
				slog.Any("error", err))
		} else {
			tokens, terr := gmail.NewJWTBearerSource(gmail.JWTBearerConfig{
				ServiceAccount:   sa,
				ImpersonatedUser: cfg.GWS.DelegatedAdmin,
			})
			if terr != nil {
				logger.Warn("sn360-es: gmail mailbox provider init failed (token source)",
					slog.Any("error", terr))
			} else {
				mbp, merr := gmail.NewMailboxProvider(gmail.MailboxProviderConfig{
					TokenSource: tokens,
					// AdminTokenSource is required for the Admin SDK
					// /admin/directory/v1/users call inside
					// ListMailboxes. Without it the provider falls
					// back to ManualMailboxes (empty in this wiring)
					// and the poller silently observes zero
					// mailboxes. The JWT bearer source above is
					// already constructed with the
					// admin.directory.user.readonly scope, so the
					// same source is valid for the Admin SDK call.
					AdminTokenSource: tokens,
					Domain:           cfg.GWS.Domain,
					AdminBaseURL:     cfg.GWS.AdminBaseURL,
					BaseURL:          cfg.GWS.BaseURL,
					TenantID:         cfg.GWS.Domain,
				})
				if merr != nil {
					logger.Warn("sn360-es: gmail mailbox provider init failed",
						slog.Any("error", merr))
				} else {
					out = append(out, mbp)
					logger.Info("sn360-es: gmail mailbox provider wired",
						slog.String("domain", cfg.GWS.Domain))
				}
			}
		}
	}
	if cfg.O365.HasOutlook() {
		tokens, terr := outlook.NewClientCredentialsSource(outlook.ClientCredentialsConfig{
			TenantID:     cfg.O365.TenantID,
			ClientID:     cfg.O365.ClientID,
			ClientSecret: cfg.O365.ClientSecret,
			TokenURL:     cfg.O365.TokenURL,
		})
		if terr != nil {
			logger.Warn("sn360-es: outlook mailbox provider init failed (token source)",
				slog.Any("error", terr))
		} else {
			mbp, merr := outlook.NewMailboxProvider(outlook.MailboxProviderConfig{
				TokenSource: tokens,
				BaseURL:     cfg.O365.BaseURL,
				TenantID:    cfg.O365.TenantID,
				// Default to admin-level user enumeration so the
				// poller actually discovers tenant mailboxes. When
				// false, ListMailboxes returns only the manually
				// configured ManualMailboxes list — empty by default
				// in this wiring — and the poller silently observes
				// zero mailboxes. The client-credentials token
				// source has User.Read.All by definition.
				EnumerateUsers: true,
			})
			if merr != nil {
				logger.Warn("sn360-es: outlook mailbox provider init failed",
					slog.Any("error", merr))
			} else {
				out = append(out, mbp)
				logger.Info("sn360-es: outlook mailbox provider wired",
					slog.String("tenant", cfg.O365.TenantID))
			}
		}
	}
	_ = ctx
	return out
}

// ingestionLockAdapter adapts *redis.DistributedLock to the
// ingestion.DistributedLock interface. The ingestion package's
// Release returns error only — we collapse the bool return from the
// Redis primitive into "no error" since "released or already
// expired" are both legitimate outcomes from the poller's
// perspective.
type ingestionLockAdapter struct {
	lock *redis.DistributedLock
}

func (a ingestionLockAdapter) Acquire(ctx context.Context) (bool, error) {
	return a.lock.Acquire(ctx)
}

func (a ingestionLockAdapter) Release(ctx context.Context) error {
	_, err := a.lock.Release(ctx)
	return err
}

// ---------------------------------------------------------------------
// Periodic worker wiring.
// ---------------------------------------------------------------------

// buildWorkers constructs the three periodic workers (relationship
// aggregation, vendor discovery, retention cleanup). Each returned
// runner is nil when its dependencies are missing so Run() can
// start only the ones that have a chance of running successfully.
func buildWorkers(cfg *config.Config, logger *slog.Logger, app *application) (*worker.Runner, *worker.Runner, *worker.Runner) {
	if app.repos == nil {
		logger.Info("sn360-es: periodic workers skipped; repository registry not wired")
		return nil, nil, nil
	}

	lockFactory := buildWorkerLockFactory(cfg, logger, app)

	// Metrics adapter — uses the worker bucket on telemetry.Metrics.
	metricsRec := workerMetricsAdapter{m: app.metrics}

	relRunner := buildRelationshipRunner(cfg, logger, app, lockFactory, metricsRec)
	vendorRunner := buildVendorRunner(cfg, logger, app, lockFactory, metricsRec)
	cleanupRunner := buildCleanupRunner(cfg, logger, app, lockFactory, metricsRec)

	return relRunner, vendorRunner, cleanupRunner
}

func buildWorkerLockFactory(cfg *config.Config, logger *slog.Logger, app *application) worker.LockFactory {
	if app.redis == nil {
		return nil
	}
	lockTTL := cfg.Worker.LockTTL
	if lockTTL <= 0 {
		lockTTL = 10 * time.Minute
	}
	client := app.redis
	return func(name string) worker.DistributedLock {
		lock, err := redis.NewDistributedLock(client, "worker:lock:"+name, lockTTL)
		if err != nil {
			logger.Warn("sn360-es: worker lock init failed; running unlocked",
				slog.String("worker", name), slog.Any("error", err))
			return workerLockNoop{}
		}
		return workerLockAdapter{lock: lock}
	}
}

func buildRelationshipRunner(cfg *config.Config, logger *slog.Logger, app *application, locks worker.LockFactory, metrics worker.MetricsRecorder) *worker.Runner {
	if app.repos.Tenants == nil || app.repos.CommunicationHistories == nil {
		return nil
	}
	// CommunicationHistoryRepository now declares ListByTenant
	// directly, so every implementation in this codebase (Postgres,
	// in-memory, fakes) satisfies worker.CommunicationStore by
	// definition. The runtime type assertion that previously gated
	// this wiring would always fail because the interface didn't
	// declare ListByTenant — workers silently never ran. Dropping
	// the assertion is safe: the compiler now enforces the contract.
	job, err := worker.NewRelationshipJob(worker.RelationshipJobConfig{
		Interval:       cfg.Worker.RelationshipInterval,
		Tenants:        app.repos.Tenants,
		Communications: app.repos.CommunicationHistories,
		Upserter:       app.repos.CommunicationHistories,
		Logger:         logger,
	})
	if err != nil {
		logger.Warn("sn360-es: relationship worker init failed",
			slog.Any("error", err))
		return nil
	}
	runner, rerr := worker.NewRunner(worker.RunnerConfig{
		Job:     job,
		Logger:  logger,
		Locks:   locks,
		Metrics: metrics,
	})
	if rerr != nil {
		logger.Warn("sn360-es: relationship runner init failed",
			slog.Any("error", rerr))
		return nil
	}
	logger.Info("sn360-es: relationship worker wired",
		slog.Duration("interval", cfg.Worker.RelationshipInterval))
	return runner
}

func buildVendorRunner(cfg *config.Config, logger *slog.Logger, app *application, locks worker.LockFactory, metrics worker.MetricsRecorder) *worker.Runner {
	if app.repos.Tenants == nil || app.repos.CommunicationHistories == nil || app.repos.Vendors == nil {
		return nil
	}
	// See comment in buildRelationshipRunner — the
	// CommunicationHistoryRepository interface now declares
	// ListByTenant so worker.CommunicationStore is satisfied at
	// compile time and no runtime assertion is needed.
	discovery := relationship.NewVendorDiscovery(relationship.VendorDiscoveryConfig{}, logger)
	job, err := worker.NewVendorJob(worker.VendorJobConfig{
		Interval:         cfg.Worker.VendorDiscoveryInterval,
		Tenants:          app.repos.Tenants,
		Communications:   app.repos.CommunicationHistories,
		Discovery:        discovery,
		VendorRepository: app.repos.Vendors,
		Logger:           logger,
	})
	if err != nil {
		logger.Warn("sn360-es: vendor worker init failed",
			slog.Any("error", err))
		return nil
	}
	runner, rerr := worker.NewRunner(worker.RunnerConfig{
		Job:     job,
		Logger:  logger,
		Locks:   locks,
		Metrics: metrics,
	})
	if rerr != nil {
		logger.Warn("sn360-es: vendor runner init failed",
			slog.Any("error", rerr))
		return nil
	}
	logger.Info("sn360-es: vendor worker wired",
		slog.Duration("interval", cfg.Worker.VendorDiscoveryInterval))
	return runner
}

func buildCleanupRunner(cfg *config.Config, logger *slog.Logger, app *application, locks worker.LockFactory, metrics worker.MetricsRecorder) *worker.Runner {
	pruners := make([]worker.Pruner, 0, 4)
	// Best-effort pruners — every pruner stays optional so the
	// cleanup worker can boot even when only some dependencies
	// are wired.
	if app.pgDB != nil {
		pruners = append(pruners, newPgPruner(app.pgDB, "evaluation_results", logger))
		pruners = append(pruners, newPgPruner(app.pgDB, "feedback_events", logger))
		pruners = append(pruners, newPgPruner(app.pgDB, "communication_histories", logger))
	}
	if len(pruners) == 0 {
		logger.Info("sn360-es: cleanup worker skipped; no pruners configured")
		return nil
	}
	job, err := worker.NewCleanupJob(worker.CleanupJobConfig{
		Interval:      cfg.Worker.CleanupInterval,
		RetentionDays: cfg.Worker.RetentionDays,
		Pruners:       pruners,
		Logger:        logger,
	})
	if err != nil {
		logger.Warn("sn360-es: cleanup worker init failed",
			slog.Any("error", err))
		return nil
	}
	runner, rerr := worker.NewRunner(worker.RunnerConfig{
		Job:     job,
		Logger:  logger,
		Locks:   locks,
		Metrics: metrics,
	})
	if rerr != nil {
		logger.Warn("sn360-es: cleanup runner init failed",
			slog.Any("error", rerr))
		return nil
	}
	logger.Info("sn360-es: cleanup worker wired",
		slog.Int("pruners", len(pruners)),
		slog.Duration("interval", cfg.Worker.CleanupInterval),
		slog.Int("retention_days", cfg.Worker.RetentionDays))
	return runner
}

// workerLockAdapter adapts *redis.DistributedLock to the worker
// package's DistributedLock interface (Release returns only an
// error there).
type workerLockAdapter struct {
	lock *redis.DistributedLock
}

func (a workerLockAdapter) Acquire(ctx context.Context) (bool, error) {
	return a.lock.Acquire(ctx)
}

func (a workerLockAdapter) Release(ctx context.Context) error {
	_, err := a.lock.Release(ctx)
	return err
}

// workerLockNoop is returned when the Redis lock primitive cannot
// be constructed — the worker still runs, it just relies on a
// single replica being deployed (the common case in dev).
type workerLockNoop struct{}

func (workerLockNoop) Acquire(context.Context) (bool, error) { return true, nil }
func (workerLockNoop) Release(context.Context) error         { return nil }

// workerMetricsAdapter funnels Job runner outcomes into the
// telemetry.Metrics counters. Nil-safe so a binary running without
// metrics still emits cycle logs.
type workerMetricsAdapter struct {
	m *telemetry.Metrics
}

func (a workerMetricsAdapter) ObserveCycle(name string, duration time.Duration, err error) {
	if a.m == nil {
		return
	}
	a.m.ObserveWorkerCycle(name, duration, err)
}

// prunableTables is the exhaustive allow-list of table names that
// newPgPruner may interpolate into a DELETE statement plus the
// per-table "prune by this column" choice. Because Go's database/sql
// does not support parameterised table or column identifiers, both
// names are injected via fmt.Sprintf — restricting the table set AND
// the column set to a compile-time map prevents accidental SQL
// injection if a caller ever passes unsanitised input.
//
// The column choice matters: most append-only tables track a
// `created_at` stamp, but the aggregation tables (e.g.
// communication_histories) carry a `last_seen_at` instead. Pruning
// communication_histories on `created_at` would fail with "column
// does not exist" because the migration in
// migrations/0001_init.up.sql:215-218 only declares
// first_seen_at / last_seen_at / updated_at. Tying the column to the
// table at registration time makes that class of bug impossible to
// reproduce at runtime.
var prunableTables = map[string]string{
	"evaluation_results":      "created_at",
	"feedback_events":         "created_at",
	"communication_histories": "last_seen_at",
	"quarantine_references":   "created_at",
	"education_lesson_events": "created_at",
	"simulation_send_events":  "created_at",
}

// newPgPruner returns a Postgres-backed pruner for the named table.
// The DELETE statement uses the prune-column registered for the
// table in prunableTables, so each table is pruned on its canonical
// age column ("created_at" for append-only tables, "last_seen_at"
// for aggregation tables like communication_histories).
//
// The table name MUST appear in prunableTables. A panic on
// construction is intentional — it catches programming errors at
// startup rather than silently ignoring a typo at the first
// cleanup tick (which might be hours later).
func newPgPruner(db *postgres.DB, table string, logger *slog.Logger) worker.Pruner {
	column, ok := prunableTables[table]
	if !ok {
		panic(fmt.Sprintf("newPgPruner: table %q is not in the allow-list", table))
	}
	query := fmt.Sprintf("DELETE FROM %s WHERE %s < $1", table, column)
	return worker.NewPruner(table, func(ctx context.Context, before time.Time) (int64, error) {
		if db == nil {
			return 0, nil
		}
		res, err := db.ExecContext(ctx, query, before)
		if err != nil {
			logger.Warn("sn360-es: cleanup prune failed",
				slog.String("table", table),
				slog.String("column", column),
				slog.Any("error", err))
			return 0, err
		}
		n, rerr := res.RowsAffected()
		if rerr != nil {
			return 0, nil
		}
		return n, nil
	})
}

// ---------------------------------------------------------------------
// AI agent wiring.
// ---------------------------------------------------------------------

// buildAgents constructs the onboarding / tuning / support agents.
// Each returned agent is nil when its inputs are missing; the
// consumer wiring (StartConsumers) checks for nil and falls back to
// the original logging-only handlers.
func buildAgents(cfg *config.Config, logger *slog.Logger, app *application) (*agent.OnboardingAgent, *agent.TuningAgent, *agent.SupportAgent) {
	var onboardA *agent.OnboardingAgent
	var tuningA *agent.TuningAgent
	var supportA *agent.SupportAgent

	pub := agentPublisherFromBus(app.eventBus)

	// Support agent — depends only on the event bus + repository
	// (for verdict lookup). When the repos are missing it still
	// wires up; the lookup adapter degrades gracefully.
	if pub != nil {
		audit := loggingAuditLog{logger: logger}
		lookup := evalLookupAdapter{repos: app.repos}
		sa, err := agent.NewSupportAgent(agent.SupportConfig{
			Lookup:         lookup,
			Audit:          audit,
			Events:         pub,
			SecOpsSubject:  "es.action.escalation.created",
			ReleaseSubject: "es.action.quarantine.release",
			Logger:         logger,
		})
		if err != nil {
			logger.Warn("sn360-es: support agent init failed",
				slog.Any("error", err))
		} else {
			supportA = sa
			logger.Info("sn360-es: support agent wired")
		}
	}

	// Onboarding agent — requires a directory client + LabelApplier.
	// Today we only wire it when GWS or O365 credentials are
	// configured so it has something to call.
	if app.providers != nil && app.providers.hasAny() && pub != nil {
		dir := buildDirectoryClient(cfg, logger)
		labels := buildLabelApplier(app)
		piiHasher := buildPIIHasher(cfg)
		if dir != nil && labels != nil {
			oa, err := agent.NewOnboardingAgent(agent.OnboardingConfig{
				Directory:             dir,
				Labels:                labels,
				Events:                pub,
				Audit:                 loggingAuditLog{logger: logger},
				Logger:                logger,
				Hasher:                piiHasher,
				Persister:             buildUserPersister(app, piiHasher),
				SensitivityClassifier: buildSensitivityClassifier(cfg, logger),
				VendorScanner:         buildVendorScanner(app),
				Config:                newMemoryConfigStore(),
			})
			if err != nil {
				logger.Warn("sn360-es: onboarding agent init failed",
					slog.Any("error", err))
			} else {
				onboardA = oa
				logger.Info("sn360-es: onboarding agent wired")
			}
		}
	}

	// Tuning agent — needs a feedback / weights / thresholds
	// repository. The repository registry doesn't expose
	// ConfigStore today, so we degrade to an in-memory store.
	if app.repos != nil && app.repos.FeedbackEvents != nil {
		results := tuningResultAdapter{repos: app.repos}
		store := newMemoryConfigStore()
		ta, err := agent.NewTuningAgent(agent.TuningConfig{
			Results: results,
			Config:  store,
			Audit:   loggingAuditLog{logger: logger},
			Logger:  logger,
		})
		if err != nil {
			logger.Warn("sn360-es: tuning agent init failed",
				slog.Any("error", err))
		} else {
			tuningA = ta
			logger.Info("sn360-es: tuning agent wired")
		}
	}
	return onboardA, tuningA, supportA
}

// agentEventBusAdapter narrows the full event.Service surface to the
// minimal Publish(ctx, subject, data) shape the agent package depends
// on. Returns nil when bus is nil so callers can short-circuit.
type agentEventBusAdapter struct {
	bus events.EventService
}

// Publish forwards to the underlying bus with no publish options.
func (a agentEventBusAdapter) Publish(ctx context.Context, subject string, data []byte) error {
	return a.bus.Publish(ctx, subject, data)
}

// agentPublisherFromBus returns nil when bus is nil; otherwise the
// adapter that satisfies agent.EventPublisher.
func agentPublisherFromBus(bus events.EventService) agent.EventPublisher {
	if bus == nil {
		return nil
	}
	return agentEventBusAdapter{bus: bus}
}

// buildLabelApplier wires the onboarding agent's LabelApplier to the
// already-configured provider registry. It iterates the registry on
// each EnsureTierLabels call so multi-tenant deployments are routed
// to the correct provider.
func buildLabelApplier(app *application) agent.LabelApplier {
	if app == nil || app.providers == nil {
		return nil
	}
	return registryLabelApplier{registry: app.providers}
}

// registryLabelApplier dispatches EnsureTierLabels to whichever
// provider (Gmail / Outlook) is registered for the tenant. If no
// provider is registered the call is a no-op (best-effort).
type registryLabelApplier struct {
	registry *providerRegistry
}

// EnsureTierLabels resolves the tenant's provider and seeds the five
// canonical SN360 tier labels on the target mailbox.
func (r registryLabelApplier) EnsureTierLabels(ctx context.Context, tenantID, mailbox string) error {
	entry := r.registry.lookup(tenantID)
	if entry == nil {
		return nil
	}
	if entry.labelProvider == nil {
		return nil
	}
	tiers := []constant.Tier{
		constant.TierBlocked,
		constant.TierHighRisk,
		constant.TierWarning,
		constant.TierCaution,
		constant.TierInformational,
	}
	for _, t := range tiers {
		if _, err := entry.labelProvider.EnsureLabel(ctx, mailbox, "SN360 / "+string(t), action.ColorFor(t)); err != nil {
			return err
		}
	}
	return nil
}

// buildDirectoryClient returns an agent.DirectoryClient sourced from
// the GWS Admin SDK or the Microsoft Graph /users endpoint. Returns
// nil when no provider is configured — the onboarding agent then
// stays inactive.
func buildDirectoryClient(cfg *config.Config, logger *slog.Logger) agent.DirectoryClient {
	if cfg.GWS.HasGmail() {
		// The Gmail MailboxProvider already wraps the Admin SDK
		// client; it also satisfies the DirectoryClient surface
		// via its ListUsers / ListGroups methods.
		sa, err := gmail.LoadServiceAccount(cfg.GWS.ServiceAccountJSON)
		if err != nil {
			logger.Warn("sn360-es: directory client (gmail) init failed",
				slog.Any("error", err))
			return nil
		}
		tokens, terr := gmail.NewJWTBearerSource(gmail.JWTBearerConfig{
			ServiceAccount:   sa,
			ImpersonatedUser: cfg.GWS.DelegatedAdmin,
		})
		if terr != nil {
			logger.Warn("sn360-es: directory client (gmail) token init failed",
				slog.Any("error", terr))
			return nil
		}
		dc, derr := gmail.NewDirectoryClient(gmail.DirectoryClientConfig{
			TokenSource:  tokens,
			Domain:       cfg.GWS.Domain,
			AdminBaseURL: cfg.GWS.AdminBaseURL,
		})
		if derr != nil {
			logger.Warn("sn360-es: directory client (gmail) wire failed",
				slog.Any("error", derr))
			return nil
		}
		return dc
	}
	if cfg.O365.HasOutlook() {
		tokens, terr := outlook.NewClientCredentialsSource(outlook.ClientCredentialsConfig{
			TenantID:     cfg.O365.TenantID,
			ClientID:     cfg.O365.ClientID,
			ClientSecret: cfg.O365.ClientSecret,
			TokenURL:     cfg.O365.TokenURL,
		})
		if terr != nil {
			logger.Warn("sn360-es: directory client (outlook) token init failed",
				slog.Any("error", terr))
			return nil
		}
		dc, derr := outlook.NewDirectoryClient(outlook.DirectoryClientConfig{
			TokenSource: tokens,
			BaseURL:     cfg.O365.BaseURL,
			TenantID:    cfg.O365.TenantID,
		})
		if derr != nil {
			logger.Warn("sn360-es: directory client (outlook) wire failed",
				slog.Any("error", derr))
			return nil
		}
		return dc
	}
	return nil
}

// loggingAuditLog implements agent.AuditLog by emitting structured
// log lines. Production deployments can swap it for a Postgres
// implementation once the schema is in place.
type loggingAuditLog struct {
	logger *slog.Logger
}

func (l loggingAuditLog) Record(_ context.Context, entry agent.AuditEntry) error {
	l.logger.Info("agent.audit",
		slog.String("agent", entry.Agent),
		slog.String("tenant_id", entry.TenantID),
		slog.String("action", entry.Action),
		slog.String("reason", entry.Reason),
		slog.Time("occurred_at", entry.OccurredAt),
		slog.Any("detail", entry.Detail))
	return nil
}

// evalLookupAdapter wraps the EvaluationResultRepository so the
// support agent can fetch the stored verdict for a message.
type evalLookupAdapter struct {
	repos *repository.Registry
}

func (a evalLookupAdapter) FindResult(ctx context.Context, tenantID, messageID string) (dto.EvaluateResult, error) {
	if a.repos == nil || a.repos.EvaluationResults == nil {
		return dto.EvaluateResult{}, fmt.Errorf("evaluation lookup: not wired")
	}
	hash := sha256.Sum256([]byte(messageID))
	row, err := a.repos.EvaluationResults.GetByMessageHash(ctx, tenantID, hash[:])
	if err != nil {
		return dto.EvaluateResult{}, err
	}
	return dto.EvaluateResult{
		TenantID:    row.TenantID,
		MessageID:   messageID,
		Tier:        constant.Tier(row.Tier),
		Primary:     constant.Category(row.Primary),
		Score:       row.Score,
		ReasonCodes: row.ReasonCodes,
		EvaluatedAt: row.EvaluatedAt,
	}, nil
}

// tuningResultAdapter exposes the FeedbackEventRepository as the
// ResultRepository surface the tuning agent needs.
type tuningResultAdapter struct {
	repos *repository.Registry
}

func (a tuningResultAdapter) RecentFeedback(ctx context.Context, tenantID string, since time.Time) ([]agent.Feedback, error) {
	if a.repos == nil || a.repos.FeedbackEvents == nil {
		return nil, nil
	}
	rows, err := a.repos.FeedbackEvents.ListSince(ctx, tenantID, since)
	if err != nil {
		return nil, err
	}
	out := make([]agent.Feedback, 0, len(rows))
	for _, r := range rows {
		out = append(out, agent.Feedback{
			TenantID:   r.TenantID,
			MessageID:  r.PseudoMessageID,
			Action:     agent.FeedbackKind(r.Action),
			PriorTier:  constant.Tier(r.Tier),
			OccurredAt: r.OccurredAt,
		})
	}
	return out, nil
}

func (a tuningResultAdapter) CurrentWeights(ctx context.Context, tenantID string) (agent.ScoreWeights, error) {
	if a.repos == nil || a.repos.ScoreEngines == nil {
		return agent.ScoreWeights{}, fmt.Errorf("tuning: score engines not wired")
	}
	row, err := a.repos.ScoreEngines.Get(ctx, tenantID)
	if err != nil {
		return agent.ScoreWeights{}, err
	}
	return agent.ScoreWeights{
		AI:          float64(row.WeightAI),
		Rspamd:      float64(row.WeightRspamd),
		Attachments: float64(row.WeightAttachments),
		Links:       float64(row.WeightLinks),
	}, nil
}

func (a tuningResultAdapter) CurrentThresholds(ctx context.Context, tenantID string) (agent.Thresholds, error) {
	if a.repos == nil || a.repos.ScoreEngines == nil {
		return agent.Thresholds{}, fmt.Errorf("tuning: score engines not wired")
	}
	row, err := a.repos.ScoreEngines.Get(ctx, tenantID)
	if err != nil {
		return agent.Thresholds{}, err
	}
	return agent.Thresholds{
		BannerBlocked:  row.ThresholdBlocked,
		BannerHighRisk: row.ThresholdHigh,
		BannerWarning:  row.ThresholdWarning,
		BannerCaution:  row.ThresholdCaution,
		BannerInfo:     row.ThresholdInfo,
	}, nil
}

// memoryConfigStore is a tiny in-memory ConfigStore implementation
// used until the management service exposes a proper score-engine
// write endpoint. Decisions are logged so audit pipes can re-derive
// the changes from logs.
type memoryConfigStore struct {
	mu         sync.Mutex
	weights    map[string]agent.ScoreWeights
	thresholds map[string]agent.Thresholds
}

func newMemoryConfigStore() *memoryConfigStore {
	return &memoryConfigStore{
		weights:    map[string]agent.ScoreWeights{},
		thresholds: map[string]agent.Thresholds{},
	}
}

func (s *memoryConfigStore) UpdateWeights(_ context.Context, tenantID string, w agent.ScoreWeights) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.weights[tenantID] = w
	return nil
}

func (s *memoryConfigStore) UpdateThresholds(_ context.Context, tenantID string, t agent.Thresholds) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.thresholds[tenantID] = t
	return nil
}

// ---------------------------------------------------------------------
// Onboarding agent smart-dependency builders.
// ---------------------------------------------------------------------

// piiHasherAdapter implements agent.PIIHasher by wrapping
// privacy.Pseudonymizer with a deterministic tenant key derivation.
type piiHasherAdapter struct {
	pseudo privacy.Pseudonymizer
	secret string
}

func (h *piiHasherAdapter) HashPII(tenantID string, input string) string {
	key := sha256.Sum256([]byte(h.secret + ":" + tenantID))
	return h.pseudo.HashOrEmpty(key[:], input)
}

func buildPIIHasher(cfg *config.Config) agent.PIIHasher {
	secret := cfg.Banner.TokenSecret
	if secret == "" {
		return nil
	}
	return &piiHasherAdapter{
		pseudo: privacy.NewPseudonymizer("sn360"),
		secret: secret,
	}
}

// userPersisterAdapter implements agent.UserPersister by upserting
// discovered users and groups into the Postgres repositories.
type userPersisterAdapter struct {
	users  repository.UserRepository
	groups repository.GroupRepository
	hasher agent.PIIHasher
}

func (p *userPersisterAdapter) PersistDiscoveredUsers(ctx context.Context, tenantID string, users []agent.DiscoveredUser, groups []agent.DiscoveredGroup) error {
	now := time.Now().UTC()
	for _, g := range groups {
		if err := p.groups.Upsert(ctx, &repository.Group{
			ID:          g.ID,
			TenantID:    tenantID,
			Name:        g.Name,
			Description: g.Description,
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			return fmt.Errorf("persist group %s: %w", g.ID, err)
		}
	}
	for _, u := range users {
		if u.Email == "" {
			continue
		}
		var emailHash []byte
		if p.hasher != nil {
			emailHash = []byte(p.hasher.HashPII(tenantID, u.Email))
		}
		if err := p.users.Upsert(ctx, &repository.User{
			ID:              u.ID,
			TenantID:        tenantID,
			EmailHash:       emailHash,
			Role:            u.JobTitle,
			Department:      u.Department,
			SensitivityTier: u.SensitivityHint.DBTier(),
			CreatedAt:       now,
			UpdatedAt:       now,
		}); err != nil {
			return fmt.Errorf("persist user %s: %w", u.ID, err)
		}
	}
	return nil
}

func buildUserPersister(app *application, hasher agent.PIIHasher) agent.UserPersister {
	if app.repos == nil || app.repos.Users == nil || app.repos.Groups == nil || hasher == nil {
		return nil
	}
	return &userPersisterAdapter{
		users:  app.repos.Users,
		groups: app.repos.Groups,
		hasher: hasher,
	}
}

func buildSensitivityClassifier(cfg *config.Config, logger *slog.Logger) agent.SensitivityClassifier {
	if cfg.Tier1.URL == "" {
		return nil
	}
	encoder := agent.NewEncoderSensitivityClassifier(cfg.Tier1.URL, nil, cfg.Tier1.Timeout, logger)
	return agent.NewTieredSensitivityClassifier(agent.TieredClassifierConfig{
		Encoder:  encoder,
		Fallback: agent.KeywordClassifyInput,
		Logger:   logger,
	})
}

// vendorScannerAdapter implements agent.VendorScanner using the
// communication-history repository.
type vendorScannerAdapter struct {
	histories repository.CommunicationHistoryRepository
}

func (v *vendorScannerAdapter) ScanRecentSenders(ctx context.Context, tenantID string, since time.Time) ([]agent.VendorCandidate, error) {
	histories, err := v.histories.ListByTenant(ctx, tenantID, since, 0)
	if err != nil {
		return nil, err
	}
	var candidates []agent.VendorCandidate
	for _, h := range histories {
		count := h.Count30d
		candidates = append(candidates, agent.VendorCandidate{
			Domain:     h.SenderDomain,
			SeenCount:  count,
			Confidence: vendorConfidence(count),
		})
	}
	return candidates, nil
}

func vendorConfidence(count int) float64 {
	switch {
	case count >= 50:
		return 0.95
	case count >= 20:
		return 0.85
	case count >= 10:
		return 0.75
	case count >= 5:
		return 0.65
	default:
		return 0.5
	}
}

func buildVendorScanner(app *application) agent.VendorScanner {
	if app.repos == nil || app.repos.CommunicationHistories == nil {
		return nil
	}
	return &vendorScannerAdapter{histories: app.repos.CommunicationHistories}
}

// ---------------------------------------------------------------------
// Background lifecycle.
// ---------------------------------------------------------------------

// StartBackground starts the poller + worker goroutines. They each
// respect context cancellation so SIGTERM cleanly stops them.
// Errors from the long-running goroutines are logged but never
// surfaced to the caller because a missed cycle on a recurring
// worker is recoverable on the next tick.
//
// Every goroutine launched here is tracked on a.bgWG so the shutdown
// sequence in run() can call WaitBackground() and drain them before
// the bus and database connections close. Without that wait, an
// in-flight poller cycle could publish to a closed bus or write to a
// closed *sql.DB after the parent context fires.
func (a *application) StartBackground(ctx context.Context) {
	a.spawn(ctx, "ingestion poller", func(ctx context.Context) error {
		if a.poller == nil {
			return nil
		}
		return a.poller.Run(ctx)
	})
	a.spawn(ctx, "relationship worker", func(ctx context.Context) error {
		if a.relationshipRunner == nil {
			return nil
		}
		return a.relationshipRunner.Run(ctx)
	})
	a.spawn(ctx, "vendor worker", func(ctx context.Context) error {
		if a.vendorRunner == nil {
			return nil
		}
		return a.vendorRunner.Run(ctx)
	})
	a.spawn(ctx, "cleanup worker", func(ctx context.Context) error {
		if a.cleanupRunner == nil {
			return nil
		}
		return a.cleanupRunner.Run(ctx)
	})
	a.spawn(ctx, "memoryLabelCache janitor", func(ctx context.Context) error {
		if a.memLabelCache == nil {
			return nil
		}
		a.memLabelCache.runJanitor(ctx, memoryLabelCacheJanitorInterval, a.logger)
		return nil
	})
}

// spawn launches a tracked background goroutine. The Add(1) executes
// on the calling goroutine BEFORE the spawned function runs so a
// concurrent WaitBackground call cannot race past the counter.
// Components whose handle is nil short-circuit inside fn; we still
// spawn a goroutine that immediately returns because the alternative
// (skipping spawn() when nil) bakes a sequencing dependency between
// newApplication and StartBackground that is easy to break later.
func (a *application) spawn(ctx context.Context, name string, fn func(ctx context.Context) error) {
	a.bgWG.Add(1)
	go func() {
		defer a.bgWG.Done()
		if err := fn(ctx); err != nil && !errors.Is(err, context.Canceled) {
			a.logger.Warn("sn360-es: background goroutine terminated",
				slog.String("component", name),
				slog.Any("error", err))
		}
	}()
}

// WaitBackground blocks until every goroutine launched by
// StartBackground has returned. Callers must cancel the context they
// passed to StartBackground first — otherwise the long-running
// runners (poller, periodic workers) will not exit and Wait blocks
// forever.
func (a *application) WaitBackground() {
	a.bgWG.Wait()
}

// ---------------------------------------------------------------------------
// Onboarding service wiring
// ---------------------------------------------------------------------------

// buildOnboardingService constructs the OAuth consent + post-consent
// discovery service. The caller has already validated that
// cfg.Onboarding.StateSecret and cfg.Onboarding.CallbackURL are set.
func buildOnboardingService(cfg *config.Config, logger *slog.Logger, app *application) (*onboarding.Service, error) {
	signer, err := onboarding.NewStateSigner([]byte(cfg.Onboarding.StateSecret))
	if err != nil {
		return nil, fmt.Errorf("state signer: %w", err)
	}

	// Token store — PgTokenStore requires Postgres + an encryptor.
	if app.pgDB == nil {
		return nil, fmt.Errorf("onboarding requires PostgreSQL (PG_HOST not set)")
	}
	enc, err := buildTokenEncryptor(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("token encryptor: %w", err)
	}
	store, err := onboarding.NewPgTokenStore(app.pgDB, enc)
	if err != nil {
		return nil, fmt.Errorf("token store: %w", err)
	}

	// Nonce store — Redis when available, in-memory fallback.
	var nonces onboarding.NonceStore
	if app.redis != nil {
		ns, nerr := onboarding.NewRedisNonceStore(app.redis.Raw(), "")
		if nerr != nil {
			logger.Warn("sn360-es: onboarding redis nonce store failed, using in-memory",
				slog.Any("error", nerr))
			nonces = onboarding.NewInMemoryNonceStore()
		} else {
			nonces = ns
		}
	} else {
		nonces = onboarding.NewInMemoryNonceStore()
	}

	validator := onboarding.NewHTTPPostConsentValidator(nil, cfg.GWS.Domain)
	exch := onboarding.NewHTTPExchanger(nil)

	// Provider configs.
	providers := make(map[onboarding.ProviderType]onboarding.ProviderConfig)
	if cfg.GWS.OAuthClientID != "" && cfg.GWS.OAuthClientSecret != "" {
		providers[onboarding.ProviderGoogle] = onboarding.ProviderConfig{
			ClientID:     cfg.GWS.OAuthClientID,
			ClientSecret: cfg.GWS.OAuthClientSecret,
			AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			Scopes:       []string{"https://www.googleapis.com/auth/admin.directory.user.readonly", "https://www.googleapis.com/auth/admin.directory.group.readonly"},
			RedirectURL:  cfg.Onboarding.CallbackURL,
		}
	}
	if cfg.O365.HasOutlook() {
		providers[onboarding.ProviderMicrosoft] = onboarding.ProviderConfig{
			ClientID:     cfg.O365.ClientID,
			ClientSecret: cfg.O365.ClientSecret,
			AuthURL:      "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
			TokenURL:     "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
			Scopes:       []string{"https://graph.microsoft.com/.default", "offline_access"},
			RedirectURL:  cfg.Onboarding.CallbackURL,
		}
	}
	if len(providers) == 0 {
		return nil, fmt.Errorf("at least one provider (GWS or O365) must be configured")
	}

	// Post-consent trigger (agent bridge).
	var trigger onboarding.PostConsentTrigger
	if app.onboardAgent != nil {
		trigger = &onboarding.AgentBridge{
			Onboarding: app.onboardAgent,
			Log:        logger,
			WG:         &app.bgWG,
			Draining:   &app.draining,
		}
	}

	// Provider registrar — holds a pointer to the service which is
	// set below after NewService returns. RegisterFromToken is only
	// called post-construction (from the callback handler), so the
	// pointer is always populated before first use.
	var reg *providerRegistrarAdapter
	var registrar onboarding.ProviderRegistrar
	if app.providers != nil {
		reg = &providerRegistrarAdapter{
			registry: app.providers,
			cfg:      cfg,
			logger:   logger,
		}
		registrar = reg
	}

	svc, svcErr := onboarding.NewService(onboarding.ServiceConfig{
		Providers: providers,
		Store:     store,
		Exch:      exch,
		State:     signer,
		Trigger:   trigger,
		Registrar: registrar,
		Nonces:    nonces,
		Validator: validator,
		Logger:    logger,
	})
	if svcErr != nil {
		return nil, svcErr
	}
	if reg != nil {
		reg.svc = svc
	}
	return svc, nil
}

// aesGCMTokenEncryptor implements onboarding.TokenEncryptor using
// AES-256-GCM. Used to encrypt OAuth tokens at rest in Postgres.
type aesGCMTokenEncryptor struct {
	aead cipher.AEAD
}

func newAESGCMTokenEncryptor(key []byte) (*aesGCMTokenEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("token encryptor: key must be 32 bytes (got %d)", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("token encryptor: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("token encryptor: %w", err)
	}
	return &aesGCMTokenEncryptor{aead: aead}, nil
}

func (e *aesGCMTokenEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *aesGCMTokenEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	ns := e.aead.NonceSize()
	if len(ciphertext) < ns+e.aead.Overhead() {
		return nil, fmt.Errorf("token encryptor: ciphertext too short")
	}
	return e.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

// buildTokenEncryptor returns an onboarding.TokenEncryptor for the
// PgTokenStore. Priority: ONBOARDING_TOKEN_KEY_HEX (dedicated) →
// KMS_MOCK_KEY_HEX (shared) → derived from StateSecret (fallback).
func buildTokenEncryptor(cfg *config.Config, logger *slog.Logger) (onboarding.TokenEncryptor, error) {
	if seed := strings.TrimSpace(cfg.Onboarding.TokenKeyHex); seed != "" {
		decoded, err := hex.DecodeString(seed)
		if err == nil && len(decoded) == 32 {
			logger.Info("sn360-es: onboarding token encryptor using ONBOARDING_TOKEN_KEY_HEX")
			return newAESGCMTokenEncryptor(decoded)
		}
		logger.Warn("sn360-es: ONBOARDING_TOKEN_KEY_HEX is set but invalid (must be 64 hex chars encoding 32 bytes); falling back",
			slog.Bool("hex_error", err != nil), slog.Int("decoded_len", len(decoded)))
	}
	if seed := strings.TrimSpace(cfg.AWS.KMSMockKeyHex); seed != "" {
		decoded, err := hex.DecodeString(seed)
		if err == nil && len(decoded) == 32 {
			logger.Info("sn360-es: onboarding token encryptor using KMS_MOCK_KEY_HEX")
			return newAESGCMTokenEncryptor(decoded)
		}
		logger.Warn("sn360-es: KMS_MOCK_KEY_HEX is set but invalid (must be 64 hex chars encoding 32 bytes); falling back",
			slog.Bool("hex_error", err != nil), slog.Int("decoded_len", len(decoded)))
	}
	h := sha256.Sum256([]byte("onboarding-token-encryption:" + cfg.Onboarding.StateSecret))
	logger.Warn("sn360-es: onboarding token encryptor using derived key from state secret; set ONBOARDING_TOKEN_KEY_HEX for production")
	return newAESGCMTokenEncryptor(h[:])
}

// onboardingServiceAdapter wraps *onboarding.Service to implement
// handler.OnboardingService by adding the Status method backed by
// the repository layer.
type onboardingServiceAdapter struct {
	svc   *onboarding.Service
	repos *repository.Registry
}

func (a *onboardingServiceAdapter) AuthURL(provider onboarding.ProviderType, tenantID string) (string, error) {
	return a.svc.AuthURL(provider, tenantID)
}

func (a *onboardingServiceAdapter) HandleCallback(ctx context.Context, stateTok, code string) (string, onboarding.ProviderType, error) {
	return a.svc.HandleCallback(ctx, stateTok, code)
}

func (a *onboardingServiceAdapter) Revoke(ctx context.Context, tenantID string, provider onboarding.ProviderType) error {
	return a.svc.Revoke(ctx, tenantID, provider)
}

func (a *onboardingServiceAdapter) Status(ctx context.Context, tenantID string) (handler.OnboardingStatus, error) {
	status := handler.OnboardingStatus{TenantID: tenantID, Status: "not_started"}
	if a.repos == nil {
		return status, nil
	}
	if a.repos.Users != nil {
		n, err := a.repos.Users.Count(ctx, tenantID)
		if err == nil {
			status.UsersDiscovered = n
		}
	}
	if a.repos.Groups != nil {
		n, err := a.repos.Groups.Count(ctx, tenantID)
		if err == nil {
			status.GroupsDiscovered = n
		}
	}
	switch {
	case status.UsersDiscovered > 0 || status.GroupsDiscovered > 0:
		status.Status = "completed"
	case a.svc != nil:
		// Token exists but no users/groups discovered yet → in_progress.
		// HasToken is a pure read (no refresh side-effect).
		for _, p := range []onboarding.ProviderType{onboarding.ProviderGoogle, onboarding.ProviderMicrosoft} {
			if a.svc.HasToken(ctx, tenantID, p) {
				status.Status = "in_progress"
				break
			}
		}
	}
	return status, nil
}
