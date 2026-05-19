package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/constant"
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
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
	"github.com/kennguy3n/sn360-es/internal/service/tier1"
	"github.com/kennguy3n/sn360-es/internal/service/worker"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/events/bus"
	natsbus "github.com/kennguy3n/sn360-es/pkg/events/nats"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
	"github.com/kennguy3n/sn360-es/pkg/storage/redis"
	"github.com/kennguy3n/sn360-es/pkg/telemetry"
)

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

	// Provider-side action machinery.
	providers     *providerRegistry
	labelApplier  *action.LabelApplier
	quarantineSvc *action.QuarantineService

	// Evaluation pipeline.
	tier0Gate    *tier0.Gate
	tier1Raw     *tier1.Client
	tier1Client  evaluate.Tier1Client
	tier2Client  evaluate.Tier2Client
	rspamdClient evaluate.RspamdClient
	evaluator    *evaluate.Evaluator
	batchOrch    *evaluate.BatchOrchestrator

	// Ingestion polling.
	poller *ingestion.Poller

	// Periodic workers.
	relationshipRunner  *worker.Runner
	vendorRunner        *worker.Runner
	cleanupRunner       *worker.Runner
	directorySyncRunner *worker.Runner

	// AI agents.
	onboardAgent  *agent.OnboardingAgent
	tuningAgent   *agent.TuningAgent
	supportAgent  *agent.SupportAgent
	onboardingSvc *onboarding.Service

	// In-process caches that own a janitor goroutine.
	memLabelCache *memoryLabelCache

	// Lifecycle.
	subs    []events.Subscription
	subsMu  sync.Mutex
	closers []func() error
	dlqProc *service.DLQProcessor

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

	// Event bus is required.
	eventBus, err := bus.New(ctx, factoryConfigFromAppConfig(cfg), logger)
	if err != nil {
		return nil, fmt.Errorf("event bus: %w", err)
	}
	app.eventBus = eventBus
	app.closers = append(app.closers, func() error {
		return bus.CloseWithTimeout(eventBus, 5*time.Second)
	})

	// Postgres is optional but strongly preferred.
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

	// Redis.
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

	// JWT issuer.
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

	// Banner renderer (HTML templates).
	if catalog, cerr := action.DefaultBannerCatalog(); cerr == nil {
		if renderer, rerr := action.NewBannerRenderer(catalog); rerr == nil {
			app.bannerRenderer = renderer
		} else {
			logger.Warn("sn360-es: banner renderer init failed", slog.Any("error", rerr))
		}
	} else {
		logger.Warn("sn360-es: banner i18n catalog load failed", slog.Any("error", cerr))
	}

	// Feedback service.
	if app.jwtIssuer != nil {
		app.feedbackSvc = action.NewFeedbackService(logger, app.jwtIssuer, eventBus, nil)
	}

	// Quarantine service + release service.
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

	// URL rewriter.
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

	// Micro-lesson service.
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

	// Simulation engine.
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

	// Simulation tracker.
	if tracker, terr := education.NewSimulationTracker(education.TrackerConfig{
		Store:  education.NewMemoryInteractionStore(),
		Logger: logger,
	}); terr == nil {
		app.simulationTracker = tracker
	} else {
		logger.Warn("sn360-es: simulation tracker init failed", slog.Any("error", terr))
	}

	// Recipient + Open predict services.
	app.recipientSvc = predict.NewRecipientService(predict.RecipientServiceConfig{})
	app.openSvc = predict.NewOpenService(predict.OpenServiceConfig{})

	// Escalation service.
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

	// Dashboard generator.
	if app.pgDB != nil {
		dcfg := dashboard.PostgresSourceConfig{}
		if app.repos != nil && app.repos.FeedbackEvents != nil {
			dcfg.Feedback = feedbackCountsAdapter{repo: app.repos.FeedbackEvents}
		}
		src, serr := dashboard.NewPostgresSourceWithConfig(app.pgDB, dcfg)
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

	// Optional Tier 1 batch orchestrator.
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
					Fallback:      fallbackEvaluatorAdapter{eval: app.evaluator},
					Categorizer:   categorizer,
					TierDecider:   tierDeciderAdapt,
					Weights:       weights,
					Sink:          app.eventBus,
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

	// Provider registry.
	app.providers = buildProviderRegistry(ctx, cfg, logger)

	// Label applier.
	if app.providers != nil && app.providers.hasAny() {
		labelCache, memCache := newLabelCache(app.redis)
		app.memLabelCache = memCache
		app.labelApplier = action.NewLabelApplier(logger, labelCache, app.providers.labelProviders()...)
	}

	// Provider-aware quarantine service.
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

	// Ingestion poller.
	app.poller = buildPoller(ctx, cfg, logger, app)

	// Periodic workers.
	app.relationshipRunner, app.vendorRunner, app.cleanupRunner, app.directorySyncRunner = buildWorkers(cfg, logger, app)

	// AI agents.
	app.onboardAgent, app.tuningAgent, app.supportAgent = buildAgents(cfg, logger, app)

	// Onboarding service.
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

// Close runs every registered closer in reverse order.
func (a *application) Close(logger *slog.Logger) {
	for i := len(a.closers) - 1; i >= 0; i-- {
		if err := a.closers[i](); err != nil {
			logger.Warn("sn360-es: closer error", slog.Any("error", err))
		}
	}
}

// StartBackground starts the poller + worker goroutines.
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
	a.spawn(ctx, "directory sync worker", func(ctx context.Context) error {
		if a.directorySyncRunner == nil {
			return nil
		}
		return a.directorySyncRunner.Run(ctx)
	})
	a.spawn(ctx, "memoryLabelCache janitor", func(ctx context.Context) error {
		if a.memLabelCache == nil {
			return nil
		}
		a.memLabelCache.runJanitor(ctx, memoryLabelCacheJanitorInterval, a.logger)
		return nil
	})
}

// spawn launches a tracked background goroutine.
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
// StartBackground has returned.
func (a *application) WaitBackground() {
	a.bgWG.Wait()
}
