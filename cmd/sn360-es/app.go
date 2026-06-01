package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/handler"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/internal/service/bridge"
	"github.com/kennguy3n/sn360-es/internal/service/cache"
	"github.com/kennguy3n/sn360-es/internal/service/dashboard"
	"github.com/kennguy3n/sn360-es/internal/service/education"
	"github.com/kennguy3n/sn360-es/internal/service/escalation"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
	"github.com/kennguy3n/sn360-es/internal/service/investigation"
	"github.com/kennguy3n/sn360-es/internal/service/onboarding"
	"github.com/kennguy3n/sn360-es/internal/service/predict"
	"github.com/kennguy3n/sn360-es/internal/service/selfrelease"
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
	"github.com/kennguy3n/sn360-es/internal/service/tier1"
	"github.com/kennguy3n/sn360-es/internal/service/worker"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/events/bus"
	natsbus "github.com/kennguy3n/sn360-es/pkg/events/nats"

	// Side-effect imports so every Tier 2 SLM provider self-registers
	// with the slm registry at process boot. New providers added under
	// pkg/inference/slm/providers/* are picked up by this aggregator —
	// no further changes to the composition root are required.
	_ "github.com/kennguy3n/sn360-es/pkg/inference/slm/all"
	"github.com/kennguy3n/sn360-es/pkg/intel"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
	"github.com/kennguy3n/sn360-es/pkg/storage/redis"
	"github.com/kennguy3n/sn360-es/pkg/telemetry"
)

// pushShutdownTimeout bounds how long the push-manager teardown
// (DELETE /subscriptions for Outlook, users.stop for Gmail) may take
// during application.Close. The value is generous enough to absorb
// a handful of slow provider round-trips serially (the manager
// processes subscriptions in a single goroutine) but tight enough
// that a misbehaving Graph or Gmail endpoint cannot stall process
// exit indefinitely. A leftover subscription on the provider side
// is recovered on the next boot — either by re-Subscribe (Gmail,
// idempotent) or by the natural 48h Outlook expiry — so failing
// fast on shutdown is the right trade-off.
const pushShutdownTimeout = 10 * time.Second

// application bundles every wired dependency so handlers, middleware,
// and consumers can read from a single composition root. Each field is
// optional from the perspective of unit tests; handlers gracefully
// return 503 when their service is nil so a partial wiring still
// produces a navigable mux.
type application struct {
	cfg     *config.Config
	logger  *slog.Logger
	metrics *telemetry.Metrics
	// tracer is the W3C-traceparent span source. When
	// OTEL_EXPORTER_OTLP_ENDPOINT is set its exporter is the OTLP
	// bridge from pkg/telemetry/otel.go; otherwise it uses the
	// no-op exporter so call sites can record spans
	// unconditionally without paying any I/O cost.
	tracer *telemetry.Tracer

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
	selfReleaseSvc    *selfrelease.Service
	urlRewriter       *action.URLRewriter
	microLessonSvc    *education.MicroLessonService
	simulationEng     *education.SimulationEngine
	simulationTracker *education.SimulationTracker
	// usingMemoryCampaignStore / usingMemoryInteractionStore record
	// whether newApplication had to fall back to the in-memory
	// education stores even though pgDB was wired (e.g. EnsureSchema
	// failed against a degraded database). assertProductionDurableStores
	// reads these so the prod boot gate fires on the real in-memory
	// state, not just on pgDB == nil.
	usingMemoryCampaignStore    bool
	usingMemoryInteractionStore bool
	// usingMemoryConfigStore records whether buildConfigStore in
	// wire_services.go had to fall back to memoryConfigStore (i.e.
	// score_engine repository was unavailable). Read by
	// assertProductionDurableStores so the prod boot gate fires on
	// the real in-memory state.
	usingMemoryConfigStore bool
	// tenantScoringConfig is the shared evaluator-side cache of
	// per-tenant score_engine rows. It is read by the evaluator and
	// batch orchestrator at verdict time and invalidated by
	// postgresConfigStore after every successful tuning write so
	// the cache cannot return stale values across a tuning pass.
	// Nil when score_engine is not wired (memoryConfigStore fallback).
	tenantScoringConfig *tenantScoringConfigAdapter
	dashboardGen        *dashboard.DashboardGenerator
	recipientSvc        *predict.RecipientService
	openSvc             *predict.OpenService
	escalationSvc       *agent.EscalationService

	// escalationResolver implements the WS-5A.6 consumer-side
	// cross-repo reconciliation loop: takes IncidentResolved
	// payloads emitted by sn360-security-platform's soc-triage
	// service, looks up the matching EvaluationResult, flips
	// the analyst-overridable final_verdict, fires a banner
	// reopen when the original banner was actually delivered,
	// and persists one audit row per invocation. Nil when the
	// Postgres registry is unavailable (memory-only
	// deployments); the soc.incident.resolved subscription is
	// suppressed in that case so the audit-row invariant is
	// not silently violated.
	escalationResolver *escalation.Resolver

	// investigationSvc backs the WS-3b operator investigation API
	// (GET /v1/investigation/message/{pseudo_id} +
	// GET /v1/investigation/sender/{sender_hash}). Nil when the
	// repository registry is unavailable (memory-only deployments
	// without evaluation_results / communication_histories);
	// handler renders 503 in that case so the route still 404s
	// cleanly under role-gated mux and 503s under wired mux.
	investigationSvc *investigation.Service

	// platformBridge fans HighRisk+ verdicts, quarantine actions,
	// and escalation ticket transitions out to the
	// sn360-security-platform NATS stream (WS-5A.1). Always non-nil
	// — a disabled bridge is returned from bridge.New when
	// PLATFORM_NATS_ENABLED is false so handlers can call its
	// methods unconditionally.
	platformBridge bridge.PlatformPublisher

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
	// signalEnricher folds per-(tenant, sender, recipient) state
	// from communication_histories onto the base RiskSignals the
	// normalizer produced. It runs at consumer-side ingress
	// (handleEvaluateRequest + BatchOrchestrator) so the Tier 0
	// ATO heuristic sees the freshest TypicalSendHour /
	// CommunicationFrequency / IsFirstContact / CurrentHourUTC at
	// evaluation time rather than at publish time. The composition
	// root substitutes evaluate.NoopEnricher when the repository or
	// PII hasher dependency is missing so call sites never have to
	// nil-check.
	signalEnricher evaluate.SignalEnricher

	// Ingestion polling.
	poller *ingestion.Poller

	// Push-notification ingestion.
	//
	// pushManager is nil unless INGESTION_MODE includes push and at
	// least one push receiver could be wired (see buildPushManager).
	// pushSignatureVerifier authenticates inbound /v1/push callbacks
	// BEFORE they reach pushManager; it is nil iff pushManager is nil
	// so the route is only mounted when both halves are present.
	pushManager           *ingestion.PushManager
	pushSignatureVerifier handler.PushSignatureVerifier

	// Periodic workers.
	relationshipRunner  *worker.Runner
	vendorRunner        *worker.Runner
	cleanupRunner       *worker.Runner
	directorySyncRunner *worker.Runner
	partitionRunner     *worker.Runner
	intelRunner         *worker.Runner

	// Threat-intel feed integration (WS-5B.3).
	//
	// intelStore is the deployment-scoped IntelStore — backed by
	// PgIntelStore in production and *repository.MemoryIntelStore
	// in dev / unit-test runs. Nil only when both Postgres AND
	// the in-memory fallback are absent (a configuration the
	// build does not emit in practice).
	intelStore intel.IntelStore
	// intelJob is the worker job that polls intel_feeds, upserts
	// indicators and runs the 30-day GC. It is also the
	// IntelFeedRefresher consumed by the admin /refresh endpoint.
	intelJob *worker.IntelJob

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

	// WS-5A.6: the SOC resolution durable consumer is wired
	// best-effort (a failure does not stop the binary — see
	// the comment block above startSOCResolutionConsumer in
	// consumers.go for the rationale). To keep that
	// "best-effort" from being silent, the boot attempt
	// records its outcome here so /readyz's
	// "escalation_sync" checker can surface the dark loop
	// to operators. A non-nil pointer means the boot
	// subscribe failed and the cross-repo reconciliation
	// loop is currently dark on this instance.
	socResolutionSubErr atomic.Pointer[error]

	bgWG     sync.WaitGroup
	draining atomic.Bool
}

// newApplication wires every component the binary needs. Required
// pieces (event bus) hard-fail; optional pieces (postgres, redis, JWT
// secret) log warnings and leave their consumers in a degraded mode so
// the binary still answers /healthz and the routes that do not require
// the missing dependency.
//
// On any error past the first opened resource the function closes
// every closer it has accumulated so far before returning, so a
// partial-wire failure cannot leak Postgres pools, Redis clients, or
// the NATS connection. The defer below executes the public
// [application.Close] path unless the function reaches its happy-path
// `return app, nil` and sets `wired = true`.
func newApplication(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*application, error) {
	app := &application{cfg: cfg, logger: logger, metrics: telemetry.DefaultMetrics()}
	wired := false
	defer func() {
		if !wired {
			// Reverse-apply every closer the partial wire-up
			// registered so far. Safe to call on a struct whose
			// closers slice is empty (e.g. event-bus init
			// itself failed) — Close is a plain range over
			// closers and degrades to a no-op.
			app.Close(logger)
		}
	}()

	// Build the tracer up front so every downstream wiring can
	// attach to it. When OTEL_EXPORTER_OTLP_ENDPOINT is set we
	// stand up the real OTel SDK bridge — finished SN360 spans
	// are forwarded through a BatchSpanProcessor to the
	// configured collector with trace/span IDs preserved. When
	// the env var is unset the tracer falls back to a no-op
	// exporter so instrumented call sites pay no cost in dev /
	// tests but the API contract (SpanContextFromContext, etc.)
	// keeps working.
	tracer, tracerCloser, err := buildTracer(ctx, cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("telemetry: %w", err)
	}
	app.tracer = tracer
	if tracerCloser != nil {
		app.closers = append(app.closers, tracerCloser)
	}

	// Event bus is required.
	eventBus, err := bus.New(ctx, factoryConfigFromAppConfig(cfg), logger)
	if err != nil {
		return nil, fmt.Errorf("event bus: %w", err)
	}
	app.eventBus = eventBus
	app.closers = append(app.closers, func() error {
		return bus.CloseWithTimeout(eventBus, 5*time.Second)
	})

	// Wire the EventLagSeconds gauge to the NATS service if that's
	// the backing implementation. Other backends (Redis, in-memory)
	// silently no-op — the gauge is intended for the production bus.
	if natsSvc, ok := eventBus.(*natsbus.Service); ok && app.metrics != nil && app.metrics.EventLagSeconds != nil {
		gauge := app.metrics.EventLagSeconds
		natsSvc.SetMessageObserver(func(stream, _ string, lag time.Duration) {
			gauge.WithLabelValues("nats", stream).Set(lag.Seconds())
		})
	}

	// Platform NATS bridge (WS-5A.1). The bridge is gated behind
	// PLATFORM_NATS_ENABLED — when disabled it returns a no-op
	// publisher so the consumer handlers can call its methods
	// unconditionally. The bridge uses nats.RetryOnFailedConnect
	// internally, so a transient platform-NATS outage at boot
	// degrades to "publishes buffered until reconnect" rather
	// than blocking sn360-es boot — the core email-security
	// pipeline does not depend on the platform bridge.
	// bridge.New only returns an error for genuine configuration
	// bugs (invalid TLS material, malformed URL) which are worth
	// failing boot on. Production validation in
	// internal/config/validate.go rejects ENABLED=true with empty
	// URLs before we reach this point.
	platformPub, perr := bridge.New(ctx, platformBridgeConfig(cfg), logger)
	if perr != nil {
		return nil, fmt.Errorf("platform bridge: %w", perr)
	}
	app.platformBridge = platformPub
	app.closers = append(app.closers, platformPub.Close)

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

			// WS-2a (Read-Replica Routing): when PG_READ_HOST
			// is set, attach a second pool against the
			// replica. Unbound Query* calls then route to the
			// replica automatically; tenant-bound queries
			// stay on the primary (their conn already holds
			// the RLS session GUC). A failed AttachReader is
			// fatal because a deployment that explicitly
			// configured a replica AND wired the URL into the
			// rollout almost certainly relies on the read
			// offload for capacity — silently degrading to
			// single-pool would mask a real misconfig until
			// the primary saturates under load. Operators who
			// want to disable replica routing without
			// changing manifests should unset PG_READ_HOST.
			if cfg.Postgres.Read.Host != "" {
				readCfg := postgres.Config{
					Host:            cfg.Postgres.Read.Host,
					Port:            cfg.Postgres.Read.Port,
					User:            cfg.Postgres.Read.User,
					Password:        cfg.Postgres.Read.Password,
					Database:        cfg.Postgres.Read.Database,
					SSLMode:         cfg.Postgres.Read.SSLMode,
					MaxOpenConns:    cfg.Postgres.Read.MaxOpenConns,
					MaxIdleConns:    cfg.Postgres.Read.MaxIdleConns,
					ConnMaxLifetime: cfg.Postgres.Read.ConnMaxLifetime,
				}
				if rerr := pgDB.AttachReader(ctx, readCfg); rerr != nil {
					return nil, fmt.Errorf("postgres read replica: %w", rerr)
				}
				logger.Info("sn360-es: postgres read replica attached",
					slog.String("read_host", pgDB.ReadHost()),
					slog.String("primary_host", cfg.Postgres.Host))
			}
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
			// 7 days matches the explicit default in
			// internal/config/scoring.go::loadBanner() and the
			// NewJWTIssuer fallback in pkg/privacy/jwt.go. Keeping
			// the three call-sites in sync caps the replay window
			// for leaked banner / quarantine / interstitial tokens
			// at one week — long enough that real-world banner
			// rendering still works after a holiday but short
			// enough that a rotated secret or offboarded user
			// retires their outstanding tokens within a sane
			// forensic horizon.
			ttl = 7 * 24 * time.Hour
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

	// Quarantine store — a single instance shared by both the quarantine
	// and release flows. Created here so it's available to the provider-
	// aware QuarantineService built after providers are registered.
	qstore := newQuarantineStore(app.redis)

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
	// Simulation campaign store: prefer the durable Postgres
	// backend when PG_HOST is configured so campaigns survive a
	// restart; fall back to in-memory only in local/dev to keep
	// integration tests and `make run` working without a database.
	var campaignStore education.CampaignStore
	if app.pgDB != nil {
		pgStore := education.NewPostgresCampaignStore(app.pgDB)
		if err := pgStore.EnsureSchema(ctx); err != nil {
			logger.Warn("sn360-es: campaign store schema check failed; falling back to memory",
				slog.Any("error", err))
			campaignStore = education.NewMemoryCampaignStore()
			app.usingMemoryCampaignStore = true
		} else {
			campaignStore = pgStore
		}
	} else {
		campaignStore = education.NewMemoryCampaignStore()
		app.usingMemoryCampaignStore = true
	}
	if eng, eerr := education.NewSimulationEngine(education.EngineConfig{
		Store:     campaignStore,
		Templates: education.NewTemplateLibrary(),
		Sender:    simSender,
		Publisher: eventBus,
		Logger:    logger,
	}); eerr == nil {
		app.simulationEng = eng
	} else {
		logger.Warn("sn360-es: simulation engine init failed", slog.Any("error", eerr))
	}

	// Simulation tracker: same fallback policy as the campaign
	// store. The PostgresInteractionStore persists each interaction
	// into the education_interactions table (created on first boot
	// via EnsureSchema) so per-target opens/clicks/reports survive
	// a restart.
	var interactionStore education.InteractionStore
	if app.pgDB != nil {
		pgTrack := education.NewPostgresInteractionStore(app.pgDB)
		if err := pgTrack.EnsureSchema(ctx); err != nil {
			logger.Warn("sn360-es: interaction store schema check failed; falling back to memory",
				slog.Any("error", err))
			interactionStore = education.NewMemoryInteractionStore()
			app.usingMemoryInteractionStore = true
		} else {
			interactionStore = pgTrack
		}
	} else {
		interactionStore = education.NewMemoryInteractionStore()
		app.usingMemoryInteractionStore = true
	}
	if tracker, terr := education.NewSimulationTracker(education.TrackerConfig{
		Store:  interactionStore,
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

	// WS-3b investigation service. Requires both repositories to be
	// wired (evaluation_results + communication_histories) — the
	// in-memory registry NewMemoryRegistry satisfies the contract
	// for tests, the Postgres registry for production. When neither
	// is wired (a degraded headless-worker deployment), the
	// constructor refuses and the handler renders 503 so the route
	// is honest about its readiness.
	if app.repos != nil && app.repos.EvaluationResults != nil && app.repos.CommunicationHistories != nil {
		if inv, ierr := investigation.NewService(investigation.ServiceConfig{
			EvaluationResults:      app.repos.EvaluationResults,
			CommunicationHistories: app.repos.CommunicationHistories,
			Logger:                 logger,
		}); ierr == nil {
			app.investigationSvc = inv
		} else {
			logger.Warn("sn360-es: investigation service init failed", slog.Any("error", ierr))
		}
	}

	// WS-5A.6 escalation resolver. Requires the four
	// repositories that back the cross-repo reconciliation
	// loop: EvaluationResults (for the verdict lookup +
	// SetFinalVerdict flip), EmailVerdictAudits (for the
	// audit-row INSERT-ON-CONFLICT idempotency key), and
	// BannerStates (for the "delivered_at IS NOT NULL"
	// reopen gate). Memory-only deployments without
	// Postgres skip this wiring — the soc.incident.resolved
	// consumer detects the nil resolver and drops at the
	// subscription boundary so the audit-row invariant is
	// not violated by a partially-wired path.
	if app.repos != nil &&
		app.repos.EvaluationResults != nil &&
		app.repos.EmailVerdictAudits != nil &&
		app.repos.BannerStates != nil {
		reopener, rerr := newBannerReopener(logger, app.repos.BannerStates, app.providers)
		if rerr != nil {
			logger.Warn("sn360-es: banner reopener init failed", slog.Any("error", rerr))
		} else if res, eerr := escalation.New(
			app.repos.EvaluationResults,
			app.repos.EmailVerdictAudits,
			app.repos.BannerStates,
			reopener,
			logger,
		); eerr != nil {
			logger.Warn("sn360-es: escalation resolver init failed", slog.Any("error", eerr))
		} else {
			app.escalationResolver = res
		}
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

	// Threat-intel feed store (WS-5B.3). Deployment-scoped — no
	// tenant binder; the worker / Tier 0 gate read across feeds.
	// In-memory fallback when Postgres isn't wired keeps unit
	// tests + dev mode functional.
	if app.pgDB != nil {
		app.intelStore = repository.NewPgIntelStore(app.pgDB)
	} else {
		app.intelStore = repository.NewMemoryIntelStore()
		logger.Info("sn360-es: intel store using in-memory backend (postgres not configured)")
	}

	// Evaluation pipeline.
	app.tier0Gate = tier0.NewGate(tier0.GateConfig{
		SkipInternal:         cfg.Tier0.SkipInternal,
		SkipVendor:           cfg.Tier0.SkipVendor,
		SkipRecurring:        cfg.Tier0.SkipRecurring,
		HighVolumeRspamdOnly: cfg.Tier0.HighVolumeRspamdOnly,
	}, nil)
	// Threat-intel hook on the gate. Optional Redis negative
	// cache fronts the lookup when Redis is wired.
	if app.intelStore != nil {
		ticker := &tier0.StoreTIChecker{Store: app.intelStore}
		if app.redis != nil {
			ticker.Cache = &tier0.RedisTICache{
				Client: app.redis,
				TTL:    5 * time.Minute,
				Logger: logger.With(slog.String("component", "ti_cache")),
			}
		}
		app.tier0Gate = app.tier0Gate.
			WithTIChecker(ticker).
			WithTIObserver(intelTier0Observer{m: app.metrics}).
			WithLogger(logger.With(slog.String("component", "tier0_ti")))
	}

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

	// Initialise the tenant scoring-config adapter before the Tier 2
	// client is constructed, because the slm.Router needs the adapter
	// as its TenantProviderLoader so per-tenant overrides can resolve
	// at evaluation time. The adapter is idempotent — buildAgents
	// reuses the same instance via buildConfigStore.
	ensureTenantScoringConfigAdapter(app)

	app.tier2Client = buildTier2Client(app, cfg, logger)

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

	// app.tenantScoringConfig is already populated at this point —
	// the slm.Router setup above needs it as its
	// TenantProviderLoader, so ensureTenantScoringConfigAdapter ran
	// before buildTier2Client. ensureTenantScoringConfigAdapter is
	// idempotent (early-returns when app.tenantScoringConfig is
	// non-nil), so the original buildAgents-ordering protection
	// described in the historical comment no longer needs a second
	// call here.

	// tenantScoringConfig is non-nil when score_engine is wired —
	// in that case the same table the tuning agent writes to is
	// also the source of per-tenant Weights / Tier1*Threshold
	// overrides for evaluation. Pass a typed nil through when
	// score_engine is not wired so the evaluator falls back to its
	// static defaults instead of dereferencing a nil interface at
	// verdict time.
	var tenantConfigLoader evaluate.TenantScoringConfigLoader
	if app.tenantScoringConfig != nil {
		tenantConfigLoader = app.tenantScoringConfig
	}

	// Signal enricher bridges communication_histories →
	// dto.RiskSignals. Both newCommHistorySignalEnricher (real
	// implementation) and NoopEnricher satisfy the interface, so
	// the consumer-side call site never has to nil-check.
	// Wiring requires the communication-histories repo AND a PII
	// hasher (the same one ingestion / directory / relationship
	// workers use); a missing dependency degrades to no-op
	// enrichment, matching the pre-enricher behaviour where
	// Tier 0's timing anomaly check sees no baseline and
	// short-circuits.
	app.signalEnricher = buildSignalEnricher(cfg, logger, app)

	app.evaluator = evaluate.NewEvaluator(evaluate.Config{
		Tier0:                app.tier0Gate,
		Tier1:                app.tier1Client,
		Tier2:                app.tier2Client,
		Rspamd:               app.rspamdClient,
		Categorizer:          categorizer,
		TierDecider:          tierDeciderAdapt,
		Weights:              weights,
		Tier1PassThreshold:   cfg.Tier1.PassThreshold,
		Tier1FlagThreshold:   cfg.Tier1.FlagThreshold,
		Tier1SuppressPartner: cfg.Tier1.SuppressPartner,
		Tier1Timeout:         cfg.Tier1.Timeout,
		Tier2Timeout:         cfg.AI.Timeout,
		RspamdTimeout:        cfg.Rspamd.Timeout,
		TenantConfig:         tenantConfigLoader,
		Logger:               logger,
		Observer:             app.metrics.PipelineObserver(),
	})

	// Optional Tier 1 batch orchestrator.
	if cfg.Tier1.BatchEnabled {
		switch app.tier1Raw {
		case nil:
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
					// Tier0BatchGate is now an alias of
					// evaluate.Tier0Gate, and *tier0.Gate
					// satisfies it directly because Apply
					// takes (req, signals) on both sides.
					// The previous tier0BatchAdapter only
					// existed to bridge two different gate
					// signatures.
					Tier0: app.tier0Gate,
					Tier1: app.tier1Raw,
					Thresholds: tier1.Thresholds{
						PassBelow: cfg.Tier1.PassThreshold,
						FlagAbove: cfg.Tier1.FlagThreshold,
						// SuppressPartner mirrors the per-message
						// Evaluator (see Tier1SuppressPartner above).
						// Reading from cfg.Tier1 ensures both paths
						// honour the same TIER1_SUPPRESS_PARTNER
						// override and a Partner/Customer sender gets
						// the same verdict in per-message and batch.
						SuppressPartner: cfg.Tier1.SuppressPartner,
					},
					// *evaluate.Evaluator now matches
					// evaluate.MessageEvaluator directly
					// (Evaluate takes req + signals), so
					// the fallbackEvaluatorAdapter wrapper
					// is no longer required.
					Fallback:      app.evaluator,
					Categorizer:   categorizer,
					TierDecider:   tierDeciderAdapt,
					Weights:       weights,
					TenantConfig:  tenantConfigLoader,
					Sink:          app.eventBus,
					ResultSubject: "es.evaluate.result",
					// Same enricher both paths consume so per-message
					// and batch verdicts see identical
					// per-relationship signals for the same input.
					Enricher: app.signalEnricher,
					Logger:   logger,
					// Surface legacy-shape arrivals so operators
					// can pinpoint the publisher fleet that still
					// emits a flat dto.EvaluateRequest payload.
					// The orchestrator handles both shapes — the
					// metric only exists to gate the eventual
					// removal of the tolerance shim.
					OnLegacyPayload: func(req dto.EvaluateRequest) {
						if app.metrics == nil {
							return
						}
						tenant := req.TenantID
						if tenant == "" {
							tenant = "unknown"
						}
						app.metrics.Tier1BatchLegacyPayloadTotal.WithLabelValues(tenant).Inc()
					},
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

	// Quarantine + release services.
	//
	// A single QuarantineService is built with providers so that
	// ReleaseService.Release() can call Provider() to physically
	// restore messages. Both the quarantine consumer and the release
	// consumer use this same instance.
	if qencryptor, eerr := buildURLEncryptor(cfg, logger); eerr == nil && app.providers != nil && app.providers.hasAny() {
		qsvc, qerr := action.NewQuarantineService(action.QuarantineConfig{
			Logger:    logger,
			Providers: app.providers.quarantineProviders(),
			Store:     qstore,
			Encryptor: qencryptor,
			Publisher: eventBus,
		})
		if qerr == nil {
			app.quarantineSvc = qsvc
			reevaluator := newLatestVerdictReevaluator(app.repos, logger)
			rsvc, rerr := action.NewReleaseService(action.ReleaseConfig{
				Logger:      logger,
				Quarantine:  qsvc,
				Reevaluator: reevaluator,
				Publisher:   eventBus,
			})
			if rerr == nil {
				app.releaseSvc = rsvc
				// Wire the WS-3a self-service release
				// coordinator on top of the same
				// ReleaseService used by the SOC-operator
				// flow. Only register when the audit /
				// policy repos are available — a
				// deployment without a durable repository
				// must NOT accept self-release tokens,
				// because there is nowhere to record
				// audit rows and rate-limit counters.
				if app.repos != nil &&
					app.repos.QuarantineReleaseAudit != nil &&
					app.repos.TenantReleasePolicies != nil {
					selfSvc, srErr := selfrelease.NewService(selfrelease.Config{
						Logger:     logger,
						Quarantine: qsvc,
						Runner:     rsvc,
						Audit:      app.repos.QuarantineReleaseAudit,
						Policies:   app.repos.TenantReleasePolicies,
					})
					if srErr == nil {
						app.selfReleaseSvc = selfSvc
					} else {
						logger.Warn("sn360-es: self-release service init failed",
							slog.Any("error", srErr))
					}
				} else {
					logger.Info("sn360-es: self-release service skipped (audit / policy repository not configured)")
				}
			} else {
				logger.Warn("sn360-es: release service init failed", slog.Any("error", rerr))
			}
		} else {
			logger.Warn("sn360-es: quarantine service init failed",
				slog.Any("error", qerr))
		}
	}

	// Ingestion poller.
	if cfg.Ingestion.PollEnabled() {
		app.poller = buildPoller(ctx, cfg, logger, app)
	} else {
		logger.Info("sn360-es: ingestion poller skipped via mode",
			slog.String("mode", cfg.Ingestion.Mode))
	}

	// Push-notification ingestion. The manager + verifier are built
	// in lock-step: if either fails we drop both so the /v1/push
	// route is never mounted with a half-functional pipeline.
	if mgr, receivers := buildPushManager(ctx, cfg, logger, app); mgr != nil {
		verifier := buildPushSignatureVerifier(cfg, receivers, logger)
		if verifier == nil {
			logger.Warn("sn360-es: push manager built but signature verifier could not be wired; push disabled")
		} else {
			app.pushManager = mgr
			app.pushSignatureVerifier = verifier
			// Register Close() so graceful shutdown unwinds
			// every tracked provider-side subscription. Skipping
			// this leaves Outlook subscriptions delivering for
			// up to 48h to a process that no longer exists, and
			// a restart would create a second subscription
			// alongside the orphan — duplicate notifications for
			// that whole window. Closers run in reverse order
			// after bgWG.Wait() so RenewLoop has already exited
			// when Close fires; the deadline is bounded by the
			// shutdown context plumbed into application.Close.
			pushMgr := mgr
			app.closers = append(app.closers, func() error {
				teardownCtx, cancel := context.WithTimeout(context.Background(), pushShutdownTimeout)
				defer cancel()
				return pushMgr.Close(teardownCtx)
			})
		}
	}

	// Periodic workers.
	app.relationshipRunner, app.vendorRunner, app.cleanupRunner, app.directorySyncRunner, app.partitionRunner, app.intelRunner = buildWorkers(cfg, logger, app)

	// AI agents.
	app.onboardAgent, app.tuningAgent, app.supportAgent = buildAgents(cfg, logger, app)

	// Onboarding service.
	if cfg.Onboarding.StateSecret != "" && cfg.Onboarding.CallbackURL != "" {
		obSvc, obErr := buildOnboardingService(cfg, logger, app)
		switch {
		case obErr != nil:
			logger.Warn("sn360-es: onboarding service init failed", slog.Any("error", obErr))
		case obSvc == nil:
			// Intentional disable: builder logged at Info level
			// why (no OAuth providers configured). Skip the
			// success-wired Info log to avoid contradicting that.
		default:
			app.onboardingSvc = obSvc
			logger.Info("sn360-es: onboarding service wired",
				slog.String("callback_url", cfg.Onboarding.CallbackURL))
		}
	} else {
		logger.Info("sn360-es: onboarding service disabled (ONBOARDING_STATE_SECRET or ONBOARDING_CALLBACK_URL not set)")
	}

	if err := assertProductionDurableStores(cfg, app, logger); err != nil {
		return nil, err
	}

	wired = true
	return app, nil
}

// assertProductionDurableStores refuses to boot in production (UAT or
// prod) when any service that owns durable state is backed by an
// in-memory store. The matching persistent backends — Postgres for
// ticket state, Redis for quarantine — are both already optional at
// startup; this check is the safety belt that turns "silently
// degraded" into "fail fast at boot" when running in an environment
// where data loss would constitute an incident.
//
// In non-production environments this still logs each in-memory
// fallback at warn level so operators see what's running with what
// backend without blocking the binary.
func assertProductionDurableStores(cfg *config.Config, app *application, logger *slog.Logger) error {
	type memStore struct {
		name    string
		fix     string
		blocker bool
	}
	var inMemory []memStore

	if app.escalationSvc != nil && app.pgDB == nil {
		inMemory = append(inMemory, memStore{
			name:    "escalation ticket store",
			fix:     "configure PG_HOST/PG_DATABASE so escalation tickets survive a restart",
			blocker: true,
		})
	}
	if app.quarantineSvc != nil && app.redis == nil {
		inMemory = append(inMemory, memStore{
			name:    "quarantine envelope store",
			fix:     "configure REDIS_ADDR so quarantined messages aren't lost on restart",
			blocker: true,
		})
	}
	// Simulation engine + tracker now have durable Postgres
	// backends (PostgresCampaignStore + PostgresInteractionStore)
	// wired in newApplication. We check the actual fallback flags
	// (set on EnsureSchema failure OR pgDB == nil) rather than just
	// `pgDB == nil` so a degraded database that fails the schema
	// check still trips the boot gate — otherwise pgDB would be
	// non-nil but the runtime store would be the in-memory
	// fallback, silently losing data on the next restart.
	if app.simulationEng != nil && app.usingMemoryCampaignStore {
		inMemory = append(inMemory, memStore{
			name:    "simulation campaign store",
			fix:     "configure PG_HOST/PG_DATABASE (and ensure migrations are applied) so simulation campaigns survive a restart",
			blocker: true,
		})
	}
	if app.simulationTracker != nil && app.usingMemoryInteractionStore {
		inMemory = append(inMemory, memStore{
			name:    "simulation interaction store",
			fix:     "configure PG_HOST/PG_DATABASE (and ensure migrations are applied) so simulation interactions survive a restart",
			blocker: true,
		})
	}
	if app.usingMemoryConfigStore {
		inMemory = append(inMemory, memStore{
			name:    "agent config store",
			fix:     "configure PG_HOST/PG_DATABASE (and ensure migrations are applied) so onboarding/tuning agent config (score_engine row) survives a restart",
			blocker: true,
		})
	}

	if len(inMemory) == 0 {
		return nil
	}

	prod := cfg.Environment.IsProduction()
	var blockerMsgs []string
	for _, s := range inMemory {
		level := slog.LevelWarn
		if prod && s.blocker {
			level = slog.LevelError
			blockerMsgs = append(blockerMsgs, s.name+" ("+s.fix+")")
		}
		logger.Log(context.Background(), level,
			"sn360-es: in-memory store in use — data lost on restart",
			slog.String("store", s.name),
			slog.String("fix", s.fix),
			slog.String("environment", string(cfg.Environment)),
		)
	}
	if len(blockerMsgs) > 0 {
		return fmt.Errorf("refusing to boot in %s: in-memory stores would lose data on restart: %s",
			cfg.Environment, strings.Join(blockerMsgs, "; "))
	}
	return nil
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
	role := a.cfg.Role

	// Role gating. Each background goroutine belongs to exactly
	// one role bucket:
	//
	//   consumers — ingestion poller, push subscription setup /
	//               renewal. These pull mail or maintain the
	//               provider-side webhook registration, both of
	//               which are part of the consumer role's mandate.
	//   workers   — periodic jobs (relationship, vendor, cleanup,
	//               directory sync).
	//   all roles — in-process cache janitors. These keep memory
	//               bounded for any role that touches the cache;
	//               the cost is a single goroutine per cache so
	//               the gating cost is zero.
	if role.RunsConsumers() {
		a.spawn(ctx, "ingestion poller", func(ctx context.Context) error {
			if a.poller == nil {
				return nil
			}
			return a.poller.Run(ctx)
		})
		a.spawn(ctx, "push subscription setup", func(ctx context.Context) error {
			if a.pushManager == nil {
				return nil
			}
			// SetupSubscriptions performs IO against each provider's
			// subscription API and may take seconds per tenant. Run it
			// as a one-shot background goroutine so it doesn't block
			// the HTTP listener boot — the renewal loop below covers
			// recovery if a subscription failed to register on this
			// pass (renew falls through to Subscribe on missing IDs).
			if err := a.pushManager.SetupSubscriptions(ctx); err != nil {
				a.logger.Warn("sn360-es: push subscription setup completed with errors",
					slog.Any("error", err))
			}
			return nil
		})
		a.spawn(ctx, "push subscription renewal", func(ctx context.Context) error {
			if a.pushManager == nil {
				return nil
			}
			a.pushManager.RenewLoop(ctx)
			return nil
		})
	}

	if role.RunsWorkers() {
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
		// Partition maintenance is a workers-role concern: it
		// creates forward monthly partitions and drops retention-
		// expired ones for the append-only tables (introduced in
		// PR #45's 0017 migration). Running it on the workers
		// role means a single replica owns the DDL stream, which
		// dovetails with the singleton + Redis-lock model the
		// rest of the workers role uses.
		a.spawn(ctx, "partition worker", func(ctx context.Context) error {
			if a.partitionRunner == nil {
				return nil
			}
			return a.partitionRunner.Run(ctx)
		})
		// Threat-intel feed-consumption worker (WS-5B.3). The
		// Redis lock keyed on "worker:lock:intel" serialises
		// polling across replicas so a single replica owns the
		// poller fleet per cycle, mirroring the cleanup /
		// partition workers' lock pattern.
		a.spawn(ctx, "intel worker", func(ctx context.Context) error {
			if a.intelRunner == nil {
				return nil
			}
			return a.intelRunner.Run(ctx)
		})
	}

	a.spawn(ctx, "memoryLabelCache janitor", func(ctx context.Context) error {
		if a.memLabelCache == nil {
			return nil
		}
		a.memLabelCache.runJanitor(ctx, memoryLabelCacheJanitorInterval, a.logger)
		return nil
	})
	a.spawn(ctx, "tenantScoringConfig janitor", func(ctx context.Context) error {
		if a.tenantScoringConfig == nil {
			return nil
		}
		a.tenantScoringConfig.runJanitor(ctx, tenantScoringConfigJanitorInterval, a.logger)
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

// buildTracer constructs the application's Tracer. When the
// standard OTEL_EXPORTER_OTLP_ENDPOINT env var is set, finished
// spans are batched through the OTel SDK bridge (telemetry.
// NewOTLPBridge) and shipped to the configured collector with
// trace/span IDs preserved 1:1. The collector type (Jaeger, Tempo,
// OTel collector + Datadog exporter, etc.) is opaque to us — we
// speak OTLP/HTTP and let the collector handle the rest.
//
// When OTEL_EXPORTER_OTLP_ENDPOINT is unset, the function returns
// a tracer with the no-op exporter so call sites can still record
// spans for the W3C traceparent header propagation without paying
// any network I/O. This is the right default for dev / unit tests
// and avoids ever silently dropping spans on a misconfigured
// collector URL.
//
// The returned closer (when non-nil) drains in-flight spans and
// shuts down the OTel SDK BatchSpanProcessor + OTLP exporter; it
// MUST be registered on the application's closer chain so a
// graceful shutdown doesn't lose telemetry.
func buildTracer(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*telemetry.Tracer, func() error, error) {
	serviceName := cfg.AppName
	if serviceName == "" {
		serviceName = "sn360-es"
	}
	serviceVersion := strings.TrimSpace(cfg.Telemetry.ServiceVersion)
	env := strings.TrimSpace(string(cfg.Environment))
	endpoint := strings.TrimSpace(cfg.Telemetry.OTLPEndpoint)
	if endpoint == "" {
		return telemetry.NewTracer(telemetry.TracerConfig{
			ServiceName:    serviceName,
			ServiceVersion: serviceVersion,
			Environment:    env,
		}), nil, nil
	}
	exp, shutdown, err := telemetry.NewOTLPBridge(ctx, telemetry.OTLPBridgeConfig{
		Endpoint:       endpoint,
		ServiceName:    serviceName,
		ServiceVersion: serviceVersion,
		Environment:    env,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("build OTLP bridge: %w", err)
	}
	logger.Info("sn360-es: OTLP tracing enabled",
		slog.String("endpoint", endpoint),
		slog.String("service_version", serviceVersion))
	tr := telemetry.NewTracer(telemetry.TracerConfig{
		ServiceName:    serviceName,
		ServiceVersion: serviceVersion,
		Environment:    env,
		Exporter:       exp,
	})
	closer := func() error {
		flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return shutdown(flushCtx)
	}
	return tr, closer, nil
}
