package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
	"github.com/kennguy3n/sn360-es/internal/service/relationship"
	"github.com/kennguy3n/sn360-es/internal/service/worker"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/gmail"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/outlook"
	"github.com/kennguy3n/sn360-es/pkg/events/bus"
	natsbus "github.com/kennguy3n/sn360-es/pkg/events/nats"
	redisbus "github.com/kennguy3n/sn360-es/pkg/events/redis"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
	"github.com/kennguy3n/sn360-es/pkg/storage/redis"
)

// factoryConfigFromAppConfig maps the application config into the
// event-bus factory configuration that bus.New expects.
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
// URL / quarantine encryption wiring.
// ---------------------------------------------------------------------

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

func derivedRootKey(id string) []byte {
	sum := sha256.Sum256([]byte("sn360-es:mock-kms:" + id))
	return sum[:]
}

func newQuarantineStore(client *redis.Client) action.QuarantineStore {
	if client != nil {
		return redisQuarantineStore{client: client}
	}
	return newMemoryQuarantineStore()
}

// ---------------------------------------------------------------------
// Ingestion poller wiring.
// ---------------------------------------------------------------------

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
					TokenSource:      tokens,
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
				TokenSource:    tokens,
				BaseURL:        cfg.O365.BaseURL,
				TenantID:       cfg.O365.TenantID,
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

// ---------------------------------------------------------------------
// Periodic worker wiring.
// ---------------------------------------------------------------------

func buildWorkers(cfg *config.Config, logger *slog.Logger, app *application) (*worker.Runner, *worker.Runner, *worker.Runner, *worker.Runner) {
	if app.repos == nil {
		logger.Info("sn360-es: periodic workers skipped; repository registry not wired")
		return nil, nil, nil, nil
	}

	lockFactory := buildWorkerLockFactory(cfg, logger, app)
	metricsRec := workerMetricsAdapter{m: app.metrics}

	relRunner := buildRelationshipRunner(cfg, logger, app, lockFactory, metricsRec)
	vendorRunner := buildVendorRunner(cfg, logger, app, lockFactory, metricsRec)
	cleanupRunner := buildCleanupRunner(cfg, logger, app, lockFactory, metricsRec)
	dirSyncRunner := buildDirectorySyncRunner(cfg, logger, app, lockFactory, metricsRec)

	return relRunner, vendorRunner, cleanupRunner, dirSyncRunner
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

func buildDirectorySyncRunner(cfg *config.Config, logger *slog.Logger, app *application, locks worker.LockFactory, metrics worker.MetricsRecorder) *worker.Runner {
	if app.repos.Tenants == nil || app.repos.Users == nil || app.repos.Groups == nil {
		return nil
	}
	dir := buildDirectoryClient(cfg, logger)
	if dir == nil {
		logger.Info("sn360-es: directory sync worker skipped; no directory client")
		return nil
	}
	piiHasher := buildPIIHasher(cfg)
	var hasherFn func(string, string) ([]byte, error)
	if piiHasher != nil {
		hasherFn = func(tenantID, input string) ([]byte, error) {
			return []byte(piiHasher.HashPII(tenantID, input)), nil
		}
	}
	job, err := worker.NewDirectorySyncJob(worker.DirectorySyncJobConfig{
		Interval:        cfg.Worker.DirectorySyncInterval,
		Tenants:         app.repos.Tenants,
		Directory:       dir,
		Users:           app.repos.Users,
		Groups:          app.repos.Groups,
		Memberships:     app.repos.GroupMemberships,
		Classifier:      buildSensitivityClassifier(cfg, logger),
		Events:          agentPublisherFromBus(app.eventBus),
		Hasher:          hasherFn,
		Logger:          logger,
		SyncCheckpoints: app.repos.SyncCheckpoints,
		OrgGraphs:       app.repos.OrgGraphs,
	})
	if err != nil {
		logger.Warn("sn360-es: directory sync worker init failed",
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
		logger.Warn("sn360-es: directory sync runner init failed",
			slog.Any("error", rerr))
		return nil
	}
	logger.Info("sn360-es: directory sync worker wired",
		slog.Duration("interval", cfg.Worker.DirectorySyncInterval))
	return runner
}

// prunableTables is the exhaustive allow-list of table names that
// newPgPruner may interpolate into a DELETE statement plus the
// per-table "prune by this column" choice.
var prunableTables = map[string]string{
	"evaluation_results":      "created_at",
	"feedback_events":         "created_at",
	"communication_histories": "last_seen_at",
	"quarantine_references":   "created_at",
	"education_lesson_events": "created_at",
	"simulation_send_events":  "created_at",
}

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
