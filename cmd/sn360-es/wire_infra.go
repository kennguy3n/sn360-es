package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/handler"
	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/bridge"
	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
	"github.com/kennguy3n/sn360-es/internal/service/relationship"
	"github.com/kennguy3n/sn360-es/internal/service/worker"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/fastmail"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/gmail"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/outlook"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/workmail"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/zoho"
	"github.com/kennguy3n/sn360-es/pkg/events/bus"
	natsbus "github.com/kennguy3n/sn360-es/pkg/events/nats"
	redisbus "github.com/kennguy3n/sn360-es/pkg/events/redis"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
	"github.com/kennguy3n/sn360-es/pkg/storage/redis"
)

// platformBridgeConfig projects the application config into the
// bridge package's Config. Kept here next to factoryConfigFromAppConfig
// so the (config.Config → wiring-specific struct) translations all live
// in the same file.
func platformBridgeConfig(cfg *config.Config) bridge.Config {
	if cfg == nil {
		return bridge.Config{}
	}
	clusterID := cfg.Platform.ClusterID
	if clusterID == "" {
		clusterID = cfg.AppName
	}
	return bridge.Config{
		Enabled:        cfg.Platform.NATSEnabled,
		URLs:           cfg.Platform.NATSURLs,
		CredsFile:      cfg.Platform.NATSCredsFile,
		Token:          cfg.Platform.NATSToken,
		Name:           cfg.Platform.NATSName,
		Source:         cfg.AppName,
		ClusterID:      clusterID,
		TLSCAFile:      cfg.Platform.NATSTLSCAFile,
		TLSCertFile:    cfg.Platform.NATSTLSCertFile,
		TLSKeyFile:     cfg.Platform.NATSTLSKeyFile,
		TLSInsecure:    cfg.Platform.NATSTLSInsecure,
		ReconnectWait:  cfg.Platform.NATSReconnectWait,
		MaxReconnects:  cfg.Platform.NATSMaxReconnects,
		PublishTimeout: cfg.Platform.NATSPublishTimeout,
		PublishRetries: cfg.Platform.NATSPublishRetries,
		Stream:         cfg.Platform.NATSStream,
	}
}

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
	// Passthrough encryptor stores URL pre-images in Redis as plaintext.
	// That is acceptable for local dev and CI but never in production —
	// a Redis dump or rogue replica would leak every rewritten URL.
	//
	// In a healthy UAT/prod boot this branch is unreachable because
	// Config.validate() already refuses to load a production config
	// with KMS_USE_MOCK=false and an empty AWS_KMS_MASTER_KEY_ID. The
	// guard below is defense-in-depth so the passthrough encryptor
	// cannot reach a production process even if some future call site
	// bypasses validate() or constructs a Config in-memory without
	// going through Load(). The caller in app.go logs this error as a
	// warning and continues with URL rewriting disabled, which is the
	// right behaviour in dev (where the validate() guard does not
	// fire) but would be a silent downgrade in prod — hence the
	// upstream validate() check.
	if cfg.Environment.IsProduction() {
		// KMS_USE_MOCK=true is itself refused in UAT/prod by
		// Config.validate(); the only valid remediation in
		// production is a real KMS key ARN, so we do not point
		// the operator at the mock as a workaround.
		return nil, errors.New("sn360-es: url encryptor has no KMS configured; passthrough encryptor is not allowed in production environments (UAT/prod) — set AWS_KMS_MASTER_KEY_ID to a real KMS key ARN")
	}
	logger.Warn("sn360-es: url rewriter falling back to passthrough encryptor — URL pre-images will be stored UNENCRYPTED in Redis. Set KMS_USE_MOCK=true or AWS_KMS_MASTER_KEY_ID to fix.")
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
	// The legacy INGESTION_ENABLED bool gates polling for deployments
	// predating the INGESTION_MODE knob. INGESTION_MODE=hybrid is an
	// explicit operator opt-in to running polling alongside push, so
	// we treat it as Enabled=true regardless of the bool — requiring
	// operators to set BOTH would defeat the point of having a single
	// mode switch.
	if !cfg.Ingestion.Enabled && cfg.Ingestion.Mode != "hybrid" {
		logger.Info("sn360-es: ingestion polling disabled via config",
			slog.String("mode", cfg.Ingestion.Mode))
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
	out := make([]ingestion.MailboxProvider, 0, 5)
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
	if cfg.Zoho.HasZoho() {
		tokens, terr := zoho.NewRefreshTokenSource(zoho.RefreshTokenConfig{
			ClientID:     cfg.Zoho.ClientID,
			ClientSecret: cfg.Zoho.ClientSecret,
			RefreshToken: cfg.Zoho.RefreshToken,
			AccountsURL:  cfg.Zoho.AccountsURL,
			DataCenter:   cfg.Zoho.DataCenter,
		})
		if terr != nil {
			logger.Warn("sn360-es: zoho mailbox provider init failed (token source)",
				slog.Any("error", terr))
		} else {
			client, cerr := zoho.NewClient(zoho.ClientConfig{
				TokenSource: tokens,
				BaseURL:     cfg.Zoho.BaseURL,
				DataCenter:  cfg.Zoho.DataCenter,
				OrgID:       cfg.Zoho.OrgID,
			})
			if cerr != nil {
				logger.Warn("sn360-es: zoho mailbox provider init failed (client)",
					slog.Any("error", cerr))
			} else {
				// HasZoho requires Domain to be set, so use it
				// directly as the registry / TenantID key.
				mbp, merr := zoho.NewMailboxProvider(zoho.MailboxProviderConfig{
					Client:   client,
					TenantID: cfg.Zoho.Domain,
				})
				if merr != nil {
					logger.Warn("sn360-es: zoho mailbox provider init failed",
						slog.Any("error", merr))
				} else {
					out = append(out, mbp)
					logger.Info("sn360-es: zoho mailbox provider wired",
						slog.String("data_center", cfg.Zoho.DataCenter),
						slog.String("org_id", cfg.Zoho.OrgID))
				}
			}
		}
	}
	if cfg.Fastmail.HasFastmail() {
		tokens := fastmail.StaticTokenSource{APIToken: cfg.Fastmail.APIToken}
		client, cerr := fastmail.NewClient(fastmail.ClientConfig{
			TokenSource: tokens,
			BaseURL:     cfg.Fastmail.BaseURL,
			AccountID:   cfg.Fastmail.AccountID,
		})
		if cerr != nil {
			logger.Warn("sn360-es: fastmail mailbox provider init failed (client)",
				slog.Any("error", cerr))
		} else {
			mbp, merr := fastmail.NewMailboxProvider(fastmail.MailboxProviderConfig{Client: client})
			if merr != nil {
				logger.Warn("sn360-es: fastmail mailbox provider init failed",
					slog.Any("error", merr))
			} else {
				out = append(out, mbp)
				logger.Info("sn360-es: fastmail mailbox provider wired",
					slog.String("account_id", cfg.Fastmail.AccountID))
			}
		}
	}
	if cfg.WorkMail.HasWorkMail() {
		creds := buildWorkmailCredentials(cfg)
		signer, serr := workmail.NewSigner(workmail.SignerConfig{
			Region:      cfg.WorkMail.Region,
			Service:     "workmail",
			Credentials: creds,
		})
		if serr != nil {
			logger.Warn("sn360-es: workmail mailbox provider init failed (signer)",
				slog.Any("error", serr))
		} else {
			client, cerr := workmail.NewClient(workmail.ClientConfig{
				Signer: signer,
				Region: cfg.WorkMail.Region,
				OrgID:  cfg.WorkMail.OrganizationID,
			})
			ews, eerr := workmail.NewEWSClient(workmail.EWSClientConfig{
				Signer:   signer,
				Endpoint: cfg.WorkMail.EWSBaseURL,
				Region:   cfg.WorkMail.Region,
			})
			switch {
			case cerr != nil:
				logger.Warn("sn360-es: workmail mailbox provider init failed (client)",
					slog.Any("error", cerr))
			case eerr != nil:
				logger.Warn("sn360-es: workmail mailbox provider init failed (ews)",
					slog.Any("error", eerr))
			default:
				mbp, merr := workmail.NewMailboxProvider(workmail.MailboxProviderConfig{
					Client:   client,
					EWS:      ews,
					TenantID: cfg.WorkMail.OrganizationID,
				})
				if merr != nil {
					logger.Warn("sn360-es: workmail mailbox provider init failed",
						slog.Any("error", merr))
				} else {
					out = append(out, mbp)
					logger.Info("sn360-es: workmail mailbox provider wired",
						slog.String("region", cfg.WorkMail.Region),
						slog.String("org_id", cfg.WorkMail.OrganizationID))
				}
			}
		}
	}
	_ = ctx
	return out
}

// ---------------------------------------------------------------------
// Push-notification ingestion wiring.
// ---------------------------------------------------------------------

// buildPushManager constructs the PushManager that owns Gmail and
// Outlook push receivers. It is closed-by-default:
//
//   - If the mode does not include push ("poll" or empty), returns
//     nil so callers can skip the subscription / renewal goroutines.
//   - If the callback base URL is empty, returns nil and logs a
//     warning — push deliveries cannot be routed back to us without
//     it, so wiring the manager would only register doomed
//     subscriptions and pin tokens.
//   - Per-provider receivers are built only when both (a) the
//     provider credentials are configured and (b) the provider-specific
//     push secret/topic is set. A misconfigured Gmail half does NOT
//     prevent the Outlook half from initialising, and vice versa, so
//     partial-tenant rollouts are supported without an all-or-nothing
//     wire-up.
//
// The returned manager has at least one receiver registered; if the
// caller wired push mode but no provider receiver could be built, we
// return (nil, nil) with a warning rather than constructing a
// no-receiver manager that would always fail SetupSubscriptions.
//
// The receivers slice is returned alongside the manager so the
// caller can pass it to buildPushSignatureVerifier without
// re-running buildPushReceivers (which would log every wiring
// decision twice and — worse — attempt to re-initialise OAuth
// token sources).
func buildPushManager(ctx context.Context, cfg *config.Config, logger *slog.Logger, app *application) (*ingestion.PushManager, []ingestion.PushReceiver) {
	if !cfg.Ingestion.PushEnabled() {
		logger.Info("sn360-es: push ingestion disabled via config",
			slog.String("mode", cfg.Ingestion.Mode))
		return nil, nil
	}
	if cfg.Ingestion.PushCallbackBaseURL == "" {
		logger.Warn("sn360-es: push ingestion enabled but INGESTION_PUSH_CALLBACK_BASE_URL is unset; manager not wired")
		return nil, nil
	}
	if app.eventBus == nil {
		// PushManager.NewPushManager requires a non-nil publisher.
		// In practice the event bus is the only Required dependency
		// of newApplication, so this branch is defensive — but
		// keeping it makes wiring failures observable instead of
		// panicking inside NewPushManager.
		logger.Warn("sn360-es: push ingestion skipped; event bus not wired")
		return nil, nil
	}

	receivers := buildPushReceivers(ctx, cfg, logger)
	if len(receivers) == 0 {
		logger.Warn("sn360-es: push ingestion enabled but no push receivers could be built; manager not wired")
		return nil, nil
	}

	mgr, err := ingestion.NewPushManager(ingestion.PushConfig{
		Receivers:       receivers,
		Publisher:       app.eventBus,
		Logger:          logger,
		Normalizer:      ingestion.NewDefaultNormalizer(),
		CallbackBaseURL: cfg.Ingestion.PushCallbackBaseURL,
	})
	if err != nil {
		logger.Warn("sn360-es: push manager init failed; push disabled",
			slog.Any("error", err))
		return nil, nil
	}
	kinds := make([]string, 0, len(receivers))
	for _, r := range receivers {
		kinds = append(kinds, r.Kind())
	}
	logger.Info("sn360-es: push manager wired",
		slog.String("mode", cfg.Ingestion.Mode),
		slog.String("callback_base_url", cfg.Ingestion.PushCallbackBaseURL),
		slog.Any("providers", kinds))
	return mgr, receivers
}

// buildPushReceivers builds the per-provider push receivers from
// configured credentials. Each provider is wired independently so a
// half-configured deployment still delivers push for whichever
// provider IS fully configured.
//
// Closed-by-default gating: each receiver is built only when its
// credentials AND its edge-verifier requirements are both present.
// Building a receiver without its verifier (e.g. Gmail topic set but
// PushGoogleAudience missing) would create subscriptions whose
// callbacks the edge verifier rejects, producing a stuck pipeline
// that's hard to diagnose from outside.
func buildPushReceivers(ctx context.Context, cfg *config.Config, logger *slog.Logger) []ingestion.PushReceiver {
	out := make([]ingestion.PushReceiver, 0, 2)
	// HasGmail / HasOutlook already require Domain / TenantID to be
	// non-empty, so we don't re-check them here. The provider-specific
	// switch below only covers fields HasGmail / HasOutlook do NOT
	// validate (push topic, audience, client-state secret); the tenant
	// identifier itself is already guaranteed to be present by the
	// outer predicate.
	if cfg.GWS.HasGmail() {
		switch {
		case cfg.Ingestion.PushGmailTopic == "":
			logger.Warn("sn360-es: gmail push receiver skipped; INGESTION_PUSH_GMAIL_TOPIC is unset")
		case cfg.Ingestion.PushGoogleAudience == "":
			// The Gmail Pub/Sub callback is gated at the edge by
			// [handler.GoogleOIDCVerifier], which requires the
			// configured audience to validate the bearer token.
			// Building the receiver without an audience would
			// register watches whose notifications the verifier
			// 401-rejects — orphaned subscriptions on Google's
			// side, stuck pipeline on ours. Skip with a loud
			// warning instead.
			logger.Warn("sn360-es: gmail push receiver skipped; INGESTION_PUSH_GOOGLE_AUDIENCE is unset (verifier would reject every callback)")
		default:
			if sa, err := gmail.LoadServiceAccount(cfg.GWS.ServiceAccountJSON); err != nil {
				logger.Warn("sn360-es: gmail push receiver skipped; service-account load failed",
					slog.Any("error", err))
			} else if tokens, terr := gmail.NewJWTBearerSource(gmail.JWTBearerConfig{
				ServiceAccount:   sa,
				ImpersonatedUser: cfg.GWS.DelegatedAdmin,
			}); terr != nil {
				logger.Warn("sn360-es: gmail push receiver skipped; token source init failed",
					slog.Any("error", terr))
			} else {
				out = append(out, &ingestion.GmailPushReceiver{
					BaseURL:     cfg.GWS.BaseURL,
					TopicName:   cfg.Ingestion.PushGmailTopic,
					TokenSource: tokens,
					TenantList:  []string{cfg.GWS.Domain},
				})
				logger.Info("sn360-es: gmail push receiver wired",
					slog.String("topic", cfg.Ingestion.PushGmailTopic),
					slog.String("tenant", cfg.GWS.Domain))
			}
		}
	}
	if cfg.O365.HasOutlook() {
		if cfg.Ingestion.PushMicrosoftClientStateSecret == "" {
			logger.Warn("sn360-es: outlook push receiver skipped; INGESTION_PUSH_MICROSOFT_CLIENT_STATE_SECRET is unset")
		} else if tokens, terr := outlook.NewClientCredentialsSource(outlook.ClientCredentialsConfig{
			TenantID:     cfg.O365.TenantID,
			ClientID:     cfg.O365.ClientID,
			ClientSecret: cfg.O365.ClientSecret,
			TokenURL:     cfg.O365.TokenURL,
		}); terr != nil {
			logger.Warn("sn360-es: outlook push receiver skipped; token source init failed",
				slog.Any("error", terr))
		} else {
			out = append(out, &ingestion.OutlookPushReceiver{
				BaseURL:              cfg.O365.BaseURL,
				TokenSource:          tokens,
				TenantList:           []string{cfg.O365.TenantID},
				ClientStateForTenant: outlookClientStateForTenant(cfg.Ingestion.PushMicrosoftClientStateSecret),
			})
			logger.Info("sn360-es: outlook push receiver wired",
				slog.String("tenant", cfg.O365.TenantID))
		}
	}
	_ = ctx
	return out
}

// outlookClientStateForTenant returns a function that maps tenantID
// to the clientState the Outlook push pipeline stamps on subscription-
// create requests and expects on inbound notifications.
//
// The value is HMAC-SHA256(secret, tenantID) prefixed with "sn360-es-"
// and truncated to fit comfortably inside Microsoft Graph's 128-character
// clientState limit. Two properties matter:
//
//   - Deterministic per (secret, tenantID): the same function is
//     consulted by [ingestion.OutlookPushReceiver] (Subscribe +
//     HandleNotification) AND by [handler.MicrosoftClientStateVerifier]
//     (ExpectedFor) so the subscription-create payload, the inbound
//     notification, and the verifier all agree on a single string.
//
//   - Unguessable without the secret: a stale tenantID is not enough
//     for an attacker to forge a notification, because the clientState
//     embeds an HMAC keyed by the deployment-scoped secret.
//
// When secret is empty the function returns the legacy obscured-only-
// by-the-prefix value to keep test fixtures and dev wiring (where the
// receiver is constructed directly without setting ClientStateForTenant)
// compatible. Production wiring MUST supply a non-empty secret — the
// buildPushReceivers / buildPushSignatureVerifier callers already gate
// on PushMicrosoftClientStateSecret != "" before invoking this helper.
func outlookClientStateForTenant(secret string) func(tenantID string) string {
	if secret == "" {
		return func(tenantID string) string { return "sn360-es-" + tenantID }
	}
	return func(tenantID string) string {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(tenantID))
		// 32-char base64url payload → final value is well under
		// Graph's 128-char clientState limit ("sn360-es-" + 32).
		return "sn360-es-" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:32]
	}
}

// buildPushSignatureVerifier constructs the [handler.PushSignatureVerifier]
// the webhook handler uses to authenticate inbound /v1/push callbacks
// BEFORE they reach the push manager.
//
// Verifier construction is driven by the receiver list, not by the
// raw config flags. For every receiver in `receivers`, the matching
// edge verifier is wired:
//
//   - "gmail":   [handler.GoogleOIDCVerifier] validates the OIDC
//     bearer token Google Pub/Sub attaches to push deliveries. The
//     audience is read from cfg.Ingestion.PushGoogleAudience (env
//     INGESTION_PUSH_GOOGLE_AUDIENCE).
//
//   - "outlook": [handler.MicrosoftClientStateVerifier] confirms
//     each value[i].clientState matches the tenant-scoped value
//     issued at subscription-create time. ExpectedFor is wired to
//     the same outlookClientStateForTenant closure passed to the
//     OutlookPushReceiver, so the subscription side and the
//     verification side cannot drift apart.
//
// Because buildPushReceivers refuses to build a Gmail receiver
// without PushGoogleAudience and refuses to build an Outlook
// receiver without PushMicrosoftClientStateSecret, the verifier
// dependency for every receiver in `receivers` is guaranteed to be
// present. We DO NOT emit "missing verifier secret" warnings for
// providers whose receivers were never built — those warnings would
// be pure noise in a single-provider deployment where only one half
// of the matrix is configured on purpose.
//
// Returns nil only when `receivers` is empty (caller should also
// have refused to wire the PushManager in that case).
func buildPushSignatureVerifier(cfg *config.Config, receivers []ingestion.PushReceiver, logger *slog.Logger) handler.PushSignatureVerifier {
	if len(receivers) == 0 {
		return nil
	}
	verifiers := make(map[string]handler.PushSignatureVerifier, len(receivers))
	for _, r := range receivers {
		switch r.Kind() {
		case "gmail":
			if cfg.Ingestion.PushGoogleAudience == "" {
				// Should be unreachable: buildPushReceivers gates
				// the gmail receiver on PushGoogleAudience != "".
				// Emitted here as a fail-loud signal in case a
				// future refactor widens the gate without keeping
				// the verifier dependency in lock-step.
				logger.Warn("sn360-es: gmail push receiver built but PushGoogleAudience is empty; verifier dropped (this should be unreachable — check buildPushReceivers gating)")
				continue
			}
			verifiers["gmail"] = &handler.GoogleOIDCVerifier{
				Audience: cfg.Ingestion.PushGoogleAudience,
			}
			logger.Info("sn360-es: push signature verifier wired (gmail)",
				slog.String("audience", cfg.Ingestion.PushGoogleAudience))
		case "outlook":
			if cfg.Ingestion.PushMicrosoftClientStateSecret == "" {
				// Should be unreachable: buildPushReceivers gates
				// the outlook receiver on PushMicrosoftClientStateSecret != "".
				logger.Warn("sn360-es: outlook push receiver built but PushMicrosoftClientStateSecret is empty; verifier dropped (this should be unreachable — check buildPushReceivers gating)")
				continue
			}
			// Keyed by the OutlookPushReceiver.Kind() string
			// ("outlook"), which the router uses to look up the
			// verifier when the inbound request URL is
			// /v1/push/outlook/{tenant}.
			verifiers["outlook"] = &handler.MicrosoftClientStateVerifier{
				ExpectedFor: outlookClientStateForTenant(cfg.Ingestion.PushMicrosoftClientStateSecret),
			}
			logger.Info("sn360-es: push signature verifier wired (outlook)")
		default:
			logger.Warn("sn360-es: no edge verifier registered for push receiver kind; callbacks will be rejected",
				slog.String("kind", r.Kind()))
		}
	}
	if len(verifiers) == 0 {
		return nil
	}
	return &handler.PushSignatureRouter{Verifiers: verifiers}
}

// ---------------------------------------------------------------------
// Periodic worker wiring.
// ---------------------------------------------------------------------

func buildWorkers(cfg *config.Config, logger *slog.Logger, app *application) (*worker.Runner, *worker.Runner, *worker.Runner, *worker.Runner, *worker.Runner) {
	if app.repos == nil {
		logger.Info("sn360-es: periodic workers skipped; repository registry not wired")
		return nil, nil, nil, nil, nil
	}

	lockFactory := buildWorkerLockFactory(cfg, logger, app)
	metricsRec := workerMetricsAdapter{m: app.metrics}

	relRunner := buildRelationshipRunner(cfg, logger, app, lockFactory, metricsRec)
	vendorRunner := buildVendorRunner(cfg, logger, app, lockFactory, metricsRec)
	// Build the partition runner BEFORE the cleanup runner so the
	// cleanup runner can gate its partitioned-table pruners on the
	// actual partition-runner outcome rather than on
	// cfg.Worker.PartitionInterval. If the partition runner failed
	// to wire (NewPartitionMaintenanceJob / NewRunner returned an
	// error) while the config still says PartitionInterval > 0,
	// neither runner would manage retention for evaluation_results /
	// audit_logs / feedback_events — rows would accumulate forever.
	// Passing the live partition-runner reference into
	// buildCleanupRunner re-registers the row-level pruners as the
	// fallback retention path in that failure mode.
	partitionRunner := buildPartitionRunner(cfg, logger, app, lockFactory, metricsRec)
	cleanupRunner := buildCleanupRunner(cfg, logger, app, lockFactory, metricsRec, partitionRunner)
	dirSyncRunner := buildDirectorySyncRunner(cfg, logger, app, lockFactory, metricsRec)

	return relRunner, vendorRunner, cleanupRunner, dirSyncRunner, partitionRunner
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

// pgWorkerBinder adapts *postgres.DB to worker.TenantBinder. The
// adapter exists because *postgres.DB.WithTenant returns the named
// type `postgres.ReleaseFunc`, and Go's method-set matching does
// not equate two named `func() error` types from different
// packages — so *postgres.DB does not satisfy worker.TenantBinder
// directly even though both releases are zero-arg, error-returning
// closures. Conversion via `worker.TenantConnReleaseFunc(r)` keeps
// the worker package free of any concrete-storage import.
type pgWorkerBinder struct{ db *postgres.DB }

func (b pgWorkerBinder) WithTenant(ctx context.Context, tenantID string) (context.Context, worker.TenantConnReleaseFunc, error) {
	c, r, e := b.db.WithTenant(ctx, tenantID)
	return c, worker.TenantConnReleaseFunc(r), e
}

func (b pgWorkerBinder) WithCrossTenant(ctx context.Context) (context.Context, worker.TenantConnReleaseFunc, error) {
	c, r, e := b.db.WithCrossTenant(ctx)
	return c, worker.TenantConnReleaseFunc(r), e
}

// workerTenantBinder returns a worker.TenantBinder when the app has a
// Postgres handle; nil otherwise (in-memory mode). The worker
// configs treat a nil binder as a valid no-op so unit tests with
// in-memory repositories continue to pass unchanged.
func workerTenantBinder(app *application) worker.TenantBinder {
	if app == nil || app.pgDB == nil {
		return nil
	}
	return pgWorkerBinder{db: app.pgDB}
}

func buildRelationshipRunner(cfg *config.Config, logger *slog.Logger, app *application, locks worker.LockFactory, metrics worker.MetricsRecorder) *worker.Runner {
	if app.repos.Tenants == nil || app.repos.CommunicationHistories == nil {
		return nil
	}
	// Wire the per-(recipient, sender_domain) baseline-accumulation
	// path: the worker needs the BehavioralBaselines repository to
	// load/persist the typical_send_hours distribution and a PII
	// hasher so it can derive the baseline keys from the same
	// secret-keyed BLAKE2 namespace the ingestion pipeline uses.
	// When either dependency is unavailable (no PII hasher
	// configured, no behavioural-baseline repo wired) the worker's
	// internal nil guards short-circuit the baseline path and the
	// CAS write on communication_histories still runs unaffected —
	// so a misconfigured deployment degrades to the pre-PR
	// behaviour rather than failing outright.
	piiHasher := buildPIIHasher(cfg)
	var hasherFn func(string, string) ([]byte, error)
	if piiHasher != nil {
		hasherFn = func(tenantID, input string) ([]byte, error) {
			return []byte(piiHasher.HashPII(tenantID, input)), nil
		}
	}
	job, err := worker.NewRelationshipJob(worker.RelationshipJobConfig{
		Interval:       cfg.Worker.RelationshipInterval,
		Tenants:        app.repos.Tenants,
		Communications: app.repos.CommunicationHistories,
		Upserter:       app.repos.CommunicationHistories,
		Baselines:      app.repos.BehavioralBaselines,
		Hasher:         hasherFn,
		Logger:         logger,
		Binder:         workerTenantBinder(app),
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
		Binder:           workerTenantBinder(app),
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

// cleanupPlan is the pure decision a buildCleanupRunner makes about
// which parent tables the row-level cleanup worker should prune. It
// is split out so we can unit-test the partition-worker fallback
// without needing a real Postgres handle.
type cleanupPlan struct {
	// Parents is the ordered list of parent table names the cleanup
	// worker should register a pruner for.
	Parents []string
	// PartitionFallback is true when the partitioned-table pruners
	// are included in Parents because the partition worker is NOT
	// wired (either explicitly disabled or init-failure). Operators
	// use this together with FallbackReason to disambiguate.
	PartitionFallback bool
	// FallbackReason is the human-readable explanation logged when
	// PartitionFallback is true. Empty when the partition worker is
	// wired normally.
	FallbackReason string
}

// planCleanupPruners decides which parent tables the row-level cleanup
// worker should prune given the live partition-runner reference and
// the configured partition interval. Gating on the live runner (rather
// than on cfg.Worker.PartitionInterval > 0) keeps the contention
// mutex correct in the happy path AND fails-safe in the init-error
// path where the operator believes partition maintenance is on but
// the runner failed to wire.
func planCleanupPruners(partitionRunner *worker.Runner, partitionInterval time.Duration) cleanupPlan {
	plan := cleanupPlan{
		Parents: make([]string, 0, 4),
	}
	if partitionRunner == nil {
		plan.PartitionFallback = true
		if partitionInterval > 0 {
			plan.FallbackReason = "partition worker init failed; falling back to row-level pruners"
		} else {
			plan.FallbackReason = "partition worker disabled"
		}
		for _, t := range partitionedAppendOnlyTables() {
			plan.Parents = append(plan.Parents, t.Parent)
		}
	}
	// communication_histories is NOT partitioned (it's an
	// upsert/aggregate, the wrong shape for time-range
	// partitioning — see PR #45 migration 0017 design notes).
	// The cleanup worker is its only retention path regardless of
	// partition-worker state.
	plan.Parents = append(plan.Parents, "communication_histories")
	return plan
}

func buildCleanupRunner(cfg *config.Config, logger *slog.Logger, app *application, locks worker.LockFactory, metrics worker.MetricsRecorder, partitionRunner *worker.Runner) *worker.Runner {
	pruners := make([]worker.Pruner, 0, 4)
	if app.pgDB != nil {
		plan := planCleanupPruners(partitionRunner, cfg.Worker.PartitionInterval)
		for _, parent := range plan.Parents {
			pruners = append(pruners, newPgPruner(app.pgDB, parent, logger))
		}
		if plan.PartitionFallback {
			// Surface WHY the cleanup worker took over so an
			// operator can tell "explicit opt-out" from "partition
			// runner failed to start" at a glance.
			logger.Info("sn360-es: cleanup worker handling partitioned tables",
				slog.String("reason", plan.FallbackReason),
				slog.Duration("partition_interval", cfg.Worker.PartitionInterval))
		}
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
		Binder:        workerTenantBinder(app),
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
		Binder:          workerTenantBinder(app),
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
//
// Invariant (1): every parent table returned by partitionedAppendOnlyTables()
// MUST also appear here, because the cleanup-worker fallback path
// (planCleanupPruners with a nil partitionRunner) registers a
// row-level pruner for every partitioned parent. Without this entry
// newPgPruner panics on the fallback path, taking the worker bootstrap
// down whenever the partition runner is disabled or fails to init —
// exactly the time the row-level fallback needs to be available.
//
// Invariant (2): for every partitioned parent, the column declared
// here MUST equal that parent's PartitionKey on its
// partitionedAppendOnlyTables() entry. The fallback DELETE runs as
//
//	DELETE FROM <parent> WHERE <column> < $1
//
// which only matches the partition-drop's retention semantics — and
// only benefits from partition-pruning at the query planner — when
// <column> is the same column the parent is partitioned on. Using
// any other timestamp column (e.g. an audit `created_at` on a table
// partitioned by `evaluated_at`) silently diverges from the
// partition-drop behaviour for rows where the two columns differ
// (back-fills, retroactive evaluation, replay imports, ...).
var prunableTables = map[string]string{
	"evaluation_results":      "evaluated_at",
	"audit_logs":              "created_at",
	"feedback_events":         "occurred_at",
	"communication_histories": "last_seen_at",
	"quarantine_references":   "created_at",
	"education_lesson_events": "created_at",
	"simulation_send_events":  "created_at",
}

// pgPruneBatchSize bounds the per-iteration DELETE in newPgPruner.
//
// A single unbounded `DELETE FROM ... WHERE ts < cutoff` against a
// table that has accumulated millions of stale rows holds a row-lock
// on every matched row, generates a single oversized WAL record,
// and stalls every other writer on that table for the duration of
// the transaction. Splitting into bounded batches keeps each
// transaction small enough to fit comfortably in a single WAL
// segment and gives ingestion-time INSERTs frequent windows to
// commit between batches.
const pgPruneBatchSize = 5000

// pruneBatchFn is the per-batch DELETE callback that runBatchedPrune
// drives. It returns the number of rows the batch removed; a value
// strictly less than `batchSize` is interpreted as "no rows left
// older than the cutoff" and terminates the loop. The
// rowsAffectedUnknown sentinel lets a driver that cannot report
// RowsAffected (very unusual; lib/pq always can) bail out cleanly
// without spinning forever.
type pruneBatchFn func(ctx context.Context) (rows int64, rowsAffectedUnknown bool, err error)

// runBatchedPrune loops `batch` until it short-reads (rows <
// batchSize), an error fires, or ctx is cancelled. Pulled out as a
// pure function so it can be exercised with a fake batch closure
// (see wire_infra_pruner_test.go) without spinning up a real
// Postgres connection.
func runBatchedPrune(ctx context.Context, batchSize int, batch pruneBatchFn) (int64, error) {
	// Defensive guard: a non-positive batchSize would make the
	// short-read termination condition (`n < int64(batchSize)`)
	// unreachable for any non-negative RowsAffected, spinning the
	// loop indefinitely. The only production caller passes the
	// const pgPruneBatchSize = 5000, so this is hardening for
	// any future caller that builds batchSize from configuration
	// or test inputs.
	if batchSize <= 0 {
		return 0, nil
	}
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, unknown, err := batch(ctx)
		if err != nil {
			return total, err
		}
		if unknown {
			// Driver couldn't report the affected count; we
			// can't tell whether we just emptied the tail.
			// Return progress so far rather than spinning.
			return total, nil
		}
		total += n
		if n < int64(batchSize) {
			return total, nil
		}
	}
}

func newPgPruner(db *postgres.DB, table string, logger *slog.Logger) worker.Pruner {
	column, ok := prunableTables[table]
	if !ok {
		panic(fmt.Sprintf("newPgPruner: table %q is not in the allow-list", table))
	}
	// ctid-IN-LIMIT is the canonical Postgres batched-delete shape:
	// the planner uses the column's btree index to find a bounded
	// candidate set, the outer DELETE then resolves those ctids
	// directly. Looping with the same query is safe because each
	// iteration sees the rows the previous DELETE committed (we
	// commit per ExecContext via autocommit on the lib/pq driver).
	query := fmt.Sprintf(
		"DELETE FROM %s WHERE ctid IN (SELECT ctid FROM %s WHERE %s < $1 LIMIT %d)",
		table, table, column, pgPruneBatchSize,
	)
	return worker.NewPruner(table, func(ctx context.Context, before time.Time) (int64, error) {
		if db == nil {
			return 0, nil
		}
		batch := func(ctx context.Context) (int64, bool, error) {
			res, err := db.ExecContext(ctx, query, before)
			if err != nil {
				logger.Warn("sn360-es: cleanup prune batch failed",
					slog.String("table", table),
					slog.String("column", column),
					slog.Any("error", err))
				return 0, false, err
			}
			n, rerr := res.RowsAffected()
			if rerr != nil {
				return 0, true, nil
			}
			return n, false, nil
		}
		return runBatchedPrune(ctx, pgPruneBatchSize, batch)
	})
}
