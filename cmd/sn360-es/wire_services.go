package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/internal/service/onboarding"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/fastmail"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/gmail"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/outlook"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/workmail"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/zoho"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// ---------------------------------------------------------------------
// AI agent wiring.
// ---------------------------------------------------------------------

func buildAgents(cfg *config.Config, logger *slog.Logger, app *application) (*agent.OnboardingAgent, *agent.TuningAgent, *agent.SupportAgent) {
	var onboardA *agent.OnboardingAgent
	var tuningA *agent.TuningAgent
	var supportA *agent.SupportAgent

	pub := agentPublisherFromBus(app.eventBus)
	configStore := buildConfigStore(logger, app)

	// Support agent.
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

	// Onboarding agent.
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
				Config:                configStore,
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

	// Tuning agent.
	if app.repos != nil && app.repos.FeedbackEvents != nil {
		results := tuningResultAdapter{repos: app.repos}
		ta, err := agent.NewTuningAgent(agent.TuningConfig{
			Results: results,
			Config:  configStore,
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

// ensureTenantScoringConfigAdapter assigns app.tenantScoringConfig
// the first time it is called when a score_engine repo is wired,
// and is a no-op on subsequent calls. It exists so newApplication
// can guarantee the evaluator-side cache is non-nil BEFORE
// NewEvaluator / NewBatchOrchestrator capture
// app.tenantScoringConfig at construction time, while still letting
// buildConfigStore reuse the same instance for the tuning agent's
// invalidation path. Without this split, buildAgents (which calls
// buildConfigStore) ran AFTER the evaluator block in newApplication
// — so app.tenantScoringConfig was nil at line 573 and both the
// per-message Evaluator and the BatchOrchestrator received a nil
// TenantConfig, silently collapsing every verdict back onto the
// static defaults and defeating the entire per-tenant scoring
// config feature.
func ensureTenantScoringConfigAdapter(app *application) {
	if app == nil || app.repos == nil || app.repos.ScoreEngines == nil {
		return
	}
	if app.tenantScoringConfig != nil {
		return
	}
	app.tenantScoringConfig = newTenantScoringConfigAdapter(app.repos.ScoreEngines, 0)
}

// buildConfigStore returns the ConfigStore used by both the
// onboarding and tuning agents. It prefers the durable Postgres-
// backed store (postgresConfigStore on score_engine); only when the
// repository registry / score-engine repo is absent does it fall
// back to memoryConfigStore. The fallback is recorded on the
// application so assertProductionDurableStores can promote the
// warning to a hard boot error in production.
func buildConfigStore(logger *slog.Logger, app *application) agent.ConfigStore {
	if app != nil && app.repos != nil && app.repos.ScoreEngines != nil {
		// Construct (or reuse) the evaluator-side cache so the
		// tuning agent's writes (postgresConfigStore.Update*) can
		// invalidate the same instance that the evaluator + batch
		// orchestrator read from. newApplication calls
		// ensureTenantScoringConfigAdapter BEFORE constructing the
		// evaluator, so by the time buildConfigStore runs the
		// adapter is already wired — this idempotent ensure call
		// preserves the invariant if buildConfigStore is ever
		// invoked through a different entrypoint.
		ensureTenantScoringConfigAdapter(app)
		return newPostgresConfigStore(app.repos.ScoreEngines, app.tenantScoringConfig)
	}
	logger.Warn("sn360-es: using in-memory config store; agent config will not survive restarts (set PG_HOST for persistence)")
	if app != nil {
		app.usingMemoryConfigStore = true
	}
	return newMemoryConfigStore()
}

func buildLabelApplier(app *application) agent.LabelApplier {
	if app == nil || app.providers == nil {
		return nil
	}
	return registryLabelApplier{registry: app.providers}
}

func buildDirectoryClient(cfg *config.Config, logger *slog.Logger) agent.DirectoryClient {
	if cfg.GWS.HasGmail() {
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
			TokenSource:         tokens,
			BaseURL:             cfg.O365.BaseURL,
			TenantID:            cfg.O365.TenantID,
			ResolveNestedGroups: cfg.O365.ResolveNestedGroups,
		})
		if derr != nil {
			logger.Warn("sn360-es: directory client (outlook) wire failed",
				slog.Any("error", derr))
			return nil
		}
		return dc
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
			logger.Warn("sn360-es: directory client (zoho) token init failed",
				slog.Any("error", terr))
			return nil
		}
		client, cerr := zoho.NewClient(zoho.ClientConfig{
			TokenSource: tokens,
			BaseURL:     cfg.Zoho.BaseURL,
			DataCenter:  cfg.Zoho.DataCenter,
			OrgID:       cfg.Zoho.OrgID,
		})
		if cerr != nil {
			logger.Warn("sn360-es: directory client (zoho) client init failed",
				slog.Any("error", cerr))
			return nil
		}
		dc, derr := zoho.NewDirectoryClient(zoho.DirectoryClientConfig{Client: client})
		if derr != nil {
			logger.Warn("sn360-es: directory client (zoho) wire failed",
				slog.Any("error", derr))
			return nil
		}
		return dc
	}
	if cfg.Fastmail.HasFastmail() {
		tokens := fastmail.StaticTokenSource{APIToken: cfg.Fastmail.APIToken}
		client, cerr := fastmail.NewClient(fastmail.ClientConfig{
			TokenSource: tokens,
			BaseURL:     cfg.Fastmail.BaseURL,
			AccountID:   cfg.Fastmail.AccountID,
		})
		if cerr != nil {
			logger.Warn("sn360-es: directory client (fastmail) client init failed",
				slog.Any("error", cerr))
			return nil
		}
		dc, derr := fastmail.NewDirectoryClient(fastmail.DirectoryClientConfig{Client: client})
		if derr != nil {
			logger.Warn("sn360-es: directory client (fastmail) wire failed",
				slog.Any("error", derr))
			return nil
		}
		return dc
	}
	if cfg.WorkMail.HasWorkMail() {
		creds := buildWorkmailCredentials(cfg)
		signer, serr := workmail.NewSigner(workmail.SignerConfig{
			Region:      cfg.WorkMail.Region,
			Service:     "workmail",
			Credentials: creds,
		})
		if serr != nil {
			logger.Warn("sn360-es: directory client (workmail) signer init failed",
				slog.Any("error", serr))
			return nil
		}
		client, cerr := workmail.NewClient(workmail.ClientConfig{
			Signer: signer,
			Region: cfg.WorkMail.Region,
			OrgID:  cfg.WorkMail.OrganizationID,
		})
		if cerr != nil {
			logger.Warn("sn360-es: directory client (workmail) client init failed",
				slog.Any("error", cerr))
			return nil
		}
		dc, derr := workmail.NewDirectoryClient(workmail.DirectoryClientConfig{Client: client})
		if derr != nil {
			logger.Warn("sn360-es: directory client (workmail) wire failed",
				slog.Any("error", derr))
			return nil
		}
		return dc
	}
	return nil
}

func buildSensitivityClassifier(cfg *config.Config, logger *slog.Logger) agent.SensitivityClassifier {
	if cfg.Tier1.URL == "" {
		return nil
	}
	encoder := agent.NewEncoderSensitivityClassifier(cfg.Tier1.URL, nil, cfg.Tier1.Timeout, logger)
	var bonsai *agent.BonsaiSensitivityClassifier
	if cfg.SensitivityBonsaiURL != "" {
		bonsai = agent.NewBonsaiSensitivityClassifier(cfg.SensitivityBonsaiURL, nil, cfg.SensitivityBonsaiTimeout, logger)
	}
	return agent.NewTieredSensitivityClassifier(agent.TieredClassifierConfig{
		Encoder:  encoder,
		Bonsai:   bonsai,
		Fallback: agent.KeywordClassifyInput,
		Logger:   logger,
	})
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

func buildVendorScanner(app *application) agent.VendorScanner {
	if app.repos == nil || app.repos.CommunicationHistories == nil {
		return nil
	}
	return &vendorScannerAdapter{histories: app.repos.CommunicationHistories}
}

// buildSignalEnricher constructs the consumer-side enrichment hook
// that folds per-(tenant, sender, recipient) state from
// communication_histories onto each evaluate request's RiskSignals.
//
// Returns NoopEnricher (rather than nil) when either dependency is
// missing — the communication_histories repository or the PII
// hasher. Callers therefore never have to nil-check; a partially-
// wired deployment degrades to base signals exactly as if the
// enricher hook had not existed, which is what the Tier 0 ATO
// heuristic's defensive `signals.TypicalSendHour == nil` branch
// already handles. The PII hasher MUST be the same one the
// relationship / directory workers use so the computed sender_hash
// and recipient_hash byte-for-byte match the row keys persisted in
// communication_histories.
//
// Non-obvious config dependency: buildPIIHasher reads
// cfg.Banner.TokenSecret (BANNER_TOKEN_SECRET). If that secret is
// unset, the PII hasher comes back nil and the enricher silently
// degrades to NoopEnricher even when the communication_histories
// repo is fully wired. This coupling is pre-existing — the
// relationship / directory workers also short-circuit when the
// banner token secret is missing — but a deployment that
// configures Postgres + the comm-histories repo but omits
// BANNER_TOKEN_SECRET will get no enrichment and every email will
// look like first-contact via the IsFirstContact pathway. The
// production deployment guide treats BANNER_TOKEN_SECRET as a
// required platform secret; this branch exists for development
// fallback only.
func buildSignalEnricher(cfg *config.Config, logger *slog.Logger, app *application) evaluate.SignalEnricher {
	if app.repos == nil || app.repos.CommunicationHistories == nil {
		return evaluate.NoopEnricher{}
	}
	hasher := buildPIIHasher(cfg)
	if hasher == nil {
		return evaluate.NoopEnricher{}
	}
	enricher := newCommHistorySignalEnricher(app.repos.CommunicationHistories, hasher, logger)
	if enricher == nil {
		return evaluate.NoopEnricher{}
	}
	return enricher
}

// ---------------------------------------------------------------------
// Onboarding service wiring.
// ---------------------------------------------------------------------

func buildOnboardingService(cfg *config.Config, logger *slog.Logger, app *application) (*onboarding.Service, error) {
	signer, err := onboarding.NewStateSigner([]byte(cfg.Onboarding.StateSecret))
	if err != nil {
		return nil, fmt.Errorf("state signer: %w", err)
	}

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

	// Resolve the regional Zoho Mail REST endpoint up front so the
	// post-consent validator hits the data centre that matches the
	// operator's ZOHO_DATA_CENTER setting (e.g. .eu, .in). Zoho's
	// six data centres are isolated, so a US-default validator would
	// silently 401 every non-US tenant.
	validator := onboarding.NewHTTPPostConsentValidator(nil, cfg.GWS.Domain, zoho.MailBaseURL(cfg.Zoho.DataCenter))
	// Strict org-match: when ZOHO_ORG_ID is configured, the post-
	// consent validator parses /api/organization and requires the
	// returned zoid to equal cfg.Zoho.OrgID. Without this, the
	// validator would accept any valid Zoho token — weaker than the
	// Microsoft (tenant ID) and Google (domain) checks. Empty leaves
	// the field unset, matching the documented "only confirm the
	// token can read the org endpoint" behaviour.
	validator.ZohoExpectedOrgID = cfg.Zoho.OrgID
	exch := onboarding.NewHTTPExchanger(nil)

	providers := buildOAuthProviderConfigs(cfg)
	if len(providers) == 0 {
		return nil, fmt.Errorf("at least one OAuth provider (GWS, O365, or Zoho) must be configured for the onboarding flow; Fastmail and WorkMail use non-OAuth auth and are not registered here")
	}

	var trigger onboarding.PostConsentTrigger
	if app.onboardAgent != nil {
		trigger = &onboarding.AgentBridge{
			Onboarding: app.onboardAgent,
			Log:        logger,
			WG:         &app.bgWG,
			Draining:   &app.draining,
		}
	}

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

// buildOAuthProviderConfigs maps the env-loaded provider credentials
// onto the onboarding service's per-provider OAuth config map. The
// map keys (onboarding.ProviderType) are the values surfaced on the
// /v1/onboarding/start?provider=… query string and looked up by both
// AuthURL and HandleCallback. A provider absent from this map cannot
// complete the OAuth handshake — so the predicates here are the
// gating mechanism for whether each provider's consent flow is
// reachable at all.
//
// Gating rules:
//
//   - Google (GWS): OAuthClientID + OAuthClientSecret. These are the
//     credentials the consent flow needs; the long-lived refresh
//     token is produced by the flow itself, so we don't require it
//     here.
//   - Microsoft (O365): cfg.O365.HasOutlook() (ClientID + ClientSecret
//   - Tenant).
//   - Zoho: ClientID + ClientSecret. Like Google, the refresh token is
//     produced by the flow. AuthURL / TokenURL are data-centre-
//     specific (Zoho's six regions are isolated), so they're derived
//     from cfg.Zoho.DataCenter via the canonical AccountsBaseURL
//     helper rather than hardcoding the US endpoint.
//   - Fastmail: not registered — API-token auth, no OAuth consent.
//   - WorkMail: not registered — AWS IAM SigV4 auth, no OAuth consent.
//
// Extracted into its own function (vs. inlined into
// buildOnboardingService) so the per-provider gating can be unit-
// tested without requiring a live application/PostgreSQL bootstrap.
func buildOAuthProviderConfigs(cfg *config.Config) map[onboarding.ProviderType]onboarding.ProviderConfig {
	providers := make(map[onboarding.ProviderType]onboarding.ProviderConfig)
	if cfg.GWS.OAuthClientID != "" && cfg.GWS.OAuthClientSecret != "" {
		providers[onboarding.ProviderGoogle] = onboarding.ProviderConfig{
			ClientID:     cfg.GWS.OAuthClientID,
			ClientSecret: cfg.GWS.OAuthClientSecret,
			AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			Scopes: []string{
				"https://www.googleapis.com/auth/admin.directory.user.readonly",
				"https://www.googleapis.com/auth/admin.directory.group.readonly",
			},
			RedirectURL: cfg.Onboarding.CallbackURL,
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
	if cfg.Zoho.ClientID != "" && cfg.Zoho.ClientSecret != "" {
		accountsBase := zoho.AccountsBaseURL(cfg.Zoho.DataCenter)
		providers[onboarding.ProviderZoho] = onboarding.ProviderConfig{
			ClientID:     cfg.Zoho.ClientID,
			ClientSecret: cfg.Zoho.ClientSecret,
			AuthURL:      accountsBase + "/oauth/v2/auth",
			TokenURL:     accountsBase + "/oauth/v2/token",
			Scopes: []string{
				"ZohoMail.messages.ALL",
				"ZohoMail.folders.ALL",
				"ZohoMail.tags.ALL",
				"ZohoMail.accounts.READ",
				"ZohoMail.organization.READ",
			},
			RedirectURL: cfg.Onboarding.CallbackURL,
		}
	}
	return providers
}
