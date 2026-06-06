// Package config loads SN360-ES runtime configuration from the environment.
//
// All configuration is environment-driven (12-factor). A `.env` file is loaded
// up front if present, but real values are read from the process environment so
// that container deployments (k8s, ECS) work without source changes.
//
// The package deliberately has no external dependencies beyond the Go standard
// library so it can be safely imported from tests, tools, and migrations.
//
// Layout. The package is split across domain-scoped files so each section
// stays scannable. Adding a new sub-struct should add a new
// load<Name>() helper in the appropriate file and one extra field +
// assignment in this file's Config / Load:
//
//   - types.go      — Environment, EventBusType enums + Valid methods
//   - server.go     — Log, HTTP, Telemetry
//   - eventbus.go   — NATS, Redis
//   - storage.go    — Postgres, AWS
//   - ai.go         — Rspamd, AI, Tier0, Tier1
//   - scoring.go    — CircuitBreaker, Privacy, Banner, ScoreThresholds,
//     URLRewrite, SMTP
//   - providers.go  — GWS, O365, Zoho, Fastmail, WorkMail (+ Has* predicates,
//     zohoDataCenterOrDefault)
//   - pipeline.go   — Ingestion, Worker, Onboarding, CORS, RateLimit
//   - platform.go   — Platform (sn360-security-platform bridge config)
//   - validate.go   — Config.validate() + isLowEntropy()
//   - helpers.go    — env-reading helpers (getStr, getInt, getIntStrict, etc.)
//     and loadDotEnv
package config

import (
	"errors"
	"strings"
	"time"
)

// Config is the top-level service configuration.
//
// All sub-structs are exported so that tests and helper packages can build
// custom configurations without re-reading the environment.
type Config struct {
	Environment Environment
	AppName     string
	// Role selects which subsystem this process runs. See the
	// Role doc-comment for the four values and their semantics.
	// Loaded from SN360_ROLE; defaults to RoleAll for backward
	// compatibility with the single-binary deployment.
	Role Role

	Log                      Log
	HTTP                     HTTP
	EventBus                 EventBusType
	NATS                     NATS
	Redis                    Redis
	Postgres                 Postgres
	AWS                      AWS
	Rspamd                   Rspamd
	AI                       AI
	Tier1                    Tier1
	Tier0                    Tier0
	SensitivityBonsaiURL     string
	SensitivityBonsaiTimeout time.Duration
	CB                       CircuitBreaker
	Privacy                  Privacy
	Banner                   Banner
	Score                    ScoreThresholds
	URLRewrite               URLRewrite
	CORS                     CORS
	RateLimit                RateLimit
	SMTP                     SMTP
	GWS                      GWS
	O365                     O365
	Zoho                     Zoho
	Fastmail                 Fastmail
	WorkMail                 WorkMail
	Ingestion                Ingestion
	Worker                   Worker
	Onboarding               Onboarding
	Telemetry                Telemetry
	Platform                 Platform
	IAMCore                  IAMCore

	// DirectorySyncSource selects where the directory-sync worker
	// pulls its user roster from (native provider vs iam-core
	// Management API). Loaded from DIRECTORY_SYNC_SOURCE; defaults to
	// DirectorySourceNative so existing deployments are unchanged.
	DirectorySyncSource DirectorySyncSource
}

// Load reads configuration from the environment.
//
// It loads ".env" if present in the working directory (best-effort) and
// then parses all known variables, returning a populated [Config].
//
// Required variables: APP_NAME, ENVIRONMENT. Other variables fall back to
// sensible defaults so that scripts and unit tests can run without a full
// environment.
func Load() (Config, error) {
	_ = loadDotEnv(".env")

	cfg := Config{
		Environment: Environment(getStr("ENVIRONMENT", string(EnvironmentLocal))),
		AppName:     getStr("APP_NAME", "sn360-es"),
		Role:        Role(getStr("SN360_ROLE", string(RoleAll))),

		Log:                      loadLog(),
		HTTP:                     loadHTTP(),
		EventBus:                 EventBusType(strings.ToLower(getStr("EVENT_BUS_TYPE", string(EventBusNATS)))),
		NATS:                     loadNATS(),
		Redis:                    loadRedis(),
		Postgres:                 loadPostgres(),
		AWS:                      loadAWS(),
		Rspamd:                   loadRspamd(),
		AI:                       loadAI(),
		Tier1:                    loadTier1(),
		Tier0:                    loadTier0(),
		SensitivityBonsaiURL:     getStr("SENSITIVITY_BONSAI_URL", ""),
		SensitivityBonsaiTimeout: getDuration("SENSITIVITY_BONSAI_TIMEOUT", 30*time.Second),
		CB:                       loadCircuitBreaker(),
		Privacy:                  loadPrivacy(),
		Banner:                   loadBanner(),
		Score:                    loadScoreThresholds(),
		URLRewrite:               loadURLRewrite(),
		CORS:                     loadCORS(),
		RateLimit:                loadRateLimit(),
		SMTP:                     loadSMTP(),
		GWS:                      loadGWS(),
		O365:                     loadO365(),
		Zoho:                     loadZoho(),
		Fastmail:                 loadFastmail(),
		WorkMail:                 loadWorkMail(),
		Ingestion:                loadIngestion(),
		Worker:                   loadWorker(),
		Onboarding:               loadOnboarding(),
		Telemetry:                loadTelemetry(),
		Platform:                 loadPlatform(),
		IAMCore:                  loadIAMCore(),
		DirectorySyncSource:      DirectorySyncSource(strings.ToLower(getStr("DIRECTORY_SYNC_SOURCE", string(DirectorySourceNative)))),
	}

	// Critical numeric settings: re-parse with the strict helpers so a
	// typo (e.g. HTTP_PORT="80a", TIER1_TIMEOUT="5second") fails boot
	// loudly instead of silently reverting to the default and giving
	// us an off-by-many-seconds tier client timeout in production.
	// Settings here are the ones an operator most plausibly tunes by
	// hand and whose silent fallback is the most surprising
	// operationally; non-critical knobs continue to use the lenient
	// getInt/getDuration helpers.
	var strictErrs []error
	if v, err := getIntStrict("HTTP_PORT", 8080); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.HTTP.Port = v
	}
	if v, err := getDurationStrict("TIER1_TIMEOUT", 5*time.Second); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.Tier1.Timeout = v
	}
	if v, err := getIntStrict("TIER1_BATCH_SIZE", 64); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.Tier1.BatchSize = v
	}
	if v, err := getIntStrict("TIER1_PASS_THRESHOLD", 20); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.Tier1.PassThreshold = v
	}
	if v, err := getIntStrict("TIER1_FLAG_THRESHOLD", 60); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.Tier1.FlagThreshold = v
	}
	if v, err := getIntStrict("TIER1_SUPPRESS_PARTNER", -10); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.Tier1.SuppressPartner = v
	}
	if v, err := getDurationStrict("AI_TIMEOUT", 30*time.Second); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.AI.Timeout = v
	}
	if v, err := getDurationStrict("RSPAMD_TIMEOUT", 5*time.Second); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.Rspamd.Timeout = v
	}
	if len(strictErrs) > 0 {
		return cfg, errors.Join(strictErrs...)
	}

	// WS-7a multi-region routing: PG_REGION_MAP is parsed AFTER
	// loadPostgres so the regional URLs can inherit pool-shape
	// fields (MaxOpenConns / MaxIdleConns / ConnMaxLifetime) from
	// the primary Postgres struct. Empty / unset returns (nil,
	// nil) and the binary continues running single-pool against
	// PG_HOST — backwards-compatible default for single-region
	// deployments.
	rm, err := parsePostgresRegionMap(getStr("PG_REGION_MAP", ""), cfg.Postgres)
	if err != nil {
		return cfg, err
	}
	cfg.Postgres.RegionMap = rm

	// WS-7a multi-region routing: NATS_SUPERCLUSTER carries the
	// region -> leaf-cluster URL mapping used by the cross-region
	// SOC bridge publisher / subscriber. Empty / unset returns
	// (nil, nil); the binary still connects to the primary
	// NATS_URL for its in-region traffic. Malformed JSON or an
	// empty region entry fails boot here instead of at first
	// cross-region publish.
	sc, err := parseNATSSuperclusterMap(getStr("NATS_SUPERCLUSTER", ""))
	if err != nil {
		return cfg, err
	}
	cfg.NATS.Supercluster = sc

	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// MustLoad calls [Load] and panics on error. Useful in main() only.
func MustLoad() Config {
	cfg, err := Load()
	if err != nil {
		panic(err)
	}
	return cfg
}
