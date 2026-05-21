// Package config loads SN360-ES runtime configuration from the environment.
//
// All configuration is environment-driven (12-factor). A `.env` file is loaded
// up front if present, but real values are read from the process environment so
// that container deployments (k8s, ECS) work without source changes.
//
// The package deliberately has no external dependencies beyond the Go standard
// library so it can be safely imported from tests, tools, and migrations.
package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment is the deployment stage the service is running in.
type Environment string

const (
	EnvironmentLocal Environment = "local"
	EnvironmentDev   Environment = "dev"
	EnvironmentQA    Environment = "qa"
	EnvironmentUAT   Environment = "uat"
	EnvironmentProd  Environment = "prod"
)

// IsDevelopment reports whether the environment is local or dev.
func (e Environment) IsDevelopment() bool {
	return e == EnvironmentLocal || e == EnvironmentDev
}

// IsProduction reports whether the environment requires production-grade
// security controls. Returns true for UAT and prod; QA, test, dev, and
// local are exempt (they may legitimately use mock KMS or weak secrets).
func (e Environment) IsProduction() bool {
	return e == EnvironmentUAT || e == EnvironmentProd
}

// String implements fmt.Stringer.
func (e Environment) String() string { return string(e) }

// EventBusType selects the event-bus implementation (`pkg/events`).
type EventBusType string

const (
	EventBusNATS  EventBusType = "nats"
	EventBusRedis EventBusType = "redis"
)

// Valid reports whether the value is a recognised event bus.
func (t EventBusType) Valid() bool {
	switch t {
	case EventBusNATS, EventBusRedis:
		return true
	default:
		return false
	}
}

// Config is the top-level service configuration.
//
// All sub-structs are exported so that tests and helper packages can build
// custom configurations without re-reading the environment.
type Config struct {
	Environment Environment
	AppName     string

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
	Ingestion                Ingestion
	Worker                   Worker
	Onboarding               Onboarding
	Telemetry                Telemetry
}

// Telemetry carries OTel SDK bridge configuration. Wiring is
// centralised here (rather than read straight from os.Getenv in
// the bridge constructor) so that startup config is fully
// inspectable from one place — useful for `sn360-es validate`,
// for snapshot tests of the resolved configuration, and for any
// future operator who has to debug a misconfigured deploy.
type Telemetry struct {
	// OTLPEndpoint is the OTLP/HTTP collector endpoint. When empty
	// the OTel SDK bridge is disabled and the in-process tracer
	// falls back to the no-op exporter — spans are still recorded
	// for W3C traceparent propagation but never leave the process.
	OTLPEndpoint string
	// ServiceVersion populates the OTel resource attribute
	// service.version. Typically the release tag or git SHA.
	ServiceVersion string
}

// Log carries structured-logging configuration.
type Log struct {
	Level  string
	Format string // "json" or "text"
}

// HTTP holds the HTTP server config.
type HTTP struct {
	Host string
	Port int
	// ReadTimeout caps the total time the server spends reading
	// each request, including its body. Mapped to http.Server.ReadTimeout.
	ReadTimeout time.Duration
	// ReadHeaderTimeout caps the time the server spends reading
	// just the request headers, defending against Slowloris-style
	// header-stuffing attacks independent of body upload speed.
	// Mapped to http.Server.ReadHeaderTimeout. Typically shorter
	// than ReadTimeout.
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
}

// Addr returns the listen address (host:port).
func (h HTTP) Addr() string {
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

// NATS contains all NATS / JetStream connection settings.
type NATS struct {
	URL                  string
	Name                 string
	User                 string
	Password             string
	Token                string
	CredsFile            string
	TLSCAFile            string
	TLSCertFile          string
	TLSKeyFile           string
	TLSInsecure          bool
	ReconnectWait        time.Duration
	MaxReconnects        int
	RequestTimeout       time.Duration
	PublishRetryAttempts int
	PublishRetryDelay    time.Duration
	DedupWindow          time.Duration
	Replicas             int
	Storage              string // "file" or "memory"
	FetchBatchSize       int
	FetchMaxWait         time.Duration
}

// Redis carries Redis client + optional event-bus config.
type Redis struct {
	Addr             string
	Password         string
	DB               int
	PoolSize         int
	MinIdleConns     int
	DialTimeout      time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	ReconnectTimeout time.Duration
	MinRetryBackoff  time.Duration
	ConsumerBlock    time.Duration
	// FetchBatchSize is the default XREADGROUP COUNT used when the
	// Redis backend is the event-bus implementation. Has no effect
	// when EVENT_BUS_TYPE=nats.
	FetchBatchSize int
}

// Postgres carries database connection config.
type Postgres struct {
	Host            string
	Port            int
	User            string
	Password        string
	Database        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// DSN returns a libpq connection string.
func (p Postgres) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		p.Host, p.Port, p.User, p.Password, p.Database, p.SSLMode,
	)
}

// AWS holds AWS-related configuration (KMS, S3).
type AWS struct {
	Region              string
	KMSMasterKeyID      string
	S3CredentialsBucket string
	KMSUseMock          bool
	KMSMockKeyHex       string
}

// Rspamd configures the Rspamd HTTP client.
type Rspamd struct {
	URL      string
	Password string
	Timeout  time.Duration
	CacheTTL time.Duration
}

// AI configures the Tier 2 LLM client.
type AI struct {
	URL      string
	APIKey   string
	Timeout  time.Duration
	CacheTTL time.Duration
}

// Tier1 configures the Tier 1 (encoder) client.
type Tier1 struct {
	URL           string
	Timeout       time.Duration
	BatchSize     int
	PassThreshold int
	FlagThreshold int
	// BatchEnabled selects the batched-orchestrator path on
	// es.evaluate.request (pulls in batches of up to BatchSize and
	// calls the encoder's /predict/batch endpoint). When false the
	// per-message handler is used instead.
	BatchEnabled bool
}

// Tier0 controls the Tier 0 classification gates.
type Tier0 struct {
	SkipInternal         bool
	SkipVendor           bool
	SkipRecurring        bool
	HighVolumeRspamdOnly bool
}

// CircuitBreaker holds shared circuit-breaker defaults.
type CircuitBreaker struct {
	FailureThreshold int
	SuccessThreshold int
	OpenTimeout      time.Duration
}

// Privacy holds privacy-layer toggles.
type Privacy struct {
	PseudonymizeLogs bool
}

// Banner holds banner / action-token configuration.
type Banner struct {
	TokenSecret   string
	TokenTTL      time.Duration
	DefaultLocale string
}

// ScoreThresholds defines the default per-tier score boundaries.
type ScoreThresholds struct {
	Blocked  int
	HighRisk int
	Warning  int
	Caution  int
	Info     int
}

// URLRewrite configures the URL-rewriter interstitial.
type URLRewrite struct {
	Base string
}

// SMTP configures the simulation-email transport used by the
// education engine. All fields are optional; when Host or From is
// empty the simulation sender is disabled and SimulationEngine
// continues to record interactions without dispatching mail.
type SMTP struct {
	Host       string
	Port       int
	User       string
	Password   string
	From       string
	StartTLS   bool
	Timeout    time.Duration
	SkipVerify bool
}

// GWS holds Google Workspace API credentials. ServiceAccountJSON is
// the path or inline JSON of a service-account key with domain-wide
// delegation; DelegatedAdmin is the admin user the service account
// impersonates when calling the Admin SDK Directory API.
//
// All fields are optional: when ServiceAccountJSON is empty the GWS
// provider is disabled and the action consumers / mailbox poller
// fall back to logging-only mode.
type GWS struct {
	ServiceAccountJSON string
	DelegatedAdmin     string
	// Domain is the workspace primary domain (e.g. "example.com");
	// used by the mailbox poller's Admin SDK list-users call.
	Domain string
	// BaseURL overrides the Gmail / Admin API endpoint; left blank in
	// production. Tests use httptest server URLs here.
	BaseURL string
	// AdminBaseURL overrides the Admin SDK endpoint; production
	// leaves this blank to use https://admin.googleapis.com.
	AdminBaseURL string
	// OAuthClientID and OAuthClientSecret are the web-application
	// OAuth 2.0 credentials used by the self-service onboarding
	// consent flow (separate from the domain-wide-delegation service
	// account). Only needed when the onboarding service is enabled.
	OAuthClientID     string
	OAuthClientSecret string
}

// O365 holds Microsoft 365 client-credentials configuration. All
// fields are optional; when ClientID + ClientSecret + TenantID are
// not all set the O365 provider is disabled.
type O365 struct {
	ClientID     string
	ClientSecret string
	TenantID     string
	// BaseURL overrides the Graph API endpoint; tests inject
	// httptest URLs here.
	BaseURL string
	// TokenURL overrides https://login.microsoftonline.com when the
	// caller needs to point at a mock OAuth server.
	TokenURL string
	// ResolveNestedGroups enables transitiveMemberOf queries so
	// users inherit parent-group memberships.
	ResolveNestedGroups bool
}

// HasGmail reports whether enough fields are set to build a Gmail
// provider. Domain is required because the mailbox poller's Admin
// SDK list-users call needs it; without it the poller silently
// observes zero mailboxes and the provider registry would hold an
// unreachable entry. Keeping Domain in the predicate ensures the
// provider registry, mailbox poller, and directory client all agree
// on a single "Gmail is wired" gate.
func (g GWS) HasGmail() bool {
	return g.ServiceAccountJSON != "" && g.DelegatedAdmin != "" && g.Domain != ""
}

// HasOutlook reports whether enough fields are set to build an
// Outlook provider.
func (o O365) HasOutlook() bool {
	return o.ClientID != "" && o.ClientSecret != "" && o.TenantID != ""
}

// Ingestion holds the per-mailbox poller tuning knobs.
type Ingestion struct {
	// Enabled gates the entire poller. Default false so a deployment
	// without provider credentials never starts a noop ticker.
	Enabled bool
	// Interval is the gap between polls per mailbox. Default 30s.
	Interval time.Duration
	// BatchSize is the max number of messages fetched per mailbox
	// per cycle.
	BatchSize int
	// Concurrency is the max number of concurrent mailbox fetches.
	Concurrency int
	// LockTTL is the Redis-lock TTL per (tenant, mailbox). Should be
	// at least 1.5x Interval to absorb drift.
	LockTTL time.Duration
	// InitialBackfill is how far back to look on first poll (when no
	// checkpoint exists yet). Default 1h.
	InitialBackfill time.Duration
	// PushGoogleAudience is the expected `aud` claim on Google
	// Pub/Sub OIDC bearer tokens accompanying push deliveries.
	// Typically the absolute push endpoint URL configured on the
	// subscription (e.g. "https://api.sn360.example.com/v1/push/gws").
	// When empty, the Google push verifier rejects all callbacks —
	// preserving the closed-by-default invariant.
	PushGoogleAudience string
}

// Worker holds the periodic-worker tuning knobs.
type Worker struct {
	// RelationshipInterval is the gap between relationship-aggregation
	// cycles. Default 4h.
	RelationshipInterval time.Duration
	// VendorDiscoveryInterval is the gap between vendor-discovery
	// cycles. Default 7 * 24h.
	VendorDiscoveryInterval time.Duration
	// CleanupInterval is the gap between data-retention cycles.
	// Default 24h.
	CleanupInterval time.Duration
	// RetentionDays is the maximum age of historical rows before
	// the cleanup worker deletes them. Default 90.
	RetentionDays int
	// LockTTL is the Redis-lock TTL for leader election. Should be
	// at least 1.5x the cycle duration the workers expect.
	LockTTL time.Duration
	// DirectorySyncInterval is the gap between directory sync cycles.
	// Default 6h.
	DirectorySyncInterval time.Duration
}

// Onboarding holds the OAuth onboarding flow configuration.
type Onboarding struct {
	// StateSecret is the HMAC key for signing OAuth state tokens.
	StateSecret string
	// CallbackURL is the redirect URI registered with providers.
	CallbackURL string
	// TokenKeyHex is an optional 32-byte hex-encoded AES-256 key
	// dedicated to encrypting OAuth tokens at rest. When empty the
	// encryptor falls back to KMS_MOCK_KEY_HEX, then to a key
	// derived from StateSecret.
	TokenKeyHex string
}

// CORS configures the cross-origin policy applied to every HTTP route.
//
// AllowedOrigins is read from the CORS_ALLOWED_ORIGINS environment
// variable as a comma-separated list. A single "*" entry means
// "echo any origin"; other entries must match the request's Origin
// header exactly (case-insensitive). Defaults to empty. Set
// CORS_ALLOWED_ORIGINS to a comma-separated list of allowed origins,
// or "*" to allow all.
type CORS struct {
	AllowedOrigins []string
}

// RateLimit configures the per-IP token-bucket rate limiter that
// wraps the HTTP mux. Defaults are tuned for typical action-banner
// click traffic (30 req/s, burst 60). Operators tighten via
// RATE_LIMIT_RATE / RATE_LIMIT_BURST when sitting behind a CDN that
// already coalesces traffic, and disable entirely by setting
// RATE_LIMIT_ENABLED=false (e.g. when a dedicated WAF handles it).
type RateLimit struct {
	Enabled         bool
	Rate            float64
	Burst           int
	CleanupInterval time.Duration
	IdleTTL         time.Duration
	// TrustedProxies is the raw comma-separated list of reverse-proxy
	// CIDR ranges from RATE_LIMIT_TRUSTED_PROXIES. Parsing happens at
	// the wiring layer so a malformed entry fails boot fast rather
	// than silently widening (or narrowing) the trust set.
	//
	// When empty, the limiter buckets on r.RemoteAddr only and
	// ignores X-Forwarded-For / X-Real-IP entirely. Operators
	// deploying behind a single ALB should set e.g.
	// RATE_LIMIT_TRUSTED_PROXIES=10.0.0.0/8 so the limiter picks the
	// real client IP from the ALB-appended XFF.
	TrustedProxies string
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

		Log: Log{
			Level:  getStr("LOG_LEVEL", "info"),
			Format: getStr("LOG_FORMAT", "json"),
		},
		HTTP: HTTP{
			Host:              getStr("HTTP_HOST", "0.0.0.0"),
			Port:              getInt("HTTP_PORT", 8080),
			ReadTimeout:       getDuration("HTTP_READ_TIMEOUT", 15*time.Second),
			ReadHeaderTimeout: getDuration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
			WriteTimeout:      getDuration("HTTP_WRITE_TIMEOUT", 30*time.Second),
		},
		EventBus: EventBusType(strings.ToLower(getStr("EVENT_BUS_TYPE", string(EventBusNATS)))),
		NATS: NATS{
			URL:                  getStr("NATS_URL", "nats://127.0.0.1:4222"),
			Name:                 getStr("NATS_NAME", "sn360-es"),
			User:                 getStr("NATS_USER", ""),
			Password:             getStr("NATS_PASSWORD", ""),
			Token:                getStr("NATS_TOKEN", ""),
			CredsFile:            getStr("NATS_CREDS_FILE", ""),
			TLSCAFile:            getStr("NATS_TLS_CA", ""),
			TLSCertFile:          getStr("NATS_TLS_CERT", ""),
			TLSKeyFile:           getStr("NATS_TLS_KEY", ""),
			TLSInsecure:          getBool("NATS_TLS_INSECURE", false),
			ReconnectWait:        getDuration("NATS_RECONNECT_WAIT", 2*time.Second),
			MaxReconnects:        getInt("NATS_MAX_RECONNECTS", -1),
			RequestTimeout:       getDuration("NATS_REQUEST_TIMEOUT", 5*time.Second),
			PublishRetryAttempts: getInt("NATS_PUBLISH_RETRY_ATTEMPTS", 3),
			PublishRetryDelay:    getDuration("NATS_PUBLISH_RETRY_DELAY", 200*time.Millisecond),
			DedupWindow:          getDuration("NATS_DEDUP_WINDOW", 2*time.Minute),
			Replicas:             getInt("NATS_REPLICAS", 1),
			Storage:              getStr("NATS_STORAGE", "file"),
			FetchBatchSize:       getInt("NATS_FETCH_BATCH_SIZE", 50),
			FetchMaxWait:         getDuration("NATS_FETCH_MAX_WAIT", 200*time.Millisecond),
		},
		Redis: Redis{
			Addr:             getStr("REDIS_ADDR", "127.0.0.1:6379"),
			Password:         getStr("REDIS_PASSWORD", ""),
			DB:               getInt("REDIS_DB", 0),
			PoolSize:         getInt("REDIS_POOL_SIZE", 20),
			MinIdleConns:     getInt("REDIS_MIN_IDLE_CONNS", 4),
			DialTimeout:      getDuration("REDIS_DIAL_TIMEOUT", 5*time.Second),
			ReadTimeout:      getDuration("REDIS_READ_TIMEOUT", 2*time.Second),
			WriteTimeout:     getDuration("REDIS_WRITE_TIMEOUT", 2*time.Second),
			ReconnectTimeout: getDuration("REDIS_RECONNECT_TIMEOUT", 30*time.Second),
			MinRetryBackoff:  getDuration("REDIS_MIN_RETRY_BACKOFF", 100*time.Millisecond),
			ConsumerBlock:    getDuration("REDIS_CONSUMER_BLOCK", 0),
			FetchBatchSize:   getInt("REDIS_FETCH_BATCH_SIZE", 10),
		},
		Postgres: Postgres{
			Host:            getStr("PG_HOST", "127.0.0.1"),
			Port:            getInt("PG_PORT", 5432),
			User:            getStr("PG_USER", "sn360es"),
			Password:        getStr("PG_PASSWORD", "sn360es"),
			Database:        getStr("PG_DATABASE", "sn360es"),
			SSLMode:         getStr("PG_SSLMODE", "disable"),
			MaxOpenConns:    getInt("PG_MAX_OPEN_CONNS", 20),
			MaxIdleConns:    getInt("PG_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getDuration("PG_CONN_MAX_LIFETIME", time.Hour),
		},
		AWS: AWS{
			Region:              getStr("AWS_REGION", "ap-southeast-1"),
			KMSMasterKeyID:      getStr("AWS_KMS_MASTER_KEY_ID", ""),
			S3CredentialsBucket: getStr("AWS_S3_BUCKET_CREDENTIALS", ""),
			KMSUseMock:          getBool("KMS_USE_MOCK", true),
			KMSMockKeyHex:       getStr("KMS_MOCK_KEY_HEX", ""),
		},
		Rspamd: Rspamd{
			URL:      getStr("RSPAMD_URL", "http://127.0.0.1:11333"),
			Password: getStr("RSPAMD_PASSWORD", ""),
			Timeout:  getDuration("RSPAMD_TIMEOUT", 5*time.Second),
			CacheTTL: getDuration("RSPAMD_CACHE_TTL", 30*time.Minute),
		},
		AI: AI{
			URL:      getStr("AI_URL", "http://127.0.0.1:9000"),
			APIKey:   getStr("AI_API_KEY", ""),
			Timeout:  getDuration("AI_TIMEOUT", 30*time.Second),
			CacheTTL: getDuration("AI_CACHE_TTL", time.Hour),
		},
		Tier1: Tier1{
			URL:           getStr("TIER1_URL", "http://127.0.0.1:9100"),
			Timeout:       getDuration("TIER1_TIMEOUT", 5*time.Second),
			BatchSize:     getInt("TIER1_BATCH_SIZE", 64),
			PassThreshold: getInt("TIER1_PASS_THRESHOLD", 20),
			FlagThreshold: getInt("TIER1_FLAG_THRESHOLD", 60),
			BatchEnabled:  getBool("TIER1_BATCH_ENABLED", false),
		},
		SensitivityBonsaiURL:     getStr("SENSITIVITY_BONSAI_URL", ""),
		SensitivityBonsaiTimeout: getDuration("SENSITIVITY_BONSAI_TIMEOUT", 30*time.Second),
		Tier0: Tier0{
			SkipInternal:         getBool("TIER0_SKIP_INTERNAL", true),
			SkipVendor:           getBool("TIER0_SKIP_VENDOR", true),
			SkipRecurring:        getBool("TIER0_SKIP_RECURRING", true),
			HighVolumeRspamdOnly: getBool("TIER0_HIGH_VOLUME_RSPAMD_ONLY", true),
		},
		CB: CircuitBreaker{
			FailureThreshold: getInt("CB_FAILURE_THRESHOLD", 5),
			SuccessThreshold: getInt("CB_SUCCESS_THRESHOLD", 2),
			OpenTimeout:      getDuration("CB_OPEN_TIMEOUT", 30*time.Second),
		},
		Privacy: Privacy{
			PseudonymizeLogs: getBool("PRIVACY_PSEUDONYMIZE_LOGS", true),
		},
		Banner: Banner{
			TokenSecret:   getStr("BANNER_TOKEN_SECRET", ""),
			TokenTTL:      getDuration("BANNER_TOKEN_TTL", 7*24*time.Hour),
			DefaultLocale: getStr("BANNER_DEFAULT_LOCALE", "en"),
		},
		Score: ScoreThresholds{
			Blocked:  getInt("SCORE_BLOCKED_THRESHOLD", 85),
			HighRisk: getInt("SCORE_HIGH_RISK_THRESHOLD", 70),
			Warning:  getInt("SCORE_WARNING_THRESHOLD", 50),
			Caution:  getInt("SCORE_CAUTION_THRESHOLD", 30),
			Info:     getInt("SCORE_INFO_THRESHOLD", 15),
		},
		URLRewrite: URLRewrite{
			Base: getStr("URL_REWRITER_BASE", "https://l.sn360.io"),
		},
		CORS: CORS{
			AllowedOrigins: parseCSV(getStr("CORS_ALLOWED_ORIGINS", "")),
		},
		RateLimit: RateLimit{
			Enabled:         getBool("RATE_LIMIT_ENABLED", true),
			Rate:            getFloat("RATE_LIMIT_RATE", 30),
			Burst:           getInt("RATE_LIMIT_BURST", 60),
			CleanupInterval: getDuration("RATE_LIMIT_CLEANUP_INTERVAL", time.Minute),
			IdleTTL:         getDuration("RATE_LIMIT_IDLE_TTL", 5*time.Minute),
			TrustedProxies:  getStr("RATE_LIMIT_TRUSTED_PROXIES", ""),
		},
		SMTP: SMTP{
			Host:       getStr("SMTP_HOST", ""),
			Port:       getInt("SMTP_PORT", 587),
			User:       getStr("SMTP_USER", ""),
			Password:   getStr("SMTP_PASSWORD", ""),
			From:       getStr("SMTP_FROM", ""),
			StartTLS:   getBool("SMTP_STARTTLS", true),
			Timeout:    getDuration("SMTP_TIMEOUT", 10*time.Second),
			SkipVerify: getBool("SMTP_SKIP_VERIFY", false),
		},
		GWS: GWS{
			// ServiceAccountJSON is either a file path or inline
			// JSON. JSON tolerates surrounding whitespace, but a
			// stray newline at the end of a file path (Helm `tpl`
			// indirection, k8s ConfigMap rendering, `echo $path`
			// piping) makes os.ReadFile fail with a "no such file"
			// the operator then has to debug. Trim here so the same
			// invariant the other four credential fields enforce
			// — no leading/trailing whitespace — applies uniformly.
			ServiceAccountJSON: strings.TrimSpace(getStr("GWS_SERVICE_ACCOUNT_JSON", "")),
			DelegatedAdmin:     strings.TrimSpace(getStr("GWS_DELEGATED_ADMIN", "")),
			// Domain is the registry key the provider lookup
			// matches against the MailboxProvider's emitted
			// TenantID. Both flow from this single field, so we
			// trim once at the source — otherwise a stray space
			// in GWS_DOMAIN silently desyncs the registry key
			// (which used to be trimmed in providers.go) from
			// the TenantID (which is not), and action consumers
			// drop every event for the tenant.
			Domain:            strings.TrimSpace(getStr("GWS_DOMAIN", "")),
			BaseURL:           getStr("GWS_GMAIL_BASE_URL", ""),
			AdminBaseURL:      getStr("GWS_ADMIN_BASE_URL", ""),
			OAuthClientID:     strings.TrimSpace(getStr("GWS_OAUTH_CLIENT_ID", "")),
			OAuthClientSecret: getStr("GWS_OAUTH_CLIENT_SECRET", ""),
		},
		O365: O365{
			ClientID:     strings.TrimSpace(getStr("O365_CLIENT_ID", "")),
			ClientSecret: getStr("O365_CLIENT_SECRET", ""),
			// TenantID has the same registry-key invariant as
			// GWS.Domain above — trim at the source.
			TenantID:            strings.TrimSpace(getStr("O365_TENANT_ID", "")),
			BaseURL:             getStr("O365_BASE_URL", ""),
			TokenURL:            getStr("O365_TOKEN_URL", ""),
			ResolveNestedGroups: getBool("O365_RESOLVE_NESTED_GROUPS", true),
		},
		Ingestion: Ingestion{
			Enabled:            getBool("INGESTION_ENABLED", false),
			Interval:           getDuration("INGESTION_INTERVAL", 30*time.Second),
			BatchSize:          getInt("INGESTION_BATCH_SIZE", 50),
			Concurrency:        getInt("INGESTION_CONCURRENCY", 10),
			LockTTL:            getDuration("INGESTION_LOCK_TTL", 45*time.Second),
			InitialBackfill:    getDuration("INGESTION_INITIAL_BACKFILL", time.Hour),
			PushGoogleAudience: strings.TrimSpace(getStr("INGESTION_PUSH_GOOGLE_AUDIENCE", "")),
		},
		Worker: Worker{
			RelationshipInterval:    getDuration("WORKER_RELATIONSHIP_INTERVAL", 4*time.Hour),
			VendorDiscoveryInterval: getDuration("WORKER_VENDOR_DISCOVERY_INTERVAL", 7*24*time.Hour),
			CleanupInterval:         getDuration("WORKER_CLEANUP_INTERVAL", 24*time.Hour),
			RetentionDays:           getInt("WORKER_RETENTION_DAYS", 90),
			LockTTL:                 getDuration("WORKER_LOCK_TTL", 5*time.Minute),
			DirectorySyncInterval:   getDuration("WORKER_DIRECTORY_SYNC_INTERVAL", 6*time.Hour),
		},
		Onboarding: Onboarding{
			StateSecret: getStr("ONBOARDING_STATE_SECRET", ""),
			CallbackURL: getStr("ONBOARDING_CALLBACK_URL", ""),
			TokenKeyHex: getStr("ONBOARDING_TOKEN_KEY_HEX", ""),
		},
		Telemetry: Telemetry{
			OTLPEndpoint:   getStr("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
			ServiceVersion: getStr("SERVICE_VERSION", ""),
		},
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

// validate enforces minimal correctness invariants.
func (c Config) validate() error {
	if c.AppName == "" {
		return errors.New("APP_NAME must be set")
	}
	if c.Environment == "" {
		return errors.New("ENVIRONMENT must be set")
	}
	if !c.EventBus.Valid() {
		return fmt.Errorf("EVENT_BUS_TYPE: invalid value %q (expected nats or redis)", c.EventBus)
	}
	if c.HTTP.Port <= 0 || c.HTTP.Port > 65535 {
		return fmt.Errorf("HTTP_PORT out of range: %d", c.HTTP.Port)
	}
	if c.Score.Blocked <= c.Score.HighRisk ||
		c.Score.HighRisk <= c.Score.Warning ||
		c.Score.Warning <= c.Score.Caution ||
		c.Score.Caution <= c.Score.Info {
		return errors.New("SCORE_*_THRESHOLD must be strictly decreasing: blocked > high > warning > caution > info")
	}
	if c.Onboarding.StateSecret != "" && len(c.Onboarding.StateSecret) < 16 {
		return errors.New("ONBOARDING_STATE_SECRET must be at least 16 bytes when set")
	}
	// B3 + B4: Production-only security validations (UAT + prod).
	if c.Environment.IsProduction() {
		if c.AWS.KMSUseMock {
			return errors.New("KMS_USE_MOCK=true is not allowed in production environments (UAT/prod); current: " + string(c.Environment))
		}
		// Transport-security skips never belong in prod. Refusing
		// here at config-load gives operators a hard, immediate
		// signal at boot rather than a silent compromise of the
		// trust chain.
		if c.NATS.TLSInsecure {
			return errors.New("NATS_TLS_INSECURE=true is not allowed in production environments (UAT/prod)")
		}
		if c.SMTP.SkipVerify {
			return errors.New("SMTP_SKIP_VERIFY=true is not allowed in production environments (UAT/prod)")
		}
		secret := c.Banner.TokenSecret
		if secret != "" {
			if len(secret) < 32 {
				return errors.New("BANNER_TOKEN_SECRET must be at least 32 bytes in production environments (UAT/prod)")
			}
			if secret == "replace-me-with-a-strong-secret" {
				return errors.New("BANNER_TOKEN_SECRET must not be the default placeholder in production environments (UAT/prod)")
			}
			if isLowEntropy(secret) {
				return errors.New("BANNER_TOKEN_SECRET has low entropy (all-same character, sequential bytes, or repeated short pattern); generate one with: openssl rand -base64 48")
			}
		}
		if c.Onboarding.StateSecret != "" && isLowEntropy(c.Onboarding.StateSecret) {
			return errors.New("ONBOARDING_STATE_SECRET has low entropy (all-same character, sequential bytes, or repeated short pattern); generate one with: openssl rand -base64 48")
		}
	}
	return nil
}

// isLowEntropy reports whether s is so obviously non-random that we
// refuse to accept it as a secret. The detector combines three
// cheap, complementary signals:
//
//  1. Shannon entropy over the byte alphabet — catches all-same-byte
//     ("aaaa…") and short-period repeats ("passwordpassword…",
//     "1234123412341234"), which both compress to a tiny effective
//     alphabet.
//  2. Long contiguous monotone runs — catches "abcdefghij…" style
//     keyboard-walk secrets that Shannon would happily score at >4
//     bits because their byte diversity is high.
//  3. Repeated short pattern — catches periodic strings whose period
//     evenly divides len(s) ("abababab…"). Shannon also catches
//     these for short periods but starts failing once the period is
//     longer than the length divided by the alphabet size; the
//     structural check is a strict superset there.
//
// The Shannon threshold (2.5 bits/byte) sits below the ~5.8 bits/byte
// you'd expect from base64-encoded crypto-random output and the
// ~4 bits/byte from hex-encoded crypto-random output (with the finite-
// sample variance that pulls 32-char samples down toward 3.0), but
// well above the ~1.5 bits/byte you get from a typical human
// "passwordpasswordpassword" mistake or a 2/4-period repeat.
func isLowEntropy(s string) bool {
	if s == "" {
		return false
	}
	// (1) Shannon entropy.
	counts := [256]int{}
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	// Tuned threshold: < 2.5 bits/byte means the message could be
	// described in ≤ 2.5·n bits of payload. Random-quality secrets
	// drawn from a 16-symbol (hex) alphabet have an expected Shannon
	// of ~4 bits/byte, but a 32-char finite sample can dip to ~3.0
	// purely from sampling variance. We keep enough margin below that
	// for legitimate UUIDs while still catching obvious low-entropy
	// strings (e.g. "passwordpassword" sits near 1.5 bits/byte).
	if entropy < 2.5 {
		return true
	}
	// (2) Long monotone run: ≥ ceil(len(s)/2) consecutive bytes where
	// each differs from its predecessor by exactly +1 (covers
	// "abc…xyz" style walks even when they wrap around or contain
	// non-monotone tail bytes).
	threshold := (len(s) + 1) / 2
	run := 1
	maxRun := 1
	for i := 1; i < len(s); i++ {
		if int(s[i])-int(s[i-1]) == 1 {
			run++
			if run > maxRun {
				maxRun = run
			}
		} else {
			run = 1
		}
	}
	if maxRun >= threshold {
		return true
	}
	// (3) Repeated short pattern that exactly tiles the string.
	for period := 2; period <= len(s)/2; period++ {
		if len(s)%period != 0 {
			continue
		}
		repeats := true
		for i := period; i < len(s); i++ {
			if s[i] != s[i%period] {
				repeats = false
				break
			}
		}
		if repeats {
			return true
		}
	}
	return false
}

// --- env helpers ------------------------------------------------------------

func getStr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return def
}

// getIntStrict is the variant of getInt used for critical settings
// (HTTP_PORT, tier timeouts, decision thresholds) where a typo or
// stray whitespace must fail boot rather than silently fall back to
// a default that may differ from the operator's intent. It returns:
//
//   - (def, nil)  when the env var is unset or empty.
//   - (n,   nil)  when the env var parses cleanly as an int.
//   - (0,   err)  when the env var is set but unparseable.
//
// The error wraps the offending value (NOT the secret value of the
// env var, since these are all numeric tunables) so operators get an
// actionable diagnostic at boot.
func getIntStrict(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid integer: %w", key, v, err)
	}
	return n, nil
}

// getDurationStrict is the duration twin of getIntStrict. We apply
// the strict policy to the same set of critical settings (tier
// timeouts in particular) so a malformed value like '5second'
// surfaces as a boot error instead of silently reverting to the
// (potentially much shorter or much longer) default.
func getDurationStrict(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid duration: %w", key, v, err)
	}
	return d, nil
}

func getBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

func getFloat(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return f
		}
	}
	return def
}

func getDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}

// parseCSV splits a comma-separated list into a trimmed slice. Empty
// fields are dropped so trailing or duplicate commas do not produce
// empty allow-list entries.
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// loadDotEnv parses a minimal .env file and assigns variables that aren't
// already in the process environment. Lines beginning with `#` and blank
// lines are ignored. Values may be optionally quoted.
//
// This is intentionally tiny: production deployments should source the
// environment from the orchestrator (k8s ConfigMap/Secret, ECS env, etc.).
func loadDotEnv(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[0] == val[len(val)-1] {
			val = val[1 : len(val)-1]
		}
		if _, ok := os.LookupEnv(key); ok {
			continue
		}
		_ = os.Setenv(key, val)
	}
	return nil
}
