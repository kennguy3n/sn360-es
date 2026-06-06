package config

import (
	"strings"
	"time"
)

// Ingestion holds the per-mailbox poller and push-notification tuning knobs.
type Ingestion struct {
	// Mode controls how the service acquires messages. Valid values:
	//   "poll"   — pull-based polling only (default).
	//   "push"   — push-notification webhooks only.
	//   "hybrid" — both push and poll run concurrently.
	// An empty value is treated as "poll".
	Mode string
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
	// PushCallbackBaseURL is the externally-reachable URL prefix
	// that providers will POST push notifications to. The handler
	// appends /{provider}/{tenant} as a path suffix.
	// Required when Mode is "push" or "hybrid".
	PushCallbackBaseURL string
	// PushGmailTopic is the fully-qualified Google Cloud Pub/Sub
	// topic that Gmail's users.watch API publishes to (e.g.
	// "projects/<project-id>/topics/sn360-gmail-push"). Required to
	// wire the Gmail push receiver; when empty, the Gmail half of
	// the push manager is skipped while Outlook remains operational.
	PushGmailTopic string
	// PushGoogleAudience is the expected `aud` claim on Google
	// Pub/Sub OIDC bearer tokens accompanying push deliveries.
	// Typically the absolute push endpoint URL configured on the
	// subscription (e.g. "https://api.sn360.example.com/v1/push/gmail").
	// When empty, the Google push verifier rejects all callbacks —
	// preserving the closed-by-default invariant.
	PushGoogleAudience string
	// PushMicrosoftClientStateSecret is the shared secret used to
	// validate Microsoft Graph change notification callbacks. Each
	// subscription is created with this value as clientState, and
	// the verifier confirms inbound notifications carry the
	// matching value via constant-time comparison.
	// Required when Mode is "push" or "hybrid" and an Outlook
	// provider is configured.
	PushMicrosoftClientStateSecret string

	// SMTPGateway configures the optional pre-delivery MX gateway.
	SMTPGateway SMTPGateway
}

// SMTPGateway configures the optional pre-delivery SMTP MX gateway.
// The gateway is an independent ingress alongside poll/push: mail
// servers route inbound mail to it via MX records and it scans each
// message before relaying it downstream. It is gated separately from
// INGESTION_MODE because an operator may run the gateway without (or
// in addition to) provider-API polling.
type SMTPGateway struct {
	// Enabled starts the SMTP listener. Default false.
	Enabled bool
	// Addr is the listen address. Default ":25".
	Addr string
	// Domain is the hostname announced in the SMTP banner. Defaults
	// to the binary's configured public domain or "sn360-es".
	Domain string
	// RequireTLS refuses MAIL FROM on a plaintext session. Only
	// meaningful when a TLS cert/key pair is configured.
	RequireTLS bool
	// TLSCertFile / TLSKeyFile enable STARTTLS when both are set.
	TLSCertFile string
	TLSKeyFile  string
	// MaxMessageBytes caps the accepted message size. Default 25 MiB.
	MaxMessageBytes int64
	// MaxRecipients caps RCPT TO per transaction. Default 100.
	MaxRecipients int
	// ReadTimeout / WriteTimeout bound per-connection IO. Default 60s.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// PushEnabled reports whether the configured INGESTION_MODE
// INCLUDES push-notification handling — i.e. "push" or "hybrid".
//
// It is a mode predicate, NOT an active-runtime gate. Returning
// true means the wiring layer should attempt to build a
// [ingestion.PushManager]; the manager itself may still end up nil
// at runtime if no provider receiver could be built (missing
// credentials, missing push topic / audience / client-state secret,
// or buildPushManager could not initialise the OAuth token source).
// Callers that need "is the push pipeline ACTIVE right now?"
// should check the wired application.pushManager handle directly
// instead.
func (i Ingestion) PushEnabled() bool {
	return i.Mode == "push" || i.Mode == "hybrid"
}

// PollEnabled reports whether the configured INGESTION_MODE
// INCLUDES the legacy polling pipeline — i.e. "", "poll", or
// "hybrid". The empty-string default is treated as "poll" for
// backwards compatibility with deployments that pre-date the
// INGESTION_MODE variable.
//
// It is a mode predicate, NOT an active-runtime gate. PollEnabled()
// returning true means the wiring layer should attempt to build a
// poller; the poller itself only actually runs when (a) PollEnabled
// is true AND (b) Ingestion.Enabled is set (the legacy
// INGESTION_ENABLED flag, retained as the explicit off-switch for
// poll-mode deployments). A deployment with Mode="poll" and
// Enabled=false still returns true here but produces a nil poller
// at runtime — by design, so push-only deployments don't have to
// also disable poll mode through two separate flags.
//
// Callers that need "is the poller ACTIVELY running right now?"
// should check the wired application.poller handle directly instead.
func (i Ingestion) PollEnabled() bool {
	return i.Mode == "" || i.Mode == "poll" || i.Mode == "hybrid"
}

func loadIngestion() Ingestion {
	return Ingestion{
		Mode:                           strings.ToLower(strings.TrimSpace(getStr("INGESTION_MODE", "poll"))),
		Enabled:                        getBool("INGESTION_ENABLED", false),
		Interval:                       getDuration("INGESTION_INTERVAL", 30*time.Second),
		BatchSize:                      getInt("INGESTION_BATCH_SIZE", 50),
		Concurrency:                    getInt("INGESTION_CONCURRENCY", 10),
		LockTTL:                        getDuration("INGESTION_LOCK_TTL", 45*time.Second),
		InitialBackfill:                getDuration("INGESTION_INITIAL_BACKFILL", time.Hour),
		PushCallbackBaseURL:            strings.TrimRight(strings.TrimSpace(getStr("INGESTION_PUSH_CALLBACK_BASE_URL", "")), "/"),
		PushGmailTopic:                 strings.TrimSpace(getStr("INGESTION_PUSH_GMAIL_TOPIC", "")),
		PushGoogleAudience:             strings.TrimSpace(getStr("INGESTION_PUSH_GOOGLE_AUDIENCE", "")),
		PushMicrosoftClientStateSecret: getStr("INGESTION_PUSH_MICROSOFT_CLIENT_STATE_SECRET", ""),
		SMTPGateway:                    loadSMTPGateway(),
	}
}

func loadSMTPGateway() SMTPGateway {
	return SMTPGateway{
		Enabled:         getBool("SMTP_GATEWAY_ENABLED", false),
		Addr:            strings.TrimSpace(getStr("SMTP_GATEWAY_ADDR", ":25")),
		Domain:          strings.TrimSpace(getStr("SMTP_GATEWAY_DOMAIN", "")),
		RequireTLS:      getBool("SMTP_GATEWAY_REQUIRE_TLS", false),
		TLSCertFile:     strings.TrimSpace(getStr("SMTP_GATEWAY_TLS_CERT_FILE", "")),
		TLSKeyFile:      strings.TrimSpace(getStr("SMTP_GATEWAY_TLS_KEY_FILE", "")),
		MaxMessageBytes: int64(getInt("SMTP_GATEWAY_MAX_MESSAGE_BYTES", 25<<20)),
		MaxRecipients:   getInt("SMTP_GATEWAY_MAX_RECIPIENTS", 100),
		ReadTimeout:     getDuration("SMTP_GATEWAY_READ_TIMEOUT", 60*time.Second),
		WriteTimeout:    getDuration("SMTP_GATEWAY_WRITE_TIMEOUT", 60*time.Second),
	}
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
	// PartitionInterval is the gap between
	// partition-maintenance cycles for the partitioned append-only
	// tables (see migrations/0017_partition_append_only_tables.up.sql).
	// Default 24h — monthly partition cadence is generous enough
	// that running daily still leaves a wide forward-creation
	// window even if several cycles are missed.
	PartitionInterval time.Duration
	// PartitionLookaheadMonths controls how far ahead the
	// maintenance worker pre-creates monthly partitions. Default 3:
	// even if the worker is offline for a couple of months, the
	// parent table still has somewhere to route inserts.
	PartitionLookaheadMonths int
	// PartitionRetentionMonths bounds how many calendar months of
	// historical data each partitioned table keeps. Default 12. The
	// maintenance worker DROPS partitions whose upper bound is at-
	// or-before `now - PartitionRetentionMonths`; the legacy
	// (pre-cutover) partition is always preserved and operators
	// archive + drop it manually. Set to 0 to disable partition-
	// drop entirely (forward-creation still runs).
	PartitionRetentionMonths int

	// IntelEnabled gates the threat-intel feed-consumption worker
	// (migrations/0024_threat_intel_feeds.up.sql). When false the
	// scheduler does not start; the Tier 0 ti_match reason code
	// still works against any rows already in intel_indicators
	// because the gate consults the table directly.
	IntelEnabled bool
	// IntelInterval is the scheduler tick interval — how often the
	// worker scans intel_feeds for due rows. Default 1m.
	IntelInterval time.Duration
	// IntelMaxConcurrent caps the number of simultaneously-running
	// feed pollers per cycle. Default 4 — IO-bound enough that the
	// system tolerates more, conservative enough to keep one slow
	// MISP from blocking URLhaus refreshes.
	IntelMaxConcurrent int
	// IntelGCInterval is how often the garbage-collection sweep runs.
	// Default 6h.
	IntelGCInterval time.Duration
	// IntelGCRetention is the maximum age of an indicator row
	// (relative to its last_seen) before it is eligible for GC.
	// Default 30 days. URLhaus rotates aggressively; older rows
	// produce false positives.
	IntelGCRetention time.Duration
	// IntelMISPAPIKey is the MISP API token. Required for the misp
	// provider; ignored by other providers.
	IntelMISPAPIKey string
	// IntelSTIXAPIKey is the STIX-TAXII Bearer token. Optional —
	// public TAXII collections require no auth.
	IntelSTIXAPIKey string
	// IntelFeedTimeout caps the per-feed HTTP poll duration before
	// the worker considers the poll failed. Default 60s.
	IntelFeedTimeout time.Duration
	// IntelStaleThreshold is the number of consecutive failures at
	// which the worker raises the Prometheus stale-feed alert and
	// writes the audit row. Default 3.
	IntelStaleThreshold int
}

func loadWorker() Worker {
	return Worker{
		RelationshipInterval:     getDuration("WORKER_RELATIONSHIP_INTERVAL", 4*time.Hour),
		VendorDiscoveryInterval:  getDuration("WORKER_VENDOR_DISCOVERY_INTERVAL", 7*24*time.Hour),
		CleanupInterval:          getDuration("WORKER_CLEANUP_INTERVAL", 24*time.Hour),
		RetentionDays:            getInt("WORKER_RETENTION_DAYS", 90),
		LockTTL:                  getDuration("WORKER_LOCK_TTL", 5*time.Minute),
		DirectorySyncInterval:    getDuration("WORKER_DIRECTORY_SYNC_INTERVAL", 6*time.Hour),
		PartitionInterval:        getDuration("WORKER_PARTITION_INTERVAL", 24*time.Hour),
		PartitionLookaheadMonths: getInt("WORKER_PARTITION_LOOKAHEAD_MONTHS", 3),
		PartitionRetentionMonths: getInt("WORKER_PARTITION_RETENTION_MONTHS", 12),
		IntelEnabled:             getBool("WORKER_INTEL_ENABLED", false),
		IntelInterval:            getDuration("WORKER_INTEL_INTERVAL", time.Minute),
		IntelMaxConcurrent:       getInt("WORKER_INTEL_MAX_CONCURRENT", 4),
		IntelGCInterval:          getDuration("WORKER_INTEL_GC_INTERVAL", 6*time.Hour),
		IntelGCRetention:         getDuration("WORKER_INTEL_GC_RETENTION", 30*24*time.Hour),
		IntelMISPAPIKey:          getStr("INTEL_MISP_API_KEY", ""),
		IntelSTIXAPIKey:          getStr("INTEL_STIX_API_KEY", ""),
		IntelFeedTimeout:         getDuration("WORKER_INTEL_FEED_TIMEOUT", 60*time.Second),
		IntelStaleThreshold:      getInt("WORKER_INTEL_STALE_FAILURES", 3),
	}
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

func loadOnboarding() Onboarding {
	return Onboarding{
		StateSecret: getStr("ONBOARDING_STATE_SECRET", ""),
		CallbackURL: getStr("ONBOARDING_CALLBACK_URL", ""),
		TokenKeyHex: getStr("ONBOARDING_TOKEN_KEY_HEX", ""),
	}
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

func loadCORS() CORS {
	return CORS{
		AllowedOrigins: parseCSV(getStr("CORS_ALLOWED_ORIGINS", "")),
	}
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
	// Backend selects the bucket store. "memory" (default) keeps
	// the existing per-replica behaviour. "redis" shares token
	// state across every replica that points at the same Redis,
	// which is the configuration required for the documented
	// rate to actually hold cluster-wide. Set via
	// RATE_LIMIT_BACKEND.
	Backend string
	// RedisKeyPrefix is prepended to every bucket key in Redis. A
	// stable, deployment-scoped string prevents two services on
	// the same Redis from colliding on the same client identifier
	// (e.g. two services both bucketing on "1.2.3.4"). Defaults
	// to "sn360-es:rl"; set via RATE_LIMIT_REDIS_KEY_PREFIX.
	RedisKeyPrefix string
	// RedisTTL is the auto-expiry on every bucket hash in Redis.
	// Defaults to 10 minutes (the effective TTL on each write is
	// max(RedisTTL, refill-from-empty)). Set via
	// RATE_LIMIT_REDIS_TTL.
	RedisTTL time.Duration
	// RedisTimeout caps every Redis Take call. A slow Redis
	// otherwise extends every request's tail latency. Defaults to
	// 200 ms; negative disables. Set via RATE_LIMIT_REDIS_TIMEOUT.
	RedisTimeout time.Duration
	// FailureMode controls the limiter's behaviour when the
	// configured store (typically Redis) is hard-down: "open"
	// (default) lets requests through, "closed" returns 503. Set
	// via RATE_LIMIT_FAILURE_MODE.
	FailureMode string
	// FallbackToMemory, when true, has the limiter consult a
	// per-replica memory store whenever the primary store returns
	// an availability error. The fallback is less correct (per-
	// replica counting) but still safer than fail-open in most
	// production setups. Defaults to true; set via
	// RATE_LIMIT_FALLBACK_TO_MEMORY.
	FallbackToMemory bool
}

func loadRateLimit() RateLimit {
	return RateLimit{
		Enabled:          getBool("RATE_LIMIT_ENABLED", true),
		Rate:             getFloat("RATE_LIMIT_RATE", 30),
		Burst:            getInt("RATE_LIMIT_BURST", 60),
		CleanupInterval:  getDuration("RATE_LIMIT_CLEANUP_INTERVAL", time.Minute),
		IdleTTL:          getDuration("RATE_LIMIT_IDLE_TTL", 5*time.Minute),
		TrustedProxies:   getStr("RATE_LIMIT_TRUSTED_PROXIES", ""),
		Backend:          strings.ToLower(getStr("RATE_LIMIT_BACKEND", "memory")),
		RedisKeyPrefix:   getStr("RATE_LIMIT_REDIS_KEY_PREFIX", "sn360-es:rl"),
		RedisTTL:         getDuration("RATE_LIMIT_REDIS_TTL", 10*time.Minute),
		RedisTimeout:     getDuration("RATE_LIMIT_REDIS_TIMEOUT", 200*time.Millisecond),
		FailureMode:      strings.ToLower(getStr("RATE_LIMIT_FAILURE_MODE", "open")),
		FallbackToMemory: getBool("RATE_LIMIT_FALLBACK_TO_MEMORY", true),
	}
}
