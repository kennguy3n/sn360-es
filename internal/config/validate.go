package config

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/bridge"
)

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
	if !c.Role.Valid() {
		return fmt.Errorf("SN360_ROLE: invalid value %q (expected one of: all, api, consumers, workers)", c.Role)
	}
	if c.HTTP.Port <= 0 || c.HTTP.Port > 65535 {
		return fmt.Errorf("HTTP_PORT out of range: %d", c.HTTP.Port)
	}
	// INTERNAL_HTTP_PORT is opt-in: 0 disables the internal listener.
	// When set it must be a valid port and must not collide with the
	// public HTTP_PORT, so a misconfiguration surfaces at boot with a
	// clear message rather than as an opaque bind failure later.
	if c.HTTP.InternalPort != 0 {
		if c.HTTP.InternalPort < 0 || c.HTTP.InternalPort > 65535 {
			return fmt.Errorf("INTERNAL_HTTP_PORT out of range: %d", c.HTTP.InternalPort)
		}
		if c.HTTP.InternalPort == c.HTTP.Port {
			return fmt.Errorf("INTERNAL_HTTP_PORT (%d) must differ from HTTP_PORT (%d)", c.HTTP.InternalPort, c.HTTP.Port)
		}
	}
	// RATE_LIMIT_BACKEND / RATE_LIMIT_FAILURE_MODE accept a closed
	// set of values. A typo (e.g. "memry", "Closd") would silently
	// fall through to the default code path and produce
	// counter-intuitive behaviour at runtime — fail fast at boot
	// instead. Empty values are permitted because Load() injects
	// the documented defaults.
	switch c.RateLimit.Backend {
	case "", "memory", "redis":
		// ok
	default:
		return fmt.Errorf("RATE_LIMIT_BACKEND: invalid value %q (expected one of: memory, redis)", c.RateLimit.Backend)
	}
	switch c.RateLimit.FailureMode {
	case "", "open", "closed":
		// ok
	default:
		return fmt.Errorf("RATE_LIMIT_FAILURE_MODE: invalid value %q (expected one of: open, closed)", c.RateLimit.FailureMode)
	}
	if c.RateLimit.Backend == "redis" && c.RateLimit.RedisKeyPrefix == "" {
		return errors.New("RATE_LIMIT_REDIS_KEY_PREFIX must not be empty when RATE_LIMIT_BACKEND=redis (a stable, deployment-scoped prefix prevents two services on the same Redis from colliding on the same client key)")
	}
	// INGESTION_MODE must be one of the documented values. Without
	// this check, a typo (e.g. "polll", "Push") silently falls
	// through both PollEnabled() and PushEnabled(), leaving the
	// service running but ingesting nothing — exactly the kind of
	// failure that's invisible until a downstream queue stays empty.
	switch c.Ingestion.Mode {
	case "", "poll", "push", "hybrid":
		// ok
	default:
		return fmt.Errorf("INGESTION_MODE: invalid value %q (expected one of: poll, push, hybrid, or empty)", c.Ingestion.Mode)
	}
	// DIRECTORY_SYNC_SOURCE selects the directory-sync user roster
	// source. A typo (e.g. "iamcore", "Native") must fail fast at
	// boot rather than silently fall back to the native provider and
	// leave an operator believing iam-core is the source of truth.
	// Empty is accepted and treated as native — Load() injects the
	// default, but a directly-constructed Config (tests, embedders)
	// leaves it zero-valued.
	switch c.DirectorySyncSource {
	case "", DirectorySourceNative, DirectorySourceIAMCore:
		// ok
	default:
		return fmt.Errorf("DIRECTORY_SYNC_SOURCE: invalid value %q (expected one of: native, iam-core)", c.DirectorySyncSource)
	}
	// When the directory-sync source is iam-core the Management API
	// must be reachable. Fail fast at boot so the worker never starts
	// a sync that would immediately error on a missing base URL or an
	// unauthenticated Management API call.
	if c.DirectorySyncSource == DirectorySourceIAMCore {
		if c.IAMCore.ManagementURL == "" {
			return errors.New("IAM_CORE_MANAGEMENT_URL must be set when DIRECTORY_SYNC_SOURCE=iam-core")
		}
		if c.IAMCore.ManagementToken == "" {
			return errors.New("IAM_CORE_MANAGEMENT_TOKEN must be set when DIRECTORY_SYNC_SOURCE=iam-core (Management API requires a bearer token with the read:users scope)")
		}
	}
	// Dual-issuer JWT validation is opt-in via IAM_CORE_JWKS_URL.
	// When it is set, the expected `iss` claim must also be set or
	// the middleware cannot pin tokens to iam-core — accepting any
	// issuer would be an authentication bypass.
	if c.IAMCore.JWKSEndpoint != "" && c.IAMCore.Issuer == "" {
		return errors.New("IAM_CORE_ISSUER must be set when IAM_CORE_JWKS_URL is configured (the middleware pins the iam-core `iss` claim)")
	}
	if c.Score.Blocked <= c.Score.HighRisk ||
		c.Score.HighRisk <= c.Score.Warning ||
		c.Score.Warning <= c.Score.Caution ||
		c.Score.Caution <= c.Score.Info {
		return errors.New("SCORE_*_THRESHOLD must be strictly decreasing: blocked > high > warning > caution > info")
	}
	// WS-7a multi-region routing: every multi-region deployment must
	// carry a PG_REGION_MAP entry for its home region so the primary
	// PG_HOST pool maps cleanly into the regional router. Without
	// this check, a tenant whose `tenants.region` equals
	// PG_HOME_REGION would have no pool to bind to and every request
	// for that tenant would fail closed at the middleware boundary —
	// a fail-fast at boot is more useful than fail-closed-at-runtime
	// because the operator catches the misconfig before any traffic
	// arrives. Empty / nil RegionMap (single-region default) leaves
	// the guard a no-op.
	if len(c.Postgres.RegionMap) > 0 {
		if c.Postgres.HomeRegion == "" {
			return errors.New("PG_HOME_REGION must be set when PG_REGION_MAP is configured (it names which region the primary PG_HOST pool serves)")
		}
		homePG, ok := c.Postgres.RegionMap[c.Postgres.HomeRegion]
		if !ok {
			return fmt.Errorf("PG_REGION_MAP must contain an entry for PG_HOME_REGION=%q; got regions %v", c.Postgres.HomeRegion, sortedRegionKeys(c.Postgres.RegionMap))
		}
		// WS-7a: the primary pool (PG_HOST/PG_PORT/PG_DATABASE)
		// doubles as the home-region pool —
		// docs/MULTI_REGION.md:54-58 documents the
		// contract, but without a code-level check an operator
		// who pointed the home entry at a different host or
		// database would silently get a single pool to the
		// primary PG_HOST/PG_DATABASE while the home entry's URL
		// was parsed-and-validated-but-never-dialled. Fail boot
		// if the home entry's (host, port, database) tuple does
		// not match (PG_HOST, PG_PORT, PG_DATABASE). User and
		// password are intentionally not compared — operators
		// commonly omit credentials from DSN strings and supply
		// them via PG_USER/PG_PASSWORD env vars instead, so a
		// user mismatch is ambiguous; a database mismatch is
		// always a misconfig because the primary pool's database
		// is what the home region actually serves.
		if homePG.Host != c.Postgres.Host || homePG.Port != c.Postgres.Port || homePG.Database != c.Postgres.Database {
			return fmt.Errorf("PG_REGION_MAP[%s] points at %s:%d/%s but PG_HOST/PG_PORT/PG_DATABASE is %s:%d/%s — the home-region entry must reach the same Postgres as the primary pool (see docs/MULTI_REGION.md)",
				c.Postgres.HomeRegion, homePG.Host, homePG.Port, homePG.Database, c.Postgres.Host, c.Postgres.Port, c.Postgres.Database)
		}
	}
	// WS-7a: NATS super-cluster mirrors the PG_REGION_MAP guard
	// above. The NATS client's home-region check in
	// pkg/events/nats/supercluster.go:resolveSuperclusterServers
	// also fails at boot, but centralising the check in validate()
	// catches the misconfig before bus.New attempts any
	// infrastructure connection — the operator's error experience
	// is consistent between PG and NATS supercluster misconfig.
	// NATS HomeRegion is sourced from Postgres.HomeRegion at
	// wiring time (cmd/sn360-es/wire_infra.go:103), so the same
	// home-region label drives both validators.
	if len(c.NATS.Supercluster) > 0 {
		if c.Postgres.HomeRegion == "" {
			return errors.New("PG_HOME_REGION must be set when NATS_SUPERCLUSTER is configured (the home-region label is shared across PG and NATS super-cluster routing)")
		}
		if _, ok := c.NATS.Supercluster[c.Postgres.HomeRegion]; !ok {
			return fmt.Errorf("NATS_SUPERCLUSTER must contain an entry for PG_HOME_REGION=%q; got regions %v", c.Postgres.HomeRegion, sortedRegionKeys(c.NATS.Supercluster))
		}
	}
	// TIER1_SUPPRESS_PARTNER is the (typically negative) offset
	// applied to Tier1 PassBelow / FlagAbove for Partner / Customer
	// senders. .env.example documents the contract as "Must be <= 0"
	// — a positive value would RAISE both thresholds (the opposite
	// of the documented tightening intent) and make Partner /
	// Customer senders MORE likely to pass without escalation.
	// tier1.Thresholds.AdjustForRelationship has floor guards on
	// PassBelow >= 0 / FlagAbove >= PassBelow+1 but no ceiling
	// guard, so without this validate() check an operator typo (e.g.
	// "10" instead of "-10") boots cleanly and silently undermines
	// platform-wide relationship-aware scoring. Fail-fast at config
	// load so the misconfiguration surfaces during deploy rather
	// than as a stream of unexpectedly-passed Tier 1 verdicts.
	if c.Tier1.SuppressPartner > 0 {
		return fmt.Errorf("TIER1_SUPPRESS_PARTNER must be <= 0; got %d (positive values would raise Partner/Customer thresholds, the opposite of the documented tightening intent)", c.Tier1.SuppressPartner)
	}
	if c.Onboarding.StateSecret != "" && len(c.Onboarding.StateSecret) < 16 {
		return errors.New("ONBOARDING_STATE_SECRET must be at least 16 bytes when set")
	}
	// INGESTION_PUSH_MICROSOFT_CLIENT_STATE_SECRET is the HMAC key
	// used to derive per-tenant Microsoft Graph clientState values.
	// Enforce a minimum length across ALL environments (not just
	// production) because a tiny key is just as easy to brute-force
	// in dev/staging — and a leaked dev clientState scheme is the
	// kind of thing that quietly migrates into a production .env.
	// 16 bytes ≥ matches Onboarding.StateSecret's floor (same
	// HMAC-based threat model). Production gets an additional 32-byte
	// floor + low-entropy check below to align with BANNER_TOKEN_SECRET.
	if c.Ingestion.PushMicrosoftClientStateSecret != "" && len(c.Ingestion.PushMicrosoftClientStateSecret) < 16 {
		return errors.New("INGESTION_PUSH_MICROSOFT_CLIENT_STATE_SECRET must be at least 16 bytes when set")
	}
	// FU-A: WS-5A.1 bridge — reject the zero-value MaxReconnects
	// ambiguity ANY time the bridge is enabled. Go's int zero-value
	// semantics make it impossible to distinguish "unset" from
	// "explicit 0" at the config layer, so bridge.Config.withDefaults()
	// maps 0 to -1 ("retry forever") — the SAFER default for
	// fire-and-forget SOC publishing, but the OPPOSITE of what an
	// operator expects when they explicitly set
	// PLATFORM_NATS_MAX_RECONNECTS=0 intending "no reconnect". The
	// NATS Go client itself treats every MaxReconnects < 0 as infinite
	// (nats-io/nats.go conn.go: the reconnect loop only breaks when
	// MaxReconnects >= 0 && i >= MaxReconnects), so there is NO numeric
	// value that means "give up after the first disconnect" — and
	// there should not be, because silently dropping every SOC event
	// after a transient network blip is never an operationally-sensible
	// posture for a security event bridge. Refusing 0 at boot forces
	// the operator to make an explicit, documented choice: a positive
	// N for N retries, or -1 for infinite. Surfaces the latent footgun
	// from PR #56 finding #3.
	//
	// All bridge-related env validations below are gated behind
	// NATSEnabled so a stand-alone sn360-es deployment that never
	// publishes to the platform stream isn't punished for having
	// zero-valued bridge fields it doesn't use.
	if c.Platform.NATSEnabled {
		if c.Platform.NATSMaxReconnects == 0 {
			return errors.New("PLATFORM_NATS_MAX_RECONNECTS=0 is ambiguous and not allowed when PLATFORM_NATS_ENABLED=true: Go's int zero-value cannot be distinguished from \"unset\", and the NATS Go client has no value that means \"no reconnect\" — use -1 for infinite retries (default), or a positive N for N attempts; if you genuinely want the bridge to stop forwarding on the first disconnect, contact platform-eng (no operational reason currently exists)")
		}
		// FU-A: enforce the dedup-budget invariant. The platform-side
		// `sn360-events` JetStream stream de-duplicates by the
		// deterministic MsgID `<tenant>:<msgID>:<subject>` we set on
		// every publish (see
		// internal/service/bridge/platform_publisher.go dedupID()),
		// but only within its configured `duplicate_window_seconds`
		// (FU-B platform-side config — 600s on sn360-events). If THIS
		// bridge's own per-call retry budget
		// (PublishTimeout × PublishRetries) outlasts the platform dedup
		// window, a late-succeeding retry from an earlier NATS
		// redelivery would land AFTER the platform forgot the original
		// MsgID and would be accepted as a fresh message — silently
		// producing duplicates downstream in the correlation engine
		// and every alert-forwarder OpenSearch index. Refuse the
		// pathological config at boot. The check fires in every
		// environment (not just prod) because duplicate alerts in
		// dev/staging are still a misleading SOC-correctness regression,
		// and the same .env file usually drives every tier.
		if c.Platform.NATSDedupWindow > 0 {
			// Mirror bridge.Config.withDefaults() exactly by
			// pulling the runtime defaults from the bridge package's
			// exported constants. This eliminates the silent-desync
			// risk that would otherwise exist if the validator's
			// floor and the runtime's floor were two unconnected
			// magic numbers — if either default ever changes, both
			// sites move together.
			retries := c.Platform.NATSPublishRetries
			if retries <= 0 {
				retries = bridge.DefaultPublishRetries
			}
			timeout := c.Platform.NATSPublishTimeout
			if timeout <= 0 {
				timeout = bridge.DefaultPublishTimeout
			}
			budget := timeout * time.Duration(retries)
			if budget > c.Platform.NATSDedupWindow {
				return fmt.Errorf("PLATFORM_NATS_PUBLISH_TIMEOUT (%s) × PLATFORM_NATS_PUBLISH_RETRIES (%d) = %s exceeds PLATFORM_NATS_DEDUP_WINDOW (%s); a late-succeeding retry could land after the platform-side JetStream dedup window expires and be re-accepted as a fresh message, producing silent duplicates in the correlation engine and OpenSearch — either shorten the publish-retry budget or raise the dedup window to match the platform-side sn360-events stream's duplicate_window_seconds", timeout, retries, budget, c.Platform.NATSDedupWindow)
			}
		}
	}
	// B3 + B4: Production-only security validations (UAT + prod).
	if c.Environment.IsProduction() {
		if c.AWS.KMSUseMock {
			return errors.New("KMS_USE_MOCK=true is not allowed in production environments (UAT/prod); current: " + string(c.Environment))
		}
		// With KMS_USE_MOCK=false a real KMS key ARN is the only
		// thing standing between the URL rewriter and a passthrough
		// encryptor that would store URL pre-images in Redis in
		// plaintext. buildURLEncryptor refuses to construct the
		// passthrough in prod, but the caller in app.go logs that
		// error as a warning and continues — disabling URL
		// rewriting and quarantine instead of crashing the
		// process. That is a quiet downgrade, exactly what these
		// production guards exist to prevent. Promote the check
		// here so boot fails fast at config-load with a clear
		// error before any wiring decides to run on without it.
		if strings.TrimSpace(c.AWS.KMSMasterKeyID) == "" {
			return errors.New("AWS_KMS_MASTER_KEY_ID is required in production environments (UAT/prod) when KMS_USE_MOCK=false; passthrough encryptor would store URL pre-images in Redis as plaintext")
		}
		// Transport-security skips never belong in prod. Refusing
		// here at config-load gives operators a hard, immediate
		// signal at boot rather than a silent compromise of the
		// trust chain.
		if c.NATS.TLSInsecure {
			return errors.New("NATS_TLS_INSECURE=true is not allowed in production environments (UAT/prod)")
		}
		// Mirror the NATS_TLS_INSECURE check for the platform
		// bridge connection. PLATFORM_NATS_TLS_INSECURE=true would
		// silently strip transport security on the cross-cluster
		// link that carries every HighRisk+ verdict to the SOC —
		// exactly the kind of integrity-critical channel that must
		// not ship a quiet downgrade.
		if c.Platform.NATSTLSInsecure {
			return errors.New("PLATFORM_NATS_TLS_INSECURE=true is not allowed in production environments (UAT/prod)")
		}
		// WS-5A.1 bridge requires URLs to be set when enabled.
		// Enforce at boot so a misconfigured deploy fails fast
		// instead of silently running with bridge publishes
		// going nowhere.
		if c.Platform.NATSEnabled && strings.TrimSpace(c.Platform.NATSURLs) == "" {
			return errors.New("PLATFORM_NATS_URLS must be set when PLATFORM_NATS_ENABLED=true")
		}
		if c.SMTP.SkipVerify {
			return errors.New("SMTP_SKIP_VERIFY=true is not allowed in production environments (UAT/prod)")
		}
		// PG_SSLMODE=disable would send the Postgres password (and
		// every subsequent row) over an unencrypted TCP connection.
		// Same fail-closed treatment as NATS_TLS_INSECURE /
		// SMTP_SKIP_VERIFY: refuse at boot rather than ship a quiet
		// downgrade. Empty / unset is treated as "library default"
		// (which is "prefer" for lib/pq) and is intentionally not
		// rejected here — the rolling default in load() lands on
		// "require", so only an operator who explicitly sets
		// PG_SSLMODE=disable trips this guard.
		if strings.EqualFold(strings.TrimSpace(c.Postgres.SSLMode), "disable") {
			return errors.New("PG_SSLMODE=disable is not allowed in production environments (UAT/prod); set PG_SSLMODE=require or PG_SSLMODE=verify-full")
		}
		// WS-2a: the read replica carries the same row-level data
		// as the primary, so PG_READ_SSLMODE=disable downgrades
		// the trust chain in exactly the same way as the primary
		// guard above. Only check when an operator has explicitly
		// wired a replica (PG_READ_HOST != "") — when the field
		// is left blank the replica path is not used at all and
		// the guard is moot.
		if c.Postgres.Read.Host != "" &&
			strings.EqualFold(strings.TrimSpace(c.Postgres.Read.SSLMode), "disable") {
			return errors.New("PG_READ_SSLMODE=disable is not allowed in production environments (UAT/prod) when PG_READ_HOST is set; set PG_READ_SSLMODE=require or PG_READ_SSLMODE=verify-full")
		}
		// WS-7a multi-region routing: every regional pool carries
		// the same RLS-scoped data, so a PG_REGION_MAP entry with
		// sslmode=disable downgrades the trust chain identically
		// to the primary guard above. Only kicks in when the
		// operator actually wired a region map; the empty / nil
		// map (single-region default) leaves the loop a no-op.
		// Iterate in lex-sorted key order so the first error an
		// operator sees is stable across boots — matches the
		// deterministic-ordering convention used by the regional
		// pool open loop in cmd/sn360-es/app.go.
		for _, region := range sortedRegionKeys(c.Postgres.RegionMap) {
			pg := c.Postgres.RegionMap[region]
			if strings.EqualFold(strings.TrimSpace(pg.SSLMode), "disable") {
				return fmt.Errorf("PG_REGION_MAP[%s]: sslmode=disable is not allowed in production environments (UAT/prod); set sslmode=require or sslmode=verify-full on the connection URL", region)
			}
		}
		// CORS_ALLOWED_ORIGINS=* (wildcard) defeats browser SOP for
		// every authenticated route. middleware/cors.go already
		// fails closed by defaulting to no origins in non-dev, but
		// an operator who explicitly sets the wildcard in their
		// production .env would otherwise sail past that guard.
		// Catch it at config-load.
		for _, o := range c.CORS.AllowedOrigins {
			if strings.TrimSpace(o) == "*" {
				return errors.New("CORS_ALLOWED_ORIGINS=* (wildcard) is not allowed in production environments (UAT/prod); specify explicit origin(s)")
			}
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
		// Microsoft Graph clientState is delivered to providers via
		// the subscription-create payload (not over wire to clients)
		// but acts as a shared HMAC key — same threat model as
		// BANNER_TOKEN_SECRET. Hold it to the same 32-byte floor and
		// low-entropy check in production environments. The general
		// 16-byte floor above catches the dev/staging case.
		if pcss := c.Ingestion.PushMicrosoftClientStateSecret; pcss != "" {
			if len(pcss) < 32 {
				return errors.New("INGESTION_PUSH_MICROSOFT_CLIENT_STATE_SECRET must be at least 32 bytes in production environments (UAT/prod)")
			}
			if isLowEntropy(pcss) {
				return errors.New("INGESTION_PUSH_MICROSOFT_CLIENT_STATE_SECRET has low entropy (all-same character, sequential bytes, or repeated short pattern); generate one with: openssl rand -base64 48")
			}
		}
		// The internal listener carries the same row-level tenant data
		// as the public plane but skips the public JWT/CORS/rate-limit
		// chain (see cmd/sn360-es/main.go) — its only application-layer
		// defence is the INTERNAL_AUTH_TOKEN shared secret on top of
		// network isolation. Treating that token as optional in prod
		// means a single network-policy slip exposes every tenant's
		// verdicts with no second factor, so when the listener is
		// enabled in UAT/prod the token is mandatory and held to the
		// same low-entropy floor as the other HMAC-keyed secrets above.
		// Dev keeps it optional so a laptop can run the portal BFF
		// without minting a secret.
		if c.HTTP.InternalPort != 0 {
			token := strings.TrimSpace(c.HTTP.InternalAuthToken)
			if token == "" {
				return errors.New("INTERNAL_AUTH_TOKEN is required in production environments (UAT/prod) when INTERNAL_HTTP_PORT is set; the internal listener bypasses the public JWT/CORS/rate-limit chain, so its shared-secret gate must not be left open. Generate one with: openssl rand -base64 48")
			}
			// Same 32-byte floor as the other HMAC-keyed secrets above
			// (BANNER_TOKEN_SECRET, INGESTION_PUSH_MICROSOFT_CLIENT_STATE_SECRET):
			// a short token can be high-entropy yet brute-forceable, and
			// this token is the internal listener's only application-layer
			// defence, so the length floor must match, not just the
			// entropy floor.
			if len(token) < 32 {
				return errors.New("INTERNAL_AUTH_TOKEN must be at least 32 bytes in production environments (UAT/prod); generate one with: openssl rand -base64 48")
			}
			if isLowEntropy(token) {
				return errors.New("INTERNAL_AUTH_TOKEN has low entropy (all-same character, sequential bytes, or repeated short pattern); generate one with: openssl rand -base64 48")
			}
		}
	}
	return nil
}

// cloudMetadataIP is the link-local cloud instance-metadata service
// address (IMDS) used by AWS / GCP / Azure / OpenStack. It is the
// highest-value SSRF target the webhook-sink egress guard blocks, so an
// allow-list entry that re-permits it warrants a loud boot-time warning
// even though adding such a CIDR is a deliberate operator choice.
var cloudMetadataIP = netip.MustParseAddr("169.254.169.254")

// SecurityWarnings returns non-fatal production-posture advisories that
// should be logged loudly at boot but must NOT fail startup. Unlike the
// fail-closed guards in validate(), these cover deliberate operator
// escape hatches that weaken a security control: refusing them outright
// would break legitimate deployments (e.g. shipping verdicts to a
// private SIEM with no public ingress), but an operator who enables
// them in production should see an explicit warning rather than a
// silent downgrade — mirroring the posture validate() applies to
// NATS_TLS_INSECURE / SMTP_SKIP_VERIFY / KMS_USE_MOCK as hard errors.
//
// It is called once at boot (cmd/sn360-es/main.go) and each returned
// string is emitted via logger.Warn. Non-production environments return
// nil: the escape hatches are expected in local/dev/QA/staging.
func (c Config) SecurityWarnings() []string {
	if !c.Environment.IsProduction() {
		return nil
	}
	var warns []string
	// WEBHOOK_EGRESS_ALLOW_PRIVATE=true turns the dial-time SSRF
	// egress guard off entirely; the allow-list is then moot, so emit
	// a single warning rather than one per CIDR.
	if c.WebhookEgress.AllowPrivate {
		return append(warns, "WEBHOOK_EGRESS_ALLOW_PRIVATE=true disables the webhook-sink SSRF egress guard entirely: the dispatcher will POST verdict payloads to any private/loopback/link-local destination a tenant registers, including the 169.254.169.254 cloud-metadata endpoint. Prefer WEBHOOK_EGRESS_ALLOWED_CIDRS to whitelist only the specific internal receiver subnet.")
	}
	// With the guard active, an allow-list entry can still re-open it.
	// Two cases warrant a warning: a default-route prefix that
	// whitelists the entire address space (functionally identical to
	// AllowPrivate=true), and any prefix that re-permits the
	// cloud-metadata endpoint (the canonical SSRF target). A narrow
	// internal subnet — the allow-list's intended use — trips neither.
	for _, p := range c.WebhookEgress.AllowedCIDRs {
		switch {
		case p.Bits() == 0:
			warns = append(warns, fmt.Sprintf("WEBHOOK_EGRESS_ALLOWED_CIDRS contains %s, which covers the entire address space and effectively disables the SSRF egress guard; whitelist only the specific internal receiver subnet instead.", p))
		case p.Contains(cloudMetadataIP):
			warns = append(warns, fmt.Sprintf("WEBHOOK_EGRESS_ALLOWED_CIDRS entry %s re-permits the cloud-metadata endpoint %s, re-opening the primary SSRF target the egress guard exists to block.", p, cloudMetadataIP))
		}
	}
	return warns
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
