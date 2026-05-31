package config

import (
	"errors"
	"fmt"
	"math"
	"strings"
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
	if c.Score.Blocked <= c.Score.HighRisk ||
		c.Score.HighRisk <= c.Score.Warning ||
		c.Score.Warning <= c.Score.Caution ||
		c.Score.Caution <= c.Score.Info {
		return errors.New("SCORE_*_THRESHOLD must be strictly decreasing: blocked > high > warning > caution > info")
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
