package config

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// TestLoad_RedisFetchBatchSize_DefaultsTo10 verifies the Redis event-bus
// FetchBatchSize is sourced from REDIS_FETCH_BATCH_SIZE (not from the
// NATS counterpart) and defaults to 10 — the documented default of
// the redis bus implementation. This guards against the pre-existing
// copy-paste bug where cmd/sn360-es/main.go wired the Redis Config's
// FetchBatchSize off cfg.NATS.FetchBatchSize, which silently inherited
// the NATS env var and defaulted to 50 on the Redis backend.
func TestLoad_RedisFetchBatchSize_DefaultsTo10(t *testing.T) {
	withEnv(t, map[string]string{
		"APP_NAME":    "sn360-es-test",
		"ENVIRONMENT": "local",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Redis.FetchBatchSize != 10 {
		t.Fatalf("Redis.FetchBatchSize default = %d, want 10",
			cfg.Redis.FetchBatchSize)
	}
}

// TestLoad_RedisFetchBatchSize_ReadsRedisEnv verifies that
// REDIS_FETCH_BATCH_SIZE drives cfg.Redis.FetchBatchSize and that it
// is NOT cross-contaminated by NATS_FETCH_BATCH_SIZE. The latter must
// continue to drive only cfg.NATS.FetchBatchSize.
func TestLoad_RedisFetchBatchSize_ReadsRedisEnv(t *testing.T) {
	withEnv(t, map[string]string{
		"APP_NAME":               "sn360-es-test",
		"ENVIRONMENT":            "local",
		"REDIS_FETCH_BATCH_SIZE": "37",
		"NATS_FETCH_BATCH_SIZE":  "123",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Redis.FetchBatchSize != 37 {
		t.Fatalf("Redis.FetchBatchSize = %d, want 37 (from REDIS_FETCH_BATCH_SIZE)",
			cfg.Redis.FetchBatchSize)
	}
	if cfg.NATS.FetchBatchSize != 123 {
		t.Fatalf("NATS.FetchBatchSize = %d, want 123 (from NATS_FETCH_BATCH_SIZE)",
			cfg.NATS.FetchBatchSize)
	}
}

// TestLoad_RedisFetchBatchSize_IndependentOfNATS pins the independence
// invariant: setting only NATS_FETCH_BATCH_SIZE must NOT change the
// Redis backend's batch size. Before the fix this assertion would
// have failed because main.go sourced Redis from cfg.NATS.
func TestLoad_RedisFetchBatchSize_IndependentOfNATS(t *testing.T) {
	withEnv(t, map[string]string{
		"APP_NAME":              "sn360-es-test",
		"ENVIRONMENT":           "local",
		"NATS_FETCH_BATCH_SIZE": "999",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Redis.FetchBatchSize != 10 {
		t.Fatalf("Redis.FetchBatchSize = %d, want 10 (unaffected by NATS_FETCH_BATCH_SIZE)",
			cfg.Redis.FetchBatchSize)
	}
}

// withEnv sets each key in m via t.Setenv (which auto-restores on
// test cleanup) and clears any env var the test relies on being
// unset. It also unsets REDIS_FETCH_BATCH_SIZE / NATS_FETCH_BATCH_SIZE
// up front so default-path tests aren't contaminated by the host
// environment.
func withEnv(t *testing.T, m map[string]string) {
	t.Helper()
	for _, k := range []string{"REDIS_FETCH_BATCH_SIZE", "NATS_FETCH_BATCH_SIZE"} {
		if _, ok := m[k]; !ok {
			t.Setenv(k, "")
		}
	}
	for k, v := range m {
		t.Setenv(k, v)
	}
}

// validProdConfig returns a Config that passes validation in a
// production-like environment.
func validProdConfig() Config {
	return Config{
		Environment: EnvironmentProd,
		AppName:     "sn360-es",
		EventBus:    EventBusNATS,
		HTTP:        HTTP{Port: 8080},
		Score:       ScoreThresholds{Blocked: 90, HighRisk: 70, Warning: 50, Caution: 30, Info: 10},
	}
}

func TestValidate_KMSUseMockBlockedInProd(t *testing.T) {
	cfg := validProdConfig()
	cfg.AWS.KMSUseMock = true
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for KMS_USE_MOCK=true in prod")
	}
}

func TestValidate_KMSUseMockAllowedInDev(t *testing.T) {
	cfg := validProdConfig()
	cfg.Environment = EnvironmentDev
	cfg.AWS.KMSUseMock = true
	if err := cfg.validate(); err != nil {
		t.Fatalf("KMS_USE_MOCK should be allowed in dev: %v", err)
	}
}

func TestValidate_KMSUseMockAllowedInQA(t *testing.T) {
	cfg := validProdConfig()
	cfg.Environment = EnvironmentQA
	cfg.AWS.KMSUseMock = true
	if err := cfg.validate(); err != nil {
		t.Fatalf("KMS_USE_MOCK should be allowed in QA: %v", err)
	}
}

func TestValidate_BannerTokenSecretTooShortInProd(t *testing.T) {
	cfg := validProdConfig()
	cfg.Banner.TokenSecret = "short"
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for short BANNER_TOKEN_SECRET in prod")
	}
}

func TestValidate_BannerTokenSecretDefaultPlaceholderInProd(t *testing.T) {
	cfg := validProdConfig()
	cfg.Banner.TokenSecret = "replace-me-with-a-strong-secret"
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for default placeholder BANNER_TOKEN_SECRET in prod")
	}
}

func TestValidate_BannerTokenSecretGoodInProd(t *testing.T) {
	cfg := validProdConfig()
	cfg.Banner.TokenSecret = "this-is-a-sufficiently-long-secret-for-production-use"
	if err := cfg.validate(); err != nil {
		t.Fatalf("valid BANNER_TOKEN_SECRET should pass: %v", err)
	}
}

func TestValidate_BannerTokenSecretEmptyAllowedInProd(t *testing.T) {
	cfg := validProdConfig()
	cfg.Banner.TokenSecret = ""
	if err := cfg.validate(); err != nil {
		t.Fatalf("empty BANNER_TOKEN_SECRET should be allowed (banners just suppress CTAs): %v", err)
	}
}

func TestValidate_BannerTokenSecretLowEntropyRejected(t *testing.T) {
	cases := map[string]string{
		"all-same":            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sequential":          "abcdefghijklmnopqrstuvwxyzABCDEF",
		"two-byte-repeat":     "ababababababababababababababababab",
		"eight-byte-repeat":   "passwordpasswordpasswordpassword",
		"sixteen-byte-repeat": "abcdefghijklmnopabcdefghijklmnop",
	}
	for name, secret := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validProdConfig()
			cfg.Banner.TokenSecret = secret
			if err := cfg.validate(); err == nil {
				t.Fatalf("expected low-entropy secret %q (%d bytes) to be rejected", secret, len(secret))
			}
		})
	}
}

func TestValidate_BannerTokenSecretHighEntropyAccepted(t *testing.T) {
	// Real openssl-rand-style output: not all-same, not sequential,
	// not a short repeat. Must pass.
	cfg := validProdConfig()
	cfg.Banner.TokenSecret = "Z9p/+kK4mQwT2cVbN7sA1yLrXgEoUjF6"
	if err := cfg.validate(); err != nil {
		t.Fatalf("high-entropy BANNER_TOKEN_SECRET rejected: %v", err)
	}
}

func TestValidate_OnboardingStateSecretLowEntropyRejected(t *testing.T) {
	cfg := validProdConfig()
	cfg.Onboarding.StateSecret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := cfg.validate(); err == nil {
		t.Fatal("expected low-entropy ONBOARDING_STATE_SECRET to be rejected in prod")
	}
}

func TestIsLowEntropy(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"single-char-allsame", "aaaaaa", true},
		{"sequential-letters", "abcdefghij", true},
		{"sequential-digits", "0123456789", true},
		{"two-byte-period", "abababab", true},
		{"four-byte-period", "abcdabcd", true},
		// "abcabcabcab" — 3 distinct chars over 11 bytes —
		// Shannon ≈ 1.58 bits/byte, well below the 3.0 threshold.
		// The function is intentionally aggressive on tiny alphabets
		// because real openssl-rand secrets have ≥ 30+ distinct bytes.
		{"non-divisor-period-low-alphabet", "abcabcabcab", true},
		{"real-random-base64", "Z9p/+kK4mQwT2cVbN7sA1yLrXgEoUjF6", false},
		// Below 16 bytes the function will sometimes fire on benign
		// short strings; that's fine because production validation
		// only invokes it on secrets ≥ 32 bytes. We still pin the
		// behaviour so future refactors don't regress it.
		{"three-char-sequential", "xyz", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLowEntropy(tc.in); got != tc.want {
				t.Fatalf("isLowEntropy(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestIsLowEntropy_RealisticSecretsNeverFalsePositive is a property
// test that drives isLowEntropy with the four secret encodings ken
// would actually generate at the command line — UUID hex, base32,
// base58, and base64 — at the two lengths production validation
// actually uses (the 16-byte ONBOARDING_STATE_SECRET gate at config.go
// validate() and the 32-byte BANNER_TOKEN_SECRET gate). The function
// must classify each generated value as high-entropy, otherwise a
// legitimate `openssl rand -base64 32` output would prevent the
// binary from booting in production.
//
// The pool size (1000 samples per shape) catches statistical edge
// cases — periodic accidents, monotone-run accidents — that a
// hand-picked test table would miss. Failures fail the test with the
// offending sample so the regression is reproducible by inspection.
func TestIsLowEntropy_RealisticSecretsNeverFalsePositive(t *testing.T) {
	t.Parallel()

	// Realistic v4 UUIDs without hyphens — what `uuidgen | tr -d '-'`
	// produces and what services occasionally use as state secrets.
	// 32 hex chars = 16 bytes of randomness, encoded as 16 distinct
	// nibble characters.
	t.Run("uuid-hex-32", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			raw := make([]byte, 16)
			if _, err := rand.Read(raw); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			// Stamp v4 / variant bits so generated values look
			// like real UUIDs (does not affect entropy).
			raw[6] = (raw[6] & 0x0f) | 0x40
			raw[8] = (raw[8] & 0x3f) | 0x80
			s := hex.EncodeToString(raw)
			if isLowEntropy(s) {
				t.Fatalf("uuid-hex sample %d=%q false-positive (Shannon should be ~4 bits/byte over 16 distinct symbols)", i, s)
			}
		}
	})

	// 32 random bytes encoded as 64 hex chars — what
	// `openssl rand -hex 32` emits. Same alphabet as UUID hex but
	// double the length, so a property accident at length 32 still
	// has another 1000 trials at length 64.
	t.Run("hex-64", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			s := hex.EncodeToString(raw)
			if isLowEntropy(s) {
				t.Fatalf("hex-64 sample %d=%q false-positive", i, s)
			}
		}
	})

	// 32 random bytes encoded as base32 (no padding) — used by some
	// configuration tools and by `openssl rand -base32`. Alphabet
	// of 32 distinct chars, Shannon ≈ 5 bits/byte.
	t.Run("base32-32bytes", func(t *testing.T) {
		enc := base32.StdEncoding.WithPadding(base32.NoPadding)
		for i := 0; i < 1000; i++ {
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			s := enc.EncodeToString(raw)
			if isLowEntropy(s) {
				t.Fatalf("base32 sample %d=%q false-positive (len=%d)", i, s, len(s))
			}
		}
	})

	// Base58 (Bitcoin alphabet, no 0/O/I/l) — what some k8s secret
	// generators emit. Alphabet of 58 distinct chars, Shannon ≈
	// 5.86 bits/byte.
	t.Run("base58-32bytes", func(t *testing.T) {
		const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
		for i := 0; i < 1000; i++ {
			// Sample one character per output byte directly
			// from crypto/rand using rejection sampling so the
			// alphabet stays uniform. This sidesteps the
			// big-int divisions of a real base58 encoder while
			// producing the same character distribution.
			out := make([]byte, 44) // ≈ 32 bytes of base58 worth of payload
			for j := range out {
				out[j] = uniformByte(t, alphabet)
			}
			s := string(out)
			if isLowEntropy(s) {
				t.Fatalf("base58 sample %d=%q false-positive", i, s)
			}
		}
	})

	// 32 random bytes encoded as raw base64 (no padding) — what
	// `openssl rand -base64 32` produces after stripping the
	// trailing '=='. Alphabet of 64 distinct chars, Shannon ≈
	// 6 bits/byte.
	t.Run("base64-32bytes", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			s := base64.RawStdEncoding.EncodeToString(raw)
			if isLowEntropy(s) {
				t.Fatalf("base64-32 sample %d=%q false-positive", i, s)
			}
		}
	})

	// 64 random bytes encoded as base64 — what the wider
	// JWT-friendly env vars use. Higher entropy budget; failure here
	// would indicate a structural bug in isLowEntropy because the
	// signal-to-noise of 64 base64 chars is overwhelming.
	t.Run("base64-64bytes", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			raw := make([]byte, 64)
			if _, err := rand.Read(raw); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			s := base64.RawStdEncoding.EncodeToString(raw)
			if isLowEntropy(s) {
				t.Fatalf("base64-64 sample %d=%q false-positive", i, s)
			}
		}
	})
}

// uniformByte returns a single character from alphabet using
// rejection sampling on crypto/rand, so the resulting distribution is
// uniform across alphabet regardless of |alphabet|. Used for
// alphabet-based property generation (e.g. base58) where we want the
// natural character distribution rather than a constructed encoder.
func uniformByte(t *testing.T, alphabet string) byte {
	t.Helper()
	n := uint16(len(alphabet))
	// Largest multiple of n that fits in a byte; reject the
	// remainder so each draw stays uniform. The arithmetic is done
	// in uint16 to keep 256 representable.
	cutoff := uint16(256) - (uint16(256) % n)
	for {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		if uint16(b[0]) < cutoff {
			return alphabet[uint16(b[0])%n]
		}
	}
}

// TestIsLowEntropy_CryptoRandomBytesAreHighEntropy is the most
// general property the function must satisfy: any 32 random bytes
// converted to a printable hex string (the cheapest realistic
// representation we can both generate and feed back through the
// validator) must look high-entropy. This 1000-trial run is what the
// reviewer asked for under M4.
func TestIsLowEntropy_CryptoRandomBytesAreHighEntropy(t *testing.T) {
	t.Parallel()
	for i := 0; i < 1000; i++ {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		s := hex.EncodeToString(raw)
		if isLowEntropy(s) {
			t.Fatalf("crypto-random 32-byte secret sample %d=%q false-positive — production gate would refuse a legitimate openssl-rand secret", i, s)
		}
	}
}

// TestIsLowEntropy_CatchesKnownWeakInputs guards the other side of
// the contract: the function must still trip on the structural-weak
// inputs it was designed for. The cases below are constructed
// (rather than randomised) because they are the patterns operators
// type by hand when they don't realise the secret matters.
//
// All cases here either (a) fail the Shannon ≥ 3.0 floor, (b) contain
// a monotone run ≥ ceil(len/2), or (c) tile the string with a period
// that divides len exactly. These are the three structural shapes
// isLowEntropy is documented to catch. Borderline inputs (e.g. a
// non-tiling periodic-looking string whose period does not divide
// the length) are explicitly outside scope — the production gate
// invokes isLowEntropy alongside a min-length check, and operators
// who manage to type a 32-byte secret whose only weakness is a
// 10-character cycle that doesn't tile have crossed enough other
// guardrails that we don't need to block them here.
func TestIsLowEntropy_CatchesKnownWeakInputs(t *testing.T) {
	t.Parallel()
	weak := []string{
		strings.Repeat("a", 32),                  // Shannon = 0
		strings.Repeat("a", 64),                  // Shannon = 0
		"abcdefghijklmnopqrstuvwxyz012345",       // monotone run ≥ 26
		strings.Repeat("ab", 32),                 // period 2 tiles len 64
		strings.Repeat("abcd", 16),               // period 4 tiles len 64
		strings.Repeat("password", 4),            // period 8 tiles len 32
		fmt.Sprintf("%s%s", strings.Repeat("01234567", 4), ""), // period 8 tiles len 32
	}
	for i, s := range weak {
		if !isLowEntropy(s) {
			t.Fatalf("weak input %d=%q passed isLowEntropy", i, s)
		}
	}
}
