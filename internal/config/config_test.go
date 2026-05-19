package config

import (
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
