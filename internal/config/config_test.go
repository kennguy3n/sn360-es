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
