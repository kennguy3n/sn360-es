package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/pkg/inference/slm"
)

// silentLogger discards output so test runs do not litter stderr with
// the warn/info lines buildTier2Client emits on the success path.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestBuildTier2Client_DefaultProvider asserts that a vanilla
// AI_URL deployment (no per-tenant override, default provider name)
// gets a working ternarybonsai-backed client that round-trips a
// verdict through the production wire format.
func TestBuildTier2Client_DefaultProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("path = %q, want /v1/chat/completions", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": `{"score": 65, "confidence": 0.7}`}},
			},
		})
	}))
	defer srv.Close()

	app := &application{}
	cfg := &config.Config{AI: config.AI{
		URL:      srv.URL,
		Provider: "ternarybonsai",
		Timeout:  2 * time.Second,
	}}
	c := buildTier2Client(app, cfg, silentLogger())
	if c == nil {
		t.Fatal("buildTier2Client returned nil")
	}
	out, err := c.Evaluate(context.Background(), dto.EvaluateRequest{TenantID: "t-1"}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Score != 65 {
		t.Errorf("Score = %d, want 65", out.Score)
	}
}

// TestBuildTier2Client_DisabledWhenAIURLEmpty asserts the back-compat
// "tier 2 disabled" path: no AI_URL means buildTier2Client returns nil
// and the evaluator skips Tier 2 escalation.
func TestBuildTier2Client_DisabledWhenAIURLEmpty(t *testing.T) {
	app := &application{}
	cfg := &config.Config{AI: config.AI{URL: ""}}
	if c := buildTier2Client(app, cfg, silentLogger()); c != nil {
		t.Errorf("buildTier2Client = %v, want nil when AI.URL is empty", c)
	}
}

// TestBuildTier2Client_UnknownProviderReturnsNil asserts a typo in
// TIER2_PROVIDER does not crash the boot — buildTier2Client logs a
// warn and returns nil so the evaluator runs without Tier 2 instead
// of panicking. This is the documented graceful-degradation contract.
func TestBuildTier2Client_UnknownProviderReturnsNil(t *testing.T) {
	app := &application{}
	cfg := &config.Config{AI: config.AI{URL: "http://stub", Provider: "definitely-not-a-real-provider"}}
	if c := buildTier2Client(app, cfg, silentLogger()); c != nil {
		t.Errorf("buildTier2Client = %v, want nil when provider is unknown", c)
	}
}

// TestBuildTier2Client_NamedProvider exercises the llamaserver
// factory to prove that TIER2_PROVIDER=llamaserver flows through
// slm.New to the correct adapter (response model gets path-trimmed,
// which is the llamaserver-specific quirk we test here).
func TestBuildTier2Client_NamedProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "/models/llama-3-8b-instruct.Q4_K_M.gguf",
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": `{"score": 22}`}},
			},
		})
	}))
	defer srv.Close()

	app := &application{}
	cfg := &config.Config{AI: config.AI{
		URL:      srv.URL,
		Provider: "llamaserver",
		Timeout:  2 * time.Second,
	}}
	c := buildTier2Client(app, cfg, silentLogger())
	if c == nil {
		t.Fatal("buildTier2Client returned nil")
	}
	out, err := c.Evaluate(context.Background(), dto.EvaluateRequest{TenantID: "t-1"}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.ModelName != "llama-3-8b-instruct.Q4_K_M" {
		t.Errorf("ModelName = %q, want path-trimmed llama-3-8b-instruct.Q4_K_M", out.ModelName)
	}
}

// TestBuildTier2Client_PerTenantOverride exercises the slm.Router
// path. The default deployment provider is ternarybonsai (URL =
// defaultSrv), but the fakeProviderLoader returns "openai" for
// tenant T-OVERRIDE, which should route the request to overrideSrv
// instead. Tenants without an override stay on the default.
func TestBuildTier2Client_PerTenantOverride(t *testing.T) {
	defaultSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": `{"score": 11, "confidence": 0.3}`}},
			},
		})
	}))
	defer defaultSrv.Close()

	// The router reuses the same connection config for overrides —
	// see buildDefaultTier2ProviderConfig — so both factories hit
	// defaultSrv. The override is the provider NAME (and therefore
	// the adapter's parsing quirks), not the URL.
	repo := newFakeScoreEngineRepo()
	overrideName := "openai"
	repo.rows["T-OVERRIDE"] = repository.ScoreEngine{TenantID: "T-OVERRIDE", Tier2Provider: &overrideName}
	app := &application{
		tenantScoringConfig: newTenantScoringConfigAdapter(repo, 0),
	}
	cfg := &config.Config{AI: config.AI{
		URL:      defaultSrv.URL,
		Provider: "ternarybonsai",
		Timeout:  2 * time.Second,
	}}
	c := buildTier2Client(app, cfg, silentLogger())
	if c == nil {
		t.Fatal("buildTier2Client returned nil")
	}
	router, ok := c.(*slm.Router)
	if !ok {
		t.Fatalf("buildTier2Client returned %T, want *slm.Router", c)
	}
	if router.Default() == nil {
		t.Fatal("router.Default() = nil, want non-nil default")
	}

	if _, err := router.Evaluate(context.Background(), dto.EvaluateRequest{TenantID: "T-DEFAULT"}, dto.Tier1Outcome{}); err != nil {
		t.Fatalf("Evaluate (default tenant): %v", err)
	}
	if _, err := router.Evaluate(context.Background(), dto.EvaluateRequest{TenantID: "T-OVERRIDE"}, dto.Tier1Outcome{}); err != nil {
		t.Fatalf("Evaluate (override tenant): %v", err)
	}
}

// Compile-time guard so a future refactor of tenantScoringConfigAdapter
// cannot silently break the slm.Router contract this file exercises.
var _ slm.TenantProviderLoader = (*tenantScoringConfigAdapter)(nil)
