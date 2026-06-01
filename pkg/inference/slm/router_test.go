package slm

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// labelledClient lets a test assert which client serviced a request.
type labelledClient struct {
	label string
	calls int32
}

func (c *labelledClient) Evaluate(_ context.Context, _ dto.EvaluateRequest, _ dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	atomic.AddInt32(&c.calls, 1)
	return dto.Tier2Outcome{ModelName: c.label}, nil
}

// stubLoader returns a fixed provider name (or err) for every
// tenant. Counts invocations so tests can assert the cache short-
// circuits subsequent lookups.
type stubLoader struct {
	provider string
	err      error
	calls    int32
}

func (s *stubLoader) LoadTenantTier2Provider(_ context.Context, _ string) (string, error) {
	atomic.AddInt32(&s.calls, 1)
	return s.provider, s.err
}

func TestRouter_NoLoaderUsesDefault(t *testing.T) {
	def := &labelledClient{label: "default"}
	r, err := NewRouter(RouterConfig{Default: def})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	out, err := r.Evaluate(context.Background(), dto.EvaluateRequest{TenantID: "t-1"}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.ModelName != "default" {
		t.Errorf("ModelName = %q, want default", out.ModelName)
	}
}

func TestRouter_LoaderReturnsEmptyFallsToDefault(t *testing.T) {
	def := &labelledClient{label: "default"}
	loader := &stubLoader{provider: ""}
	r, err := NewRouter(RouterConfig{
		Default:       def,
		Loader:        loader,
		ResolveConfig: func(_ string) (ProviderConfig, error) { return ProviderConfig{}, nil },
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := r.Evaluate(context.Background(), dto.EvaluateRequest{TenantID: "t-1"}, dto.Tier1Outcome{}); err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
	}
	// Loader called once for the first request; cache short-
	// circuits the next two.
	if got := atomic.LoadInt32(&loader.calls); got != 1 {
		t.Errorf("loader.calls = %d, want 1", got)
	}
}

func TestRouter_LoaderReturnsOverrideConstructsAndCaches(t *testing.T) {
	def := &labelledClient{label: "default"}
	override := &labelledClient{label: "override"}

	// Register the override factory under a deterministic name
	// for this test, then clean up to keep the registry tidy for
	// other tests in this package.
	const overrideName = "router_test_override"
	t.Cleanup(resetForTest)
	Register(overrideName, func(_ ProviderConfig) (Client, error) {
		return override, nil
	})

	loader := &stubLoader{provider: overrideName}
	var resolveCalls int32
	r, err := NewRouter(RouterConfig{
		Default: def,
		Loader:  loader,
		ResolveConfig: func(name string) (ProviderConfig, error) {
			atomic.AddInt32(&resolveCalls, 1)
			if name != overrideName {
				return ProviderConfig{}, errors.New("unexpected name")
			}
			return ProviderConfig{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	for i := 0; i < 3; i++ {
		out, err := r.Evaluate(context.Background(), dto.EvaluateRequest{TenantID: "t-1"}, dto.Tier1Outcome{})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if out.ModelName != "override" {
			t.Errorf("ModelName = %q, want override", out.ModelName)
		}
	}
	if got := atomic.LoadInt32(&loader.calls); got != 1 {
		t.Errorf("loader.calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&resolveCalls); got != 1 {
		t.Errorf("resolveCalls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&def.calls); got != 0 {
		t.Errorf("default.calls = %d, want 0 (override should service every request)", got)
	}
}

func TestRouter_LoaderErrorFallsToDefault(t *testing.T) {
	def := &labelledClient{label: "default"}
	loader := &stubLoader{err: errors.New("db blip")}
	r, err := NewRouter(RouterConfig{
		Default: def,
		Loader:  loader,
		ResolveConfig: func(_ string) (ProviderConfig, error) {
			t.Fatal("ResolveConfig should not be called when loader errors")
			return ProviderConfig{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	out, err := r.Evaluate(context.Background(), dto.EvaluateRequest{TenantID: "t-1"}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.ModelName != "default" {
		t.Errorf("ModelName = %q, want default", out.ModelName)
	}
}

func TestRouter_InvalidateForcesRelookup(t *testing.T) {
	def := &labelledClient{label: "default"}
	loader := &stubLoader{provider: ""}
	r, err := NewRouter(RouterConfig{Default: def, Loader: loader})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	_, _ = r.Evaluate(context.Background(), dto.EvaluateRequest{TenantID: "t-1"}, dto.Tier1Outcome{})
	_, _ = r.Evaluate(context.Background(), dto.EvaluateRequest{TenantID: "t-1"}, dto.Tier1Outcome{})
	if got := atomic.LoadInt32(&loader.calls); got != 1 {
		t.Fatalf("loader.calls = %d, want 1 before Invalidate", got)
	}
	r.Invalidate("t-1")
	_, _ = r.Evaluate(context.Background(), dto.EvaluateRequest{TenantID: "t-1"}, dto.Tier1Outcome{})
	if got := atomic.LoadInt32(&loader.calls); got != 2 {
		t.Errorf("loader.calls = %d, want 2 after Invalidate", got)
	}
}

func TestRouter_NoDefaultAndNoLoaderErrors(t *testing.T) {
	if _, err := NewRouter(RouterConfig{}); err == nil {
		t.Fatal("NewRouter(empty) err = nil, want non-nil")
	}
}

func TestRouter_EmptyTenantIDUsesDefault(t *testing.T) {
	def := &labelledClient{label: "default"}
	loader := &stubLoader{provider: "should-not-be-called"}
	r, err := NewRouter(RouterConfig{Default: def, Loader: loader})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	_, _ = r.Evaluate(context.Background(), dto.EvaluateRequest{TenantID: ""}, dto.Tier1Outcome{})
	if got := atomic.LoadInt32(&loader.calls); got != 0 {
		t.Errorf("loader.calls = %d, want 0 (empty tenant should skip loader)", got)
	}
}
