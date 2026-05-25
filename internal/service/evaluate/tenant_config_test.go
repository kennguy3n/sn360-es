package evaluate

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// stubTenantLoader is the test double for TenantScoringConfigLoader.
// It is intentionally local to this file so the evaluator-level
// contract (LoadTenantScoringConfig signature, return shape) is
// exercised without dragging in the production adapter from
// cmd/sn360-es/adapters.go.
type stubTenantLoader struct {
	tc  TenantScoringConfig
	err error
}

func (s stubTenantLoader) LoadTenantScoringConfig(_ context.Context, _ string) (TenantScoringConfig, error) {
	return s.tc, s.err
}

// intPtr is a small helper so the threshold-pointer fields in
// TenantScoringConfig can be populated inline in test fixtures
// without taking the address of a temporary.
func intPtr(v int) *int { return &v }

// TestResolveTenantConfig_PerTenantOverridesStatic asserts the
// happy path: when the loader returns a tuned config, every field it
// populates wins over the static cfg defaults, while unset fields
// fall back to the static defaults so a partially-tuned tenant
// still gets a sensible mix.
func TestResolveTenantConfig_PerTenantOverridesStatic(t *testing.T) {
	e := NewEvaluator(Config{
		Weights:            Weights{AI: 0.5, Rspamd: 0.5},
		Tier1PassThreshold: 20,
		Tier1FlagThreshold: 60,
		TenantConfig: stubTenantLoader{
			tc: TenantScoringConfig{
				Weights:            Weights{AI: 0.9, Rspamd: 0.1},
				Tier1PassThreshold: intPtr(30),
				Tier1FlagThreshold: intPtr(70),
			},
		},
	})

	w, th := e.resolveTenantConfig(context.Background(), "tenant-a")
	if w.AI != 0.9 || w.Rspamd != 0.1 {
		t.Fatalf("expected per-tenant weights AI=0.9 Rspamd=0.1, got %+v", w)
	}
	if th.PassBelow != 30 || th.FlagAbove != 70 {
		t.Fatalf("expected per-tenant thresholds 30/70, got %d/%d", th.PassBelow, th.FlagAbove)
	}
}

// TestResolveTenantConfig_PartialOverridesPreserveStatic asserts the
// "leave fields zero → keep static defaults" contract. Tuning that
// has only adjusted thresholds (but not yet weights) must NOT
// silently zero the weights — that would devolve the verdict path
// to the all-zero scorer and emit res.Score = 0 for every message.
func TestResolveTenantConfig_PartialOverridesPreserveStatic(t *testing.T) {
	staticWeights := Weights{AI: 0.6, Rspamd: 0.3, Attachments: 0.1}
	e := NewEvaluator(Config{
		Weights:            staticWeights,
		Tier1PassThreshold: 20,
		Tier1FlagThreshold: 60,
		TenantConfig: stubTenantLoader{
			tc: TenantScoringConfig{
				// Weights left zero — must fall back to static.
				Tier1PassThreshold: intPtr(25), // only PassBelow tuned
				// Tier1FlagThreshold left nil — must fall back.
			},
		},
	})

	w, th := e.resolveTenantConfig(context.Background(), "tenant-b")
	if w != staticWeights {
		t.Fatalf("expected static weights to survive when loader weights are zero; got %+v", w)
	}
	if th.PassBelow != 25 {
		t.Fatalf("expected per-tenant PassThreshold=25, got %d", th.PassBelow)
	}
	if th.FlagAbove != 60 {
		t.Fatalf("expected static FlagThreshold=60 (loader left it nil), got %d", th.FlagAbove)
	}
}

// TestResolveTenantConfig_ZeroPointerDistinctFromNil asserts the
// architecturally-important difference between *int(nil) ("not
// configured") and *int(0) ("configured to 0"). The pointer-based
// sentinel is the whole reason TenantScoringConfig moved off the
// `> 0` guard: a tuning agent that legitimately emits PassBelow=0
// (legal per clampThresholds + the DB CHECK constraint) must reach
// the verdict path, not be collapsed onto the static default.
func TestResolveTenantConfig_ZeroPointerDistinctFromNil(t *testing.T) {
	e := NewEvaluator(Config{
		Weights:            Weights{AI: 0.5, Rspamd: 0.5},
		Tier1PassThreshold: 20,
		Tier1FlagThreshold: 60,
		TenantConfig: stubTenantLoader{
			tc: TenantScoringConfig{
				Tier1PassThreshold: intPtr(0), // deliberately 0 — every msg escalates
				// Tier1FlagThreshold nil — keep static 60
			},
		},
	})

	_, th := e.resolveTenantConfig(context.Background(), "tenant-zero")
	if th.PassBelow != 0 {
		t.Fatalf("expected configured PassBelow=0 to be honoured, got %d (static fallback)", th.PassBelow)
	}
	if th.FlagAbove != 60 {
		t.Fatalf("expected nil pointer to fall back to static FlagAbove=60, got %d", th.FlagAbove)
	}
}

// TestResolveTenantConfig_LoaderErrorFallsBackToStatic asserts the
// degraded-mode contract: a transient DB blip MUST NOT block verdict
// emission. The loader returns an error and the evaluator must fall
// back to the static defaults rather than surfacing the failure.
func TestResolveTenantConfig_LoaderErrorFallsBackToStatic(t *testing.T) {
	staticWeights := Weights{AI: 0.7, Rspamd: 0.3}
	e := NewEvaluator(Config{
		Logger:             slog.Default(),
		Weights:            staticWeights,
		Tier1PassThreshold: 20,
		Tier1FlagThreshold: 60,
		TenantConfig: stubTenantLoader{
			err: errors.New("postgres: connection refused"),
		},
	})

	w, th := e.resolveTenantConfig(context.Background(), "tenant-c")
	if w != staticWeights {
		t.Fatalf("expected static weights on loader error, got %+v", w)
	}
	if th.PassBelow != 20 || th.FlagAbove != 60 {
		t.Fatalf("expected static thresholds 20/60 on loader error, got %d/%d", th.PassBelow, th.FlagAbove)
	}
}

// TestResolveTenantConfig_NilLoaderShortCircuit asserts the legacy
// wiring path (no TenantConfig configured) returns the static
// defaults verbatim — which is what existing evaluator-using tests
// rely on to remain green without per-tenant config.
func TestResolveTenantConfig_NilLoaderShortCircuit(t *testing.T) {
	staticWeights := Weights{AI: 0.8, Rspamd: 0.2}
	e := NewEvaluator(Config{
		Weights:            staticWeights,
		Tier1PassThreshold: 20,
		Tier1FlagThreshold: 60,
	})

	w, th := e.resolveTenantConfig(context.Background(), "tenant-d")
	if w != staticWeights {
		t.Fatalf("expected static weights with nil loader, got %+v", w)
	}
	if th.PassBelow != 20 || th.FlagAbove != 60 {
		t.Fatalf("expected static thresholds with nil loader, got %d/%d", th.PassBelow, th.FlagAbove)
	}
}

// TestResolveTenantConfig_EmptyTenantIDShortCircuit asserts that
// tenant-less requests (e.g. internal health-probe paths) don't
// query the loader. This protects the loader from being asked for a
// zero-id row on every probe and matches the documented contract on
// TenantScoringConfigLoader.
func TestResolveTenantConfig_EmptyTenantIDShortCircuit(t *testing.T) {
	calls := 0
	loader := callCountingLoader{
		delegate: stubTenantLoader{tc: TenantScoringConfig{
			Weights: Weights{AI: 0.9, Rspamd: 0.1},
		}},
		calls: &calls,
	}
	staticWeights := Weights{AI: 0.5, Rspamd: 0.5}
	e := NewEvaluator(Config{
		Weights:            staticWeights,
		Tier1PassThreshold: 20,
		Tier1FlagThreshold: 60,
		TenantConfig:       loader,
	})

	w, th := e.resolveTenantConfig(context.Background(), "")
	if w != staticWeights {
		t.Fatalf("expected static weights for empty tenant ID, got %+v", w)
	}
	if th.PassBelow != 20 || th.FlagAbove != 60 {
		t.Fatalf("expected static thresholds for empty tenant ID, got %d/%d", th.PassBelow, th.FlagAbove)
	}
	if calls != 0 {
		t.Fatalf("expected loader to be skipped on empty tenant ID; got %d calls", calls)
	}
}

// TestResolveTenantConfig_SuppressPartnerCarriedFromStatic asserts
// that the platform-wide SuppressPartner offset is carried through
// resolveTenantConfig so a subsequent AdjustForRelationship call
// applies the same relationship-aware adjustment the batch path
// uses. This pins the parity between the per-message and batch
// evaluation paths.
func TestResolveTenantConfig_SuppressPartnerCarriedFromStatic(t *testing.T) {
	e := NewEvaluator(Config{
		Weights:              Weights{AI: 0.5, Rspamd: 0.5},
		Tier1PassThreshold:   30,
		Tier1FlagThreshold:   80,
		Tier1SuppressPartner: -15,
	})

	_, th := e.resolveTenantConfig(context.Background(), "tenant-e")
	if th.SuppressPartner != -15 {
		t.Fatalf("expected SuppressPartner=-15 from static config, got %d", th.SuppressPartner)
	}
	adjusted := th.AdjustForRelationship(dto.RelationshipPartner)
	if adjusted.PassBelow != 30-15 || adjusted.FlagAbove != 80-15 {
		t.Fatalf("expected Partner adjustment (15/65), got (%d/%d)", adjusted.PassBelow, adjusted.FlagAbove)
	}
	first := th.AdjustForRelationship(dto.RelationshipFirstTimeExternal)
	if first.PassBelow != 0 {
		t.Fatalf("expected FirstTimeExternal to force PassBelow=0, got %d", first.PassBelow)
	}
}

type callCountingLoader struct {
	delegate stubTenantLoader
	calls    *int
}

func (c callCountingLoader) LoadTenantScoringConfig(ctx context.Context, tenantID string) (TenantScoringConfig, error) {
	*c.calls++
	return c.delegate.LoadTenantScoringConfig(ctx, tenantID)
}
