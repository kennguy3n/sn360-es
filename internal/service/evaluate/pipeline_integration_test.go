//go:build integration
// +build integration

package evaluate_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	tcnats "github.com/testcontainers/testcontainers-go/modules/nats"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/pkg/events"
	natsbus "github.com/kennguy3n/sn360-es/pkg/events/nats"
)

// fakeTier0 returns a non-bypassing outcome by default; tests can override
// individual fields via the closure below.
type fakeTier0 struct {
	apply func(dto.EvaluateRequest) dto.Tier0Outcome
}

func (f fakeTier0) Apply(req dto.EvaluateRequest) dto.Tier0Outcome { return f.apply(req) }

type fakeTier1 struct {
	score      int
	confidence float64
	err        error
}

func (f fakeTier1) Evaluate(_ context.Context, _ dto.EvaluateRequest) (dto.Tier1Outcome, error) {
	if f.err != nil {
		return dto.Tier1Outcome{}, f.err
	}
	return dto.Tier1Outcome{Score: f.score, Confidence: f.confidence, ModelName: "fake-tier1"}, nil
}

type fakeTier2 struct {
	score      int
	categories []constant.Category
}

func (f fakeTier2) Evaluate(_ context.Context, _ dto.EvaluateRequest, _ dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	return dto.Tier2Outcome{Score: f.score, Categories: f.categories, ModelName: "fake-tier2"}, nil
}

type fakeRspamd struct {
	score float64
}

func (f fakeRspamd) Score(_ context.Context, _ dto.EvaluateRequest) (dto.RspamdOutcome, error) {
	return dto.RspamdOutcome{Score: f.score, Threshold: 5.0}, nil
}

type fakeCategorizer struct{}

func (fakeCategorizer) Categorise(_ dto.EvaluateResult, _ dto.RiskSignals) (constant.Category, []constant.Category, []string) {
	return constant.CategoryLikelyPhishing, nil, []string{"e2e_test"}
}

type fakeTierDecider struct{}

func (fakeTierDecider) Decide(score int, _ constant.Category, _ dto.RiskSignals) constant.Tier {
	switch {
	case score >= 80:
		return constant.TierHighRisk
	case score >= 60:
		return constant.TierWarning
	case score >= 40:
		return constant.TierCaution
	default:
		return constant.TierTrusted
	}
}

func skipIfNoDocker(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "docker") {
		t.Skipf("docker not available, skipping: %v", err)
	}
	t.Fatalf("start container: %v", err)
}

func startNATSService(t *testing.T) *natsbus.Service {
	t.Helper()
	c, err := tcnats.Run(context.Background(), "nats:2.10-alpine",
		tcnats.WithArgument("jetstream", ""),
	)
	skipIfNoDocker(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	url, err := c.ConnectionString(context.Background())
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	cfg := natsbus.DefaultConfig()
	cfg.URL = url
	cfg.Storage = "memory"
	cfg.Replicas = 1
	svc, err := natsbus.NewService(context.Background(), cfg, "evaluate-e2e", slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

// TestPipelineIntegration_EvaluateRequestProducesBannerAction wires the
// evaluator into a NATS-backed consumer/producer pair and verifies that
// a published es.evaluate.request flows through the full pipeline
// (Tier 0 → Tier 1 → Tier 2 → Rspamd → categoriser → tier decider) and
// produces an es.action.banner message with the expected tier/score.
func TestPipelineIntegration_EvaluateRequestProducesBannerAction(t *testing.T) {
	svc := startNATSService(t)

	evaluator := evaluate.NewEvaluator(evaluate.Config{
		Tier0: fakeTier0{apply: func(_ dto.EvaluateRequest) dto.Tier0Outcome {
			return dto.Tier0Outcome{}
		}},
		Tier1:       fakeTier1{score: 90, confidence: 0.9},
		Tier2:       fakeTier2{score: 95, categories: []constant.Category{constant.CategoryLikelyPhishing}},
		Rspamd:      fakeRspamd{score: 6.5},
		Categorizer: fakeCategorizer{},
		TierDecider: fakeTierDecider{},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Consumer: drain requests, run the evaluator, republish the verdict
	// on the action subject.
	reqSub, err := svc.Subscribe(ctx, "es.evaluate.request",
		func(c context.Context, m events.Message) error {
			var req dto.EvaluateRequest
			if err := json.Unmarshal(m.Data(), &req); err != nil {
				return err
			}
			res, err := evaluator.Evaluate(c, req)
			if err != nil {
				return err
			}
			body, _ := json.Marshal(res)
			return svc.Publish(c, "es.action.banner", body,
				events.WithCorrelationID(req.CorrelationID),
				events.WithTenantID(req.TenantID),
				events.WithEventType("action.banner"),
			)
		},
		events.WithDurable("e2e-evaluate"),
	)
	if err != nil {
		t.Fatalf("subscribe request: %v", err)
	}
	defer reqSub.Close()

	results := make(chan dto.EvaluateResult, 1)
	actSub, err := svc.Subscribe(ctx, "es.action.banner",
		func(_ context.Context, m events.Message) error {
			var res dto.EvaluateResult
			if err := json.Unmarshal(m.Data(), &res); err != nil {
				return err
			}
			results <- res
			return nil
		},
		events.WithDurable("e2e-banner"),
	)
	if err != nil {
		t.Fatalf("subscribe action: %v", err)
	}
	defer actSub.Close()

	req := dto.EvaluateRequest{
		MessageID:     "msg-e2e-001",
		TenantID:      "tenant-e2e",
		CorrelationID: "corr-e2e-001",
		Sender:        "ceo-impostor@example.com",
		Recipient:     "finance@acme.test",
		Subject:       "URGENT: wire transfer",
		Body:          "please wire $50k today",
		ReceivedAt:    time.Now().UTC(),
	}
	body, _ := json.Marshal(req)
	if err := svc.Publish(ctx, "es.evaluate.request", body,
		events.WithCorrelationID(req.CorrelationID),
		events.WithTenantID(req.TenantID),
		events.WithEventType("evaluate.request"),
	); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case res := <-results:
		if res.MessageID != "msg-e2e-001" {
			t.Fatalf("wrong message id: %q", res.MessageID)
		}
		if res.Tier != constant.TierHighRisk {
			t.Fatalf("expected HighRisk, got %q (score=%d)", res.Tier, res.Score)
		}
		if res.Primary != constant.CategoryLikelyPhishing {
			t.Fatalf("expected likely_phishing, got %q", res.Primary)
		}
		if res.Tier1 == nil || res.Tier2 == nil || res.Rspamd == nil {
			t.Fatalf("expected all stages populated; tier1=%v tier2=%v rspamd=%v", res.Tier1, res.Tier2, res.Rspamd)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for banner action")
	}
}

// TestPipelineIntegration_Tier0BypassShortCircuits proves that a Tier 0
// bypass produces a Trusted verdict without invoking downstream stages.
func TestPipelineIntegration_Tier0BypassShortCircuits(t *testing.T) {
	svc := startNATSService(t)

	var tier1Called bool
	evaluator := evaluate.NewEvaluator(evaluate.Config{
		Tier0: fakeTier0{apply: func(_ dto.EvaluateRequest) dto.Tier0Outcome {
			return dto.Tier0Outcome{
				Bypass:         true,
				Reason:         "internal_trusted",
				ForcedCategory: constant.CategoryInternalTrusted,
				SkipML:         true,
			}
		}},
		Tier1: fakeTier1{score: 90, err: func() error {
			tier1Called = true
			return errors.New("tier1 should not have been called")
		}()},
		Tier2:       fakeTier2{score: 90},
		Rspamd:      fakeRspamd{score: 6.0},
		Categorizer: fakeCategorizer{},
		TierDecider: fakeTierDecider{},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	out := make(chan dto.EvaluateResult, 1)
	sub, err := svc.Subscribe(ctx, "es.evaluate.request",
		func(c context.Context, m events.Message) error {
			var req dto.EvaluateRequest
			_ = json.Unmarshal(m.Data(), &req)
			res, _ := evaluator.Evaluate(c, req)
			out <- res
			return nil
		},
		events.WithDurable("e2e-tier0-bypass"),
	)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Close()

	body, _ := json.Marshal(dto.EvaluateRequest{MessageID: "msg-bypass-001", TenantID: "tenant"})
	if err := svc.Publish(ctx, "es.evaluate.request", body); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case res := <-out:
		if res.Tier != constant.TierTrusted {
			t.Fatalf("expected Trusted, got %q", res.Tier)
		}
		if res.Tier1 != nil || res.Tier2 != nil || res.Rspamd != nil {
			t.Fatalf("expected no downstream stages for bypass; tier1=%v tier2=%v rspamd=%v",
				res.Tier1, res.Tier2, res.Rspamd)
		}
		// The tier1Called flag is captured at construction time so it's
		// always false; what matters is res.Tier1 is nil.
		_ = tier1Called
	case <-ctx.Done():
		t.Fatal("timeout waiting for bypass result")
	}
}
