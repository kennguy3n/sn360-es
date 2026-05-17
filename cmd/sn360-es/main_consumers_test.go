package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// recordingBus is a richer test double than stubBus: it captures both
// subjects and payloads on Publish and lets tests configure return
// values for Subscribe so we can exercise both the critical and
// best-effort branches of StartConsumers.
type recordingBus struct {
	mu           sync.Mutex
	publishes    []recordedPublish
	subscribes   []recordedSubscribe
	subscribeErr error
}

type recordedPublish struct {
	Subject string
	Payload []byte
}

type recordedSubscribe struct {
	Subject string
	Sub     events.Subscription
	Err     error
}

func (b *recordingBus) Publish(_ context.Context, subject string, data []byte, _ ...events.PublishOption) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	payload := append([]byte(nil), data...)
	b.publishes = append(b.publishes, recordedPublish{Subject: subject, Payload: payload})
	return nil
}

func (b *recordingBus) Subscribe(_ context.Context, subject string, _ events.MessageHandler, _ ...events.SubscribeOption) (events.Subscription, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subscribeErr != nil {
		err := b.subscribeErr
		b.subscribes = append(b.subscribes, recordedSubscribe{Subject: subject, Err: err})
		return nil, err
	}
	sub := &countingSubscription{subject: subject}
	b.subscribes = append(b.subscribes, recordedSubscribe{Subject: subject, Sub: sub})
	return sub, nil
}

func (b *recordingBus) Health(_ context.Context) error { return nil }
func (b *recordingBus) Close() error                   { return nil }

func (b *recordingBus) publishedSubjects() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.publishes))
	for i, p := range b.publishes {
		out[i] = p.Subject
	}
	return out
}

func (b *recordingBus) firstPayload(subject string) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.publishes {
		if p.Subject == subject {
			return p.Payload
		}
	}
	return nil
}

func (b *recordingBus) subscribedSubjects() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.subscribes))
	for _, s := range b.subscribes {
		if s.Err == nil {
			out = append(out, s.Subject)
		}
	}
	return out
}

// countingSubscription tracks Close calls so consumer-shutdown tests
// can assert that StopConsumers really released every handle.
type countingSubscription struct {
	subject string
	closed  int
}

func (s *countingSubscription) Subject() string { return s.subject }
func (s *countingSubscription) Close() error {
	s.closed++
	return nil
}

// payloadMessage is a Message whose Data() returns a fixed JSON blob.
type payloadMessage struct {
	data    []byte
	subject string
}

func (m payloadMessage) Data() []byte                              { return m.data }
func (m payloadMessage) Subject() string                           { return m.subject }
func (m payloadMessage) Headers() map[string]string                { return nil }
func (m payloadMessage) Ack() error                                { return nil }
func (m payloadMessage) Nak(time.Duration) error                   { return nil }
func (m payloadMessage) Metadata() (events.MessageMetadata, error) { return events.MessageMetadata{}, nil }

// fakeTier1 produces a deterministic, high-risk score so the evaluator
// drops the message in the Warning band without contacting any
// upstream service.
type fakeTier1 struct{ score int }

func (f fakeTier1) Evaluate(_ context.Context, _ dto.EvaluateRequest) (dto.Tier1Outcome, error) {
	return dto.Tier1Outcome{
		Score:      f.score,
		Confidence: 0.95,
		Language:   "en",
		ModelName:  "fake-tier1",
		Flag:       f.score >= 60,
		Escalate:   f.score >= 60 && f.score < 80,
	}, nil
}

// fakeTier2 returns a fixed verdict so handleEvaluateRequest can be
// exercised end-to-end. We only need it when the score lands between
// the configured pass/flag thresholds.
type fakeTier2 struct{}

func (fakeTier2) Evaluate(_ context.Context, _ dto.EvaluateRequest, _ dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	return dto.Tier2Outcome{
		Score:      82,
		Confidence: 0.88,
		Categories: []constant.Category{constant.CategoryCredentialHarvesting, constant.CategorySuspiciousURL},
		ModelName:  "fake-tier2",
	}, nil
}

// fakeDecider adapts the per-component Decide(int, Category, RiskSignals)
// signature expected by evaluate.TierDecider onto the action package's
// Decide(EvaluateResult) implementation. The production binary uses an
// equivalent adapter; we reproduce it here to avoid taking a dependency
// on an unexported main.go helper from a sibling test file.
type fakeDecider struct{ d *action.TierDecider }

func (a fakeDecider) Decide(score int, primary constant.Category, _ dto.RiskSignals) constant.Tier {
	return a.d.Decide(dto.EvaluateResult{Score: score, Primary: primary})
}

// buildEvaluator returns an *evaluate.Evaluator using the same wiring
// pattern as the production newApplication path, but with fake clients
// so the test does not need a running Tier 1/Tier 2/Rspamd stack.
func buildEvaluator(t *testing.T, tier1 evaluate.Tier1Client) *evaluate.Evaluator {
	t.Helper()
	decider, err := action.NewTierDecider(action.TierThresholds{})
	if err != nil {
		t.Fatalf("tier decider: %v", err)
	}
	gate := tier0.NewGate(tier0.GateConfig{}, nil)
	return evaluate.NewEvaluator(evaluate.Config{
		Tier0:              gate,
		Tier1:              tier1,
		Tier2:              fakeTier2{},
		Categorizer:        evaluate.NewRuleCategorizer(),
		TierDecider:        fakeDecider{d: decider},
		Weights:            evaluate.DefaultWeights(),
		Tier1PassThreshold: 20,
		Tier1FlagThreshold: 60,
		Tier1Timeout:       time.Second,
		Tier2Timeout:       2 * time.Second,
		RspamdTimeout:      time.Second,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

// TestHandleEvaluateRequest_HappyPath wires a real evaluator with fake
// Tier 1/2 clients, feeds a known EvaluateRequest through the
// es.evaluate.request handler, and verifies the resulting verdict is
// published on es.evaluate.result.
func TestHandleEvaluateRequest_HappyPath(t *testing.T) {
	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	app.evaluator = buildEvaluator(t, fakeTier1{score: 75})

	req := dto.EvaluateRequest{
		MessageID:     "msg-eval-1",
		TenantID:      "t-1",
		CorrelationID: "corr-1",
		Subject:       "Verify your account now",
		Body:          "Please click http://example.com/login",
		Signals:       dto.RiskSignals{IsExternal: true},
		ReceivedAt:    time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC),
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := app.handleEvaluateRequest(context.Background(), payloadMessage{data: payload}); err != nil {
		t.Fatalf("handleEvaluateRequest: %v", err)
	}

	subjects := bus.publishedSubjects()
	if len(subjects) != 1 || subjects[0] != "es.evaluate.result" {
		t.Fatalf("subjects: %v, want exactly [es.evaluate.result]", subjects)
	}
	raw := bus.firstPayload("es.evaluate.result")
	var got dto.EvaluateResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if got.MessageID != req.MessageID {
		t.Errorf("message id: got %q, want %q", got.MessageID, req.MessageID)
	}
	if got.TenantID != req.TenantID {
		t.Errorf("tenant id: got %q, want %q", got.TenantID, req.TenantID)
	}
	if got.CorrelationID != req.CorrelationID {
		t.Errorf("correlation id: got %q, want %q", got.CorrelationID, req.CorrelationID)
	}
	if !got.Tier.Valid() {
		t.Errorf("tier: got %q, want a valid tier", got.Tier)
	}
	if got.Primary == "" {
		t.Errorf("primary category: empty (expected categorizer to populate)")
	}
	if got.EvaluatedAt.IsZero() {
		t.Errorf("evaluated_at: zero, want fallback-now")
	}
}

// TestHandleEvaluateRequest_NoEvaluator pins the dev-mode contract:
// when the evaluator is nil the handler short-circuits to nil without
// publishing anything. The bus must not receive any traffic.
func TestHandleEvaluateRequest_NoEvaluator(t *testing.T) {
	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	app.evaluator = nil

	payload, _ := json.Marshal(dto.EvaluateRequest{MessageID: "m", TenantID: "t"})
	if err := app.handleEvaluateRequest(context.Background(), payloadMessage{data: payload}); err != nil {
		t.Fatalf("handleEvaluateRequest: %v", err)
	}
	if subs := bus.publishedSubjects(); len(subs) != 0 {
		t.Errorf("expected no publishes, got %v", subs)
	}
}

// TestHandleEvaluateRequest_DropsMalformed verifies poison-message
// handling: a body that is not valid JSON, or a body missing the
// required identifiers, must NOT propagate an error (which would
// trigger redelivery up to MaxDeliver) and must NOT publish a result.
func TestHandleEvaluateRequest_DropsMalformed(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{name: "invalid json", body: []byte("not json")},
		{name: "missing message id", body: mustJSON(t, dto.EvaluateRequest{TenantID: "t-1"})},
		{name: "missing tenant id", body: mustJSON(t, dto.EvaluateRequest{MessageID: "m-1"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bus := &recordingBus{}
			app := newTestApp(t)
			app.eventBus = bus
			app.evaluator = buildEvaluator(t, fakeTier1{score: 30})
			if err := app.handleEvaluateRequest(context.Background(), payloadMessage{data: tc.body}); err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
			if subs := bus.publishedSubjects(); len(subs) != 0 {
				t.Errorf("expected no publishes, got %v", subs)
			}
		})
	}
}

// TestHandleIngestionAction_RendersBannerForRiskyTiers verifies the
// banner step of the action chain: when a banner renderer is wired
// and the verdict is non-Trusted, we publish the rendered banner on
// es.action.banner.
func TestHandleIngestionAction_RendersBannerForRiskyTiers(t *testing.T) {
	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	cat, err := action.DefaultBannerCatalog()
	if err != nil {
		t.Fatalf("default catalog: %v", err)
	}
	br, err := action.NewBannerRenderer(cat)
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	app.bannerRenderer = br
	// URL rewrite fires only when a rewriter is wired; the handler
	// checks for presence, not behaviour, so a zero-value rewriter is
	// enough to exercise the publish path.
	app.urlRewriter = &action.URLRewriter{}

	// HighRisk is the cleanest non-Trusted tier to exercise the full
	// banner path: it does not allow Mark Safe so BannerInput.Validate
	// is satisfied without an ActionToken, but it is still risky enough
	// to fire the URL-rewrite signal. Warning would also exercise the
	// banner path, but only when a JWT issuer is wired to mint the
	// ActionToken — that wiring is covered by handler-level tests in
	// the privacy package, so we keep this fixture token-free.
	res := dto.EvaluateResult{
		MessageID:     "msg-1",
		TenantID:      "t-1",
		CorrelationID: "corr-1",
		Tier:          constant.TierHighRisk,
		Primary:       constant.CategoryCredentialHarvesting,
	}
	body, _ := json.Marshal(res)
	if err := app.handleIngestionAction(context.Background(), payloadMessage{data: body}); err != nil {
		t.Fatalf("handleIngestionAction: %v", err)
	}

	// Banner + label always publish for non-Trusted verdicts; URL
	// rewrite fires for HighRisk/Blocked; quarantine fires only for
	// Blocked, so we must NOT see it here.
	subjects := bus.publishedSubjects()
	mustHave := map[string]bool{
		"es.action.banner":      false,
		"es.action.label":       false,
		"es.action.url_rewrite": false,
	}
	for _, s := range subjects {
		if _, ok := mustHave[s]; ok {
			mustHave[s] = true
		}
		if s == "es.action.quarantine" {
			t.Errorf("quarantine published for HighRisk tier; expected only Blocked")
		}
	}
	for s, seen := range mustHave {
		if !seen {
			t.Errorf("missing expected subject: %s (got %v)", s, subjects)
		}
	}
}

// TestHandleIngestionAction_BlockedTriggersAllSignals verifies the
// Blocked tier fan-out: banner, label, URL rewrite, and quarantine
// signals are all published on the bus so the downstream ingestion-
// svc consumers can pick each one up.
func TestHandleIngestionAction_BlockedTriggersAllSignals(t *testing.T) {
	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	cat, _ := action.NewJSONCatalog(map[string]map[string]string{
		"en": {
			"banner.tier.blocked.headline":    "Blocked",
			"banner.tier.blocked.description": "Blocked by SN360.",
			"banner.cta.report_phishing":      "Report",
			"banner.disclaimer":               "SN360 analysed this message.",
		},
	}, "en")
	br, err := action.NewBannerRenderer(cat)
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	app.bannerRenderer = br
	// A non-nil URL rewriter is enough to enable the publish step;
	// the handler only checks for presence, not behaviour.
	app.urlRewriter = &action.URLRewriter{}

	res := dto.EvaluateResult{
		MessageID:     "msg-blocked",
		TenantID:      "t-1",
		CorrelationID: "corr-1",
		Tier:          constant.TierBlocked,
		Primary:       constant.CategoryCredentialHarvesting,
		Score:         95,
	}
	body, _ := json.Marshal(res)
	if err := app.handleIngestionAction(context.Background(), payloadMessage{data: body}); err != nil {
		t.Fatalf("handleIngestionAction: %v", err)
	}

	want := map[string]bool{
		"es.action.banner":      false,
		"es.action.url_rewrite": false,
		"es.action.quarantine":  false,
		"es.action.label":       false,
	}
	for _, s := range bus.publishedSubjects() {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for s, seen := range want {
		if !seen {
			t.Errorf("missing subject %s in %v", s, bus.publishedSubjects())
		}
	}
}

// TestHandleIngestionAction_TrustedTierSkipsBanner pins the contract
// that Trusted messages don't get a banner: the only signal allowed
// for Trusted is no signal at all (it's an early-out tier).
func TestHandleIngestionAction_TrustedTierSkipsBanner(t *testing.T) {
	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	cat, _ := action.NewJSONCatalog(map[string]map[string]string{
		"en": {"banner.disclaimer": "SN360."},
	}, "en")
	br, _ := action.NewBannerRenderer(cat)
	app.bannerRenderer = br

	res := dto.EvaluateResult{
		MessageID: "msg-safe",
		TenantID:  "t-1",
		Tier:      constant.TierTrusted,
		Primary:   constant.CategoryInternalTrusted,
	}
	body, _ := json.Marshal(res)
	if err := app.handleIngestionAction(context.Background(), payloadMessage{data: body}); err != nil {
		t.Fatalf("handleIngestionAction: %v", err)
	}
	for _, s := range bus.publishedSubjects() {
		if s == "es.action.banner" || s == "es.action.label" || s == "es.action.url_rewrite" || s == "es.action.quarantine" {
			t.Errorf("Trusted tier published %q, want no action signals", s)
		}
	}
}

// TestHandleIngestionAction_DropsMalformed asserts the poison-message
// behaviour: invalid JSON or a payload missing identifiers must
// short-circuit to nil without publishing anything.
func TestHandleIngestionAction_DropsMalformed(t *testing.T) {
	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	cases := [][]byte{
		[]byte("not json"),
		mustJSON(t, dto.EvaluateResult{TenantID: "t"}),
		mustJSON(t, dto.EvaluateResult{MessageID: "m"}),
	}
	for _, body := range cases {
		if err := app.handleIngestionAction(context.Background(), payloadMessage{data: body}); err != nil {
			t.Fatalf("handleIngestionAction: %v", err)
		}
	}
	if subs := bus.publishedSubjects(); len(subs) != 0 {
		t.Errorf("expected no publishes, got %v", subs)
	}
}

// TestStartConsumers_WiresExpectedSubjects exercises the consumer
// registration path: when the evaluator + banner renderer are wired,
// StartConsumers must register subscriptions for the documented
// subjects (es.evaluate.request, es.evaluate.result, es.onboarding.>).
// The new evaluate.request subscription added in this PR must always
// be present.
func TestStartConsumers_WiresExpectedSubjects(t *testing.T) {
	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	app.evaluator = buildEvaluator(t, fakeTier1{score: 30})
	cat, _ := action.NewJSONCatalog(map[string]map[string]string{
		"en": {"banner.disclaimer": "SN360."},
	}, "en")
	br, _ := action.NewBannerRenderer(cat)
	app.bannerRenderer = br

	if err := app.StartConsumers(context.Background()); err != nil {
		t.Fatalf("StartConsumers: %v", err)
	}
	defer app.StopConsumers(slog.New(slog.NewTextHandler(io.Discard, nil)))

	got := bus.subscribedSubjects()
	want := []string{
		"es.evaluate.request",
		"es.evaluate.result",
		"es.onboarding.>",
	}
	for _, w := range want {
		seen := false
		for _, g := range got {
			if g == w {
				seen = true
				break
			}
		}
		if !seen {
			t.Errorf("missing subscription on %q (got %v)", w, got)
		}
	}
}

// TestStartConsumers_CriticalEvaluateSubFailureSurfaces verifies the
// fail-fast contract for the evaluate.request consumer: if the bus
// refuses the subscription, StartConsumers must return a wrapped error
// so the binary fails to start instead of silently dropping evaluation
// traffic.
func TestStartConsumers_CriticalEvaluateSubFailureSurfaces(t *testing.T) {
	bus := &recordingBus{subscribeErr: errors.New("simulated bus down")}
	app := newTestApp(t)
	app.eventBus = bus
	app.evaluator = buildEvaluator(t, fakeTier1{score: 30})

	err := app.StartConsumers(context.Background())
	if err == nil {
		t.Fatal("expected StartConsumers to fail when evaluator subscription fails")
	}
	// The error must mention the consumer group so operators can
	// diagnose which subscription tripped.
	if msg := err.Error(); !contains(msg, "evaluate-svc") {
		t.Errorf("error %q does not name the failing consumer group", msg)
	}
}

// TestStopConsumers_ClosesEverySubscription verifies that
// StopConsumers walks the tracked subscriptions and calls Close on
// each one. Each subscription's closed counter must end at exactly 1.
func TestStopConsumers_ClosesEverySubscription(t *testing.T) {
	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	app.evaluator = buildEvaluator(t, fakeTier1{score: 30})

	if err := app.StartConsumers(context.Background()); err != nil {
		t.Fatalf("StartConsumers: %v", err)
	}
	app.subsMu.Lock()
	count := len(app.subs)
	subsSnapshot := make([]events.Subscription, len(app.subs))
	copy(subsSnapshot, app.subs)
	app.subsMu.Unlock()
	if count == 0 {
		t.Fatal("expected at least one tracked subscription")
	}

	app.StopConsumers(slog.New(slog.NewTextHandler(io.Discard, nil)))

	app.subsMu.Lock()
	remaining := len(app.subs)
	app.subsMu.Unlock()
	if remaining != 0 {
		t.Errorf("expected subs slice cleared, got %d remaining", remaining)
	}
	for _, s := range subsSnapshot {
		cs, ok := s.(*countingSubscription)
		if !ok {
			continue
		}
		if cs.closed != 1 {
			t.Errorf("subscription on %q close count = %d, want 1", cs.subject, cs.closed)
		}
	}
}

// contains is a tiny substring helper to keep the import block minimal
// in this test file. strings.Contains would work but bringing in the
// strings package only for one call is overkill.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
