package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// --- fakes for the quarantine handler tests -------------------------------
//
// The handler under test depends on action.ReleaseService, which in turn
// depends on a QuarantineService, a QuarantineReevaluator, and an event
// publisher. The fakes below are deliberately tiny so the test focuses on
// the HTTP shim contract (status codes + JSON body) rather than the
// underlying release business logic which has its own test suite.

type qhFakeStore struct {
	mu   sync.Mutex
	data map[string]string
}

func newQHFakeStore() *qhFakeStore { return &qhFakeStore{data: map[string]string{}} }

func (s *qhFakeStore) Set(_ context.Context, k, v string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[k] = v
	return nil
}

func (s *qhFakeStore) Get(_ context.Context, k string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[k]
	return v, ok, nil
}

func (s *qhFakeStore) Del(_ context.Context, keys ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		delete(s.data, k)
	}
	return nil
}

func (s *qhFakeStore) GetDel(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	if !ok {
		return "", false, nil
	}
	delete(s.data, key)
	return v, true, nil
}

type qhFakeEncryptor struct{}

func (qhFakeEncryptor) Encrypt(_ context.Context, tenant string, plaintext []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	k := byte(0xa5)
	if len(tenant) > 0 {
		k ^= tenant[0]
	}
	for i, b := range plaintext {
		out[i] = b ^ k
	}
	return out, nil
}

func (e qhFakeEncryptor) Decrypt(ctx context.Context, tenant string, ct []byte) ([]byte, error) {
	return e.Encrypt(ctx, tenant, ct)
}

type qhFakeProvider struct {
	mu           sync.Mutex
	restoreCalls int
}

func (p *qhFakeProvider) Kind() action.LabelProviderKind { return action.LabelProviderGmail }
func (p *qhFakeProvider) EnsureQuarantineLabel(_ context.Context, _ string) (string, error) {
	return "Label_Q", nil
}
func (p *qhFakeProvider) MoveToQuarantine(_ context.Context, _, _, _, _ string) error { return nil }
func (p *qhFakeProvider) RestoreFromQuarantine(_ context.Context, _, _, _, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.restoreCalls++
	return nil
}

type qhFakeReevaluator struct {
	verdict dto.EvaluateResult
}

func (r qhFakeReevaluator) Reevaluate(_ context.Context, _, _ string) (dto.EvaluateResult, error) {
	return r.verdict, nil
}

type qhFakePublisher struct{}

func (qhFakePublisher) Publish(_ context.Context, _ string, _ []byte, _ ...events.PublishOption) error {
	return nil
}

// qhCapturingPublisher records the most recent publish call so tests
// can assert on the JSON envelope and the bus headers (correlation_id,
// tenant_id, event_type) emitted by ReleaseService.publishOutcome.
type qhCapturingPublisher struct {
	mu      sync.Mutex
	subject string
	payload []byte
	opts    events.PublishOptions
}

func (p *qhCapturingPublisher) Publish(_ context.Context, subject string, payload []byte, opts ...events.PublishOption) error {
	resolved := events.PublishOptions{}
	for _, o := range opts {
		o(&resolved)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subject = subject
	p.payload = append([]byte(nil), payload...)
	p.opts = resolved
	return nil
}

// quarantineFixture wires a real QuarantineService + ReleaseService against
// the in-memory fakes above. The reevaluator verdict is configurable so the
// tests can drive different ReleaseReason branches.
type quarantineFixture struct {
	issuer  *privacy.JWTIssuer
	release *action.ReleaseService
	q       *action.QuarantineService
	prov    *qhFakeProvider
}

func newQuarantineFixture(t *testing.T, verdict dto.EvaluateResult) *quarantineFixture {
	t.Helper()
	issuer, err := privacy.NewJWTIssuer(privacy.JWTConfig{
		Secret: bytes.Repeat([]byte{0xab}, 32),
		Issuer: "sn360-es",
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	prov := &qhFakeProvider{}
	qsvc, err := action.NewQuarantineService(action.QuarantineConfig{
		Providers: []action.QuarantineProvider{prov},
		Store:     newQHFakeStore(),
		Encryptor: qhFakeEncryptor{},
		Publisher: qhFakePublisher{},
	})
	if err != nil {
		t.Fatalf("quarantine svc: %v", err)
	}
	if _, err := qsvc.Quarantine(context.Background(), action.QuarantineRequest{
		Tenant:               "acme",
		PseudonymizedMessage: "pmid-1",
		Provider:             action.LabelProviderGmail,
		Email:                "user@acme.com",
		MessageID:            "raw-1",
		Tier:                 constant.TierBlocked,
		Primary:              constant.CategoryLikelyPhishing,
	}); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}
	rsvc, err := action.NewReleaseService(action.ReleaseConfig{
		Quarantine:  qsvc,
		Reevaluator: qhFakeReevaluator{verdict: verdict},
		Publisher:   qhFakePublisher{},
	})
	if err != nil {
		t.Fatalf("release svc: %v", err)
	}
	return &quarantineFixture{issuer: issuer, release: rsvc, q: qsvc, prov: prov}
}

func issueQuarantineToken(t *testing.T, issuer *privacy.JWTIssuer, tenant, pmid string) string {
	t.Helper()
	tok, err := issuer.Issue(tenant, pmid, privacy.IssueOptions{Action: "release"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok
}

// hex-encode arbitrary bytes; used to build a token-shaped string that
// still fails Verify because the signature is unsigned.
func unsignedToken() string {
	return hex.EncodeToString([]byte("not.a.real.jwt"))
}

func TestQuarantineHandler_ReleaseAllowed(t *testing.T) {
	fx := newQuarantineFixture(t, dto.EvaluateResult{
		Tier:    constant.TierInformational,
		Primary: constant.CategoryFirstContactExternal,
	})
	h, err := NewQuarantineHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), fx.issuer, fx.release)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	tok := issueQuarantineToken(t, fx.issuer, "acme", "pmid-1")
	body, _ := json.Marshal(map[string]string{"token": tok})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/quarantine/release", bytes.NewReader(body)))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp quarantineReleaseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Reason != string(action.ReleaseAllowed) {
		t.Fatalf("reason=%q", resp.Reason)
	}
	if !resp.Restored {
		t.Fatal("expected Restored=true")
	}
	if fx.prov.restoreCalls != 1 {
		t.Fatalf("restoreCalls=%d", fx.prov.restoreCalls)
	}
}

func TestQuarantineHandler_ReleaseRefused(t *testing.T) {
	fx := newQuarantineFixture(t, dto.EvaluateResult{
		Tier:    constant.TierBlocked,
		Primary: constant.CategoryBECImpersonation,
	})
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release)
	tok := issueQuarantineToken(t, fx.issuer, "acme", "pmid-1")
	body, _ := json.Marshal(map[string]string{"token": tok})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/quarantine/release", bytes.NewReader(body)))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp quarantineReleaseResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Reason != string(action.ReleaseRefused) {
		t.Fatalf("reason=%q", resp.Reason)
	}
	if resp.Restored {
		t.Fatal("expected Restored=false on refusal")
	}
	if resp.ReportPath == "" {
		t.Fatal("expected report path on refusal")
	}
}

func TestQuarantineHandler_NotFound(t *testing.T) {
	fx := newQuarantineFixture(t, dto.EvaluateResult{Tier: constant.TierInformational})
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release)
	// Issue a token for an unknown pseudonymised message id so the
	// release service returns NotFound.
	tok := issueQuarantineToken(t, fx.issuer, "acme", "missing")
	body, _ := json.Marshal(map[string]string{"token": tok})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/quarantine/release", bytes.NewReader(body)))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestQuarantineHandler_Rejections(t *testing.T) {
	fx := newQuarantineFixture(t, dto.EvaluateResult{Tier: constant.TierInformational})
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release)

	cases := []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "wrong method", method: http.MethodGet, body: "", want: http.StatusMethodNotAllowed},
		{name: "invalid JSON", method: http.MethodPost, body: "garbage", want: http.StatusBadRequest},
		{name: "unknown field", method: http.MethodPost, body: `{"token":"x","unknown":1}`, want: http.StatusBadRequest},
		{name: "missing token", method: http.MethodPost, body: `{"token":""}`, want: http.StatusBadRequest},
		{name: "invalid token", method: http.MethodPost, body: `{"token":"` + unsignedToken() + `"}`, want: http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/v1/quarantine/release", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestQuarantineHandler_PropagatesCorrelationID is a regression test for
// the fix where the HTTP release path was dropping X-Correlation-ID. Bus-
// driven releases (handleQuarantineRelease at cmd/sn360-es/main.go) had
// already been threading the correlation ID through env.CorrelationID,
// but the HTTP handler constructed action.ReleaseRequest from JWT claims
// alone, so HTTP-originated releases published outcome events with an
// empty correlation_id in both the JSON body and the bus header — making
// it impossible to join the release back to the originating evaluation
// for the entire HTTP code path.
//
// We assert two surfaces here, both of which would have stayed empty
// before the fix:
//   - The JSON `correlation_id` field on the published envelope.
//   - The `events.WithCorrelationID(...)` header on the publish call.
func TestQuarantineHandler_PropagatesCorrelationID(t *testing.T) {
	// Build a ReleaseService backed by a capturing publisher so we can
	// inspect what publishOutcome actually emitted.
	issuer, err := privacy.NewJWTIssuer(privacy.JWTConfig{
		Secret: bytes.Repeat([]byte{0xab}, 32),
		Issuer: "sn360-es",
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	prov := &qhFakeProvider{}
	qsvc, err := action.NewQuarantineService(action.QuarantineConfig{
		Providers: []action.QuarantineProvider{prov},
		Store:     newQHFakeStore(),
		Encryptor: qhFakeEncryptor{},
		Publisher: qhFakePublisher{},
	})
	if err != nil {
		t.Fatalf("quarantine svc: %v", err)
	}
	if _, err := qsvc.Quarantine(context.Background(), action.QuarantineRequest{
		Tenant:               "acme",
		PseudonymizedMessage: "pmid-cid",
		Provider:             action.LabelProviderGmail,
		Email:                "user@acme.com",
		MessageID:            "raw-cid",
		Tier:                 constant.TierBlocked,
		Primary:              constant.CategoryLikelyPhishing,
	}); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}
	captured := &qhCapturingPublisher{}
	rsvc, err := action.NewReleaseService(action.ReleaseConfig{
		Quarantine: qsvc,
		Reevaluator: qhFakeReevaluator{verdict: dto.EvaluateResult{
			Tier:    constant.TierInformational,
			Primary: constant.CategoryFirstContactExternal,
		}},
		Publisher: captured,
	})
	if err != nil {
		t.Fatalf("release svc: %v", err)
	}
	h, err := NewQuarantineHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), issuer, rsvc)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}

	tok := issueQuarantineToken(t, issuer, "acme", "pmid-cid")
	body, _ := json.Marshal(map[string]string{"token": tok})
	req := httptest.NewRequest(http.MethodPost, "/v1/quarantine/release", bytes.NewReader(body))
	req.Header.Set("X-Correlation-ID", "cid-http-test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Header: must be propagated as a bus option.
	if captured.opts.CorrelationID != "cid-http-test" {
		t.Fatalf("bus correlation_id=%q want %q", captured.opts.CorrelationID, "cid-http-test")
	}
	// JSON body: must include correlation_id alongside the existing
	// release fields. We decode into a loose map so the test stays
	// resilient to future fields being added to the envelope.
	var env map[string]any
	if err := json.Unmarshal(captured.payload, &env); err != nil {
		t.Fatalf("decode published envelope: %v body=%s", err, string(captured.payload))
	}
	if got, _ := env["correlation_id"].(string); got != "cid-http-test" {
		t.Fatalf("envelope correlation_id=%q want %q", got, "cid-http-test")
	}
	// Subject sanity-check: should still be the canonical release
	// outcome subject — the fix must not have shifted it.
	if captured.subject != "es.action.quarantine.release" {
		t.Fatalf("publish subject=%q", captured.subject)
	}
}

func TestQuarantineHandler_RequiresDeps(t *testing.T) {
	if _, err := NewQuarantineHandler(nil, nil, nil); err == nil {
		t.Fatal("expected error when verifier is nil")
	}
	issuer, _ := privacy.NewJWTIssuer(privacy.JWTConfig{Secret: bytes.Repeat([]byte{1}, 32)})
	if _, err := NewQuarantineHandler(nil, issuer, nil); err == nil {
		t.Fatal("expected error when release service is nil")
	}
}
