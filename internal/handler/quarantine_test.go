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

func TestQuarantineHandler_RequiresDeps(t *testing.T) {
	if _, err := NewQuarantineHandler(nil, nil, nil); err == nil {
		t.Fatal("expected error when verifier is nil")
	}
	issuer, _ := privacy.NewJWTIssuer(privacy.JWTConfig{Secret: bytes.Repeat([]byte{1}, 32)})
	if _, err := NewQuarantineHandler(nil, issuer, nil); err == nil {
		t.Fatal("expected error when release service is nil")
	}
}
