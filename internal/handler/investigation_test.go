package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/investigation"
)

func newTestInvestigationService(t *testing.T, now time.Time) *investigation.Service {
	t.Helper()
	r := repository.NewInMemoryRegistry()
	ctx := context.Background()
	// Seed a single tenant with two verdicts on the same message
	// + a matching comm history row + a second tenant with the
	// same message id so the cross-tenant 404 path is reachable.
	for _, er := range []*repository.EvaluationResult{
		{
			TenantID: "acme", MessageIDHash: []byte("msg-1"),
			SenderHash: []byte("s-A"), RecipientHash: []byte("r-1"),
			Score: 90, Tier: "blocked",
			EvaluatedAt: now.Add(-1 * time.Hour),
		},
		{
			TenantID: "acme", MessageIDHash: []byte("msg-2"),
			SenderHash: []byte("s-A"), RecipientHash: []byte("r-1"),
			Score: 50, Tier: "medium",
			EvaluatedAt: now.Add(-2 * time.Hour),
		},
		{
			TenantID: "other", MessageIDHash: []byte("msg-1"),
			SenderHash: []byte("s-A"), RecipientHash: []byte("r-1"),
			Score: 99, Tier: "high",
			EvaluatedAt: now.Add(-1 * time.Hour),
		},
	} {
		if err := r.EvaluationResults.Create(ctx, er); err != nil {
			t.Fatalf("seed eval: %v", err)
		}
	}
	if err := r.CommunicationHistories.Upsert(ctx, &repository.CommunicationHistory{
		TenantID:      "acme",
		SenderHash:    []byte("s-A"),
		RecipientHash: []byte("r-1"),
		Count7d:       3,
		Count30d:      12,
		FirstSeenAt:   now.Add(-30 * 24 * time.Hour),
		LastSeenAt:    now.Add(-1 * time.Hour),
	}); err != nil {
		t.Fatalf("seed comm history: %v", err)
	}
	svc, err := investigation.NewService(investigation.ServiceConfig{
		EvaluationResults:      r.EvaluationResults,
		CommunicationHistories: r.CommunicationHistories,
		Logger:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:                  func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestInvestigationHandler_ServeMessage_OK(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	h := NewInvestigationHandler(nil, newTestInvestigationService(t, now))
	req := httptest.NewRequest(http.MethodGet, "/v1/investigation/message/msg-1", nil)
	req = withTenant(req, "acme")
	rec := httptest.NewRecorder()
	h.ServeMessage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp messageTrailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Result.Score != 90 {
		t.Errorf("score: got %d, want 90", resp.Result.Score)
	}
	if resp.Result.Tier != "blocked" {
		t.Errorf("tier: got %q, want blocked", resp.Result.Tier)
	}
	if resp.CommunicationHistory == nil {
		t.Fatalf("missing comm history join")
	}
	if resp.CommunicationHistory.Count30d != 12 {
		t.Errorf("count_30d: got %d, want 12", resp.CommunicationHistory.Count30d)
	}
}

func TestInvestigationHandler_ServeMessage_Unauthenticated(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	h := NewInvestigationHandler(nil, newTestInvestigationService(t, now))
	// No tenant in context — must NOT touch the service.
	req := httptest.NewRequest(http.MethodGet, "/v1/investigation/message/msg-1", nil)
	rec := httptest.NewRecorder()
	h.ServeMessage(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestInvestigationHandler_ServeMessage_CrossTenantIs404(t *testing.T) {
	// "other" tenant owns its own copy of msg-1. A caller from
	// "acme" who probes "other"'s URL space (no — same URL path,
	// the path is just /v1/investigation/message/{pseudo_id})
	// MUST see a 404 identical to "msg-doesnt-exist" so existence
	// in another tenant cannot be fingerprinted.
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	h := NewInvestigationHandler(nil, newTestInvestigationService(t, now))

	// "acme" probing msg-doesnt-exist: 404.
	req1 := withTenant(httptest.NewRequest(http.MethodGet, "/v1/investigation/message/msg-nonexistent", nil), "acme")
	rec1 := httptest.NewRecorder()
	h.ServeMessage(rec1, req1)
	// "stranger" probing msg-1 (which exists in acme and other,
	// not in "stranger"): also 404.
	req2 := withTenant(httptest.NewRequest(http.MethodGet, "/v1/investigation/message/msg-1", nil), "stranger")
	rec2 := httptest.NewRecorder()
	h.ServeMessage(rec2, req2)
	if rec1.Code != http.StatusNotFound || rec2.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant probe: got %d / %d; want 404 / 404", rec1.Code, rec2.Code)
	}
	if rec1.Body.String() != rec2.Body.String() {
		t.Errorf("cross-tenant 404 bodies must match to prevent fingerprinting; got %q vs %q",
			rec1.Body.String(), rec2.Body.String())
	}
}

func TestInvestigationHandler_ServeMessage_NilService(t *testing.T) {
	h := NewInvestigationHandler(nil, nil)
	req := withTenant(httptest.NewRequest(http.MethodGet, "/v1/investigation/message/msg-1", nil), "acme")
	rec := httptest.NewRecorder()
	h.ServeMessage(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestInvestigationHandler_ServeMessage_EmptyPathIs400(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	h := NewInvestigationHandler(nil, newTestInvestigationService(t, now))
	req := withTenant(httptest.NewRequest(http.MethodGet, "/v1/investigation/message/", nil), "acme")
	rec := httptest.NewRecorder()
	h.ServeMessage(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestInvestigationHandler_ServeMessage_MethodNotAllowed(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	h := NewInvestigationHandler(nil, newTestInvestigationService(t, now))
	req := withTenant(httptest.NewRequest(http.MethodPost, "/v1/investigation/message/msg-1", nil), "acme")
	rec := httptest.NewRecorder()
	h.ServeMessage(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", rec.Code)
	}
}

func TestInvestigationHandler_ServeSender_OK(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	h := NewInvestigationHandler(nil, newTestInvestigationService(t, now))
	rawHash := base64.RawURLEncoding.EncodeToString([]byte("s-A"))
	req := withTenant(httptest.NewRequest(http.MethodGet, "/v1/investigation/sender/"+rawHash, nil), "acme")
	rec := httptest.NewRecorder()
	h.ServeSender(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp senderTrailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.SenderHash != rawHash {
		t.Errorf("echoed sender_hash: got %q, want %q", resp.SenderHash, rawHash)
	}
	if len(resp.Verdicts) != 2 {
		t.Fatalf("verdicts: got %d, want 2", len(resp.Verdicts))
	}
	if resp.Aggregate.MaxScore != 90 {
		t.Errorf("max score: got %d, want 90", resp.Aggregate.MaxScore)
	}
	if resp.Aggregate.HighRiskVerdicts != 1 {
		t.Errorf("high risk verdicts: got %d, want 1", resp.Aggregate.HighRiskVerdicts)
	}
}

func TestInvestigationHandler_ServeSender_InvalidBase64Is400(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	h := NewInvestigationHandler(nil, newTestInvestigationService(t, now))
	req := withTenant(httptest.NewRequest(http.MethodGet, "/v1/investigation/sender/not!base64!", nil), "acme")
	rec := httptest.NewRecorder()
	h.ServeSender(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestInvestigationHandler_ServeSender_AcceptsAllFourBase64Variants
// pins the four-way contract documented in the OpenAPI spec — the
// endpoint accepts url-safe and standard alphabets, padded or
// unpadded, and all four must decode to the same bytes and reach
// the service layer (verdict shape is asserted elsewhere). Without
// this test the spec/handler can silently drift back to a
// single-variant decoder (the originally-shipped shape, per Devin
// Review BUG_0001 on PR #62).
func TestInvestigationHandler_ServeSender_AcceptsAllFourBase64Variants(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	// Pick raw bytes whose canonical (non-padded) base64url
	// encoding contains a '-' (url-safe-only character) and whose
	// standard-alphabet encoding contains a '+' (standard-only
	// character), so the alphabets are genuinely exercised against
	// the same input. 0xfb 0xef 0x3e → "++8+" (std) / "--8-" (url).
	raw := []byte{0xfb, 0xef, 0x3e}
	if u := base64.RawURLEncoding.EncodeToString(raw); !strings.Contains(u, "-") {
		t.Fatalf("test fixture invariant: rawurl encoding %q missing '-' character", u)
	}
	if s := base64.RawStdEncoding.EncodeToString(raw); !strings.Contains(s, "+") {
		t.Fatalf("test fixture invariant: rawstd encoding %q missing '+' character", s)
	}
	h := NewInvestigationHandler(nil, newServiceSeededWithSender(t, now, "acme", raw))
	cases := map[string]string{
		"rawurl": base64.RawURLEncoding.EncodeToString(raw),
		"url":    base64.URLEncoding.EncodeToString(raw),
		"rawstd": base64.RawStdEncoding.EncodeToString(raw),
		"std":    base64.StdEncoding.EncodeToString(raw),
	}
	for name, enc := range cases {
		t.Run(name, func(t *testing.T) {
			req := withTenant(
				httptest.NewRequest(http.MethodGet, "/v1/investigation/sender/"+enc, nil),
				"acme",
			)
			rec := httptest.NewRecorder()
			h.ServeSender(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("variant %s: status=%d body=%s", name, rec.Code, rec.Body.String())
			}
			var resp senderTrailResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("variant %s: decode: %v", name, err)
			}
			if len(resp.Verdicts) == 0 {
				t.Errorf("variant %s: no verdicts returned for seeded sender", name)
			}
		})
	}
}

// newServiceSeededWithSender builds an investigation.Service with a
// single seeded verdict against (tenant, senderHash). Used by the
// four-variant base64 acceptance test so the raw bytes the path
// decodes to actually match a service-layer row.
func newServiceSeededWithSender(t *testing.T, now time.Time, tenant string, senderHash []byte) *investigation.Service {
	t.Helper()
	r := repository.NewInMemoryRegistry()
	ctx := context.Background()
	if err := r.EvaluationResults.Create(ctx, &repository.EvaluationResult{
		TenantID: tenant, MessageIDHash: []byte("m-base64-variant"),
		SenderHash: senderHash, RecipientHash: []byte("r-base64-variant"),
		Score: 88, Tier: "high",
		EvaluatedAt: now.Add(-1 * time.Hour),
	}); err != nil {
		t.Fatalf("seed eval: %v", err)
	}
	svc, err := investigation.NewService(investigation.ServiceConfig{
		EvaluationResults:      r.EvaluationResults,
		CommunicationHistories: r.CommunicationHistories,
		Logger:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:                  func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestInvestigationHandler_ServeSender_CrossTenantIsolation(t *testing.T) {
	// A caller from a tenant with NO sightings under sender s-A
	// must see an empty trail — not the rows that exist for
	// "acme" or "other".
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	h := NewInvestigationHandler(nil, newTestInvestigationService(t, now))
	rawHash := base64.RawURLEncoding.EncodeToString([]byte("s-A"))
	req := withTenant(httptest.NewRequest(http.MethodGet, "/v1/investigation/sender/"+rawHash, nil), "stranger")
	rec := httptest.NewRecorder()
	h.ServeSender(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp senderTrailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Verdicts) != 0 {
		t.Errorf("stranger leaked %d verdicts; want 0", len(resp.Verdicts))
	}
	if len(resp.CommunicationHistories) != 0 {
		t.Errorf("stranger leaked %d recipient rows; want 0", len(resp.CommunicationHistories))
	}
}

func TestInvestigationHandler_ServeSender_LimitOutOfRange(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	h := NewInvestigationHandler(nil, newTestInvestigationService(t, now))
	rawHash := base64.RawURLEncoding.EncodeToString([]byte("s-A"))
	req := withTenant(httptest.NewRequest(http.MethodGet, "/v1/investigation/sender/"+rawHash+"?limit=99999", nil), "acme")
	rec := httptest.NewRecorder()
	h.ServeSender(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestParseSenderTrailOptions(t *testing.T) {
	// Pure-function coverage: zero values, valid bounded values,
	// invalid values all map to the documented behaviour.
	ok, err := parseSenderTrailOptions(nil)
	if err != nil {
		t.Fatalf("nil query: %v", err)
	}
	if ok.Limit != 0 || ok.Since != 0 {
		t.Errorf("nil query defaults: got %+v, want zero", ok)
	}
	ok, err = parseSenderTrailOptions(map[string][]string{
		"limit":       {"50"},
		"since_hours": {"24"},
	})
	if err != nil {
		t.Fatalf("valid: %v", err)
	}
	if ok.Limit != 50 || ok.Since != 24*time.Hour {
		t.Errorf("valid: got %+v", ok)
	}
	if _, err := parseSenderTrailOptions(map[string][]string{"limit": {"-1"}}); err == nil {
		t.Errorf("negative limit accepted")
	}
	if _, err := parseSenderTrailOptions(map[string][]string{"since_hours": {"99999"}}); err == nil {
		t.Errorf("out-of-range hours accepted")
	}
	if _, err := parseSenderTrailOptions(map[string][]string{"limit": {"abc"}}); err == nil {
		t.Errorf("non-numeric limit accepted")
	}
}

// _ ensures the middleware package is used even on builds where
// none of the handler tests above happen to exercise it directly.
var _ = middleware.ContextWithTenantID
