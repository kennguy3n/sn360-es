package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/dashboard"
	"github.com/kennguy3n/sn360-es/internal/service/investigation"
)

const testTenant = "11111111-1111-1111-1111-111111111111"

// fakeMetricsSource is a deterministic dashboard.MetricsSource for the
// summary test. Every method returns the canned value regardless of
// tenant/range so the assertions are stable.
type fakeMetricsSource struct{}

func (fakeMetricsSource) EmailsProcessed(context.Context, string, dto.TimeRange) (int, error) {
	return 100, nil
}

func (fakeMetricsSource) ThreatsByTier(context.Context, string, dto.TimeRange) ([]dto.TierCount, error) {
	return []dto.TierCount{{Tier: "blocked", Count: 5}, {Tier: "high", Count: 3}}, nil
}

func (fakeMetricsSource) ThreatsByCategory(context.Context, string, dto.TimeRange) ([]dto.CategoryCount, error) {
	return []dto.CategoryCount{{Category: "phishing", Count: 4}, {Category: "malware", Count: 2}}, nil
}

func (fakeMetricsSource) Feedback(context.Context, string, dto.TimeRange) (dto.FeedbackStats, error) {
	return dto.FeedbackStats{}, nil
}

func (fakeMetricsSource) Quarantine(context.Context, string, dto.TimeRange) (dto.QuarantineStats, error) {
	return dto.QuarantineStats{Quarantined: 7}, nil
}

func (fakeMetricsSource) Simulation(context.Context, string, dto.TimeRange) (dto.SimulationStats, error) {
	return dto.SimulationStats{}, nil
}

func (fakeMetricsSource) FalseRates(context.Context, string, dto.TimeRange) (int, int, error) {
	return 0, 0, nil
}

// seedEval inserts an evaluation result for testTenant into the
// in-memory repository and returns the pseudo message id the detail
// route expects.
func seedEval(t *testing.T, repo repository.EvaluationResultRepository, id, tier, category string, score int, at time.Time) string {
	t.Helper()
	r := &repository.EvaluationResult{
		ID:            id,
		TenantID:      testTenant,
		MessageIDHash: []byte("pmid-" + id),
		SenderHash:    []byte("sender-" + id),
		Score:         score,
		Tier:          tier,
		Primary:       category,
		ReasonCodes:   []string{"reason_" + category},
		EvaluatedAt:   at,
	}
	if err := repo.Create(context.Background(), r); err != nil {
		t.Fatalf("seed eval %s: %v", id, err)
	}
	return string(r.MessageIDHash)
}

func newTestEmailHandler(t *testing.T, dash *dashboard.DashboardGenerator, inv *investigation.Service, eval repository.EvaluationResultRepository) *EmailBFFHandler {
	t.Helper()
	h, err := NewEmailBFFHandler(nil, dash, inv, eval, NopTenantBinder{})
	if err != nil {
		t.Fatalf("NewEmailBFFHandler: %v", err)
	}
	return h
}

func doRequest(h http.HandlerFunc, method, target string, pathVals map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range pathVals {
		req.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestNewEmailBFFHandlerRequiresBinder(t *testing.T) {
	if _, err := NewEmailBFFHandler(nil, nil, nil, nil, nil); err == nil {
		t.Fatal("expected error when binder is nil")
	}
}

func TestServeMessages(t *testing.T) {
	reg := repository.NewInMemoryRegistry()
	now := time.Now().UTC()
	// Seed oldest-first so the in-memory repository's reverse-insertion
	// order (which the Postgres backend realises as evaluated_at DESC)
	// yields a, b, c newest-first.
	seedEval(t, reg.EvaluationResults, "c", "high", "malware", 70, now.Add(-50*time.Hour))
	seedEval(t, reg.EvaluationResults, "b", "low", "marketing", 10, now.Add(-2*time.Hour))
	seedEval(t, reg.EvaluationResults, "a", "blocked", "phishing", 90, now.Add(-1*time.Hour))
	h := newTestEmailHandler(t, nil, nil, reg.EvaluationResults)

	t.Run("all", func(t *testing.T) {
		rec := doRequest(h.ServeMessages, http.MethodGet, "/internal/tenants/x/email-security/messages", map[string]string{"tid": testTenant})
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want 200 (%s)", rec.Code, rec.Body.String())
		}
		var out emailMessagesJSON
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Count != 3 || len(out.Messages) != 3 {
			t.Fatalf("count: got %d, want 3", out.Count)
		}
		// newest first
		if out.Messages[0].MessageID != "pmid-a" {
			t.Errorf("order: got %q first, want pmid-a", out.Messages[0].MessageID)
		}
		if out.Messages[0].Verdict != "malicious" {
			t.Errorf("verdict: got %q, want malicious", out.Messages[0].Verdict)
		}
	})

	t.Run("tier filter", func(t *testing.T) {
		rec := doRequest(h.ServeMessages, http.MethodGet, "/x?tier=blocked", map[string]string{"tid": testTenant})
		var out emailMessagesJSON
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Count != 1 || out.Messages[0].Tier != "blocked" {
			t.Fatalf("tier filter: got %+v", out.Messages)
		}
	})

	t.Run("verdict filter", func(t *testing.T) {
		rec := doRequest(h.ServeMessages, http.MethodGet, "/x?verdict=suspicious", map[string]string{"tid": testTenant})
		var out emailMessagesJSON
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Count != 1 || out.Messages[0].MessageID != "pmid-c" {
			t.Fatalf("verdict filter: got %+v", out.Messages)
		}
	})

	t.Run("since_hours filter", func(t *testing.T) {
		rec := doRequest(h.ServeMessages, http.MethodGet, "/x?since_hours=24", map[string]string{"tid": testTenant})
		var out emailMessagesJSON
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Count != 2 {
			t.Fatalf("since filter: got %d, want 2", out.Count)
		}
	})

	t.Run("bad tenant", func(t *testing.T) {
		rec := doRequest(h.ServeMessages, http.MethodGet, "/x", map[string]string{"tid": "not-a-uuid"})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("bad tenant: got %d, want 400", rec.Code)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		rec := doRequest(h.ServeMessages, http.MethodPost, "/x", map[string]string{"tid": testTenant})
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("method: got %d, want 405", rec.Code)
		}
	})

	t.Run("eval unconfigured", func(t *testing.T) {
		h503 := newTestEmailHandler(t, nil, nil, nil)
		rec := doRequest(h503.ServeMessages, http.MethodGet, "/x", map[string]string{"tid": testTenant})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("nil eval: got %d, want 503", rec.Code)
		}
	})
}

func TestServeMessageDetail(t *testing.T) {
	reg := repository.NewInMemoryRegistry()
	mid := seedEval(t, reg.EvaluationResults, "a", "blocked", "phishing", 90, time.Now().UTC())
	inv, err := investigation.NewService(investigation.ServiceConfig{
		EvaluationResults:      reg.EvaluationResults,
		CommunicationHistories: reg.CommunicationHistories,
	})
	if err != nil {
		t.Fatalf("investigation.NewService: %v", err)
	}
	h := newTestEmailHandler(t, nil, inv, reg.EvaluationResults)

	t.Run("found", func(t *testing.T) {
		rec := doRequest(h.ServeMessageDetail, http.MethodGet, "/x", map[string]string{"tid": testTenant, "mid": mid})
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want 200 (%s)", rec.Code, rec.Body.String())
		}
		var out emailMessageDetailJSON
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Verdict != "malicious" {
			t.Errorf("verdict: got %q, want malicious", out.Verdict)
		}
		if out.Result.Tier != "blocked" {
			t.Errorf("tier: got %q, want blocked", out.Result.Tier)
		}
	})

	t.Run("not found", func(t *testing.T) {
		rec := doRequest(h.ServeMessageDetail, http.MethodGet, "/x", map[string]string{"tid": testTenant, "mid": "missing"})
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status: got %d, want 404", rec.Code)
		}
	})

	t.Run("inv unconfigured", func(t *testing.T) {
		h503 := newTestEmailHandler(t, nil, nil, reg.EvaluationResults)
		rec := doRequest(h503.ServeMessageDetail, http.MethodGet, "/x", map[string]string{"tid": testTenant, "mid": mid})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("nil inv: got %d, want 503", rec.Code)
		}
	})
}

func TestServeSummary(t *testing.T) {
	reg := repository.NewInMemoryRegistry()
	now := time.Now().UTC()
	seedEval(t, reg.EvaluationResults, "a", "blocked", "phishing", 90, now.Add(-1*time.Hour))
	gen, err := dashboard.NewDashboardGenerator(dashboard.DashboardGeneratorConfig{Source: fakeMetricsSource{}})
	if err != nil {
		t.Fatalf("NewDashboardGenerator: %v", err)
	}
	h := newTestEmailHandler(t, gen, nil, reg.EvaluationResults)

	t.Run("ok", func(t *testing.T) {
		rec := doRequest(h.ServeSummary, http.MethodGet, "/x", map[string]string{"tid": testTenant})
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want 200 (%s)", rec.Code, rec.Body.String())
		}
		var out emailSummaryJSON
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !out.ModuleEnabled {
			t.Error("module_enabled: got false, want true")
		}
		if out.Scanned24h != 100 {
			t.Errorf("scanned: got %d, want 100", out.Scanned24h)
		}
		if out.Blocked24h != 5 {
			t.Errorf("blocked: got %d, want 5", out.Blocked24h)
		}
		if out.Quarantined24h != 7 {
			t.Errorf("quarantined: got %d, want 7", out.Quarantined24h)
		}
		if len(out.TopThreats) != 2 || out.TopThreats[0].Kind != "phishing" {
			t.Errorf("top threats: got %+v", out.TopThreats)
		}
		if len(out.Recent) != 1 || out.Recent[0].MessageID != "pmid-a" {
			t.Errorf("recent: got %+v", out.Recent)
		}
	})

	t.Run("dash unconfigured", func(t *testing.T) {
		h503 := newTestEmailHandler(t, nil, nil, reg.EvaluationResults)
		rec := doRequest(h503.ServeSummary, http.MethodGet, "/x", map[string]string{"tid": testTenant})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("nil dash: got %d, want 503", rec.Code)
		}
	})
}

func TestDeriveVerdict(t *testing.T) {
	cases := []struct {
		tier  string
		final string
		want  string
	}{
		{"blocked", "", "malicious"},
		{"high", "", "suspicious"},
		{"low", "", "benign"},
		{"", "", "benign"},
		{"blocked", "benign", "benign"},
	}
	for _, c := range cases {
		got := deriveVerdict(repository.EvaluationResult{Tier: c.tier, FinalVerdict: c.final})
		if got != c.want {
			t.Errorf("deriveVerdict(tier=%q,final=%q): got %q, want %q", c.tier, c.final, got, c.want)
		}
	}
}

func TestTopThreats(t *testing.T) {
	in := []dto.CategoryCount{
		{Category: "b", Count: 1},
		{Category: "a", Count: 5},
		{Category: "c", Count: 5},
	}
	out := topThreats(in)
	if len(out) != 3 {
		t.Fatalf("len: got %d, want 3", len(out))
	}
	// ties (a,c at 5) break on name, so a precedes c, then b at 1.
	if out[0].Kind != "a" || out[1].Kind != "c" || out[2].Kind != "b" {
		t.Errorf("order: got %+v", out)
	}
}

func TestParseLimit(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"", 50},
		{"garbage", 50},
		{"0", 50},
		{"-3", 50},
		{"10", 10},
		{"9999", 200},
	}
	for _, c := range cases {
		if got := parseLimit(c.raw, 50, 200); got != c.want {
			t.Errorf("parseLimit(%q): got %d, want %d", c.raw, got, c.want)
		}
	}
}

func TestParseSinceHours(t *testing.T) {
	if parseSinceHours("") != 0 {
		t.Error("empty should be 0")
	}
	if parseSinceHours("1000") != 0 {
		t.Error("out-of-range should be 0")
	}
	if parseSinceHours("24") != 24*time.Hour {
		t.Error("24 should be 24h")
	}
}
