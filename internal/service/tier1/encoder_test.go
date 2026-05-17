package tier1

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

func newTestClient(t *testing.T, srv *httptest.Server, override func(*Config)) *Client {
	t.Helper()
	cfg := Config{URL: srv.URL, Timeout: 500 * time.Millisecond, BatchTimeout: 1 * time.Second}
	if override != nil {
		override(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestConfig_Validate_RequiresURL(t *testing.T) {
	if _, err := (Config{}).Validate(); err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestConfig_Validate_AppliesDefaults(t *testing.T) {
	v, err := (Config{URL: "http://encoder"}).Validate()
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if v.PredictPath != "/predict" || v.BatchPath != "/predict/batch" || v.HealthPath != "/health" {
		t.Fatalf("paths: %+v", v)
	}
	if v.Timeout != 5*time.Second || v.BatchTimeout != 15*time.Second {
		t.Fatalf("timeouts: %+v", v)
	}
	if v.MaxBatchSize != 64 {
		t.Fatalf("MaxBatchSize: %d", v.MaxBatchSize)
	}
}

func TestThresholds_Decision(t *testing.T) {
	th := DefaultThresholds()
	cases := []struct {
		score int
		want  Verdict
	}{
		{10, VerdictPass},
		{30, VerdictEscalate},
		{55, VerdictEscalate},
		{75, VerdictFlag},
	}
	for _, c := range cases {
		if got := th.Decision(c.score); got != c.want {
			t.Fatalf("score=%d got=%q want=%q", c.score, got, c.want)
		}
	}
}

func TestThresholds_AdjustForRelationship(t *testing.T) {
	th := DefaultThresholds()
	// Partner lowers thresholds by SuppressPartner (-10).
	got := th.AdjustForRelationship(dto.RelationshipPartner)
	if got.PassBelow != 10 || got.FlagAbove != 50 {
		t.Fatalf("partner: %+v", got)
	}
	// FirstTimeExternal forces escalation (PassBelow=0).
	got = th.AdjustForRelationship(dto.RelationshipFirstTimeExternal)
	if got.PassBelow != 0 {
		t.Fatalf("firsttime PassBelow: %d", got.PassBelow)
	}
}

func TestClient_Predict_Success(t *testing.T) {
	want := PredictResponse{Score: 72, Confidence: 0.91, Language: "en", ModelTag: "xlm-r-v3"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/predict" {
			t.Errorf("path: %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("auth: %q", got)
		}
		var in PredictRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode: %v", err)
		}
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, func(c *Config) { c.AuthToken = "secret" })

	got, err := c.Predict(context.Background(), PredictRequest{
		Subject:   "verify your account",
		Body:      "click here please",
		MessageID: "pmid-1",
	})
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if got.Score != want.Score || got.Confidence != want.Confidence {
		t.Fatalf("response: %+v", got)
	}
	if got.MessageID != "pmid-1" {
		t.Fatalf("MessageID should default from request: %q", got.MessageID)
	}
}

func TestClient_Predict_EmptyInputRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("server should not be called")
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)
	if _, err := c.Predict(context.Background(), PredictRequest{}); err == nil {
		t.Fatal("expected empty-input error")
	}
}

func TestClient_Predict_HTTPErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)
	if _, err := c.Predict(context.Background(), PredictRequest{Body: "x"}); err == nil {
		t.Fatal("expected error from 500")
	}
}

func TestClient_Predict_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, func(c *Config) {
		c.Timeout = 50 * time.Millisecond
		c.BatchTimeout = 100 * time.Millisecond
	})
	if _, err := c.Predict(context.Background(), PredictRequest{Body: "x"}); err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestClient_Predict_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "{not json")
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)
	if _, err := c.Predict(context.Background(), PredictRequest{Body: "x"}); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestClient_PredictBatch_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/predict/batch" {
			t.Errorf("path: %q", r.URL.Path)
		}
		var in BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode: %v", err)
		}
		out := BatchResponse{Items: make([]PredictResponse, len(in.Items))}
		for i, it := range in.Items {
			out.Items[i] = PredictResponse{
				MessageID: it.MessageID,
				Score:     50 + i,
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)

	got, err := c.PredictBatch(context.Background(), []PredictRequest{
		{Subject: "a", MessageID: "m1"},
		{Subject: "b", MessageID: "m2"},
	})
	if err != nil {
		t.Fatalf("PredictBatch: %v", err)
	}
	if len(got) != 2 || got[0].MessageID != "m1" || got[1].MessageID != "m2" {
		t.Fatalf("responses: %+v", got)
	}
}

func TestClient_PredictBatch_EmptyIsNoop(t *testing.T) {
	c := newTestClient(t, httptest.NewServer(http.NotFoundHandler()), nil)
	out, err := c.PredictBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil, got %+v", out)
	}
}

func TestClient_PredictBatch_TooLarge(t *testing.T) {
	c := newTestClient(t, httptest.NewServer(http.NotFoundHandler()), func(c *Config) { c.MaxBatchSize = 2 })
	items := make([]PredictRequest, 3)
	for i := range items {
		items[i].Body = "x"
	}
	if _, err := c.PredictBatch(context.Background(), items); err == nil {
		t.Fatal("expected too-large error")
	}
}

func TestClient_PredictBatch_FallsBackOn404(t *testing.T) {
	var singleHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/predict/batch":
			http.NotFound(w, r)
		case "/predict":
			singleHits++
			_ = json.NewEncoder(w).Encode(PredictResponse{Score: 10})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)
	out, err := c.PredictBatch(context.Background(), []PredictRequest{
		{Body: "a", MessageID: "m1"}, {Body: "b", MessageID: "m2"},
	})
	if err != nil {
		t.Fatalf("PredictBatch: %v", err)
	}
	if singleHits != 2 {
		t.Fatalf("expected 2 individual fallback calls, got %d", singleHits)
	}
	if out[0].MessageID != "m1" {
		t.Fatalf("MessageID preserved across fallback: %+v", out)
	}
}

func TestClient_PredictBatch_FallsBackOn405(t *testing.T) {
	var singleHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/predict/batch":
			w.WriteHeader(http.StatusMethodNotAllowed)
		case "/predict":
			singleHits++
			_ = json.NewEncoder(w).Encode(PredictResponse{Score: 5})
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)
	_, err := c.PredictBatch(context.Background(), []PredictRequest{{Body: "a"}})
	if err != nil {
		t.Fatalf("PredictBatch: %v", err)
	}
	if singleHits != 1 {
		t.Fatalf("singleHits=%d", singleHits)
	}
}

func TestClient_PredictBatch_NonHandlerHTTPErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)
	if _, err := c.PredictBatch(context.Background(), []PredictRequest{{Body: "a"}}); err == nil {
		t.Fatal("expected 502 error")
	}
}

func TestClient_PredictBatch_ResponseLengthMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(BatchResponse{Items: []PredictResponse{{Score: 1}}})
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)
	_, err := c.PredictBatch(context.Background(), []PredictRequest{{Body: "a"}, {Body: "b"}})
	if err == nil || !strings.Contains(err.Error(), "expected 2 responses") {
		t.Fatalf("err: %v", err)
	}
}

func TestClient_Health_200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("path: %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)
	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
}

func TestClient_Health_FailingStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)
	if err := c.Health(context.Background()); err == nil {
		t.Fatal("expected health failure")
	}
}

func TestClient_Score_ClampsAndDecides(t *testing.T) {
	cases := []struct {
		raw       int
		clamped   int
		want      Verdict
	}{
		{-10, 0, VerdictPass},
		{50, 50, VerdictEscalate},
		{120, 100, VerdictFlag},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(PredictResponse{Score: c.raw})
		}))
		client := newTestClient(t, srv, nil)
		v, score, _, err := client.Score(context.Background(), PredictRequest{Body: "x"}, DefaultThresholds())
		srv.Close()
		if err != nil {
			t.Fatalf("Score: %v", err)
		}
		if score != c.clamped {
			t.Fatalf("raw=%d clamped=%d got=%d", c.raw, c.clamped, score)
		}
		if v != c.want {
			t.Fatalf("raw=%d verdict=%q want=%q", c.raw, v, c.want)
		}
	}
}

func TestClient_Accessors(t *testing.T) {
	c, _ := New(Config{URL: "http://encoder", Timeout: 250 * time.Millisecond, MaxBatchSize: 32})
	if c.MaxBatchSize() != 32 {
		t.Fatalf("MaxBatchSize accessor: %d", c.MaxBatchSize())
	}
	if c.PredictTimeout() != 250*time.Millisecond {
		t.Fatalf("PredictTimeout accessor: %v", c.PredictTimeout())
	}
}

// Ensure New surfaces validation errors.
func TestNew_PropagatesValidate(t *testing.T) {
	if _, err := New(Config{}); err == nil || !errors.Is(err, err) {
		t.Fatalf("expected validation error, got %v", err)
	}
}
