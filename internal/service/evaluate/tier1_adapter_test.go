package evaluate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/tier1"
)

func TestTier1Adapter_Evaluate_MapsRequestAndResponse(t *testing.T) {
	t.Parallel()

	var captured tier1.PredictRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/predict" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("unexpected content-type: %s", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(tier1.PredictResponse{
			MessageID:   captured.MessageID,
			Score:       73,
			Confidence:  0.92,
			Language:    "en",
			ModelTag:    "xlm-roberta-v1.2",
			ReasonCodes: []string{"URGENT_TONE", "WIRE_REQUEST"},
		})
	}))
	t.Cleanup(srv.Close)

	client, err := tier1.New(tier1.Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("tier1.New: %v", err)
	}
	adapter := NewTier1Adapter(client, tier1.DefaultThresholds())

	req := dto.EvaluateRequest{
		MessageID: "msg-abc",
		Subject:   "URGENT wire transfer",
		Body:      "Please wire $50k now.",
		Signals: dto.RiskSignals{
			SenderDomain: "ceo-impersonator.example",
		},
	}
	got, err := adapter.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if captured.MessageID != "msg-abc" {
		t.Errorf("MessageID not propagated: got %q", captured.MessageID)
	}
	if captured.Subject != req.Subject {
		t.Errorf("Subject not propagated: got %q", captured.Subject)
	}
	if captured.Body != req.Body {
		t.Errorf("Body not propagated: got %q", captured.Body)
	}
	if captured.SenderDomain != req.Signals.SenderDomain {
		t.Errorf("SenderDomain not propagated: got %q want %q",
			captured.SenderDomain, req.Signals.SenderDomain)
	}

	if got.Score != 73 {
		t.Errorf("Score: got %d want 73", got.Score)
	}
	if got.Confidence != 0.92 {
		t.Errorf("Confidence: got %v want 0.92", got.Confidence)
	}
	if got.Language != "en" {
		t.Errorf("Language: got %q want en", got.Language)
	}
	if got.ModelName != "xlm-roberta-v1.2" {
		t.Errorf("ModelName: got %q want xlm-roberta-v1.2", got.ModelName)
	}
	if got.LatencyMs < 0 {
		t.Errorf("LatencyMs negative: %d", got.LatencyMs)
	}
}

func TestTier1Adapter_Evaluate_ClampsScore(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		emit     int
		expected int
	}{
		{"under", -5, 0},
		{"in-range", 42, 42},
		{"over", 137, 100},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(tier1.PredictResponse{Score: tc.emit})
			}))
			t.Cleanup(srv.Close)

			client, err := tier1.New(tier1.Config{URL: srv.URL})
			if err != nil {
				t.Fatalf("tier1.New: %v", err)
			}
			adapter := NewTier1Adapter(client, tier1.DefaultThresholds())

			got, err := adapter.Evaluate(context.Background(), dto.EvaluateRequest{
				Subject: "hello",
				Body:    "world",
			})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got.Score != tc.expected {
				t.Errorf("clamp(%d) = %d, want %d", tc.emit, got.Score, tc.expected)
			}
		})
	}
}

func TestTier1Adapter_Evaluate_PropagatesError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	client, err := tier1.New(tier1.Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("tier1.New: %v", err)
	}
	adapter := NewTier1Adapter(client, tier1.DefaultThresholds())

	_, err = adapter.Evaluate(context.Background(), dto.EvaluateRequest{
		Subject: "hi",
		Body:    "there",
	})
	if err == nil {
		t.Fatal("expected error from upstream 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to mention HTTP 500, got %v", err)
	}
}

func TestTier1Adapter_Evaluate_NilClient(t *testing.T) {
	t.Parallel()
	var a *Tier1Adapter
	_, err := a.Evaluate(context.Background(), dto.EvaluateRequest{Subject: "x", Body: "y"})
	if err == nil {
		t.Fatal("expected error from nil adapter")
	}
}
