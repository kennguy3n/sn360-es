package ternarybonsai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/inference/slm"
)

// TestEvaluate_HappyPath round-trips a well-formed verdict and
// asserts every Outcome field the LLM is supposed to populate.
func TestEvaluate_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q, want Bearer test-key", got)
		}
		var req slm.ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if req.Model != "ternary-bonsai-8b" {
			t.Errorf("model = %q, want ternary-bonsai-8b", req.Model)
		}
		if req.Response == nil || req.Response.Type != "json_object" {
			t.Errorf("response_format = %+v, want json_object", req.Response)
		}
		if len(req.Messages) != 2 {
			t.Fatalf("messages len = %d, want 2", len(req.Messages))
		}
		if req.Messages[0].Role != "system" {
			t.Errorf("messages[0].Role = %q, want system", req.Messages[0].Role)
		}
		_ = writeChat(w, `{"score": 73, "categories": ["LIKELY_PHISHING", "SUSPICIOUS_URL"], "confidence": 0.88, "explanation": "URL mismatch with displayed text"}`)
	}))
	defer srv.Close()

	c, err := NewClient(Config{URL: srv.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	out, err := c.Evaluate(context.Background(), dto.EvaluateRequest{
		TenantID: "tenant-1",
		Subject:  "Verify your account",
		Body:     "Click here to verify",
	}, dto.Tier1Outcome{Score: 60, Confidence: 0.7})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Score != 73 {
		t.Errorf("Score = %d, want 73", out.Score)
	}
	if out.Confidence != 0.88 {
		t.Errorf("Confidence = %f, want 0.88", out.Confidence)
	}
	if !strings.Contains(out.Explanation, "URL mismatch") {
		t.Errorf("Explanation = %q, missing URL mismatch", out.Explanation)
	}
	if out.ModelName != "ternary-bonsai-8b" {
		t.Errorf("ModelName = %q, want ternary-bonsai-8b", out.ModelName)
	}
	if out.LatencyMs < 0 {
		t.Errorf("LatencyMs = %d, want >= 0", out.LatencyMs)
	}
	wantCats := []constant.Category{constant.CategoryLikelyPhishing, constant.CategorySuspiciousURL}
	if len(out.Categories) != len(wantCats) {
		t.Fatalf("Categories len = %d, want %d (%+v)", len(out.Categories), len(wantCats), out.Categories)
	}
	for i, want := range wantCats {
		if out.Categories[i] != want {
			t.Errorf("Categories[%d] = %q, want %q", i, out.Categories[i], want)
		}
	}
}

func TestEvaluate_HTTP5xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":{"message":"upstream is on fire"}}`)
	}))
	defer srv.Close()

	c, err := NewClient(Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err == nil {
		t.Fatal("Evaluate err = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("err = %q, want substring 'HTTP 500'", err.Error())
	}
	if !strings.Contains(err.Error(), "upstream is on fire") {
		t.Errorf("err = %q, want body snippet 'upstream is on fire'", err.Error())
	}
}

func TestEvaluate_EmptyChoicesReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = writeRawJSON(w, `{"choices": []}`)
	}))
	defer srv.Close()

	c, err := NewClient(Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err == nil {
		t.Fatal("Evaluate err = nil, want non-nil")
	}
	if !errorsIs(err, slm.ErrEmptyResponse) {
		t.Errorf("err = %q, want errors.Is(slm.ErrEmptyResponse)", err.Error())
	}
}

func TestEvaluate_VerdictJSONInsideProse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = writeChat(w, "Sure — here's my verdict:\n{\"score\": 42, \"confidence\": 0.5}\nLet me know if you need more.")
	}))
	defer srv.Close()

	c, err := NewClient(Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	out, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Score != 42 {
		t.Errorf("Score = %d, want 42", out.Score)
	}
}

func TestNewClient_RejectsEmptyURL(t *testing.T) {
	if _, err := NewClient(Config{}); err == nil {
		t.Fatal("NewClient(empty) err = nil, want non-nil")
	}
}

func TestFactory_RegisteredUnderName(t *testing.T) {
	if Name != "ternarybonsai" {
		t.Errorf("Name = %q, want ternarybonsai", Name)
	}
	c, err := slm.New(slm.ProviderConfig{Name: Name, URL: "http://stub"})
	if err != nil {
		t.Fatalf("slm.New: %v", err)
	}
	if c == nil {
		t.Fatal("slm.New returned nil client")
	}
}

func TestEvaluate_PreservesDefaultsOnZeroValues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req slm.ChatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.MaxTokens != DefaultMaxTokens {
			t.Errorf("MaxTokens = %d, want %d", req.MaxTokens, DefaultMaxTokens)
		}
		if req.Temperature != DefaultTemperature {
			t.Errorf("Temperature = %f, want %f", req.Temperature, DefaultTemperature)
		}
		_ = writeChat(w, `{"score": 0}`)
	}))
	defer srv.Close()

	c, err := NewClient(Config{URL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
}

// --- helpers --------------------------------------------------------------

// writeChat encodes content as the message of a single-choice
// chat-completions response and writes it to w.
func writeChat(w http.ResponseWriter, content string) error {
	payload := map[string]any{
		"choices": []map[string]any{
			{"message": map[string]string{"role": "assistant", "content": content}},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(payload)
}

func writeRawJSON(w http.ResponseWriter, body string) error {
	w.Header().Set("Content-Type", "application/json")
	_, err := io.WriteString(w, body)
	return err
}

// errorsIs avoids importing errors in every test file.
func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
