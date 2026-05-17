package evaluate

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
)

// stubChatResponse builds a server response that wraps the supplied
// content string into the OpenAI chat-completions JSON envelope.
func stubChatResponse(t *testing.T, content string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tier2ChatResponse{
			Choices: []struct {
				Message tier2ChatMessage `json:"message"`
			}{{Message: tier2ChatMessage{Role: "assistant", Content: content}}},
		})
	})
}

func TestTier2HTTPClient_Evaluate_Success(t *testing.T) {
	t.Parallel()

	var captured tier2ChatRequest
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		authHeader = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		verdict := tier2Verdict{
			Score:       82,
			Categories:  []string{"LIKELY_PHISHING", "CREDENTIAL_HARVESTING"},
			Confidence:  0.88,
			Explanation: "Asks for credentials via lookalike domain.",
		}
		blob, _ := json.Marshal(verdict)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tier2ChatResponse{
			Choices: []struct {
				Message tier2ChatMessage `json:"message"`
			}{{Message: tier2ChatMessage{Role: "assistant", Content: string(blob)}}},
		})
	}))
	t.Cleanup(srv.Close)

	client, err := NewTier2HTTPClient(Tier2HTTPConfig{
		URL:     srv.URL,
		APIKey:  "test-key",
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewTier2HTTPClient: %v", err)
	}

	req := dto.EvaluateRequest{
		Subject: "Verify your account",
		Body:    "Click here to log in.",
		Signals: dto.RiskSignals{SenderDomain: "secure-bank-login.example"},
	}
	hint := dto.Tier1Outcome{Score: 65, Confidence: 0.7}
	got, err := client.Evaluate(context.Background(), req, hint)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if authHeader != "Bearer test-key" {
		t.Errorf("Authorization header: got %q want %q", authHeader, "Bearer test-key")
	}
	if captured.Model != "ternary-bonsai-8b" {
		t.Errorf("Model: got %q", captured.Model)
	}
	if captured.Response == nil || captured.Response.Type != "json_object" {
		t.Errorf("response_format not requested: %+v", captured.Response)
	}
	if len(captured.Messages) != 2 || captured.Messages[0].Role != "system" {
		t.Fatalf("unexpected messages: %+v", captured.Messages)
	}
	if !strings.Contains(captured.Messages[1].Content, "Verify your account") {
		t.Errorf("user prompt missing subject: %s", captured.Messages[1].Content)
	}
	if !strings.Contains(captured.Messages[1].Content, "secure-bank-login.example") {
		t.Errorf("user prompt missing sender domain")
	}
	if !strings.Contains(captured.Messages[1].Content, "Tier-1 hint") {
		t.Errorf("user prompt missing Tier-1 hint")
	}

	if got.Score != 82 {
		t.Errorf("Score: got %d want 82", got.Score)
	}
	if got.Confidence != 0.88 {
		t.Errorf("Confidence: got %v want 0.88", got.Confidence)
	}
	if got.ModelName != "ternary-bonsai-8b" {
		t.Errorf("ModelName: got %q", got.ModelName)
	}
	if got.Explanation == "" {
		t.Errorf("Explanation should be propagated")
	}
	if len(got.Categories) != 2 {
		t.Fatalf("Categories: got %v", got.Categories)
	}
	if got.Categories[0] != constant.CategoryLikelyPhishing {
		t.Errorf("Category[0]: got %q", got.Categories[0])
	}
	if got.Categories[1] != constant.CategoryCredentialHarvesting {
		t.Errorf("Category[1]: got %q", got.Categories[1])
	}
}

func TestTier2HTTPClient_Evaluate_FiltersUnknownCategories(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(stubChatResponse(t,
		`{"score":40,"categories":["LIKELY_PHISHING","MADE_UP_LABEL"],"confidence":0.5}`))
	t.Cleanup(srv.Close)

	client, err := NewTier2HTTPClient(Tier2HTTPConfig{URL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewTier2HTTPClient: %v", err)
	}
	got, err := client.Evaluate(context.Background(),
		dto.EvaluateRequest{Subject: "s", Body: "b"}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(got.Categories) != 1 {
		t.Fatalf("expected 1 valid category, got %v", got.Categories)
	}
	if got.Categories[0] != constant.CategoryLikelyPhishing {
		t.Errorf("got %q", got.Categories[0])
	}
}

func TestTier2HTTPClient_Evaluate_ClampsScoreAndConfidence(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(stubChatResponse(t,
		`{"score":150,"confidence":1.7}`))
	t.Cleanup(srv.Close)

	client, err := NewTier2HTTPClient(Tier2HTTPConfig{URL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewTier2HTTPClient: %v", err)
	}
	got, err := client.Evaluate(context.Background(),
		dto.EvaluateRequest{Subject: "s"}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Score != 100 {
		t.Errorf("Score not clamped: got %d", got.Score)
	}
	if got.Confidence != 1 {
		t.Errorf("Confidence not clamped: got %v", got.Confidence)
	}
}

func TestTier2HTTPClient_Evaluate_MalformedResponse(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `not json at all`)
	}))
	t.Cleanup(srv.Close)

	client, err := NewTier2HTTPClient(Tier2HTTPConfig{URL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewTier2HTTPClient: %v", err)
	}
	_, err = client.Evaluate(context.Background(),
		dto.EvaluateRequest{Subject: "s"}, dto.Tier1Outcome{})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestTier2HTTPClient_Evaluate_ServerError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	client, err := NewTier2HTTPClient(Tier2HTTPConfig{URL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewTier2HTTPClient: %v", err)
	}
	_, err = client.Evaluate(context.Background(),
		dto.EvaluateRequest{Subject: "s"}, dto.Tier1Outcome{})
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("expected HTTP 502 error, got %v", err)
	}
}

func TestTier2HTTPClient_Evaluate_Timeout(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(srv.Close)

	client, err := NewTier2HTTPClient(Tier2HTTPConfig{URL: srv.URL, Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewTier2HTTPClient: %v", err)
	}
	_, err = client.Evaluate(context.Background(),
		dto.EvaluateRequest{Subject: "s"}, dto.Tier1Outcome{})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestNewTier2HTTPClient_RequiresURL(t *testing.T) {
	t.Parallel()
	if _, err := NewTier2HTTPClient(Tier2HTTPConfig{}); err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestParseTier2Verdict_ExtractsEmbeddedJSON(t *testing.T) {
	t.Parallel()
	got, err := parseTier2Verdict(`Here is the verdict:
{"score":12,"categories":["NEWSLETTER"]} -- end.`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Score != 12 {
		t.Errorf("score: %d", got.Score)
	}
	if len(got.Categories) != 1 || got.Categories[0] != "NEWSLETTER" {
		t.Errorf("categories: %v", got.Categories)
	}
}

func TestParseTier2Verdict_RejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := parseTier2Verdict("   "); err == nil {
		t.Fatal("expected error for empty content")
	}
	if _, err := parseTier2Verdict("no braces here"); err == nil {
		t.Fatal("expected error for missing braces")
	}
}
