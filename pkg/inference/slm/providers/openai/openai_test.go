package openai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/inference/slm"
)

// noSleep is a context-aware sleep that returns immediately so the
// retry loop doesn't add wall-clock delay to the unit tests.
func noSleep(_ context.Context, _ time.Duration) error { return nil }

func writeChoice(w http.ResponseWriter, content string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"choices": []map[string]any{
			{"message": map[string]string{"role": "assistant", "content": content}},
		},
	})
}

func TestEvaluate_StrictHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-test" {
			t.Errorf("Authorization = %q, want Bearer sk-test", r.Header.Get("Authorization"))
		}
		writeChoice(w, `{"score": 91, "categories": ["BEC_IMPERSONATION"], "confidence": 0.99}`)
	}))
	defer srv.Close()

	c, err := NewClient(Config{URL: srv.URL, APIKey: "sk-test", Sleep: noSleep})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	out, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Score != 91 {
		t.Errorf("Score = %d, want 91", out.Score)
	}
	if out.Confidence != 0.99 {
		t.Errorf("Confidence = %f, want 0.99", out.Confidence)
	}
}

func TestEvaluate_MissingChoicesIsTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices": []}`)
	}))
	defer srv.Close()

	c, _ := NewClient(Config{URL: srv.URL, Sleep: noSleep})
	_, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err == nil {
		t.Fatal("err = nil, want non-nil")
	}
	if !errors.Is(err, slm.ErrEmptyResponse) {
		t.Errorf("err = %v, want errors.Is(slm.ErrEmptyResponse)", err)
	}
}

func TestEvaluate_EmptyContentIsTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeChoice(w, "   ")
	}))
	defer srv.Close()
	c, _ := NewClient(Config{URL: srv.URL, Sleep: noSleep})
	_, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err == nil {
		t.Fatal("err = nil, want non-nil")
	}
	if !errors.Is(err, slm.ErrEmptyResponse) {
		t.Errorf("err = %v, want errors.Is(slm.ErrEmptyResponse)", err)
	}
}

func TestEvaluate_ProseInsteadOfJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeChoice(w, "I cannot classify this email.")
	}))
	defer srv.Close()
	c, _ := NewClient(Config{URL: srv.URL, Sleep: noSleep})
	_, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err == nil {
		t.Fatal("err = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "no JSON object") {
		t.Errorf("err = %q, want substring 'no JSON object'", err.Error())
	}
}

func TestEvaluate_RateLimitedRetriedThenSucceeds(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"rate limited"}`)
			return
		}
		writeChoice(w, `{"score": 50}`)
	}))
	defer srv.Close()

	c, _ := NewClient(Config{URL: srv.URL, Sleep: noSleep, MaxRetries: 1})
	out, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Score != 50 {
		t.Errorf("Score = %d, want 50", out.Score)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

func TestEvaluate_RateLimitedExhaustsRetriesReturnsTypedError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c, _ := NewClient(Config{URL: srv.URL, Sleep: noSleep, MaxRetries: 1})
	_, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err == nil {
		t.Fatal("err = nil, want non-nil")
	}
	var rl *slm.RateLimitedError
	if !errors.As(err, &rl) {
		t.Errorf("err = %v, want *slm.RateLimitedError", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Errorf("attempts = %d, want 2 (initial + 1 retry)", got)
	}
}

func TestEvaluate_5xxThenSuccess(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		writeChoice(w, `{"score": 12}`)
	}))
	defer srv.Close()

	c, _ := NewClient(Config{URL: srv.URL, Sleep: noSleep, MaxRetries: 1})
	out, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Score != 12 {
		t.Errorf("Score = %d, want 12", out.Score)
	}
}

func TestEvaluate_4xxNotRetriedReturnsImmediately(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"model not found"}`)
	}))
	defer srv.Close()

	c, _ := NewClient(Config{URL: srv.URL, Sleep: noSleep, MaxRetries: 3})
	_, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err == nil {
		t.Fatal("err = nil, want non-nil")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("attempts = %d, want 1 (4xx is non-retryable)", got)
	}
	if !strings.Contains(err.Error(), "HTTP 400") {
		t.Errorf("err = %q, want substring 'HTTP 400'", err.Error())
	}
}

func TestReadSnippetAndRetryAfter_DeltaSeconds(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{"Retry-After": []string{"5"}},
		Body:   io.NopCloser(strings.NewReader(`{"error":"x"}`)),
	}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	snippet, d := readSnippetAndRetryAfter(resp, func() time.Time { return now })
	if d != 5*time.Second {
		t.Errorf("d = %v, want 5s", d)
	}
	if !strings.Contains(snippet, "error") {
		t.Errorf("snippet = %q, missing 'error'", snippet)
	}
}

func TestReadSnippetAndRetryAfter_HTTPDate(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	target := now.Add(10 * time.Second)
	resp := &http.Response{
		Header: http.Header{"Retry-After": []string{target.UTC().Format(http.TimeFormat)}},
		Body:   io.NopCloser(strings.NewReader("")),
	}
	_, d := readSnippetAndRetryAfter(resp, func() time.Time { return now })
	if d <= 0 || d > 11*time.Second {
		t.Errorf("d = %v, want ~10s", d)
	}
}

func TestReadSnippetAndRetryAfter_MissingHeader(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader("")),
	}
	_, d := readSnippetAndRetryAfter(resp, time.Now)
	if d != 0 {
		t.Errorf("d = %v, want 0", d)
	}
}

func TestEvaluate_RetryAfterCappedAtMaxRetryAfter(t *testing.T) {
	var sleeps []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "999999")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c, _ := NewClient(Config{
		URL: srv.URL,
		Sleep: func(_ context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return nil
		},
		MaxRetries: 1,
	})
	_, _ = c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if len(sleeps) == 0 {
		t.Fatal("sleep not called")
	}
	for _, d := range sleeps {
		if d > MaxRetryAfter {
			t.Errorf("sleep duration %v exceeds MaxRetryAfter %v", d, MaxRetryAfter)
		}
	}
}

func TestFactory_HonoursMaxRetries(t *testing.T) {
	c, err := slm.New(slm.ProviderConfig{
		Name:         Name,
		URL:          "http://stub",
		ProviderOpts: map[string]string{"max_retries": "3"},
	})
	if err != nil {
		t.Fatalf("slm.New: %v", err)
	}
	if c == nil {
		t.Fatal("slm.New returned nil")
	}
}

func TestFactory_RejectsInvalidMaxRetries(t *testing.T) {
	_, err := slm.New(slm.ProviderConfig{
		Name:         Name,
		URL:          "http://stub",
		ProviderOpts: map[string]string{"max_retries": "not-a-number"},
	})
	if err == nil {
		t.Fatal("err = nil, want non-nil")
	}
}

func TestFactory_RejectsNegativeMaxRetries(t *testing.T) {
	_, err := slm.New(slm.ProviderConfig{
		Name:         Name,
		URL:          "http://stub",
		ProviderOpts: map[string]string{"max_retries": "-2"},
	})
	if err == nil {
		t.Fatal("err = nil, want non-nil")
	}
}

func TestNewClient_RejectsEmptyURL(t *testing.T) {
	if _, err := NewClient(Config{}); err == nil {
		t.Fatal("NewClient(empty) err = nil, want non-nil")
	}
}

func TestEvaluate_RespectsContextCancellation(t *testing.T) {
	// Client-side timeout < server's response delay. The request
	// must abort before the server replies.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}))
	srv.Config.ReadTimeout = 100 * time.Millisecond
	srv.Start()
	defer srv.Close()

	c, _ := NewClient(Config{URL: srv.URL, Timeout: 30 * time.Millisecond, Sleep: noSleep})
	_, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err == nil {
		t.Fatal("err = nil, want timeout / cancellation error")
	}
}
