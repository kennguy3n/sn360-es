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

	"github.com/kennguy3n/sn360-es/internal/dto"
)

func TestRspamdHTTPClient_Score_Success(t *testing.T) {
	t.Parallel()

	var (
		capturedHeaders http.Header
		capturedBody    string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/checkv2" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		capturedHeaders = r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		capturedBody = string(raw)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"score":          7.3,
			"required_score": 5.0,
			"action":         "add header",
			"symbols": map[string]any{
				"R_DKIM_ALLOW": map[string]any{"score": -1.0, "name": "R_DKIM_ALLOW"},
				"R_SPF_FAIL":   map[string]any{"score": 4.5, "name": "R_SPF_FAIL"},
			},
		})
	}))
	t.Cleanup(srv.Close)

	client, err := NewRspamdHTTPClient(RspamdHTTPConfig{
		URL:      srv.URL,
		Password: "s3cret",
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("NewRspamdHTTPClient: %v", err)
	}

	req := dto.EvaluateRequest{
		MessageID: "msg-1",
		Sender:    "alice@example.com",
		Recipient: "bob@example.org",
		CC:        []string{"carol@example.org"},
		Subject:   "Test",
		Body:      "Hello, world",
	}
	got, err := client.Score(context.Background(), req)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	if capturedHeaders.Get("Password") != "s3cret" {
		t.Errorf("Password header: got %q want s3cret", capturedHeaders.Get("Password"))
	}
	if capturedHeaders.Get("From") != "alice@example.com" {
		t.Errorf("From header: got %q", capturedHeaders.Get("From"))
	}
	if capturedHeaders.Get("Rcpt") != "bob@example.org" {
		t.Errorf("Rcpt header: got %q", capturedHeaders.Get("Rcpt"))
	}
	if capturedHeaders.Get("Queue-Id") != "msg-1" {
		t.Errorf("Queue-Id header: got %q", capturedHeaders.Get("Queue-Id"))
	}

	wantParts := []string{
		"Message-ID: <msg-1>",
		"From: alice@example.com",
		"To: bob@example.org",
		"Cc: carol@example.org",
		"Subject: Test",
		"Hello, world",
	}
	for _, part := range wantParts {
		if !strings.Contains(capturedBody, part) {
			t.Errorf("payload missing %q\nbody: %q", part, capturedBody)
		}
	}

	if got.Score != 7.3 {
		t.Errorf("Score: got %v want 7.3", got.Score)
	}
	if got.Threshold != 5.0 {
		t.Errorf("Threshold: got %v want 5.0", got.Threshold)
	}
	if got.Action != "add header" {
		t.Errorf("Action: got %q", got.Action)
	}
	if got.Symbols["R_DKIM_ALLOW"] != -1.0 {
		t.Errorf("symbol R_DKIM_ALLOW: %v", got.Symbols)
	}
	if got.Symbols["R_SPF_FAIL"] != 4.5 {
		t.Errorf("symbol R_SPF_FAIL: %v", got.Symbols)
	}
	if got.LatencyMs < 0 {
		t.Errorf("LatencyMs negative: %d", got.LatencyMs)
	}
}

func TestRspamdHTTPClient_Score_NoPassword(t *testing.T) {
	t.Parallel()
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Password")
		_ = json.NewEncoder(w).Encode(map[string]any{"score": 0.0, "action": "no action"})
	}))
	t.Cleanup(srv.Close)

	client, err := NewRspamdHTTPClient(RspamdHTTPConfig{URL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewRspamdHTTPClient: %v", err)
	}
	if _, err := client.Score(context.Background(), dto.EvaluateRequest{Body: "hi"}); err != nil {
		t.Fatalf("Score: %v", err)
	}
	if seen != "" {
		t.Errorf("Password header should be absent when not configured, got %q", seen)
	}
}

func TestRspamdHTTPClient_Score_ClampsScore(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		emit     float64
		expected float64
	}{
		{"under", -100, -50},
		{"in-range", 12.5, 12.5},
		{"over", 500, 100},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"score": tc.emit})
			}))
			t.Cleanup(srv.Close)

			client, err := NewRspamdHTTPClient(RspamdHTTPConfig{URL: srv.URL, Timeout: time.Second})
			if err != nil {
				t.Fatalf("NewRspamdHTTPClient: %v", err)
			}
			got, err := client.Score(context.Background(), dto.EvaluateRequest{Body: "x"})
			if err != nil {
				t.Fatalf("Score: %v", err)
			}
			if got.Score != tc.expected {
				t.Errorf("clamp(%v): got %v want %v", tc.emit, got.Score, tc.expected)
			}
		})
	}
}

func TestRspamdHTTPClient_Score_MalformedResponse(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `not-json`)
	}))
	t.Cleanup(srv.Close)

	client, err := NewRspamdHTTPClient(RspamdHTTPConfig{URL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewRspamdHTTPClient: %v", err)
	}
	_, err = client.Score(context.Background(), dto.EvaluateRequest{Body: "x"})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestRspamdHTTPClient_Score_ServerError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rspamd error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	client, err := NewRspamdHTTPClient(RspamdHTTPConfig{URL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewRspamdHTTPClient: %v", err)
	}
	_, err = client.Score(context.Background(), dto.EvaluateRequest{Body: "x"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected HTTP 500 error, got %v", err)
	}
}

func TestRspamdHTTPClient_Score_Timeout(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(srv.Close)

	client, err := NewRspamdHTTPClient(RspamdHTTPConfig{URL: srv.URL, Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewRspamdHTTPClient: %v", err)
	}
	_, err = client.Score(context.Background(), dto.EvaluateRequest{Body: "x"})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestNewRspamdHTTPClient_RequiresURL(t *testing.T) {
	t.Parallel()
	if _, err := NewRspamdHTTPClient(RspamdHTTPConfig{}); err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestNewRspamdHTTPClient_NormalisesCheckPath(t *testing.T) {
	t.Parallel()
	client, err := NewRspamdHTTPClient(RspamdHTTPConfig{
		URL:       "http://localhost:11334/",
		CheckPath: "checkv2",
		Timeout:   time.Second,
	})
	if err != nil {
		t.Fatalf("NewRspamdHTTPClient: %v", err)
	}
	if client.path != "/checkv2" {
		t.Errorf("path: got %q want /checkv2", client.path)
	}
	if client.url != "http://localhost:11334" {
		t.Errorf("url: got %q", client.url)
	}
}
