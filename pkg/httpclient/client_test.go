package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, srv *httptest.Server, opts ...Option) *Client {
	t.Helper()
	opts = append(opts, WithBaseURL(srv.URL), WithRetryBaseDelay(time.Millisecond))
	return FromHTTPClient("test", srv.Client(), opts...)
}

func TestClient_JSON_SuccessAndDecode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hello":"world"}`))
	}))
	defer srv.Close()
	c := newTestClient(t, srv)
	var out struct {
		Hello string `json:"hello"`
	}
	if err := c.GetJSON(context.Background(), "/", &out); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if out.Hello != "world" {
		t.Fatalf("decoded body: %+v", out)
	}
}

func TestClient_JSON_PostEncodesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("content-type: %q", ct)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := newTestClient(t, srv)
	if err := c.PostJSON(context.Background(), "/", map[string]string{"k": "v"}, nil); err != nil {
		t.Fatalf("PostJSON: %v", err)
	}
}

func TestClient_NonRetriableErrorReturnsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"boom"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	c := newTestClient(t, srv)
	err := c.GetJSON(context.Background(), "/", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var hcErr *Error
	if !errors.As(err, &hcErr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if hcErr.Status != http.StatusBadRequest {
		t.Fatalf("status: %d", hcErr.Status)
	}
}

func TestClient_RetriesIdempotent500(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := newTestClient(t, srv, WithMaxRetries(3))
	if err := c.GetJSON(context.Background(), "/", &struct{}{}); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 calls, got %d", calls.Load())
	}
}

func TestClient_DoesNotRetryNonIdempotent(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, WithMaxRetries(3))
	err := c.PostJSON(context.Background(), "/", nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly 1 call, got %d", calls.Load())
	}
}

func TestClient_CircuitBreaker_OpensThenRecovers(t *testing.T) {
	failing := atomic.Bool{}
	failing.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv,
		WithMaxRetries(1),
		WithCircuit(3, 50*time.Millisecond),
	)
	// Trip the breaker by exhausting failures.
	for i := 0; i < 8; i++ {
		_ = c.GetJSON(context.Background(), "/", nil)
	}
	if got := c.CircuitState(); got != StateOpen {
		t.Fatalf("breaker not open after failures: %s", got)
	}
	err := c.GetJSON(context.Background(), "/", nil)
	if err == nil || !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected circuit-open error, got: %v", err)
	}

	// Wait for cooldown + recover backend.
	time.Sleep(80 * time.Millisecond)
	failing.Store(false)
	if err := c.GetJSON(context.Background(), "/", nil); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got := c.CircuitState(); got != StateClosed {
		t.Fatalf("breaker not closed after success: %s", got)
	}
}

func TestClient_NoBaseURL_RelativePath(t *testing.T) {
	c, err := New(Config{Name: "noop"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()
	if err := c.GetJSON(context.Background(), "/x", nil); err == nil {
		t.Fatal("expected error for relative path without BaseURL")
	}
}

func TestNew_DefaultsApplied(t *testing.T) {
	c, err := New(Config{Name: "n"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()
	if c.cfg.Timeout != 10*time.Second {
		t.Fatalf("default timeout: %v", c.cfg.Timeout)
	}
	if c.cfg.MaxRetries != 2 {
		t.Fatalf("default retries: %d", c.cfg.MaxRetries)
	}
}

func TestState_String(t *testing.T) {
	cases := map[State]string{
		StateClosed:   "closed",
		StateOpen:     "open",
		StateHalfOpen: "half_open",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Fatalf("State(%d).String(): got=%q want=%q", s, got, want)
		}
	}
}
