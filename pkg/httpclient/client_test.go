package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestClient_PostJSONWithBodyDoesNotRetry verifies the fix for the
// double-submission bug: PostJSON now treats POST as non-idempotent
// even when a body is present, so 5xx responses are NOT retried and
// the caller cannot accidentally create duplicate side effects (e.g.
// duplicate escalation tickets).
func TestClient_PostJSONWithBodyDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, WithMaxRetries(3))
	if err := c.PostJSON(context.Background(), "/", map[string]string{"k": "v"}, nil); err == nil {
		t.Fatal("expected error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("PostJSON must not retry on 5xx; got %d calls (expected 1)", got)
	}
}

// TestClient_PostJSONIdempotentRetriesOn500 verifies the opt-in path:
// callers whose endpoints are genuinely idempotent can use
// PostJSONIdempotent and still get retry behavior.
func TestClient_PostJSONIdempotentRetriesOn500(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Each attempt must carry the full body — the retry path
		// must rewind via req.GetBody.
		buf := make([]byte, 32)
		n, _ := r.Body.Read(buf)
		if n == 0 {
			t.Errorf("retry %d sent empty body", calls.Load())
		}
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := newTestClient(t, srv, WithMaxRetries(3))
	if err := c.PostJSONIdempotent(context.Background(), "/", map[string]string{"k": "v"}, &struct{}{}); err != nil {
		t.Fatalf("PostJSONIdempotent: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 attempts on PostJSONIdempotent, got %d", got)
	}
}

// TestClient_PutJSONRetriesAndRewindsBody verifies that the helper path
// for PUT consents to retries (PUT is semantically idempotent) and that
// the retry attempts receive the full body payload, not an empty body.
func TestClient_PutJSONRetriesAndRewindsBody(t *testing.T) {
	var calls atomic.Int32
	var emptyBodies atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 32)
		n, _ := r.Body.Read(buf)
		if n == 0 {
			emptyBodies.Add(1)
		}
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := newTestClient(t, srv, WithMaxRetries(3))
	if err := c.PutJSON(context.Background(), "/", map[string]string{"k": "v"}, &struct{}{}); err != nil {
		t.Fatalf("PutJSON: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 attempts on PutJSON, got %d", got)
	}
	if got := emptyBodies.Load(); got != 0 {
		t.Fatalf("PutJSON retry sent empty body %d time(s); expected 0", got)
	}
}

// TestClient_DoPutWithBodyButNoGetBodyIsNotRetried covers the safety
// invariant added to isIdempotent: PUT/DELETE with a body but no
// rewinder are treated as non-idempotent so we never silently retry
// with an empty body and corrupt server state.
func TestClient_DoPutWithBodyButNoGetBodyIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, WithMaxRetries(3))

	// nopReader is intentionally not one of the body types that
	// http.NewRequestWithContext auto-populates GetBody for (which
	// are *bytes.Buffer, *bytes.Reader, *strings.Reader). With this
	// reader GetBody stays nil so we exercise the actual code path:
	// PUT with non-rewindable body must NOT be retried.
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPut, srv.URL+"/", &nopReader{r: strings.NewReader(`{"k":"v"}`)})
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	if req.GetBody != nil {
		t.Fatalf("test precondition violated: GetBody auto-set despite opaque body type")
	}
	resp, err := c.Do(context.Background(), req)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("PUT without GetBody must not retry; got %d calls (expected 1)", got)
	}
}

// nopReader wraps a *strings.Reader but hides the underlying type, so
// http.NewRequestWithContext cannot recognize it and skips GetBody
// auto-population. Used by TestClient_DoPutWithBodyButNoGetBodyIsNotRetried
// to model the real-world case of an opaque streaming body (e.g. a
// network or fs reader).
type nopReader struct{ r *strings.Reader }

func (n *nopReader) Read(p []byte) (int, error) { return n.r.Read(p) }

// TestClient_DoBodylessIdempotentRetries guards against a regression in
// the isIdempotent rewrite: GET / HEAD / OPTIONS without a body must
// continue to retry on 5xx since they were always retryable.
func TestClient_DoBodylessIdempotentRetries(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		method := method
		t.Run(method, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) < 3 {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			c := newTestClient(t, srv, WithMaxRetries(3))
			req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+"/", nil)
			if err != nil {
				t.Fatalf("new req: %v", err)
			}
			resp, err := c.Do(context.Background(), req)
			if err != nil {
				t.Fatalf("%s: %v", method, err)
			}
			_ = resp.Body.Close()
			if got := calls.Load(); got != 3 {
				t.Fatalf("%s expected 3 attempts, got %d", method, got)
			}
		})
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

func TestClient_CircuitBreaker_HalfOpenAdmitsSingleTrial(t *testing.T) {
	b := newBreaker(2, 10*time.Millisecond)
	// Trip the breaker.
	b.failure()
	b.failure()
	if got := b.currentState(); got != StateOpen {
		t.Fatalf("breaker not open: %s", got)
	}
	// Within cooldown: all callers rejected.
	if b.allow() {
		t.Fatal("allow returned true within cooldown")
	}
	time.Sleep(15 * time.Millisecond)
	// After cooldown: first caller becomes the trial; concurrent
	// callers must be rejected until success/failure decides.
	if !b.allow() {
		t.Fatal("first half-open caller not allowed")
	}
	if got := b.currentState(); got != StateHalfOpen {
		t.Fatalf("expected HalfOpen, got %s", got)
	}
	for i := 0; i < 5; i++ {
		if b.allow() {
			t.Fatalf("concurrent half-open caller #%d was admitted", i)
		}
	}
	// Trial fails -> reopen, fresh cooldown.
	b.failure()
	if got := b.currentState(); got != StateOpen {
		t.Fatalf("breaker did not reopen after failed trial: %s", got)
	}
	time.Sleep(15 * time.Millisecond)
	if !b.allow() {
		t.Fatal("first half-open trial not admitted on second attempt")
	}
	// Successful trial closes the breaker AND clears trialInFlight so
	// subsequent callers are admitted normally.
	b.success()
	if got := b.currentState(); got != StateClosed {
		t.Fatalf("breaker not closed after successful trial: %s", got)
	}
	if !b.allow() {
		t.Fatal("closed breaker rejected a caller")
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
