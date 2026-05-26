package fastmail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// staticTokenSource implements TokenSource for tests.
type staticTokenSource string

func (s staticTokenSource) Token(_ context.Context) (string, error) {
	return string(s), nil
}

// newFakeFastmail spins up a fake JMAP server. The server serves both
// the session discovery endpoint and a programmable method-call
// endpoint.
func newFakeFastmail(t *testing.T, handle func(method string, args json.RawMessage, callID string) (string, any)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/jmap", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("session Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiUrl":       srv.URL + "/jmap/api/",
			"downloadUrl":  srv.URL + "/jmap/download/",
			"uploadUrl":    srv.URL + "/jmap/upload/",
			"eventSourceUrl": srv.URL + "/jmap/event/",
			"primaryAccounts": map[string]string{
				"urn:ietf:params:jmap:mail": "acct-1",
			},
		})
	})
	mux.HandleFunc("/jmap/api/", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("api Authorization = %q", got)
		}
		var body jmapRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode jmap request: %v", err)
		}
		responses := make([][]any, 0, len(body.MethodCalls))
		for _, call := range body.MethodCalls {
			method, _ := call[0].(string)
			args, _ := json.Marshal(call[1])
			callID, _ := call[2].(string)
			respName, respArgs := handle(method, args, callID)
			responses = append(responses, []any{respName, respArgs, callID})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"methodResponses": responses,
			"sessionState":    "s-1",
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestClient_SessionDiscovery_ResolvesAccountID(t *testing.T) {
	srv := newFakeFastmail(t, func(method string, _ json.RawMessage, _ string) (string, any) {
		t.Errorf("unexpected method call %q during session discovery", method)
		return method, map[string]any{}
	})
	c, err := NewClient(ClientConfig{
		TokenSource: staticTokenSource("tok"),
		BaseURL:     srv.URL,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	sess, err := c.Session(context.Background())
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if sess.APIURL == "" {
		t.Fatal("session APIURL empty")
	}
	// Discovery should also populate the account ID when not set in cfg.
	if c.AccountID() != "acct-1" {
		t.Errorf("AccountID() = %q, want acct-1", c.AccountID())
	}
}

func TestClient_SessionCachedAcrossCalls(t *testing.T) {
	var sessionHits atomic.Int32
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/jmap", func(w http.ResponseWriter, _ *http.Request) {
		sessionHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiUrl": srv.URL + "/jmap/api/",
			"primaryAccounts": map[string]string{
				"urn:ietf:params:jmap:mail": "acct-1",
			},
		})
	})
	mux.HandleFunc("/jmap/api/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"methodResponses":[["Mailbox/get",{"list":[]},"c0"]]}`))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, _ := NewClient(ClientConfig{
		TokenSource: staticTokenSource("tok"),
		BaseURL:     srv.URL,
	})
	for i := 0; i < 3; i++ {
		if _, err := c.Invoke(context.Background(), "Mailbox/get", map[string]any{"accountId": "acct-1"}); err != nil {
			t.Fatalf("invoke #%d: %v", i, err)
		}
	}
	if sessionHits.Load() != 1 {
		t.Errorf("session was discovered %d times, want exactly 1", sessionHits.Load())
	}
}

func TestClient_InvokeSurfacesJMAPError(t *testing.T) {
	srv := newFakeFastmail(t, func(method string, _ json.RawMessage, _ string) (string, any) {
		// Simulate JMAP-level error tuple.
		return "error", map[string]any{"type": "invalidArguments", "description": "bad"}
	})
	c, _ := NewClient(ClientConfig{
		TokenSource: staticTokenSource("tok"),
		BaseURL:     srv.URL,
	})
	_, err := c.Invoke(context.Background(), "Mailbox/get", nil)
	if err == nil {
		t.Fatal("expected JMAP error to surface")
	}
	if !strings.Contains(err.Error(), "invalidArguments") {
		t.Errorf("error did not propagate JMAP description: %v", err)
	}
}

func TestClient_HTTPNon2xx_SurfacedAsJMAPError(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/jmap", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiUrl": srv.URL + "/jmap/api/",
			"primaryAccounts": map[string]string{
				"urn:ietf:params:jmap:mail": "acct-1",
			},
		})
	})
	mux.HandleFunc("/jmap/api/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"type":"serverUnavailable"}`))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, _ := NewClient(ClientConfig{
		TokenSource: staticTokenSource("tok"),
		BaseURL:     srv.URL,
	})
	_, err := c.Invoke(context.Background(), "Mailbox/get", nil)
	if err == nil {
		t.Fatal("expected non-2xx to error")
	}
	je, ok := err.(*JMAPError)
	if !ok {
		t.Fatalf("error type = %T, want *JMAPError", err)
	}
	if je.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d", je.StatusCode)
	}
}
