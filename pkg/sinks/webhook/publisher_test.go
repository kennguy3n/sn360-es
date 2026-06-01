package webhook

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
)

// newTestHTTPSPublisher returns an HTTPPublisher whose Client is
// configured to skip TLS verification — required because
// httptest.NewTLSServer issues a self-signed certificate the
// production TLS bundle would reject. The Transport explicitly
// keeps Proxy=nil so the per-pod HTTP_PROXY environment cannot
// shunt the test through a real proxy.
func newTestHTTPSPublisher() *HTTPPublisher {
	return NewHTTPPublisher(HTTPPublisherConfig{
		Timeout: 2 * time.Second,
		Client: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				Proxy:           nil,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test client only
			},
		},
	})
}

func TestHTTPPublisher_Publish_2xxSuccess(t *testing.T) {
	t.Parallel()
	var (
		mu          sync.Mutex
		gotSig      string
		gotType     string
		gotEventID  string
		gotAttempt  string
		gotBodyHash string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotSig = r.Header.Get(SignatureHeader)
		gotType = r.Header.Get(EventTypeHeader)
		gotEventID = r.Header.Get("X-SN360-Event-Id")
		gotAttempt = r.Header.Get("X-SN360-Attempt")
		body, _ := io.ReadAll(r.Body)
		gotBodyHash = string(body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	p := newTestHTTPSPublisher()
	res, err := p.Publish(context.Background(), &Request{
		URL:       srv.URL,
		Format:    repository.WebhookSinkFormatECS,
		Body:      []byte(`{"hello":"world"}`),
		Signature: "sha256=deadbeef",
		EventType: EventTypeEmailEvaluation,
		EventID:   "evt-1",
		Attempt:   2,
	})
	if err != nil {
		t.Fatalf("Publish error: %v", err)
	}
	if res.Outcome != OutcomeSuccess {
		t.Errorf("Outcome = %v; want OutcomeSuccess", res.Outcome)
	}
	if res.HTTPStatus != http.StatusAccepted {
		t.Errorf("HTTPStatus = %d; want 202", res.HTTPStatus)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotSig != "sha256=deadbeef" {
		t.Errorf("server saw signature %q; want sha256=deadbeef", gotSig)
	}
	if gotType != EventTypeEmailEvaluation {
		t.Errorf("server saw event-type %q; want %s", gotType, EventTypeEmailEvaluation)
	}
	if gotEventID != "evt-1" {
		t.Errorf("server saw event id %q; want evt-1", gotEventID)
	}
	if gotAttempt != "2" {
		t.Errorf("server saw attempt %q; want 2", gotAttempt)
	}
	if gotBodyHash != `{"hello":"world"}` {
		t.Errorf("server saw body %q; want JSON payload", gotBodyHash)
	}
}

func TestHTTPPublisher_Publish_4xxPermanent(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"malformed"}`))
	}))
	defer srv.Close()
	p := newTestHTTPSPublisher()
	res, err := p.Publish(context.Background(), &Request{
		URL:       srv.URL,
		Format:    repository.WebhookSinkFormatECS,
		Body:      []byte(`x`),
		Signature: "sha256=abc",
		EventType: EventTypeEmailEvaluation,
	})
	if err != nil {
		t.Fatalf("Publish err: %v", err)
	}
	if res.Outcome != OutcomePermanentFailure {
		t.Errorf("Outcome = %v; want OutcomePermanentFailure", res.Outcome)
	}
	if res.HTTPStatus != 400 {
		t.Errorf("HTTPStatus = %d; want 400", res.HTTPStatus)
	}
}

func TestHTTPPublisher_Publish_5xxRetriable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	p := newTestHTTPSPublisher()
	res, err := p.Publish(context.Background(), &Request{
		URL:       srv.URL,
		Format:    repository.WebhookSinkFormatECS,
		Body:      []byte(`x`),
		Signature: "sha256=abc",
		EventType: EventTypeEmailEvaluation,
	})
	if err != nil {
		t.Fatalf("Publish err: %v", err)
	}
	if res.Outcome != OutcomeRetriable {
		t.Errorf("Outcome = %v; want OutcomeRetriable", res.Outcome)
	}
}

func TestHTTPPublisher_Publish_429Retriable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	p := newTestHTTPSPublisher()
	res, err := p.Publish(context.Background(), &Request{
		URL:       srv.URL,
		Format:    repository.WebhookSinkFormatECS,
		Body:      []byte(`x`),
		Signature: "sha256=abc",
		EventType: EventTypeEmailEvaluation,
	})
	if err != nil {
		t.Fatalf("Publish err: %v", err)
	}
	if res.Outcome != OutcomeRetriable {
		t.Errorf("Outcome for 429 = %v; want OutcomeRetriable", res.Outcome)
	}
	if res.HTTPStatus != 429 {
		t.Errorf("HTTPStatus = %d; want 429", res.HTTPStatus)
	}
}

func TestHTTPPublisher_Publish_RejectsHTTP(t *testing.T) {
	t.Parallel()
	p := newTestHTTPSPublisher()
	res, err := p.Publish(context.Background(), &Request{
		URL:       "http://example.com/insecure",
		Format:    repository.WebhookSinkFormatECS,
		Body:      []byte(`x`),
		Signature: "sha256=abc",
	})
	if err == nil {
		t.Fatalf("Publish accepted http:// URL; want error")
	}
	if res.Outcome == OutcomeSuccess {
		t.Errorf("Outcome should not be Success on plain-HTTP URL; got %v", res.Outcome)
	}
}

func TestHTTPPublisher_Publish_NetworkErrorRetriable(t *testing.T) {
	t.Parallel()
	// Use a server we close before publishing so the net Dial fails.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	u, _ := url.Parse(srv.URL)
	srv.Close()
	p := newTestHTTPSPublisher()
	res, err := p.Publish(context.Background(), &Request{
		URL:       "https://" + u.Host + "/closed",
		Format:    repository.WebhookSinkFormatECS,
		Body:      []byte(`x`),
		Signature: "sha256=abc",
		EventType: EventTypeEmailEvaluation,
	})
	if err != nil {
		t.Fatalf("Publish should swallow network errors and surface via outcome; got err=%v", err)
	}
	if res.Outcome != OutcomeRetriable {
		t.Errorf("Outcome for network error = %v; want OutcomeRetriable", res.Outcome)
	}
	if !strings.Contains(res.Cause, "network") && !strings.Contains(res.Cause, "timeout") {
		t.Errorf("Cause for network error = %q; want substring 'network' or 'timeout'", res.Cause)
	}
}
