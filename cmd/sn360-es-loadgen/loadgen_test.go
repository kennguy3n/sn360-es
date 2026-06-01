package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

func TestTenantIDDeterministic(t *testing.T) {
	cases := []struct {
		index int
		want  string
	}{
		{0, "00000000-0000-0000-0000-000000000000"},
		{1, "00000000-0000-0000-0000-000000000001"},
		{4999, "00000000-0000-0000-0000-000000001387"},
		{0xffffffff, "00000000-0000-0000-0000-0000ffffffff"},
	}
	for _, tc := range cases {
		got, err := tenantID("00000000-0000-0000-0000-", tc.index)
		if err != nil {
			t.Fatalf("tenantID(%d): unexpected error %v", tc.index, err)
		}
		if got != tc.want {
			t.Fatalf("tenantID(%d) = %q, want %q", tc.index, got, tc.want)
		}
	}
}

func TestTenantIDRejectsNegativeAndOverflow(t *testing.T) {
	if _, err := tenantID("00000000-0000-0000-0000-", -1); err == nil {
		t.Fatal("expected error for negative index")
	}
	// 1<<48 is exactly one past the 12-hex-char ceiling.
	if _, err := tenantID("00000000-0000-0000-0000-", 1<<48); err == nil {
		t.Fatal("expected error for index that overflows 12 hex chars")
	}
}

func TestRedactedDSN(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{
			in:   "postgres://sn360es:sn360es@localhost:5432/sn360es?sslmode=disable",
			want: "postgres://sn360es:REDACTED@localhost:5432/sn360es?sslmode=disable",
		},
		{
			in:   "postgres://localhost:5432/sn360es",
			want: "postgres://localhost:5432/sn360es", // no user:password segment
		},
		{
			in:   "host=localhost port=5432 user=sn360es password=secret",
			want: "host=localhost port=5432 user=sn360es password=secret", // libpq kv, untouched
		},
	}
	for _, tc := range cases {
		if got := redactedDSN(tc.in); got != tc.want {
			t.Fatalf("redactedDSN(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsLoopbackBind(t *testing.T) {
	loopback := []string{"127.0.0.1:9099", "[::1]:9099", "localhost:9099"}
	for _, b := range loopback {
		if !IsLoopbackBind(b) {
			t.Fatalf("IsLoopbackBind(%q) = false, want true", b)
		}
	}
	external := []string{"0.0.0.0:9099", "10.0.0.1:9099", "missing-port"}
	for _, b := range external {
		if IsLoopbackBind(b) {
			t.Fatalf("IsLoopbackBind(%q) = true, want false", b)
		}
	}
}

// TestFormatHasIntegerVerb pins the structural check the bootstrap
// flag parser uses to accept any width / precision form of an
// integer verb. The previous implementation used
// `strings.Contains("%d")` which rejected `%04d` even though it is
// the documented default.
func TestFormatHasIntegerVerb(t *testing.T) {
	t.Parallel()
	cases := []struct {
		format string
		ok     bool
	}{
		{"%d", true},
		{"%04d", true},
		{"%-5d", true},
		{"loadgen-tenant-%04d", true},
		{"Tenant %d", true},
		{"static-name", false},
		{"%s", false},
		// Two verbs but one arg: fmt prints `%!+d(MISSING)`
		// which our `%!` guard correctly rejects. Pin so a
		// future regression cannot silently accept this.
		{"%-5d|%+d", false},
	}
	for _, tc := range cases {
		got := formatHasIntegerVerb(tc.format)
		if got != tc.ok {
			t.Fatalf("formatHasIntegerVerb(%q) = %v, want %v", tc.format, got, tc.ok)
		}
	}
}

// fakeJetStream is a publish-only stand-in we wire into the
// publisher so the HTTP handler tests do not require a live NATS.
type fakeJetStream struct {
	mu       sync.Mutex
	failNext error
	subjects []string
	bodies   [][]byte
	// msgIDOpts captures the number of PublishOpt values handed to
	// each call. We can't read the jetstream.WithMsgID payload
	// because pubOpts is package-private, but the body always
	// carries the EvaluateRequest.MessageID so tests verify msg-id
	// indirectly by JSON-decoding bodies[i].
	msgIDOpts []int
}

func (f *fakeJetStream) Publish(_ context.Context, subj string, data []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return nil, err
	}
	f.subjects = append(f.subjects, subj)
	f.bodies = append(f.bodies, append([]byte(nil), data...))
	f.msgIDOpts = append(f.msgIDOpts, len(opts))
	return &jetstream.PubAck{Stream: "fake", Sequence: uint64(len(f.subjects))}, nil
}

func (f *fakeJetStream) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subjects)
}

func newServerForTest(t *testing.T, fake *fakeJetStream) *publisherServer {
	t.Helper()
	return &publisherServer{
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		publisher: fake,
		subject:   "es.evaluate.request",
		startedAt: time.Now().UTC(),
		maxBody:   64 * 1024,
		maxBatch:  16,
	}
}

func TestPublisherHandlerHealthz(t *testing.T) {
	srv := newServerForTest(t, &fakeJetStream{})
	mux := http.NewServeMux()
	srv.registerRoutes(mux, time.Second)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestPublisherHandlerStats(t *testing.T) {
	fake := &fakeJetStream{}
	srv := newServerForTest(t, fake)
	mux := http.NewServeMux()
	srv.registerRoutes(mux, time.Second)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got publisherStats
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Subject != "es.evaluate.request" {
		t.Fatalf("subject = %q", got.Subject)
	}
}

func TestPublisherHandlerSingle(t *testing.T) {
	fake := &fakeJetStream{}
	srv := newServerForTest(t, fake)
	mux := http.NewServeMux()
	srv.registerRoutes(mux, time.Second)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	body := mustMarshal(t, dto.EvaluateRequest{
		MessageID: "msg-1",
		TenantID:  "00000000-0000-0000-0000-000000000001",
		Sender:    "alice@loadgen.test",
		Recipient: "bob@loadgen.test",
		Subject:   "smoke",
		Body:      "hello",
	})
	resp, err := http.Post(ts.URL+"/publish", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	if fake.count() != 1 {
		t.Fatalf("expected 1 publish, got %d", fake.count())
	}
	// The publisher always supplies exactly one PublishOpt
	// (jetstream.WithMsgID), which is how the consumer dedupes.
	if got := fake.msgIDOpts[0]; got != 1 {
		t.Fatalf("expected exactly 1 jetstream.PublishOpt, got %d", got)
	}

	// publishOne should have filled CorrelationID + ReceivedAt for us.
	var sent dto.EvaluateRequest
	if err := json.Unmarshal(fake.bodies[0], &sent); err != nil {
		t.Fatal(err)
	}
	if sent.CorrelationID == "" {
		t.Fatal("expected correlation_id to be filled")
	}
	if sent.ReceivedAt.IsZero() {
		t.Fatal("expected received_at to be filled")
	}
}

func TestPublisherHandlerBatch(t *testing.T) {
	fake := &fakeJetStream{}
	srv := newServerForTest(t, fake)
	mux := http.NewServeMux()
	srv.registerRoutes(mux, time.Second)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	batch := []dto.EvaluateRequest{
		{
			MessageID: "msg-a", TenantID: "00000000-0000-0000-0000-00000000000a",
			Sender: "a@l.test", Recipient: "b@l.test",
		},
		{
			MessageID: "msg-b", TenantID: "00000000-0000-0000-0000-00000000000b",
			Sender: "c@l.test", Recipient: "d@l.test",
		},
	}
	body := mustMarshal(t, batch)
	resp, err := http.Post(ts.URL+"/publish/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	if fake.count() != 2 {
		t.Fatalf("expected 2 publishes, got %d", fake.count())
	}
}

func TestPublisherHandlerRejectsMissingFields(t *testing.T) {
	fake := &fakeJetStream{}
	srv := newServerForTest(t, fake)
	mux := http.NewServeMux()
	srv.registerRoutes(mux, time.Second)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	body := mustMarshal(t, dto.EvaluateRequest{TenantID: "x"}) // missing message_id, sender, recipient
	resp, err := http.Post(ts.URL+"/publish", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		// publishOne validates and returns the error after passing
		// HTTP decode; the handler maps publish errors to 502.
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if fake.count() != 0 {
		t.Fatalf("expected 0 publishes on validation failure, got %d", fake.count())
	}
}

func TestPublisherHandlerBatchTooLarge(t *testing.T) {
	fake := &fakeJetStream{}
	srv := newServerForTest(t, fake)
	srv.maxBatch = 2
	mux := http.NewServeMux()
	srv.registerRoutes(mux, time.Second)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	mk := func(id string) dto.EvaluateRequest {
		return dto.EvaluateRequest{
			MessageID: id, TenantID: "t",
			Sender: "a@l.test", Recipient: "b@l.test",
		}
	}
	body := mustMarshal(t, []dto.EvaluateRequest{mk("1"), mk("2"), mk("3")})
	resp, err := http.Post(ts.URL+"/publish/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestPublisherHandlerSurfacesPublishErrors(t *testing.T) {
	fake := &fakeJetStream{failNext: errors.New("boom")}
	srv := newServerForTest(t, fake)
	mux := http.NewServeMux()
	srv.registerRoutes(mux, time.Second)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	body := mustMarshal(t, dto.EvaluateRequest{
		MessageID: "msg-1", TenantID: "t",
		Sender: "a@l.test", Recipient: "b@l.test",
	})
	resp, err := http.Post(ts.URL+"/publish", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), "boom") {
		t.Fatalf("body does not include upstream error: %q", raw)
	}
	if srv.publishErr.Load() != 1 {
		t.Fatalf("publishErr counter = %d, want 1", srv.publishErr.Load())
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}
