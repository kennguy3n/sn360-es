package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/sn360-es/internal/dto"
	natsstreams "github.com/kennguy3n/sn360-es/pkg/events/nats"
)

// natsClient narrows the JetStream API we need so the publisher can
// be unit-tested with a fake. The fake lives next to publisher_test.go.
type natsClient interface {
	Publish(ctx context.Context, subj string, data []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

// publisherStats is the snapshot the /stats endpoint returns. It is
// also embedded in the test assertions so the structure has to stay
// JSON-marshallable.
type publisherStats struct {
	StartedAt        time.Time `json:"started_at"`
	PublishOK        uint64    `json:"publish_ok"`
	PublishErrors    uint64    `json:"publish_errors"`
	PublishLastError string    `json:"publish_last_error,omitempty"`
	Subject          string    `json:"subject"`
}

// publisherServer is the bridge k6 hits during a scenario. It is
// stateless across requests but holds the JetStream handle and a
// few atomic counters surfaced via /stats.
type publisherServer struct {
	logger     *slog.Logger
	publisher  natsClient
	subject    string
	startedAt  time.Time
	publishOK  atomic.Uint64
	publishErr atomic.Uint64
	lastError  atomic.Pointer[string]
	maxBody    int64
	maxBatch   int
}

// runPublisher parses the publisher-subcommand flags and serves
// HTTP. The function blocks until ctx is cancelled (signal handler
// in main).
func runPublisher(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := newFlagSet(cmdPublisher)
	bind := fs.String("bind", "127.0.0.1:9099",
		"address to bind the HTTP server to; defaults to loopback because this is a local-dev tool")
	natsURL := fs.String("nats-url", envDefault("LOADGEN_NATS_URL", nats.DefaultURL),
		"NATS server URL (default $LOADGEN_NATS_URL, falling back to nats://127.0.0.1:4222)")
	subject := fs.String("subject", "es.evaluate.request",
		"JetStream subject to publish on")
	maxBody := fs.Int64("max-body-bytes", 256*1024,
		"maximum HTTP body size accepted; the corpus emails fit in a few KB so this is generous")
	maxBatch := fs.Int("max-batch", 200,
		"maximum messages accepted per /publish/batch request")
	publishTimeout := fs.Duration("publish-timeout", 5*time.Second,
		"per-message NATS publish timeout")
	shutdownTimeout := fs.Duration("shutdown-timeout", 10*time.Second,
		"upper bound on graceful HTTP shutdown when SIGTERM arrives")
	natsConnTimeout := fs.Duration("nats-connect-timeout", 15*time.Second,
		"upper bound on the initial NATS connection")
	ensureStream := fs.Bool("ensure-stream", true,
		"create/update the canonical ES_EVALUATE JetStream stream on startup so the publisher works against a fresh NATS server without booting sn360-es first")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *maxBatch <= 0 {
		return fmt.Errorf("-max-batch must be > 0, got %d", *maxBatch)
	}
	if *maxBody <= 0 {
		return fmt.Errorf("-max-body-bytes must be > 0, got %d", *maxBody)
	}
	if err := warnIfNonLoopback(*bind, logger); err != nil {
		return err
	}

	connCtx, connCancel := context.WithTimeout(ctx, *natsConnTimeout)
	defer connCancel()
	nc, js, err := dialNATS(connCtx, *natsURL)
	if err != nil {
		return fmt.Errorf("dial NATS at %s: %w", *natsURL, err)
	}
	defer nc.Close()

	if *ensureStream {
		// EnsureStream is idempotent. We only provision the
		// ES_EVALUATE stream the publisher cares about — the
		// other streams (results, onboarding, soc) are owned
		// by sn360-es itself and the load harness does not
		// produce on them.
		if err := ensureEvaluateStream(connCtx, js, logger); err != nil {
			return fmt.Errorf("ensure ES_EVALUATE stream: %w", err)
		}
	}

	srv := &publisherServer{
		logger:    logger,
		publisher: js,
		subject:   *subject,
		startedAt: time.Now().UTC(),
		maxBody:   *maxBody,
		maxBatch:  *maxBatch,
	}

	mux := http.NewServeMux()
	srv.registerRoutes(mux, *publishTimeout)

	httpSrv := &http.Server{
		Addr:              *bind,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	listenErr := make(chan error, 1)
	go func() {
		logger.Info("sn360-es-loadgen: publisher listening",
			slog.String("bind", *bind),
			slog.String("subject", *subject),
			slog.String("nats_url", *natsURL),
		)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, shutCancel := context.WithTimeout(context.Background(), *shutdownTimeout)
		defer shutCancel()
		return httpSrv.Shutdown(shutCtx)
	case err := <-listenErr:
		return err
	}
}

// envDefault returns the value of env var name if non-empty, or fallback.
func envDefault(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}

// dialNATS opens a JetStream-capable connection. It is exported as a
// thin helper so the test can swap in an in-process server.
func dialNATS(ctx context.Context, url string) (*nats.Conn, jetstream.JetStream, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(15 * time.Second)
	}
	nc, err := nats.Connect(url,
		nats.Name("sn360-es-loadgen"),
		nats.Timeout(time.Until(deadline)),
	)
	if err != nil {
		return nil, nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	return nc, js, nil
}

// warnIfNonLoopback returns nil but logs a warning when the bind
// address is not loopback. The publisher publishes raw evaluate
// requests with no auth — exposing it externally is a deliberate
// choice the operator has to make consciously.
//
// `-bind=:9099` (empty host) means "bind to all interfaces", which
// is the exact case the warning is meant to catch, so we route it
// through IsLoopbackBind() and warn on anything that does not
// match a loopback literal.
func warnIfNonLoopback(bind string, logger *slog.Logger) error {
	if _, _, err := net.SplitHostPort(bind); err != nil {
		return fmt.Errorf("-bind: %w", err)
	}
	if IsLoopbackBind(bind) {
		return nil
	}
	logger.Warn("sn360-es-loadgen: publisher binding to non-loopback address; this is a local-dev tool with no auth — only do this on an isolated network",
		slog.String("bind", bind),
	)
	return nil
}

// registerRoutes wires the HTTP API.
func (s *publisherServer) registerRoutes(mux *http.ServeMux, publishTimeout time.Duration) {
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/stats", s.stats)
	mux.HandleFunc("/publish", s.publishWith(publishTimeout, false))
	mux.HandleFunc("/publish/batch", s.publishWith(publishTimeout, true))
}

func (s *publisherServer) healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *publisherServer) stats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := publisherStats{
		StartedAt:     s.startedAt,
		PublishOK:     s.publishOK.Load(),
		PublishErrors: s.publishErr.Load(),
		Subject:       s.subject,
	}
	if e := s.lastError.Load(); e != nil {
		snap.PublishLastError = *e
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

// publishWith returns an http.HandlerFunc that decodes either a
// single dto.EvaluateRequest (batch=false) or an array (batch=true)
// and publishes each onto NATS.
func (s *publisherServer) publishWith(timeout time.Duration, batch bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.maxBody)
		defer r.Body.Close()

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var msgs []dto.EvaluateRequest
		if batch {
			if err := dec.Decode(&msgs); err != nil {
				http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
				return
			}
			if len(msgs) == 0 {
				http.Error(w, "batch must contain at least one message", http.StatusBadRequest)
				return
			}
			if len(msgs) > s.maxBatch {
				http.Error(w,
					fmt.Sprintf("batch size %d exceeds limit %d", len(msgs), s.maxBatch),
					http.StatusRequestEntityTooLarge)
				return
			}
		} else {
			var single dto.EvaluateRequest
			if err := dec.Decode(&single); err != nil {
				http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
				return
			}
			msgs = []dto.EvaluateRequest{single}
		}

		published := 0
		for i := range msgs {
			if err := s.publishOne(r.Context(), &msgs[i], timeout); err != nil {
				s.publishErr.Add(1)
				errMsg := err.Error()
				s.lastError.Store(&errMsg)
				s.logger.Warn("publish failed",
					slog.Int("index", i),
					slog.String("message_id", msgs[i].MessageID),
					slog.Any("error", err),
				)
				// Surface the index of the failed message so k6
				// scenarios can correlate batch failures back to
				// their corpus row.
				http.Error(w,
					fmt.Sprintf("publish index %d (message_id=%q): %v",
						i, msgs[i].MessageID, err),
					http.StatusBadGateway)
				return
			}
			published++
		}
		s.publishOK.Add(uint64(published))

		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"published": published,
			"subject":   s.subject,
		})
	}
}

// publishOne validates and forwards a single message. The publisher
// fills the minimum required fields when k6 left them blank so we
// don't need every scenario to repeat the same boilerplate.
func (s *publisherServer) publishOne(ctx context.Context, msg *dto.EvaluateRequest, timeout time.Duration) error {
	if msg.MessageID == "" {
		return errors.New("message_id required")
	}
	if msg.TenantID == "" {
		return errors.New("tenant_id required")
	}
	if msg.Sender == "" || msg.Recipient == "" {
		return errors.New("sender and recipient required")
	}
	if msg.ReceivedAt.IsZero() {
		msg.ReceivedAt = time.Now().UTC()
	}
	if msg.CorrelationID == "" {
		msg.CorrelationID = "loadgen-" + msg.MessageID
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	pubCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err = s.publisher.Publish(pubCtx, s.subject, body,
		jetstream.WithMsgID(msg.MessageID),
	)
	if err != nil {
		return err
	}
	return nil
}

// ensureEvaluateStream provisions the ES_EVALUATE work-queue
// stream so publishing succeeds against a fresh NATS server. We
// reuse natsstreams.DefaultStreamSpecs so the on-disk config is
// byte-identical to what `sn360-es` would create itself.
func ensureEvaluateStream(ctx context.Context, js jetstream.JetStream, logger *slog.Logger) error {
	specs := natsstreams.DefaultStreamSpecs(natsstreams.Config{})
	for _, spec := range specs {
		if spec.Name != natsstreams.StreamEvaluate {
			continue
		}
		_, err := natsstreams.EnsureStream(ctx, js, spec)
		if err != nil {
			return err
		}
		logger.Info("sn360-es-loadgen: ensured ES_EVALUATE stream",
			slog.String("stream", spec.Name),
			slog.Any("subjects", spec.Subjects),
		)
		return nil
	}
	return errors.New("default stream specs did not include ES_EVALUATE")
}

// IsLoopbackBind reports whether bind is a loopback address. It is
// exported so the test can assert the default flag value stays safe.
func IsLoopbackBind(bind string) bool {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return false
	}
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}
