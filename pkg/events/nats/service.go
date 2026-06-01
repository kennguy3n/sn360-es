package nats

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/events/schema"
)

// Service is the events.EventService implementation backed by NATS
// JetStream. It wires the Client + Publisher + Consumer together and
// manages the lifecycle of all subscriptions.
type Service struct {
	client    *Client
	publisher *Publisher
	logger    *slog.Logger

	mu       sync.Mutex
	subs     []*Consumer
	observer MessageObserver

	// streamFor maps a published subject to its target stream. The map is
	// derived from the StreamSpecs at construction time so the service does
	// not need a JetStream round-trip to figure out which stream owns a
	// subscription.
	streamFor map[string]string
}

// SetMessageObserver registers a per-delivery observer used by every
// consumer subsequently returned from Subscribe. Calling it after
// subscriptions are already active does not retroactively patch
// existing consumers — wire the observer before starting consumers
// during application boot.
func (s *Service) SetMessageObserver(observer MessageObserver) {
	s.mu.Lock()
	s.observer = observer
	s.mu.Unlock()
}

// SetSchemaValidator binds a WS-7c schema.Validator onto the
// underlying Publisher so every Publish call is gated by the
// registered (subject, schema_version) contract. The optional
// mismatch hook is invoked with the original subject and the
// validator's Result whenever a mismatch is detected — typical
// implementations increment the nats_schema_mismatch_total
// Prometheus counter so the operator dashboard sees rejects in
// real time.
//
// Calling this with v == nil disables schema enforcement on
// the publisher (Validator==nil is the "validator opt-out"
// signal documented on Publisher.WithSchemaValidator). Calling
// it again after a subscription is already running does NOT
// retroactively patch the consumer-side wiring — the
// subscribe-side validation lives in cmd/sn360-es/consumers_schema.go
// because the DLQ-routing policy is a binary-level concern.
func (s *Service) SetSchemaValidator(v *schema.Validator, onMismatch func(subject string, result schema.Result)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.publisher == nil {
		return
	}
	s.publisher.WithSchemaValidator(v).WithSchemaMismatchHook(onMismatch)
}

// NewService builds a Service from a Config. It creates the connection,
// ensures all default streams exist, and returns the ready-to-use service.
func NewService(ctx context.Context, cfg Config, source string, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	client, err := NewClient(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}

	specs := DefaultStreamSpecs(cfg)
	if err := EnsureAllStreams(ctx, client.JetStream(), specs); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("nats: ensure streams: %w", err)
	}
	// Drop orphaned durables left behind by deployments where
	// ES_EVALUATE owned es.evaluate.> and the result consumers were
	// pinned to it. After the request / result split those durables
	// (management-persist, education-trigger, ingestion-action) are
	// re-created on StreamEvaluateResult, but the old definitions
	// would otherwise linger forever on ES_EVALUATE confusing
	// operators inspecting consumer state.
	if err := pruneOrphanResultConsumers(ctx, client.JetStream(), logger); err != nil {
		// Non-fatal: orphaned consumers don't block the new
		// consumers, but log loudly so it gets cleaned up.
		logger.WarnContext(ctx, "nats: prune orphan result consumers", slog.Any("error", err))
	}

	streamFor := map[string]string{}
	for _, spec := range specs {
		for _, subj := range spec.Subjects {
			streamFor[subj] = spec.Name
		}
	}

	s := &Service{
		client:    client,
		publisher: NewPublisher(client, source),
		logger:    logger,
		streamFor: streamFor,
	}
	return s, nil
}

// NewServiceWithClient wraps an existing Client, useful for tests.
func NewServiceWithClient(client *Client, source string) *Service {
	return &Service{
		client:    client,
		publisher: NewPublisher(client, source),
		logger:    client.logger,
		streamFor: map[string]string{},
	}
}

// Publish implements events.EventService.
func (s *Service) Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	return s.publisher.Publish(ctx, subject, data, opts...)
}

// Health implements events.EventService by probing the NATS connection
// and JetStream account without publishing anything. It is safe to call
// on every readiness probe — JetStream AccountInfo is the canonical
// server-side liveness query and produces no durable state.
func (s *Service) Health(ctx context.Context) error {
	if s == nil || s.client == nil {
		return errors.New("nats: service not initialized")
	}
	if !s.client.IsConnected() {
		return errors.New("nats: connection not established")
	}
	js := s.client.JetStream()
	if js == nil {
		return errors.New("nats: jetstream context not available")
	}
	if _, err := js.AccountInfo(ctx); err != nil {
		return fmt.Errorf("nats: AccountInfo: %w", err)
	}
	return nil
}

// Subscribe implements events.EventService.
//
// It resolves the target JetStream stream from the subject (based on the
// stream specs ensured at startup), creates a durable consumer if one does
// not yet exist, and starts the long-running consume loop.
func (s *Service) Subscribe(ctx context.Context, subject string, handler events.MessageHandler, opts ...events.SubscribeOption) (events.Subscription, error) {
	if subject == "" {
		return nil, errors.New("nats: subject required")
	}
	resolved := events.ResolveSubscribeOptions(events.SubscribeOptions{
		MaxDeliver:    5,
		BatchSize:     s.client.cfg.FetchBatchSize,
		MaxWait:       s.client.cfg.FetchMaxWait,
		MaxAckPending: 256,
	}, opts...)
	if resolved.Durable == "" {
		return nil, errors.New("nats: WithDurable(name) is required for subscribe")
	}

	stream := s.streamForSubject(subject)
	if stream == "" {
		return nil, fmt.Errorf("nats: no stream matches subject %q", subject)
	}

	s.mu.Lock()
	observer := s.observer
	s.mu.Unlock()

	cons, err := NewConsumerWithObserver(ctx, s.client, stream, subject, handler, s.publisher, resolved, s.logger, observer)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.subs = append(s.subs, cons)
	s.mu.Unlock()
	return cons, nil
}

// Close drains all subscriptions and the underlying client.
func (s *Service) Close() error {
	s.mu.Lock()
	subs := s.subs
	s.subs = nil
	s.mu.Unlock()

	var firstErr error
	for _, c := range subs {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := s.client.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Client exposes the underlying NATS client. Use sparingly; tests need this
// to inspect raw connection state and to publish "out-of-band" messages
// when verifying DLQ flows.
func (s *Service) Client() *Client { return s.client }

// Publisher exposes the underlying Publisher, primarily so DLQ replays can
// re-use the same retry policy.
func (s *Service) Publisher() *Publisher { return s.publisher }

// streamForSubject finds the stream that owns subject. It tolerates wildcard
// subjects in the spec (e.g. "es.evaluate.request.>" matches
// "es.evaluate.request.failing"). After the ES_EVALUATE / ES_EVALUATE_RESULT
// split, the two relevant patterns are "es.evaluate.request[.>]" and
// "es.evaluate.result[.>]"; an unrecognised "es.evaluate.<other>" subject
// falls through to StreamForSubject and returns "" rather than
// guessing a stream.
func (s *Service) streamForSubject(subject string) string {
	if name, ok := s.streamFor[subject]; ok {
		return name
	}
	for pattern, name := range s.streamFor {
		if subjectMatches(pattern, subject) {
			return name
		}
	}
	// Fall back to the canonical mapping for the well-known prefixes; this
	// keeps the service useful even when subjects are added without being
	// registered as stream specs (operationally common during testing).
	return StreamForSubject(subject)
}

// subjectMatches mirrors JetStream's wildcard rules:
//
//	"*" matches a single token
//	">" matches one or more tokens (only allowed as the last token)
func subjectMatches(pattern, subject string) bool {
	if pattern == subject {
		return true
	}
	pTokens := splitTokens(pattern)
	sTokens := splitTokens(subject)
	for i, pt := range pTokens {
		if pt == ">" {
			return i < len(sTokens)
		}
		if i >= len(sTokens) {
			return false
		}
		if pt == "*" {
			continue
		}
		if pt != sTokens[i] {
			return false
		}
	}
	return len(pTokens) == len(sTokens)
}

func splitTokens(s string) []string {
	if s == "" {
		return nil
	}
	out := make([]string, 0, 4)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
