// Package redis provides a Redis Streams implementation of the
// events.EventService interface. It is the backward-compat option behind
// the EVENT_BUS_TYPE feature flag; production deployments should use NATS
// JetStream, which is the default.
//
// Streams here use XADD for publishes and XREADGROUP for consumer-group
// reads. Pending messages older than a configurable threshold are claimed
// with XAUTOCLAIM to recover from crashed consumers — the same pattern the
// v1 NGES services use.
package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// Config holds the Redis Streams configuration.
type Config struct {
	// URL is the Redis URL (redis://...). If empty, Addr is used.
	URL  string
	Addr string

	// DB is the Redis database number.
	DB int

	// Username / Password for AUTH.
	Username string
	Password string

	// PoolSize is the number of TCP connections. 0 = default.
	PoolSize int

	// ReadBlock is how long XREADGROUP blocks for new messages.
	ReadBlock time.Duration

	// MaxStreamLength caps the size of a stream via XADD MAXLEN ~ N.
	MaxStreamLength int64

	// PendingMinIdle is how long a message can remain pending before
	// XAUTOCLAIM steals it.
	PendingMinIdle time.Duration

	// MaxRetries / RetryDelay control publish-side retries.
	MaxRetries int
	RetryDelay time.Duration

	// FetchBatchSize is the default XREADGROUP COUNT.
	FetchBatchSize int
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Addr:            "127.0.0.1:6379",
		ReadBlock:       2 * time.Second,
		MaxStreamLength: 100_000,
		PendingMinIdle:  30 * time.Second,
		MaxRetries:      3,
		RetryDelay:      200 * time.Millisecond,
		FetchBatchSize:  10,
	}
}

// Service is the Redis Streams events.EventService implementation.
type Service struct {
	cfg    Config
	logger *slog.Logger
	client goredis.UniversalClient
	source string

	mu     sync.Mutex
	subs   []*subscription
	closed bool

	// consumerName is shared across all subscriptions in this process so we
	// can route XAUTOCLAIM only to messages owned by other instances.
	consumerName string
}

// NewService builds a Service from a Config.
func NewService(ctx context.Context, cfg Config, source string, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Addr == "" && cfg.URL == "" {
		return nil, errors.New("redis: Addr or URL is required")
	}

	var client goredis.UniversalClient
	if cfg.URL != "" {
		parsed, err := goredis.ParseURL(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("redis: parse URL: %w", err)
		}
		if cfg.PoolSize > 0 {
			parsed.PoolSize = cfg.PoolSize
		}
		client = goredis.NewClient(parsed)
	} else {
		client = goredis.NewClient(&goredis.Options{
			Addr:     cfg.Addr,
			DB:       cfg.DB,
			Username: cfg.Username,
			Password: cfg.Password,
			PoolSize: cfg.PoolSize,
		})
	}

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}

	return &Service{
		cfg:          cfg,
		logger:       logger,
		client:       client,
		source:       source,
		consumerName: deriveConsumerName(),
	}, nil
}

// NewServiceWithClient wraps an existing Redis client (primarily for tests).
func NewServiceWithClient(client goredis.UniversalClient, cfg Config, source string, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		cfg:          cfg,
		logger:       logger,
		client:       client,
		source:       source,
		consumerName: deriveConsumerName(),
	}
}

func deriveConsumerName() string {
	host, _ := os.Hostname()
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	if host == "" {
		host = "sn360-es"
	}
	return host + "-" + hex.EncodeToString(buf)
}

// Publish implements events.EventService using XADD.
func (s *Service) Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	if subject == "" {
		return errors.New("redis: subject required")
	}
	resolved := events.ResolvePublishOptions(events.PublishOptions{
		MaxRetries: s.cfg.MaxRetries,
		RetryDelay: s.cfg.RetryDelay,
	}, opts...)

	values := map[string]any{
		"data":                  data,
		events.HeaderEnqueuedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if resolved.MessageID != "" {
		values[events.HeaderMessageID] = resolved.MessageID
	}
	if resolved.CorrelationID != "" {
		values[events.HeaderCorrelationID] = resolved.CorrelationID
	}
	if resolved.TenantID != "" {
		values[events.HeaderTenantID] = resolved.TenantID
	}
	if resolved.EventType != "" {
		values[events.HeaderEventType] = resolved.EventType
	}
	if s.source != "" {
		values[events.HeaderSource] = s.source
	}
	for k, v := range resolved.Headers {
		values[k] = v
	}

	args := &goredis.XAddArgs{
		Stream: subject,
		MaxLen: s.cfg.MaxStreamLength,
		Approx: true,
		Values: values,
	}

	attempts := resolved.MaxRetries
	if attempts <= 0 {
		attempts = 1
	}
	delay := resolved.RetryDelay
	if delay <= 0 {
		delay = 100 * time.Millisecond
	}

	var lastErr error
	for i := 1; i <= attempts; i++ {
		if _, err := s.client.XAdd(ctx, args).Result(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if errors.Is(lastErr, context.Canceled) || errors.Is(lastErr, context.DeadlineExceeded) {
			return lastErr
		}
		if i < attempts {
			sleep := delay * time.Duration(1<<(i-1))
			t := time.NewTimer(sleep)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
	}
	return fmt.Errorf("redis: publish %s: %w", subject, lastErr)
}

// Subscribe implements events.EventService using XREADGROUP + XAUTOCLAIM.
func (s *Service) Subscribe(ctx context.Context, subject string, handler events.MessageHandler, opts ...events.SubscribeOption) (events.Subscription, error) {
	if subject == "" {
		return nil, errors.New("redis: subject required")
	}
	resolved := events.ResolveSubscribeOptions(events.SubscribeOptions{
		MaxDeliver: 5,
		BatchSize:  s.cfg.FetchBatchSize,
		MaxWait:    s.cfg.ReadBlock,
	}, opts...)
	if resolved.Durable == "" {
		return nil, errors.New("redis: WithDurable(name) is required for subscribe")
	}

	if err := s.ensureGroup(ctx, subject, resolved.Durable); err != nil {
		return nil, err
	}

	sub := &subscription{
		service:  s,
		subject:  subject,
		group:    resolved.Durable,
		consumer: s.consumerName + "-" + resolved.Durable,
		handler:  handler,
		opts:     resolved,
		done:     make(chan struct{}),
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errors.New("redis: service is closed")
	}
	s.subs = append(s.subs, sub)
	s.mu.Unlock()

	go sub.runRead(ctx)
	go sub.runClaim(ctx)

	return sub, nil
}

// Close stops all subscriptions and closes the underlying client.
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	subs := s.subs
	s.subs = nil
	s.mu.Unlock()

	for _, sub := range subs {
		_ = sub.Close()
	}
	return s.client.Close()
}

// Client exposes the underlying Redis client (mainly for tests).
func (s *Service) Client() goredis.UniversalClient { return s.client }

// ensureGroup creates the consumer group on subject if it doesn't already
// exist. We use MKSTREAM=true so the call succeeds even when the stream
// has not been written to yet.
func (s *Service) ensureGroup(ctx context.Context, subject, group string) error {
	if _, err := s.client.XGroupCreateMkStream(ctx, subject, group, "$").Result(); err != nil {
		// BUSYGROUP means the group already exists — that's success.
		if err.Error() == "BUSYGROUP Consumer Group name already exists" {
			return nil
		}
		return fmt.Errorf("redis: XGROUP CREATE %s %s: %w", subject, group, err)
	}
	return nil
}

// publishToDLQ moves a failed message to its DLQ stream.
func (s *Service) publishToDLQ(ctx context.Context, dlqSubject string, fields map[string]string, delivery int64, cause error) error {
	hdrs := make(map[string]string, len(fields))
	for k, v := range fields {
		hdrs[k] = v
	}
	hdrs[events.HeaderDeliveryCount] = strconv.FormatInt(delivery, 10)
	if cause != nil {
		hdrs[events.HeaderError] = cause.Error()
	}
	hdrs[events.HeaderOriginSubject] = fields["__origin_subject"]

	values := map[string]any{}
	for k, v := range hdrs {
		values[k] = v
	}
	// Preserve the original payload (stored under "data") verbatim.
	values["data"] = fields["data"]

	_, err := s.client.XAdd(ctx, &goredis.XAddArgs{
		Stream: dlqSubject,
		MaxLen: s.cfg.MaxStreamLength,
		Approx: true,
		Values: values,
	}).Result()
	if err != nil {
		return fmt.Errorf("redis: DLQ publish %s: %w", dlqSubject, err)
	}
	return nil
}

// --- subscription -----------------------------------------------------------

type subscription struct {
	service  *Service
	subject  string
	group    string
	consumer string
	handler  events.MessageHandler
	opts     events.SubscribeOptions

	once sync.Once
	done chan struct{}
}

// Subject implements events.Subscription.
func (s *subscription) Subject() string { return s.subject }

// Close stops the subscription.
func (s *subscription) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

func (s *subscription) runRead(ctx context.Context) {
	logger := s.service.logger.With(
		slog.String("subject", s.subject),
		slog.String("group", s.group),
		slog.String("consumer", s.consumer),
	)

	count := int64(s.opts.BatchSize)
	if count <= 0 {
		count = 10
	}
	block := s.opts.MaxWait
	if block <= 0 {
		block = 2 * time.Second
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}

		res, err := s.service.client.XReadGroup(ctx, &goredis.XReadGroupArgs{
			Group:    s.group,
			Consumer: s.consumer,
			Streams:  []string{s.subject, ">"},
			Count:    count,
			Block:    block,
		}).Result()
		if errors.Is(err, goredis.Nil) || errors.Is(err, context.DeadlineExceeded) {
			continue
		}
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			logger.Warn("redis: XREADGROUP failed", slog.Any("error", err))
			time.Sleep(200 * time.Millisecond)
			continue
		}

		for _, stream := range res {
			for _, m := range stream.Messages {
				s.handle(ctx, m, logger)
			}
		}
	}
}

func (s *subscription) runClaim(ctx context.Context) {
	logger := s.service.logger.With(
		slog.String("subject", s.subject),
		slog.String("group", s.group),
	)
	ticker := time.NewTicker(orDefault(s.service.cfg.PendingMinIdle, 30*time.Second))
	defer ticker.Stop()

	var cursor string = "0-0"
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-ticker.C:
		}

		msgs, next, err := s.service.client.XAutoClaim(ctx, &goredis.XAutoClaimArgs{
			Stream:   s.subject,
			Group:    s.group,
			Consumer: s.consumer,
			MinIdle:  orDefault(s.service.cfg.PendingMinIdle, 30*time.Second),
			Start:    cursor,
			Count:    int64(orDefault(s.opts.BatchSize, 10)),
		}).Result()
		if err != nil && !errors.Is(err, goredis.Nil) {
			logger.Warn("redis: XAUTOCLAIM failed", slog.Any("error", err))
			continue
		}
		cursor = next
		for _, m := range msgs {
			s.handle(ctx, m, logger)
		}
		if cursor == "" {
			cursor = "0-0"
		}
	}
}

func (s *subscription) handle(ctx context.Context, raw goredis.XMessage, logger *slog.Logger) {
	fields := stringFields(raw.Values)
	fields["__origin_subject"] = s.subject

	msg := &message{
		id:      raw.ID,
		subject: s.subject,
		fields:  fields,
		client:  s.service.client,
		group:   s.group,
	}

	err := s.handler(ctx, msg)
	if err == nil {
		if !msg.terminal {
			if ackErr := s.service.client.XAck(ctx, s.subject, s.group, raw.ID).Err(); ackErr != nil {
				logger.Warn("redis: XACK failed", slog.Any("error", ackErr), slog.String("id", raw.ID))
			}
		}
		return
	}

	// Failed delivery — check delivery count and DLQ if exceeded.
	delivery, _ := s.deliveryCount(ctx, raw.ID)
	if s.opts.MaxDeliver > 0 && delivery >= int64(s.opts.MaxDeliver) {
		dlq := s.opts.DLQSubject
		if dlq == "" {
			dlq = s.subject + ".dlq"
		}
		if dlqErr := s.service.publishToDLQ(ctx, dlq, fields, delivery, err); dlqErr != nil {
			logger.Error("redis: DLQ publish failed",
				slog.Any("error", dlqErr),
				slog.String("id", raw.ID))
			return
		}
		// Ack from the origin stream so we don't redeliver again.
		_ = s.service.client.XAck(ctx, s.subject, s.group, raw.ID).Err()
		return
	}
	// Don't ack — the message will be redelivered by the next XAUTOCLAIM
	// when its pending idle time exceeds PendingMinIdle.
}

func (s *subscription) deliveryCount(ctx context.Context, id string) (int64, error) {
	res, err := s.service.client.XPendingExt(ctx, &goredis.XPendingExtArgs{
		Stream: s.subject,
		Group:  s.group,
		Start:  id,
		End:    id,
		Count:  1,
	}).Result()
	if err != nil {
		return 0, err
	}
	if len(res) == 0 {
		return 1, nil
	}
	return res[0].RetryCount, nil
}

func stringFields(values map[string]any) map[string]string {
	out := make(map[string]string, len(values))
	for k, v := range values {
		switch t := v.(type) {
		case string:
			out[k] = t
		case []byte:
			out[k] = string(t)
		case fmt.Stringer:
			out[k] = t.String()
		default:
			out[k] = fmt.Sprintf("%v", v)
		}
	}
	return out
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// --- message adapter --------------------------------------------------------

type message struct {
	id       string
	subject  string
	fields   map[string]string
	client   goredis.UniversalClient
	group    string
	terminal bool
}

func (m *message) Data() []byte {
	return []byte(m.fields["data"])
}

func (m *message) Subject() string { return m.subject }

func (m *message) Headers() map[string]string {
	out := make(map[string]string, len(m.fields))
	for k, v := range m.fields {
		if k == "data" || k == "__origin_subject" {
			continue
		}
		out[k] = v
	}
	return out
}

func (m *message) Ack() error {
	m.terminal = true
	return m.client.XAck(context.Background(), m.subject, m.group, m.id).Err()
}

func (m *message) Nak(delay time.Duration) error {
	// Redis Streams has no native NAK; not acknowledging the message causes
	// XAUTOCLAIM to redeliver after PendingMinIdle. We honour the caller's
	// `delay` argument by sleeping in-handler when > 0.
	m.terminal = true
	if delay > 0 {
		time.Sleep(delay)
	}
	return nil
}

func (m *message) Metadata() (events.MessageMetadata, error) {
	out := events.MessageMetadata{
		Subject:       m.subject,
		MessageID:     m.fields[events.HeaderMessageID],
		CorrelationID: m.fields[events.HeaderCorrelationID],
		TenantID:      m.fields[events.HeaderTenantID],
		EventType:     m.fields[events.HeaderEventType],
		Source:        m.fields[events.HeaderSource],
		Consumer:      m.group,
	}
	if v, err := strconv.ParseUint(m.fields[events.HeaderDeliveryCount], 10, 64); err == nil {
		out.NumDelivered = v
	}
	if ts := m.fields[events.HeaderEnqueuedAt]; ts != "" {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			out.Timestamp = t
		}
	}
	return out, nil
}
