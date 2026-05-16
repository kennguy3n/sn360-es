// Package events defines the abstract event-bus interface used by SN360-ES
// and the supporting types that both NATS JetStream and Redis Streams
// implementations satisfy.
//
// The interface is deliberately minimal and provider-agnostic so that any
// future migration to Kafka, RabbitMQ, Google Pub/Sub, etc. only requires a
// new implementation under `pkg/events/<provider>/` without changes to
// callers.
package events

import (
	"context"
	"errors"
	"time"
)

// Common header keys propagated across providers.
//
// They are intentionally not provider-specific (no "Nats-*" prefix) so the
// same handler code works against NATS or Redis.
const (
	HeaderMessageID     = "message-id"
	HeaderCorrelationID = "correlation-id"
	HeaderTenantID      = "tenant-id"
	HeaderEventType     = "event-type"
	HeaderSource        = "source"
	HeaderDeliveryCount = "delivery-count"
	HeaderError         = "error"
	HeaderOriginSubject = "origin-subject"
	HeaderEnqueuedAt    = "enqueued-at"
)

// ErrSubscriptionClosed is returned by a [Subscription] after [Subscription.Close]
// has been called.
var ErrSubscriptionClosed = errors.New("events: subscription closed")

// EventService is the contract every event-bus provider implements.
//
// A single EventService instance is safe for concurrent use by multiple
// goroutines.
type EventService interface {
	// Publish sends data on the given subject. Implementations are responsible
	// for retries, deduplication (where supported), and correlation ID
	// propagation via [PublishOption] / context.
	Publish(ctx context.Context, subject string, data []byte, opts ...PublishOption) error

	// Subscribe registers a durable handler on subject. Returns a Subscription
	// that the caller must Close to stop receiving messages.
	//
	// `handler` is invoked once per message. If it returns nil, the message is
	// acked; if it returns a non-nil error, the message is naked (negatively
	// acknowledged) with the implementation's default backoff so the broker
	// re-delivers it. To control redelivery timing explicitly, the handler can
	// call [Message.Nak] / [Message.Ack] directly and then return nil.
	Subscribe(ctx context.Context, subject string, handler MessageHandler, opts ...SubscribeOption) (Subscription, error)

	// Close releases all underlying resources (connections, consumers). The
	// service must not be used after Close returns.
	Close() error
}

// MessageHandler processes a single message.
type MessageHandler func(ctx context.Context, msg Message) error

// Subscription represents an active subscription returned by [EventService.Subscribe].
type Subscription interface {
	// Subject returns the subject (or stream/channel) the subscription is bound to.
	Subject() string
	// Close stops the subscription and waits for any in-flight handler to return.
	Close() error
}

// Message is a single event received by a subscriber.
type Message interface {
	// Data is the raw payload as published.
	Data() []byte
	// Subject is the topic / subject / stream the message was published on.
	Subject() string
	// Headers returns user-defined headers, including the well-known
	// HeaderCorrelationID / HeaderTenantID / etc.
	Headers() map[string]string
	// Ack positively acknowledges the message so it is not redelivered.
	Ack() error
	// Nak negatively acknowledges the message. If `delay` is > 0, the broker
	// will wait at least that long before re-delivering. A zero delay uses the
	// broker default.
	Nak(delay time.Duration) error
	// Metadata returns provider-specific metadata (delivery count, sequence,
	// stream/consumer names, etc.).
	Metadata() (MessageMetadata, error)
}

// MessageMetadata is the canonical per-message metadata.
type MessageMetadata struct {
	// MessageID is the dedup ID, when the publisher set one.
	MessageID string
	// Subject is the topic this message was delivered on.
	Subject string
	// CorrelationID propagates the request correlation across services.
	CorrelationID string
	// TenantID identifies the tenant the message belongs to (may be empty).
	TenantID string
	// EventType is the symbolic name of the event (e.g. "evaluate.request").
	EventType string
	// Source identifies the producing service.
	Source string
	// NumDelivered is 1-based; 1 means first delivery.
	NumDelivered uint64
	// Stream / Consumer are provider-specific identifiers (may be empty).
	Stream   string
	Consumer string
	// Sequence is a provider-assigned monotonic offset.
	Sequence uint64
	// Timestamp is the publish time when known.
	Timestamp time.Time
}

// --- Options ----------------------------------------------------------------

// PublishOption customises a single Publish call.
type PublishOption func(*PublishOptions)

// PublishOptions holds the resolved Publish-side configuration.
type PublishOptions struct {
	MessageID     string
	CorrelationID string
	TenantID      string
	EventType     string
	Headers       map[string]string
	Timeout       time.Duration
	// MaxRetries overrides the default per-call retry attempts.
	MaxRetries int
	// RetryDelay is the base delay between retries (exponentially backed off).
	RetryDelay time.Duration
}

// WithMessageID sets the publisher dedup ID.
func WithMessageID(id string) PublishOption {
	return func(o *PublishOptions) { o.MessageID = id }
}

// WithCorrelationID sets the correlation ID header.
func WithCorrelationID(id string) PublishOption {
	return func(o *PublishOptions) { o.CorrelationID = id }
}

// WithTenantID sets the tenant ID header.
func WithTenantID(id string) PublishOption {
	return func(o *PublishOptions) { o.TenantID = id }
}

// WithEventType sets the symbolic event name.
func WithEventType(t string) PublishOption {
	return func(o *PublishOptions) { o.EventType = t }
}

// WithHeader adds a custom header.
func WithHeader(k, v string) PublishOption {
	return func(o *PublishOptions) {
		if o.Headers == nil {
			o.Headers = map[string]string{}
		}
		o.Headers[k] = v
	}
}

// WithHeaders adds many custom headers (existing keys are overwritten).
func WithHeaders(h map[string]string) PublishOption {
	return func(o *PublishOptions) {
		if o.Headers == nil {
			o.Headers = map[string]string{}
		}
		for k, v := range h {
			o.Headers[k] = v
		}
	}
}

// WithPublishTimeout overrides the per-call publish timeout.
func WithPublishTimeout(d time.Duration) PublishOption {
	return func(o *PublishOptions) { o.Timeout = d }
}

// WithMaxRetries overrides the default publish retry count.
func WithMaxRetries(n int) PublishOption {
	return func(o *PublishOptions) { o.MaxRetries = n }
}

// WithRetryDelay overrides the base retry delay.
func WithRetryDelay(d time.Duration) PublishOption {
	return func(o *PublishOptions) { o.RetryDelay = d }
}

// ResolvePublishOptions applies opts in order to a base set.
func ResolvePublishOptions(base PublishOptions, opts ...PublishOption) PublishOptions {
	out := base
	if out.Headers != nil {
		// Make a copy so callers don't mutate the base map.
		cp := make(map[string]string, len(out.Headers))
		for k, v := range out.Headers {
			cp[k] = v
		}
		out.Headers = cp
	}
	for _, opt := range opts {
		opt(&out)
	}
	return out
}

// SubscribeOption customises a single Subscribe call.
type SubscribeOption func(*SubscribeOptions)

// SubscribeOptions holds the resolved Subscribe-side configuration.
type SubscribeOptions struct {
	// Durable is the durable consumer / group name. Required for JetStream
	// durable consumers; treated as a Redis consumer-group name.
	Durable string
	// Group is the queue / consumer group used for load balancing across
	// replicas. Defaults to Durable.
	Group string
	// MaxDeliver is the maximum delivery attempts before the message is
	// routed to a DLQ. <=0 means unlimited.
	MaxDeliver int
	// AckWait is how long the broker waits for an ack before redelivering.
	AckWait time.Duration
	// FilterSubject lets a subscription target a sub-subject of the stream
	// (used by JetStream subjects with wildcards).
	FilterSubject string
	// BatchSize is the maximum number of messages to pull per fetch (for pull
	// consumers). 0 = implementation default.
	BatchSize int
	// MaxWait is the per-batch fetch timeout for pull consumers.
	MaxWait time.Duration
	// MaxAckPending limits the number of un-acked messages per consumer.
	MaxAckPending int
	// DLQSubject is the subject to publish to once MaxDeliver is exceeded.
	// Implementations should default to "<subject>.dlq" when empty.
	DLQSubject string
}

// WithDurable names the durable consumer / group.
func WithDurable(name string) SubscribeOption {
	return func(o *SubscribeOptions) { o.Durable = name }
}

// WithGroup sets the queue group used for horizontal scaling.
func WithGroup(name string) SubscribeOption {
	return func(o *SubscribeOptions) { o.Group = name }
}

// WithMaxDeliver sets the maximum delivery attempts.
func WithMaxDeliver(n int) SubscribeOption {
	return func(o *SubscribeOptions) { o.MaxDeliver = n }
}

// WithAckWait sets the per-message ack timeout.
func WithAckWait(d time.Duration) SubscribeOption {
	return func(o *SubscribeOptions) { o.AckWait = d }
}

// WithFilterSubject narrows a wildcard subscription to a specific sub-subject.
func WithFilterSubject(s string) SubscribeOption {
	return func(o *SubscribeOptions) { o.FilterSubject = s }
}

// WithBatchSize sets the pull-consumer batch size.
func WithBatchSize(n int) SubscribeOption {
	return func(o *SubscribeOptions) { o.BatchSize = n }
}

// WithMaxWait sets the per-batch fetch timeout.
func WithMaxWait(d time.Duration) SubscribeOption {
	return func(o *SubscribeOptions) { o.MaxWait = d }
}

// WithMaxAckPending limits the number of in-flight (un-acked) messages.
func WithMaxAckPending(n int) SubscribeOption {
	return func(o *SubscribeOptions) { o.MaxAckPending = n }
}

// WithDLQSubject sets the dead-letter subject for this subscription.
func WithDLQSubject(s string) SubscribeOption {
	return func(o *SubscribeOptions) { o.DLQSubject = s }
}

// ResolveSubscribeOptions applies opts to a base set.
func ResolveSubscribeOptions(base SubscribeOptions, opts ...SubscribeOption) SubscribeOptions {
	out := base
	for _, opt := range opts {
		opt(&out)
	}
	if out.Group == "" {
		out.Group = out.Durable
	}
	return out
}
