package nats

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// FetchBatch pulls up to maxMsgs from the durable pull consumer identified
// by (stream, durable). It creates / updates the consumer with a filter
// for subject on the first call and reuses it thereafter. Each returned
// events.Message preserves the underlying ack semantics; callers MUST
// Ack or Nak every message they receive.
//
// Returns an empty slice (not an error) when no messages were ready
// within maxWait.
func (c *Client) FetchBatch(ctx context.Context, stream, durable, subject string, maxMsgs int, maxWait time.Duration) ([]events.Message, error) {
	if stream == "" || durable == "" || subject == "" {
		return nil, errors.New("nats: FetchBatch requires stream, durable, subject")
	}
	if maxMsgs <= 0 {
		return nil, nil
	}
	if maxWait <= 0 {
		maxWait = 500 * time.Millisecond
	}
	js := c.JetStream()
	if js == nil {
		return nil, errors.New("nats: jetstream not connected")
	}

	// CreateOrUpdateConsumer is idempotent; calling it from the hot path
	// is fine because JetStream short-circuits unchanged configs.
	cons, err := js.CreateOrUpdateConsumer(ctx, stream, jetstream.ConsumerConfig{
		Name:          durable,
		Durable:       durable,
		FilterSubject: subject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       30 * time.Second,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		Description:   "SN360-ES pull consumer for " + subject,
	})
	if err != nil {
		return nil, fmt.Errorf("nats: create pull consumer: %w", err)
	}

	batch, err := cons.Fetch(maxMsgs, jetstream.FetchMaxWait(maxWait))
	if err != nil {
		return nil, fmt.Errorf("nats: fetch: %w", err)
	}

	out := make([]events.Message, 0, maxMsgs)
	for jm := range batch.Messages() {
		out = append(out, &message{raw: jm})
	}
	if err := batch.Error(); err != nil && !errors.Is(err, context.Canceled) {
		return out, fmt.Errorf("nats: fetch batch error: %w", err)
	}
	return out, nil
}
