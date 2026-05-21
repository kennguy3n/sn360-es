package nats

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// DLQReplayer reads messages off the ES_DLQ stream and republishes them
// back to their original subject. It is used by an operator-facing
// admin endpoint to retry messages that failed during normal processing.
//
// Replays preserve the original headers but reset the message ID so they
// are not deduplicated against the failed original.
type DLQReplayer struct {
	js        jetstream.JetStream
	publisher *Publisher
}

// NewDLQReplayer constructs a replayer bound to a JetStream context and an
// existing Publisher (so retries, dedup, and headers behave identically
// to a regular publish).
func NewDLQReplayer(js jetstream.JetStream, pub *Publisher) *DLQReplayer {
	return &DLQReplayer{js: js, publisher: pub}
}

// ReplayOptions controls a single Replay invocation.
type ReplayOptions struct {
	// Limit caps the number of messages replayed. 0 means "no limit".
	Limit int
	// MaxAge ignores messages older than this. 0 means "no age limit".
	MaxAge time.Duration
	// Subject filter pulled by the consumer. If empty, all DLQ subjects
	// are inspected.
	Subject string
	// DryRun reports what would be replayed without acking the source
	// messages.
	DryRun bool
}

// ReplayResult summarises a Replay invocation.
type ReplayResult struct {
	Inspected int
	Replayed  int
	Skipped   int
	Errors    []error
}

// Replay walks ES_DLQ once and replays matching messages onto their
// original subjects. The original message is acked only on a successful
// replay (or always in DryRun mode).
func (r *DLQReplayer) Replay(ctx context.Context, opts ReplayOptions) (ReplayResult, error) {
	if r.js == nil {
		return ReplayResult{}, errors.New("nats: DLQReplayer requires a JetStream context")
	}
	if r.publisher == nil {
		return ReplayResult{}, errors.New("nats: DLQReplayer requires a Publisher")
	}

	stream, err := r.js.Stream(ctx, StreamDLQ)
	if err != nil {
		return ReplayResult{}, fmt.Errorf("nats: lookup DLQ stream: %w", err)
	}
	consumerCfg := jetstream.OrderedConsumerConfig{
		DeliverPolicy: jetstream.DeliverAllPolicy,
		ReplayPolicy:  jetstream.ReplayInstantPolicy,
	}
	if opts.Subject != "" {
		consumerCfg.FilterSubjects = []string{opts.Subject}
	}
	consumer, err := stream.OrderedConsumer(ctx, consumerCfg)
	if err != nil {
		return ReplayResult{}, fmt.Errorf("nats: create DLQ ordered consumer: %w", err)
	}

	result := ReplayResult{}
	cutoff := time.Time{}
	if opts.MaxAge > 0 {
		cutoff = time.Now().Add(-opts.MaxAge)
	}

	// Fetch in modest batches so we never block forever; the OrderedConsumer
	// streams all messages until exhausted.
	for opts.Limit <= 0 || result.Replayed < opts.Limit {

		batch, ferr := consumer.Fetch(50, jetstream.FetchMaxWait(500*time.Millisecond))
		if ferr != nil {
			result.Errors = append(result.Errors, ferr)
			break
		}
		drained := false
		for jm := range batch.Messages() {
			drained = true
			result.Inspected++
			if rerr := r.replayOne(ctx, jm, cutoff, opts.DryRun, &result); rerr != nil {
				result.Errors = append(result.Errors, rerr)
			}
		}
		if !drained {
			break
		}
		if err := batch.Error(); err != nil {
			result.Errors = append(result.Errors, err)
			break
		}
	}

	if len(result.Errors) > 0 {
		return result, errors.Join(result.Errors...)
	}
	return result, nil
}

// replayOne handles a single DLQ message.
func (r *DLQReplayer) replayOne(
	ctx context.Context,
	jm jetstream.Msg,
	cutoff time.Time,
	dryRun bool,
	result *ReplayResult,
) error {
	headers := jm.Headers()
	original := headers.Get(events.HeaderOriginSubject)
	if original == "" {
		// No origin recorded — refuse to republish to avoid loops.
		result.Skipped++
		_ = jm.Ack()
		return nil
	}

	if !cutoff.IsZero() {
		meta, err := jm.Metadata()
		if err == nil && meta.Timestamp.Before(cutoff) {
			result.Skipped++
			_ = jm.Ack()
			return nil
		}
	}

	if dryRun {
		_ = jm.Nak()
		return nil
	}

	// Publish a fresh copy on the original subject. New message ID so the
	// dedup window doesn't suppress the retry.
	publishOpts := []events.PublishOption{}
	for k, vs := range headers {
		if len(vs) == 0 {
			continue
		}
		switch k {
		case events.HeaderMessageID, events.HeaderError, events.HeaderDeliveryCount:
			// Skip — replayer overrides these.
			continue
		case events.HeaderOriginSubject:
			continue
		}
		publishOpts = append(publishOpts, events.WithHeader(k, vs[0]))
	}
	publishOpts = append(publishOpts, events.WithHeader("Replay-Source", "dlq"))

	if err := r.publisher.Publish(ctx, original, jm.Data(), publishOpts...); err != nil {
		_ = jm.Nak()
		return fmt.Errorf("nats: replay %s: %w", original, err)
	}
	if err := jm.Ack(); err != nil {
		return fmt.Errorf("nats: ack DLQ message after replay: %w", err)
	}
	result.Replayed++
	return nil
}
