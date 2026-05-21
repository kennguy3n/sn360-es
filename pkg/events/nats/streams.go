package nats

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// Well-known SN360-ES streams. The names are uppercased per JetStream
// convention.
const (
	StreamEvaluate   = "ES_EVALUATE"
	StreamOnboarding = "ES_ONBOARDING"
	StreamEducation  = "ES_EDUCATION"
	StreamAction     = "ES_ACTION"
	StreamDLQ        = "ES_DLQ"
)

// StreamSpec describes a JetStream stream that SN360-ES requires.
type StreamSpec struct {
	Name        string
	Subjects    []string
	Retention   jetstream.RetentionPolicy
	Storage     jetstream.StorageType
	MaxAge      time.Duration
	MaxMsgSize  int32
	DedupWindow time.Duration
	Replicas    int
	Discard     jetstream.DiscardPolicy
	Description string
}

// DefaultStreamSpecs returns the canonical set of streams the platform needs.
//
// The proposal in PROPOSAL.md Section 1 defines these. Tests assert on the
// exact configuration produced.
func DefaultStreamSpecs(cfg Config) []StreamSpec {
	storage := jetstream.FileStorage
	if strings.EqualFold(cfg.Storage, "memory") {
		storage = jetstream.MemoryStorage
	}
	replicas := cfg.Replicas
	if replicas <= 0 {
		replicas = 1
	}
	return []StreamSpec{
		{
			Name:        StreamEvaluate,
			Subjects:    []string{"es.evaluate.>"},
			Retention:   jetstream.WorkQueuePolicy,
			Storage:     storage,
			MaxAge:      24 * time.Hour,
			MaxMsgSize:  10 * 1024 * 1024,
			DedupWindow: orDefault(cfg.DedupWindow, 2*time.Minute),
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES evaluation pipeline events",
		},
		{
			Name:        StreamOnboarding,
			Subjects:    []string{"es.onboarding.>"},
			Retention:   jetstream.WorkQueuePolicy,
			Storage:     storage,
			MaxAge:      72 * time.Hour,
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES tenant / user / group lifecycle events",
		},
		{
			Name:        StreamEducation,
			Subjects:    []string{"es.education.>"},
			Retention:   jetstream.LimitsPolicy,
			Storage:     storage,
			MaxAge:      90 * 24 * time.Hour,
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES education / phishing simulation events",
		},
		{
			Name:        StreamAction,
			Subjects:    []string{"es.action.>"},
			Retention:   jetstream.WorkQueuePolicy,
			Storage:     storage,
			MaxAge:      48 * time.Hour,
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES post-evaluation action events",
		},
		{
			Name: StreamDLQ,
			// Dead-letter subjects live under a separate top-level
			// namespace so they do NOT overlap with the wildcard
			// subjects of the primary streams (es.evaluate.>,
			// es.action.>, etc.). NATS rejects subject overlap
			// between streams.
			Subjects:    []string{"es.dlq.>"},
			Retention:   jetstream.LimitsPolicy,
			Storage:     storage,
			MaxAge:      30 * 24 * time.Hour,
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES dead-letter queue (failed events)",
		},
	}
}

// EnsureStream creates the stream if it does not exist or updates it in place.
// It is idempotent and safe to call on every startup.
func EnsureStream(ctx context.Context, js jetstream.JetStream, spec StreamSpec) (jetstream.Stream, error) {
	cfg := jetstream.StreamConfig{
		Name:        spec.Name,
		Subjects:    spec.Subjects,
		Retention:   spec.Retention,
		Storage:     spec.Storage,
		MaxAge:      spec.MaxAge,
		MaxMsgSize:  spec.MaxMsgSize,
		Duplicates:  spec.DedupWindow,
		Replicas:    spec.Replicas,
		Discard:     spec.Discard,
		Description: spec.Description,
	}

	_, err := js.Stream(ctx, spec.Name)
	if err == nil {
		updated, uErr := js.UpdateStream(ctx, cfg)
		if uErr != nil {
			// If update is impossible (e.g. subject overlap), surface the error
			// rather than silently using the stale stream.
			return nil, fmt.Errorf("nats: update stream %s: %w", spec.Name, uErr)
		}
		return updated, nil
	}
	if !errors.Is(err, jetstream.ErrStreamNotFound) {
		return nil, fmt.Errorf("nats: lookup stream %s: %w", spec.Name, err)
	}

	created, cErr := js.CreateStream(ctx, cfg)
	if cErr != nil {
		return nil, fmt.Errorf("nats: create stream %s: %w", spec.Name, cErr)
	}
	return created, nil
}

// EnsureAllStreams ensures every stream in specs exists. Errors aggregate so
// that one bad stream does not prevent inspecting failures in the others.
func EnsureAllStreams(ctx context.Context, js jetstream.JetStream, specs []StreamSpec) error {
	var errs []error
	for _, spec := range specs {
		if _, err := EnsureStream(ctx, js, spec); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// StreamForSubject returns the stream name that should hold a published
// subject, or "" if none of the known streams cover it. This is used to
// route DLQ publishes back to the correct stream.
func StreamForSubject(subject string) string {
	switch {
	case strings.HasPrefix(subject, "es.dlq."):
		return StreamDLQ
	case strings.HasPrefix(subject, "es.evaluate."):
		return StreamEvaluate
	case strings.HasPrefix(subject, "es.onboarding."):
		return StreamOnboarding
	case strings.HasPrefix(subject, "es.education."):
		return StreamEducation
	case strings.HasPrefix(subject, "es.action."):
		return StreamAction
	default:
		return ""
	}
}
