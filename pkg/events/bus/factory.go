// Package bus wires the abstract events.EventService to a concrete provider
// (NATS JetStream or Redis Streams) based on configuration.
//
// It lives in a sub-package to break the import cycle that would otherwise
// occur if pkg/events itself depended on its providers.
package bus

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/events"
	natsbus "github.com/kennguy3n/sn360-es/pkg/events/nats"
	redisbus "github.com/kennguy3n/sn360-es/pkg/events/redis"
)

// Type selects the event-bus backend used by [New].
type Type string

const (
	TypeNATS  Type = "nats"
	TypeRedis Type = "redis"
)

// Config holds the inputs to [New]. Only the fields relevant to the
// selected Type are read.
type Config struct {
	Type   Type
	Source string

	NATS  natsbus.Config
	Redis redisbus.Config
}

// New returns an EventService backed by the configured Type.
//
// Switching providers is a configuration change only.
func New(ctx context.Context, cfg Config, logger *slog.Logger) (events.EventService, error) {
	if logger == nil {
		logger = slog.Default()
	}
	switch cfg.Type {
	case TypeNATS, "":
		return natsbus.NewService(ctx, cfg.NATS, cfg.Source, logger)
	case TypeRedis:
		return redisbus.NewService(ctx, cfg.Redis, cfg.Source, logger)
	default:
		return nil, fmt.Errorf("events/bus: unknown bus type %q", cfg.Type)
	}
}

// MustNew is a convenience wrapper that panics on error. Use only in main().
func MustNew(ctx context.Context, cfg Config, logger *slog.Logger) events.EventService {
	svc, err := New(ctx, cfg, logger)
	if err != nil {
		panic(err)
	}
	return svc
}

// CloseWithTimeout closes svc but gives up after timeout to avoid hanging
// service shutdown on a broken broker.
func CloseWithTimeout(svc events.EventService, timeout time.Duration) error {
	if svc == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- svc.Close() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("events/bus: close timed out after %s", timeout)
	}
}
