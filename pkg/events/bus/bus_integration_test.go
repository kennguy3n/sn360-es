//go:build integration
// +build integration

package bus_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	tcnats "github.com/testcontainers/testcontainers-go/modules/nats"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/events/bus"
	natsbus "github.com/kennguy3n/sn360-es/pkg/events/nats"
	redisbus "github.com/kennguy3n/sn360-es/pkg/events/redis"
)

func skipIfNoDocker(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "docker") {
		t.Skipf("docker not available, skipping: %v", err)
	}
	t.Fatalf("container start failed: %v", err)
}

func startNATSURL(t *testing.T) string {
	t.Helper()
	c, err := tcnats.Run(context.Background(), "nats:2.10-alpine")
	skipIfNoDocker(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	u, err := c.ConnectionString(context.Background())
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	return u
}

func startRedisAddr(t *testing.T) string {
	t.Helper()
	c, err := tcredis.Run(context.Background(), "redis:7-alpine")
	skipIfNoDocker(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	uri, _ := c.ConnectionString(context.Background())
	return strings.TrimSuffix(strings.TrimPrefix(uri, "redis://"), "/")
}

func runPublishSubscribe(t *testing.T, svc events.EventService, subject, durable string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	got := make(chan events.Message, 1)
	sub, err := svc.Subscribe(ctx, subject,
		func(_ context.Context, m events.Message) error {
			got <- m
			return nil
		},
		events.WithDurable(durable),
	)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Close()

	if err := svc.Publish(ctx, subject, []byte("flag-test")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	select {
	case m := <-got:
		if string(m.Data()) != "flag-test" {
			t.Fatalf("payload mismatch: %q", string(m.Data()))
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for delivery")
	}
}

func TestBus_NATSBackedByFlag(t *testing.T) {
	url := startNATSURL(t)
	cfg := bus.Config{
		Type:   bus.TypeNATS,
		Source: "bus-it",
		NATS: func() natsbus.Config {
			c := natsbus.DefaultConfig()
			c.URL = url
			c.Storage = "memory"
			return c
		}(),
	}
	svc, err := bus.New(context.Background(), cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("new nats: %v", err)
	}
	defer bus.CloseWithTimeout(svc, 5*time.Second)
	runPublishSubscribe(t, svc, "es.evaluate.factory", "it-factory-nats")
}

func TestBus_RedisBackedByFlag(t *testing.T) {
	addr := startRedisAddr(t)
	cfg := bus.Config{
		Type:   bus.TypeRedis,
		Source: "bus-it",
		Redis: redisbus.Config{
			Addr: addr,
		},
	}
	svc, err := bus.New(context.Background(), cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("new redis: %v", err)
	}
	defer bus.CloseWithTimeout(svc, 5*time.Second)
	runPublishSubscribe(t, svc, "es.evaluate.factory", "it-factory-redis")
}

func TestBus_UnknownTypeIsRejected(t *testing.T) {
	_, err := bus.New(context.Background(), bus.Config{Type: bus.Type("kafka")}, nil)
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

// TestBus_HealthRoutesToProvider exercises the readiness probe path end-to-end:
// the bus factory must surface a provider-specific Health that succeeds against
// a live broker, regardless of which backend the feature flag selects.
func TestBus_HealthRoutesToProvider(t *testing.T) {
	t.Run("nats", func(t *testing.T) {
		url := startNATSURL(t)
		cfg := bus.Config{
			Type:   bus.TypeNATS,
			Source: "bus-it",
			NATS: func() natsbus.Config {
				c := natsbus.DefaultConfig()
				c.URL = url
				c.Storage = "memory"
				return c
			}(),
		}
		svc, err := bus.New(context.Background(), cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
		if err != nil {
			t.Fatalf("new nats: %v", err)
		}
		defer bus.CloseWithTimeout(svc, 5*time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := svc.Health(ctx); err != nil {
			t.Fatalf("nats Health: %v", err)
		}
	})

	t.Run("redis", func(t *testing.T) {
		addr := startRedisAddr(t)
		cfg := bus.Config{
			Type:   bus.TypeRedis,
			Source: "bus-it",
			Redis: redisbus.Config{
				Addr: addr,
			},
		}
		svc, err := bus.New(context.Background(), cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
		if err != nil {
			t.Fatalf("new redis: %v", err)
		}
		defer bus.CloseWithTimeout(svc, 5*time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := svc.Health(ctx); err != nil {
			t.Fatalf("redis Health: %v", err)
		}
	})
}
