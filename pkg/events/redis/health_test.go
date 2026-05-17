package redis

import (
	"context"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
)

// TestService_Health_Connected verifies the readiness probe succeeds on a
// healthy Redis connection. It exercises the same code path the Kubernetes
// /readyz probe will hit on every interval.
func TestService_Health_Connected(t *testing.T) {
	srv := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	svc := NewServiceWithClient(rdb, DefaultConfig(), "sn360-es-test", nil)
	if err := svc.Health(context.Background()); err != nil {
		t.Fatalf("Health on a healthy miniredis instance returned: %v", err)
	}
}

// TestService_Health_ServerDown verifies the readiness probe surfaces the
// underlying connection failure when the broker is unreachable. This is the
// signal Kubernetes uses to mark the pod NotReady.
func TestService_Health_ServerDown(t *testing.T) {
	srv := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	svc := NewServiceWithClient(rdb, DefaultConfig(), "sn360-es-test", nil)
	srv.Close()

	err := svc.Health(context.Background())
	if err == nil {
		t.Fatal("Health returned nil after the miniredis server was closed")
	}
	if !strings.Contains(err.Error(), "redis: PING") {
		t.Fatalf("expected error to wrap PING failure, got: %v", err)
	}
}

// TestService_Health_NilService guards against panics when callers wire a
// nil EventService into the readiness checker.
func TestService_Health_NilService(t *testing.T) {
	var svc *Service
	if err := svc.Health(context.Background()); err == nil {
		t.Fatal("Health on nil service returned nil")
	}
}
