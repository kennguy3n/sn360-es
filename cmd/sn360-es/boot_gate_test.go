package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// TestAssertProductionDurableStores_SingleUseStore locks in the boot
// gate for the banner-action single-use (replay) guard: in production
// a process-local in-memory store is node-local across replicas and
// must refuse boot, while dev/single-instance environments only warn.
func TestAssertProductionDurableStores_SingleUseStore(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// inMemoryApp has a wired feedback service whose single-use store
	// fell back to the in-memory implementation (no Redis).
	inMemoryApp := func() *application {
		return &application{
			feedbackSvc:               &action.FeedbackService{},
			usingMemorySingleUseStore: true,
		}
	}

	t.Run("prod refuses boot", func(t *testing.T) {
		err := assertProductionDurableStores(
			&config.Config{Environment: config.EnvironmentProd}, inMemoryApp(), logger)
		if err == nil {
			t.Fatal("expected prod boot to be refused with an in-memory single-use store")
		}
		if !strings.Contains(err.Error(), "banner action single-use store") {
			t.Fatalf("error should name the offending store, got: %v", err)
		}
		if !strings.Contains(err.Error(), "REDIS_ADDR") {
			t.Fatalf("error should point operators at the fix, got: %v", err)
		}
	})

	t.Run("uat refuses boot", func(t *testing.T) {
		if err := assertProductionDurableStores(
			&config.Config{Environment: config.EnvironmentUAT}, inMemoryApp(), logger); err == nil {
			t.Fatal("expected uat boot to be refused with an in-memory single-use store")
		}
	})

	t.Run("non-prod only warns", func(t *testing.T) {
		if err := assertProductionDurableStores(
			&config.Config{Environment: config.EnvironmentLocal}, inMemoryApp(), logger); err != nil {
			t.Fatalf("non-prod must not block boot, got: %v", err)
		}
	})

	t.Run("redis-backed store passes the gate", func(t *testing.T) {
		app := &application{
			feedbackSvc:               &action.FeedbackService{},
			usingMemorySingleUseStore: false,
		}
		if err := assertProductionDurableStores(
			&config.Config{Environment: config.EnvironmentProd}, app, logger); err != nil {
			t.Fatalf("redis-backed single-use store must not block boot, got: %v", err)
		}
	})

	t.Run("no feedback service passes the gate", func(t *testing.T) {
		app := &application{usingMemorySingleUseStore: true}
		if err := assertProductionDurableStores(
			&config.Config{Environment: config.EnvironmentProd}, app, logger); err != nil {
			t.Fatalf("a nil feedback service must not block boot, got: %v", err)
		}
	})
}
