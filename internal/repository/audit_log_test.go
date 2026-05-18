package repository

import (
	"context"
	"testing"
	"time"
)

func TestInMemoryAuditLog_Record(t *testing.T) {
	repo := NewMemoryAuditLogs()
	ctx := context.Background()

	entry := AuditEntry{
		TenantID:      "t1",
		Actor:         "system",
		Action:        "onboarding.started",
		TargetType:    "tenant",
		TargetHash:    []byte("hash123"),
		CorrelationID: "corr-1",
		Metadata:      map[string]any{"provider": "google_workspace"},
	}

	if err := repo.Record(ctx, entry); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func TestInMemoryAuditLog_ListByTenant(t *testing.T) {
	repo := NewMemoryAuditLogs()
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_ = repo.Record(ctx, AuditEntry{
			TenantID: "t1",
			Actor:    "system",
			Action:   "test.action",
		})
	}
	_ = repo.Record(ctx, AuditEntry{
		TenantID: "t2",
		Actor:    "system",
		Action:   "other.action",
	})

	entries, err := repo.ListByTenant(ctx, "t1", time.Time{}, 100)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(entries) != 5 {
		t.Errorf("got %d entries, want 5", len(entries))
	}
}

func TestInMemoryAuditLog_ListByTenant_WithLimit(t *testing.T) {
	repo := NewMemoryAuditLogs()
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		_ = repo.Record(ctx, AuditEntry{
			TenantID: "t1",
			Actor:    "system",
			Action:   "test.action",
		})
	}

	entries, err := repo.ListByTenant(ctx, "t1", time.Time{}, 3)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("got %d entries, want 3", len(entries))
	}
}

func TestInMemoryAuditLog_ListByTenant_SinceFilter(t *testing.T) {
	repo := NewMemoryAuditLogs()
	ctx := context.Background()

	// Record some old entries.
	_ = repo.Record(ctx, AuditEntry{
		TenantID:  "t1",
		Actor:     "system",
		Action:    "old.action",
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})

	// Record a recent entry.
	_ = repo.Record(ctx, AuditEntry{
		TenantID:  "t1",
		Actor:     "system",
		Action:    "new.action",
		CreatedAt: time.Now(),
	})

	since := time.Now().Add(-1 * time.Hour)
	entries, err := repo.ListByTenant(ctx, "t1", since, 100)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1 (only recent)", len(entries))
	}
}
