package ingestion

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/kennguy3n/sn360-es/pkg/storage/redis"
)

// newCheckpointHarness wires a fresh miniredis behind the SN360 Redis
// wrapper and returns the store. The miniredis instance is returned
// for tests that need direct manipulation (e.g. seeding legacy
// RFC3339 payloads).
func newCheckpointHarness(t *testing.T) (*RedisCheckpointStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	client := redis.FromRaw(rdb)
	store, err := NewCheckpointStore(client, "", 0)
	if err != nil {
		t.Fatalf("new checkpoint store: %v", err)
	}
	return store, mr
}

func TestCheckpoint_SetThenGet(t *testing.T) {
	store, _ := newCheckpointHarness(t)
	want := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	if err := store.Set(context.Background(), "t-1", "alice@example.com", want); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok, err := store.Get(context.Background(), "t-1", "alice@example.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !ok {
		t.Fatal("get returned !ok after Set")
	}
	if !got.Equal(want) {
		t.Errorf("ts: got %s, want %s", got, want)
	}
}

func TestCheckpoint_MissingKeyReturnsZero(t *testing.T) {
	store, _ := newCheckpointHarness(t)
	got, ok, err := store.Get(context.Background(), "t-1", "alice@example.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if ok {
		t.Fatal("get reported ok=true for missing key")
	}
	if !got.IsZero() {
		t.Errorf("ts: got %s, want zero", got)
	}
}

func TestCheckpoint_DifferentMailboxesAreIndependent(t *testing.T) {
	store, _ := newCheckpointHarness(t)
	a := time.Date(2026, 5, 17, 1, 0, 0, 0, time.UTC)
	b := time.Date(2026, 5, 17, 2, 0, 0, 0, time.UTC)
	if err := store.Set(context.Background(), "t-1", "alice@example.com", a); err != nil {
		t.Fatalf("set a: %v", err)
	}
	if err := store.Set(context.Background(), "t-1", "bob@example.com", b); err != nil {
		t.Fatalf("set b: %v", err)
	}
	gotA, _, _ := store.Get(context.Background(), "t-1", "alice@example.com")
	gotB, _, _ := store.Get(context.Background(), "t-1", "bob@example.com")
	if !gotA.Equal(a) {
		t.Errorf("alice: got %s want %s", gotA, a)
	}
	if !gotB.Equal(b) {
		t.Errorf("bob: got %s want %s", gotB, b)
	}
}

func TestCheckpoint_MailboxCaseAndWhitespaceNormalised(t *testing.T) {
	store, _ := newCheckpointHarness(t)
	ts := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	if err := store.Set(context.Background(), "t-1", "Alice@Example.com", ts); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok, err := store.Get(context.Background(), "t-1", "  alice@EXAMPLE.com  ")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !ok {
		t.Fatal("get with different case returned !ok")
	}
	if !got.Equal(ts) {
		t.Errorf("ts: got %s want %s", got, ts)
	}
}

func TestCheckpoint_DifferentTenantsAreIndependent(t *testing.T) {
	store, _ := newCheckpointHarness(t)
	a := time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC)
	b := time.Date(2026, 5, 17, 6, 0, 0, 0, time.UTC)
	if err := store.Set(context.Background(), "t-1", "alice@example.com", a); err != nil {
		t.Fatalf("set tenant a: %v", err)
	}
	if err := store.Set(context.Background(), "t-2", "alice@example.com", b); err != nil {
		t.Fatalf("set tenant b: %v", err)
	}
	gotA, _, _ := store.Get(context.Background(), "t-1", "alice@example.com")
	gotB, _, _ := store.Get(context.Background(), "t-2", "alice@example.com")
	if !gotA.Equal(a) {
		t.Errorf("tenant 1: got %s want %s", gotA, a)
	}
	if !gotB.Equal(b) {
		t.Errorf("tenant 2: got %s want %s", gotB, b)
	}
}

func TestCheckpoint_KeyDoesNotLeakMailbox(t *testing.T) {
	store, mr := newCheckpointHarness(t)
	ts := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	if err := store.Set(context.Background(), "t-1", "alice@example.com", ts); err != nil {
		t.Fatalf("set: %v", err)
	}
	for _, key := range mr.Keys() {
		if strings.Contains(key, "alice@example.com") {
			t.Fatalf("key %q leaks mailbox in plaintext", key)
		}
	}
}

func TestCheckpoint_LegacyRFC3339Payload(t *testing.T) {
	store, mr := newCheckpointHarness(t)
	// Seed a legacy RFC3339-encoded value to simulate a pre-rollout
	// binary's checkpoint. The Get path must still parse it.
	ts := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	key := store.keyFor("t-1", "alice@example.com")
	mr.Set(key, ts.Format(time.RFC3339))
	got, ok, err := store.Get(context.Background(), "t-1", "alice@example.com")
	if err != nil {
		t.Fatalf("get legacy: %v", err)
	}
	if !ok {
		t.Fatal("legacy get returned !ok")
	}
	if !got.Equal(ts) {
		t.Errorf("legacy ts: got %s want %s", got, ts)
	}
}

func TestCheckpoint_GarbagePayloadIsDeleted(t *testing.T) {
	store, mr := newCheckpointHarness(t)
	key := store.keyFor("t-1", "alice@example.com")
	mr.Set(key, "not a timestamp")
	_, ok, err := store.Get(context.Background(), "t-1", "alice@example.com")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if ok {
		t.Fatal("expected ok=false on parse error")
	}
	// The bad key must have been removed so a subsequent Set wins
	// without manual cleanup.
	if mr.Exists(key) {
		t.Fatal("garbage key not deleted")
	}
}

func TestCheckpoint_Set_ZeroTimestampRejected(t *testing.T) {
	store, _ := newCheckpointHarness(t)
	err := store.Set(context.Background(), "t-1", "alice@example.com", time.Time{})
	if err == nil {
		t.Fatal("expected error for zero timestamp")
	}
}

func TestCheckpoint_GetSet_MissingArgsRejected(t *testing.T) {
	store, _ := newCheckpointHarness(t)
	if err := store.Set(context.Background(), "", "alice@example.com", time.Now()); err == nil {
		t.Errorf("Set: expected error for empty tenant")
	}
	if err := store.Set(context.Background(), "t-1", "", time.Now()); err == nil {
		t.Errorf("Set: expected error for empty mailbox")
	}
	if _, _, err := store.Get(context.Background(), "", "alice@example.com"); err == nil {
		t.Errorf("Get: expected error for empty tenant")
	}
	if _, _, err := store.Get(context.Background(), "t-1", ""); err == nil {
		t.Errorf("Get: expected error for empty mailbox")
	}
}

func TestNewCheckpointStore_RejectsNilClient(t *testing.T) {
	_, err := NewCheckpointStore(nil, "", 0)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}
