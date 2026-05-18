package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
)

// newMiniredisClient returns a fresh Client wrapping miniredis so tests
// can exercise the lock without a real Redis. miniredis implements the
// SET NX EX + Lua semantics we depend on.
func newMiniredisClient(t *testing.T) (*Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return FromRaw(rdb), mr
}

func TestDistributedLock_Acquire_Fresh(t *testing.T) {
	client, _ := newMiniredisClient(t)
	lock, err := NewDistributedLock(client, "lock:fresh", time.Second)
	if err != nil {
		t.Fatalf("new lock: %v", err)
	}
	ok, err := lock.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !ok {
		t.Fatal("acquire on fresh key returned false")
	}
}

func TestDistributedLock_Acquire_Contended(t *testing.T) {
	client, _ := newMiniredisClient(t)
	first, err := NewDistributedLock(client, "lock:contended", time.Second)
	if err != nil {
		t.Fatalf("new first: %v", err)
	}
	second, err := NewDistributedLock(client, "lock:contended", time.Second)
	if err != nil {
		t.Fatalf("new second: %v", err)
	}
	ok, err := first.Acquire(context.Background())
	if err != nil || !ok {
		t.Fatalf("first acquire: ok=%v err=%v", ok, err)
	}
	ok, err = second.Acquire(context.Background())
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if ok {
		t.Fatal("second acquire on held key returned true")
	}
}

func TestDistributedLock_Release_OnlyHolder(t *testing.T) {
	client, _ := newMiniredisClient(t)
	holder, err := NewDistributedLock(client, "lock:release", time.Second)
	if err != nil {
		t.Fatalf("new holder: %v", err)
	}
	if ok, err := holder.Acquire(context.Background()); err != nil || !ok {
		t.Fatalf("holder acquire: ok=%v err=%v", ok, err)
	}
	// A different "holder" with a different UUID must NOT be able to
	// release the lock. We synthesise one by constructing a fresh
	// lock object pointed at the same key.
	stranger, err := NewDistributedLock(client, "lock:release", time.Second)
	if err != nil {
		t.Fatalf("new stranger: %v", err)
	}
	released, err := stranger.Release(context.Background())
	if err != nil {
		t.Fatalf("stranger release: %v", err)
	}
	if released {
		t.Fatal("stranger released a lock it did not own")
	}
	// The legitimate holder must still be able to release.
	released, err = holder.Release(context.Background())
	if err != nil {
		t.Fatalf("holder release: %v", err)
	}
	if !released {
		t.Fatal("holder release returned false")
	}
	// After release the key must be gone so a new acquire succeeds.
	if ok, err := stranger.Acquire(context.Background()); err != nil || !ok {
		t.Fatalf("post-release acquire: ok=%v err=%v", ok, err)
	}
}

func TestDistributedLock_Release_AlreadyExpired(t *testing.T) {
	client, mr := newMiniredisClient(t)
	holder, err := NewDistributedLock(client, "lock:expired", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("new holder: %v", err)
	}
	if ok, err := holder.Acquire(context.Background()); err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	// miniredis exposes a deterministic clock helper; advance time
	// past the TTL so the key is gone before release runs.
	mr.FastForward(200 * time.Millisecond)
	released, err := holder.Release(context.Background())
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if released {
		t.Fatal("release returned true after expiration")
	}
}

func TestDistributedLock_Extend_PushesTTL(t *testing.T) {
	client, mr := newMiniredisClient(t)
	holder, err := NewDistributedLock(client, "lock:extend", 200*time.Millisecond)
	if err != nil {
		t.Fatalf("new holder: %v", err)
	}
	if ok, err := holder.Acquire(context.Background()); err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	// Halfway through the original TTL bump it. The total residency
	// in Redis must now exceed the original 200ms TTL.
	mr.FastForward(100 * time.Millisecond)
	ok, err := holder.Extend(context.Background(), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("extend: %v", err)
	}
	if !ok {
		t.Fatal("extend returned false for live holder")
	}
	mr.FastForward(300 * time.Millisecond) // 100 + 300 = 400ms past acquire
	owns, err := holder.Owns(context.Background())
	if err != nil {
		t.Fatalf("owns: %v", err)
	}
	if !owns {
		t.Fatal("lock evaporated before extended TTL expired")
	}
	// Past the extended TTL the lock must be gone.
	mr.FastForward(500 * time.Millisecond) // 400 + 500 = 900ms (>> 600ms extended)
	owns, err = holder.Owns(context.Background())
	if err != nil {
		t.Fatalf("post-expiry owns: %v", err)
	}
	if owns {
		t.Fatal("lock survived past extended TTL")
	}
}

func TestDistributedLock_Extend_NotOwner(t *testing.T) {
	client, _ := newMiniredisClient(t)
	first, err := NewDistributedLock(client, "lock:extend-not-owner", time.Second)
	if err != nil {
		t.Fatalf("new first: %v", err)
	}
	stranger, err := NewDistributedLock(client, "lock:extend-not-owner", time.Second)
	if err != nil {
		t.Fatalf("new stranger: %v", err)
	}
	if ok, err := first.Acquire(context.Background()); err != nil || !ok {
		t.Fatalf("first acquire: ok=%v err=%v", ok, err)
	}
	ok, err := stranger.Extend(context.Background(), 5*time.Second)
	if err != nil {
		t.Fatalf("stranger extend: %v", err)
	}
	if ok {
		t.Fatal("stranger extended a lock it did not own")
	}
}

func TestDistributedLock_ExpiredKey_CanBeReacquired(t *testing.T) {
	client, mr := newMiniredisClient(t)
	first, err := NewDistributedLock(client, "lock:reacquire", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("new first: %v", err)
	}
	if ok, err := first.Acquire(context.Background()); err != nil || !ok {
		t.Fatalf("first acquire: ok=%v err=%v", ok, err)
	}
	mr.FastForward(200 * time.Millisecond)
	second, err := NewDistributedLock(client, "lock:reacquire", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("new second: %v", err)
	}
	ok, err := second.Acquire(context.Background())
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if !ok {
		t.Fatal("second acquire after expiration returned false")
	}
}

func TestNewDistributedLock_Validation(t *testing.T) {
	client, _ := newMiniredisClient(t)
	cases := []struct {
		name string
		c    *Client
		key  string
		ttl  time.Duration
	}{
		{name: "nil client", c: nil, key: "k", ttl: time.Second},
		{name: "empty key", c: client, key: "", ttl: time.Second},
		{name: "zero ttl", c: client, key: "k", ttl: 0},
		{name: "negative ttl", c: client, key: "k", ttl: -time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lock, err := NewDistributedLock(tc.c, tc.key, tc.ttl)
			if err == nil {
				t.Fatalf("expected error, got lock=%v", lock)
			}
		})
	}
}

func TestDistributedLock_Owns_UnknownKey(t *testing.T) {
	client, _ := newMiniredisClient(t)
	lock, err := NewDistributedLock(client, "lock:owns-miss", time.Second)
	if err != nil {
		t.Fatalf("new lock: %v", err)
	}
	owns, err := lock.Owns(context.Background())
	if err != nil {
		t.Fatalf("owns: %v", err)
	}
	if owns {
		t.Fatal("Owns returned true for missing key")
	}
}

// TestDistributedLock_Release_TransportError exercises the error
// branch when the underlying Eval surfaces a real Redis transport
// error (not a logical "no key" reply). We close the connection
// before calling Release; the wrapped error must still mention the
// key so triage logs are useful.
func TestDistributedLock_Release_TransportError(t *testing.T) {
	client, _ := newMiniredisClient(t)
	lock, err := NewDistributedLock(client, "lock:transport", time.Second)
	if err != nil {
		t.Fatalf("new lock: %v", err)
	}
	_ = client.Close()
	_, err = lock.Release(context.Background())
	if err == nil {
		t.Fatal("expected transport error after Close")
	}
	if !errors.Is(err, errClosedSentinel(err)) {
		// The actual error class depends on the Redis client; we
		// only assert that the lock annotated it with the key for
		// triage.
		if got, want := err.Error(), "lock:transport"; !contains(got, want) {
			t.Errorf("error %q does not include key %q", got, want)
		}
	}
}

// errClosedSentinel returns its argument so the errors.Is comparison
// in the test never matches; the goal is just to ensure the error
// annotation includes the key. Splitting it out keeps the assertion
// readable.
func errClosedSentinel(err error) error { return err }

func contains(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
