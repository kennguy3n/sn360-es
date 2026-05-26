package zoho

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// TestResolveAccountID_CachesAndDedupes ensures that once
// ResolveAccountID has successfully warmed the directory, subsequent
// calls (across concurrent goroutines) do not re-hit the /accounts
// endpoint and that the answer is consistent.
func TestResolveAccountID_CachesAndDedupes(t *testing.T) {
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/organization/100200300/accounts", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		index, _ := strconv.Atoi(r.URL.Query().Get("index"))
		w.Header().Set("Content-Type", "application/json")
		switch index {
		case 1:
			_, _ = w.Write([]byte(`{"status":{"code":200},"data":[
				{"zuid":"z1","accountId":"acct-1","primaryEmailAddress":"alice@example.com","emailAliases":[{"emailAddress":"al@example.com"}]},
				{"zuid":"z2","accountId":"acct-2","primaryEmailAddress":"bob@example.com"}
			]}`))
		default:
			_, _ = w.Write([]byte(`{"status":{"code":200},"data":[]}`))
		}
	})
	c := newTestClient(t, mux)

	id, err := c.ResolveAccountID(context.Background(), "Alice@Example.com")
	if err != nil {
		t.Fatalf("first ResolveAccountID: %v", err)
	}
	if id != "acct-1" {
		t.Errorf("Alice id = %q, want acct-1", id)
	}

	// Concurrent lookups: must not trigger any further directory walks.
	const n = 32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			email := "alice@example.com"
			if i%3 == 0 {
				email = "al@example.com"
			}
			if i%5 == 0 {
				email = "bob@example.com"
			}
			if _, err := c.ResolveAccountID(context.Background(), email); err != nil {
				t.Errorf("concurrent ResolveAccountID(%s): %v", email, err)
			}
		}(i)
	}
	wg.Wait()

	// Initial warm + at most one paginate-terminator request (depending on
	// page-size loop behaviour). The directory walk must NOT run again
	// after the first success.
	if got := hits.Load(); got > 2 {
		t.Errorf("/accounts hits = %d, want <= 2 (warm + page-end probe)", got)
	}
}

// TestResolveAccountID_RetriesAfterFailure ensures that a transient
// directory error does NOT permanently disable account-id resolution
// for the lifetime of the Client. The first call should fail and the
// second call (after the upstream recovers) should succeed.
func TestResolveAccountID_RetriesAfterFailure(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/organization/100200300/accounts", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"status":{"code":500,"description":"transient"}}`))
			return
		}
		index, _ := strconv.Atoi(r.URL.Query().Get("index"))
		w.Header().Set("Content-Type", "application/json")
		switch index {
		case 1:
			_, _ = w.Write([]byte(`{"status":{"code":200},"data":[
				{"zuid":"z1","accountId":"acct-1","primaryEmailAddress":"alice@example.com"}
			]}`))
		default:
			_, _ = w.Write([]byte(`{"status":{"code":200},"data":[]}`))
		}
	})
	c := newTestClient(t, mux)

	if _, err := c.ResolveAccountID(context.Background(), "alice@example.com"); err == nil {
		t.Fatal("expected first ResolveAccountID to fail with upstream 500")
	}
	// Flip the upstream to healthy and retry — the per-Client gate must
	// have been re-armed by the failure path.
	failing.Store(false)
	id, err := c.ResolveAccountID(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("second ResolveAccountID after recovery: %v", err)
	}
	if id != "acct-1" {
		t.Errorf("id = %q, want acct-1", id)
	}
}

// TestResolveAccountID_RejectsEmptyEmail guards the input contract.
func TestResolveAccountID_RejectsEmptyEmail(t *testing.T) {
	c := newTestClient(t, http.NewServeMux())
	if _, err := c.ResolveAccountID(context.Background(), "   "); err == nil {
		t.Error("expected error for empty email")
	}
}

// TestResolveAccountID_UnknownEmailReturnsNotFound ensures the cache
// lookup surfaces a clear error when the email is not present in the
// warmed directory.
func TestResolveAccountID_UnknownEmailReturnsNotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/organization/100200300/accounts", func(w http.ResponseWriter, r *http.Request) {
		index, _ := strconv.Atoi(r.URL.Query().Get("index"))
		w.Header().Set("Content-Type", "application/json")
		switch index {
		case 1:
			_, _ = w.Write([]byte(`{"status":{"code":200},"data":[
				{"zuid":"z1","accountId":"acct-1","primaryEmailAddress":"alice@example.com"}
			]}`))
		default:
			_, _ = w.Write([]byte(`{"status":{"code":200},"data":[]}`))
		}
	})
	c := newTestClient(t, mux)
	if _, err := c.ResolveAccountID(context.Background(), "ghost@example.com"); err == nil {
		t.Error("expected not-found error for unknown email")
	}
}
