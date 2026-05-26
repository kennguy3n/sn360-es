package zoho

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

func TestLabelProvider_KindAndCompileTimeChecks(t *testing.T) {
	c := newTestClient(t, http.NewServeMux())
	lp, err := New(Config{Client: c})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if lp.Kind() != action.LabelProviderZoho {
		t.Errorf("Kind() = %q, want zoho", lp.Kind())
	}
	// Compile-time guarantee.
	var _ action.LabelProvider = lp
}

func TestLabelProvider_EnsureLabel_ReusesExisting(t *testing.T) {
	var creates atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/organization/100200300/tags", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":{"code":200},"data":[{"tagId":"tag-1","tagName":"sn360-tier1"}]}`))
		case http.MethodPost:
			creates.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"tagId":"new","tagName":"sn360-tier1"}}`))
		}
	})
	c := newTestClient(t, mux)
	lp, err := New(Config{Client: c})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := lp.EnsureLabel(context.Background(), "alice@example.com", "SN360-Tier1", action.LabelColor{Background: "#b58a00", Foreground: "#1f1f1f"})
	if err != nil {
		t.Fatalf("EnsureLabel: %v", err)
	}
	if id != "tag-1" {
		t.Errorf("EnsureLabel returned %q, want tag-1 (re-use)", id)
	}
	if creates.Load() != 0 {
		t.Errorf("expected zero POSTs (tag existed), got %d", creates.Load())
	}
}

func TestLabelProvider_EnsureLabel_CreatesWhenMissing(t *testing.T) {
	var creates atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/organization/100200300/tags", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":{"code":200},"data":[]}`))
		case http.MethodPost:
			creates.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"tagId":"tag-new","tagName":"SN360-Tier1"}}`))
		}
	})
	c := newTestClient(t, mux)
	lp, _ := New(Config{Client: c})
	id, err := lp.EnsureLabel(context.Background(), "alice@example.com", "SN360-Tier1", action.LabelColor{Background: "#b58a00", Foreground: "#1f1f1f"})
	if err != nil {
		t.Fatalf("EnsureLabel: %v", err)
	}
	if id != "tag-new" {
		t.Errorf("EnsureLabel returned %q, want tag-new", id)
	}
	if creates.Load() != 1 {
		t.Errorf("expected one POST, got %d", creates.Load())
	}
}

func TestLabelProvider_ApplyLabel_HitsAccountEndpoint(t *testing.T) {
	var capturedPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/organization/100200300/accounts", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":{"code":200},"data":[{"accountId":"acct-7","primaryEmailAddress":"alice@example.com"}]}`))
	})
	mux.HandleFunc("/accounts/acct-7/messages/tag/tag-1", func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":{"code":200}}`))
	})
	c := newTestClient(t, mux)
	lp, _ := New(Config{Client: c})
	if err := lp.ApplyLabel(context.Background(), "alice@example.com", "msg-99", "tag-1"); err != nil {
		t.Fatalf("ApplyLabel: %v", err)
	}
	if capturedPath != "/accounts/acct-7/messages/tag/tag-1" {
		t.Errorf("path = %q", capturedPath)
	}
}

func TestLabelProvider_RemoveLabel_HitsAccountEndpoint(t *testing.T) {
	var capturedPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/organization/100200300/accounts", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":{"code":200},"data":[{"accountId":"acct-7","primaryEmailAddress":"alice@example.com"}]}`))
	})
	mux.HandleFunc("/accounts/acct-7/messages/tag/tag-1", func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":{"code":200}}`))
	})
	c := newTestClient(t, mux)
	lp, _ := New(Config{Client: c})
	if err := lp.RemoveLabel(context.Background(), "alice@example.com", "msg-99", "tag-1"); err != nil {
		t.Fatalf("RemoveLabel: %v", err)
	}
	if capturedPath != "/accounts/acct-7/messages/tag/tag-1" {
		t.Errorf("path = %q", capturedPath)
	}
}
