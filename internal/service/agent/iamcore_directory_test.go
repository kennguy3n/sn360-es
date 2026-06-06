package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newIAMCoreUsersServer returns a test server emulating iam-core's
// GET /api/v1/management/users endpoint. It paginates `users` by
// pageSize and asserts the bearer token + tenant query.
func newIAMCoreUsersServer(t *testing.T, wantToken, wantTenant string, users []map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/management/users" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+wantToken {
			t.Errorf("Authorization = %q, want %q", got, "Bearer "+wantToken)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if got := r.URL.Query().Get("tenant_id"); got != wantTenant {
			t.Errorf("tenant_id = %q, want %q", got, wantTenant)
		}
		page := 1
		fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
		pageSize := 100
		fmt.Sscanf(r.URL.Query().Get("page_size"), "%d", &pageSize)

		start := (page - 1) * pageSize
		end := start + pageSize
		var pageUsers []map[string]any
		if start < len(users) {
			if end > len(users) {
				end = len(users)
			}
			pageUsers = users[start:end]
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total":     len(users),
			"page":      page,
			"page_size": pageSize,
			"tenant_id": wantTenant,
			"users":     pageUsers,
		})
	}))
}

func TestIAMCoreDirectoryClient_ListUsers_MapsAndPaginates(t *testing.T) {
	users := []map[string]any{
		{"user_id": "u1", "email": "alice@acme.com", "name": "Alice", "blocked": false,
			"metadata": map[string]any{"department": "Engineering", "job_title": "Staff Eng"}},
		{"user_id": "u2", "email": "bob@acme.com", "name": "Bob", "blocked": true},
		{"user_id": "u3", "email": "carol@acme.com", "name": "Carol", "blocked": false},
	}
	srv := newIAMCoreUsersServer(t, "tok-123", "acme", users)
	defer srv.Close()

	client, err := NewIAMCoreDirectoryClient(IAMCoreDirectoryConfig{
		BaseURL:  srv.URL,
		Token:    "tok-123",
		PageSize: 2, // force pagination across the 3 users
	})
	if err != nil {
		t.Fatalf("NewIAMCoreDirectoryClient: %v", err)
	}

	got, err := client.ListUsers(context.Background(), "acme")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d users, want 3", len(got))
	}

	if got[0].ID != "u1" || got[0].Email != "alice@acme.com" || got[0].DisplayName != "Alice" {
		t.Errorf("user[0] = %+v", got[0])
	}
	if got[0].Department != "Engineering" || got[0].JobTitle != "Staff Eng" {
		t.Errorf("user[0] metadata mapping = dept %q title %q", got[0].Department, got[0].JobTitle)
	}
	if got[0].IsSuspended {
		t.Error("user[0] should not be suspended")
	}
	if !got[1].IsSuspended {
		t.Error("user[1] (blocked) should map to IsSuspended=true")
	}
}

func TestIAMCoreDirectoryClient_ListUsers_PropagatesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, err := NewIAMCoreDirectoryClient(IAMCoreDirectoryConfig{BaseURL: srv.URL, Token: "t"})
	if err != nil {
		t.Fatalf("NewIAMCoreDirectoryClient: %v", err)
	}
	if _, err := client.ListUsers(context.Background(), "acme"); err == nil {
		t.Fatal("expected error on 500 response")
	}
}

// TestIAMCoreDirectoryClient_ListUsers_PageCap ensures a misbehaving
// API that never terminates pagination (always a non-empty page with
// total=0) is bounded by the page cap and errors rather than looping
// forever or silently returning a truncated roster.
func TestIAMCoreDirectoryClient_ListUsers_PageCap(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		// Always non-empty, total=0 → neither termination guard fires.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total": 0,
			"users": []map[string]any{{"user_id": "u", "email": "u@x.com"}},
		})
	}))
	defer srv.Close()

	client, err := NewIAMCoreDirectoryClient(IAMCoreDirectoryConfig{BaseURL: srv.URL, Token: "t"})
	if err != nil {
		t.Fatalf("NewIAMCoreDirectoryClient: %v", err)
	}
	_, err = client.ListUsers(context.Background(), "acme")
	if err == nil {
		t.Fatal("expected error when pagination never terminates")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error = %v, want page-cap 'exceeded' error", err)
	}
	if hits > iamCoreMaxPages+1 {
		t.Errorf("made %d requests, want <= %d (page cap not enforced)", hits, iamCoreMaxPages+1)
	}
}

func TestNewIAMCoreDirectoryClient_Validation(t *testing.T) {
	if _, err := NewIAMCoreDirectoryClient(IAMCoreDirectoryConfig{Token: "t"}); err == nil {
		t.Error("expected error when BaseURL missing")
	}
	if _, err := NewIAMCoreDirectoryClient(IAMCoreDirectoryConfig{BaseURL: "https://x"}); err == nil {
		t.Error("expected error when Token missing")
	}
}
