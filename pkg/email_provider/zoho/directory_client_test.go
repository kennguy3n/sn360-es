package zoho

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func newTestClient(t *testing.T, h http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientConfig{
		TokenSource: StaticTokenSource{AccessToken: "tok"},
		BaseURL:     srv.URL,
		OrgID:       "100200300",
		HTTPClient:  srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestDirectoryClient_ListUsers_HappyPath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/organization/100200300/accounts", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Zoho-oauthtoken tok" {
			t.Errorf("Authorization = %q, want Zoho-oauthtoken tok", got)
		}
		index, _ := strconv.Atoi(r.URL.Query().Get("index"))
		w.Header().Set("Content-Type", "application/json")
		// Return one page with one entry, terminating the loop because
		// len < pageSize.
		switch index {
		case 1:
			_, _ = w.Write([]byte(`{
				"status":{"code":200},
				"data":[{
					"zuid":"z1","accountId":"a1",
					"primaryEmailAddress":"Alice@Example.com",
					"displayName":"Alice",
					"department":"Eng","designation":"SWE",
					"status":"active","isAdmin":true,
					"emailAliases":[{"emailAddress":"al@example.com"}],
					"groupIds":["g1","g2"]
				}]
			}`))
		default:
			_, _ = w.Write([]byte(`{"status":{"code":200},"data":[]}`))
		}
	})
	c := newTestClient(t, mux)
	dc, err := NewDirectoryClient(DirectoryClientConfig{Client: c})
	if err != nil {
		t.Fatalf("NewDirectoryClient: %v", err)
	}
	users, err := dc.ListUsers(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users, want 1", len(users))
	}
	u := users[0]
	if u.ID != "a1" {
		t.Errorf("ID = %q", u.ID)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("Email = %q, want lower-cased", u.Email)
	}
	if u.Department != "Eng" || u.JobTitle != "SWE" {
		t.Errorf("Department/JobTitle = %q/%q", u.Department, u.JobTitle)
	}
	if !u.IsAdmin {
		t.Error("expected IsAdmin=true")
	}
	if len(u.GroupIDs) != 2 || u.GroupIDs[0] != "g1" {
		t.Errorf("GroupIDs = %v", u.GroupIDs)
	}
	if len(u.Aliases) != 1 || u.Aliases[0] != "al@example.com" {
		t.Errorf("Aliases = %v", u.Aliases)
	}
}

func TestDirectoryClient_ListUsersDelta_PropagatesUpdatedAfter(t *testing.T) {
	var capturedQS string
	mux := http.NewServeMux()
	mux.HandleFunc("/organization/100200300/accounts", func(w http.ResponseWriter, r *http.Request) {
		capturedQS = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":{"code":200},"data":[]}`))
	})
	c := newTestClient(t, mux)
	dc, _ := NewDirectoryClient(DirectoryClientConfig{Client: c})
	// ListUsersDelta uses RFC3339 cursors (so the caller can persist
	// them as plain timestamps). The provider translates that to the
	// updatedAfter millis filter Zoho expects.
	users, next, err := dc.ListUsersDelta(context.Background(), "tenant", "2023-11-14T22:13:20Z")
	if err != nil {
		t.Fatalf("ListUsersDelta: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("len(users) = %d, want 0", len(users))
	}
	if next == "" {
		t.Error("expected non-empty next delta token")
	}
	// 2023-11-14T22:13:20Z == 1700000000 sec == 1700000000000 ms.
	if !strings.Contains(capturedQS, "updatedAfter=1700000000000") {
		t.Errorf("query missing updatedAfter=1700000000000: %q", capturedQS)
	}
}

func TestDirectoryClient_ListGroups_HappyPath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/organization/100200300/groups", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": map[string]any{"code": 200},
			"data": []map[string]any{
				{
					"groupId": "g1", "groupName": "Engineering",
					"emailId": "eng@example.com", "memberCount": 42,
					"description": "Engineering team",
				},
			},
		})
	})
	c := newTestClient(t, mux)
	dc, _ := NewDirectoryClient(DirectoryClientConfig{Client: c})
	groups, err := dc.ListGroups(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups) != 1 || groups[0].ID != "g1" || groups[0].Email != "eng@example.com" {
		t.Fatalf("groups = %+v", groups)
	}
}
