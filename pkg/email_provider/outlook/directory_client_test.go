package outlook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestDirectoryClient(t *testing.T, h http.Handler, nested bool) *DirectoryClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	dc, err := NewDirectoryClient(DirectoryClientConfig{
		TokenSource:         staticToken("test-bearer"),
		HTTPClient:          srv.Client(),
		BaseURL:             srv.URL,
		ResolveNestedGroups: nested,
	})
	if err != nil {
		t.Fatalf("NewDirectoryClient: %v", err)
	}
	return dc
}

func TestListUsers_DirectMemberOf(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		resp := graphDirectoryUserList{
			Value: []graphDirectoryUser{
				{
					ID:                "u1",
					DisplayName:       "Alice",
					UserPrincipalName: "alice@example.com",
					Mail:              "alice@example.com",
					AccountEnabled:    true,
					MemberOf: []struct {
						ODataType   string `json:"@odata.type"`
						ID          string `json:"id"`
						DisplayName string `json:"displayName"`
					}{
						{ODataType: "#microsoft.graph.group", ID: "g1", DisplayName: "Engineering"},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	dc := newTestDirectoryClient(t, mux, false)
	users, err := dc.ListUsers(context.Background(), "t1")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users, want 1", len(users))
	}
	if len(users[0].GroupIDs) != 1 || users[0].GroupIDs[0] != "g1" {
		t.Fatalf("GroupIDs = %v, want [g1]", users[0].GroupIDs)
	}
}

func TestListUsers_TransitiveMemberOf(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		resp := graphDirectoryUserList{
			Value: []graphDirectoryUser{
				{
					ID:                "u1",
					DisplayName:       "Bob",
					UserPrincipalName: "bob@example.com",
					Mail:              "bob@example.com",
					AccountEnabled:    true,
					MemberOf: []struct {
						ODataType   string `json:"@odata.type"`
						ID          string `json:"id"`
						DisplayName string `json:"displayName"`
					}{
						{ODataType: "#microsoft.graph.group", ID: "g1", DisplayName: "Engineering"},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/users/u1/transitiveMemberOf", func(w http.ResponseWriter, r *http.Request) {
		resp := transitiveGroupList{
			Value: []transitiveGroupMember{
				{ODataType: "#microsoft.graph.group", ID: "g1", DisplayName: "Engineering"},
				{ODataType: "#microsoft.graph.group", ID: "g2", DisplayName: "All Staff"},
				{ODataType: "#microsoft.graph.directoryRole", ID: "r1", DisplayName: "Global Admin"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	dc := newTestDirectoryClient(t, mux, true)
	users, err := dc.ListUsers(context.Background(), "t1")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users, want 1", len(users))
	}
	// Should have both g1 (direct) and g2 (nested), but NOT r1 (role).
	if len(users[0].GroupIDs) != 2 {
		t.Fatalf("GroupIDs = %v, want 2 groups", users[0].GroupIDs)
	}
	groupSet := map[string]bool{}
	for _, id := range users[0].GroupIDs {
		groupSet[id] = true
	}
	if !groupSet["g1"] || !groupSet["g2"] {
		t.Fatalf("expected g1 and g2 in GroupIDs, got %v", users[0].GroupIDs)
	}
}

func TestListUsers_TransitiveFallback_OnError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		resp := graphDirectoryUserList{
			Value: []graphDirectoryUser{
				{
					ID:                "u1",
					DisplayName:       "Carol",
					UserPrincipalName: "carol@example.com",
					Mail:              "carol@example.com",
					AccountEnabled:    true,
					MemberOf: []struct {
						ODataType   string `json:"@odata.type"`
						ID          string `json:"id"`
						DisplayName string `json:"displayName"`
					}{
						{ODataType: "#microsoft.graph.group", ID: "g1", DisplayName: "Eng"},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/users/u1/transitiveMemberOf", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	dc := newTestDirectoryClient(t, mux, true)
	users, err := dc.ListUsers(context.Background(), "t1")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	// On transitive failure, should keep direct groups.
	if len(users[0].GroupIDs) != 1 || users[0].GroupIDs[0] != "g1" {
		t.Fatalf("GroupIDs = %v, want [g1] (fallback to direct)", users[0].GroupIDs)
	}
}
