package workmail

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newWorkMailFake spins up a fake WorkMail JSON API and a Client that
// targets it. The handler receives the X-Amz-Target operation name
// and the parsed request body, and returns the response object.
func newWorkMailFake(t *testing.T, handler func(operation string, body map[string]any) any) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		const prefix = "AWSWorkMail_20171001."
		if !strings.HasPrefix(target, prefix) {
			t.Errorf("X-Amz-Target = %q (missing prefix)", target)
		}
		operation := strings.TrimPrefix(target, prefix)
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "AWS4-HMAC-SHA256") {
			t.Errorf("missing/invalid SigV4 Authorization: %q", got)
		}
		bodyBytes, _ := io.ReadAll(r.Body)
		var body map[string]any
		if len(bodyBytes) > 0 {
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
		}
		resp := handler(operation, body)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	signer, err := NewSigner(SignerConfig{
		Region:  "us-east-1",
		Service: "workmail",
		Credentials: StaticCredentials{Credentials: Credentials{
			AccessKeyID: "AKIA", SecretAccessKey: "S",
		}},
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	c, err := NewClient(ClientConfig{
		HTTPClient: srv.Client(),
		Signer:     signer,
		Endpoint:   srv.URL,
		Region:     "us-east-1",
		OrgID:      "m-abc",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestDirectoryClient_ListUsers_HappyPath(t *testing.T) {
	c := newWorkMailFake(t, func(operation string, body map[string]any) any {
		if operation != "ListUsers" {
			t.Errorf("unexpected operation %q", operation)
		}
		if body["OrganizationId"] != "m-abc" {
			t.Errorf("OrganizationId = %v", body["OrganizationId"])
		}
		return map[string]any{
			"Users": []map[string]any{
				{
					"Id": "u1", "Email": "Alice@Example.com",
					"Name": "alice", "DisplayName": "Alice", "State": "ENABLED", "UserRole": "USER",
				},
				{
					"Id": "u2", "Email": "shared@example.com",
					"DisplayName": "Shared MBX", "State": "ENABLED", "UserRole": "RESOURCE",
				},
				{
					"Id": "u3", "Email": "svc@example.com",
					"DisplayName": "SvcAcct", "State": "DISABLED", "UserRole": "SYSTEM_USER",
				},
			},
		}
	})
	dc, err := NewDirectoryClient(DirectoryClientConfig{Client: c})
	if err != nil {
		t.Fatalf("NewDirectoryClient: %v", err)
	}
	users, err := dc.ListUsers(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("got %d users, want 3", len(users))
	}
	if users[0].Email != "alice@example.com" {
		t.Errorf("Email = %q (want lower-case)", users[0].Email)
	}
	if !users[1].IsSharedMailbox {
		t.Errorf("user[1] should be SharedMailbox")
	}
	if !users[2].IsServiceAccount {
		t.Errorf("user[2] should be ServiceAccount")
	}
	if !users[2].IsSuspended {
		t.Errorf("user[2] should be Suspended (State=DISABLED)")
	}
}

func TestDirectoryClient_ListUsers_FollowsPagination(t *testing.T) {
	call := 0
	c := newWorkMailFake(t, func(_ string, body map[string]any) any {
		call++
		switch call {
		case 1:
			if _, ok := body["NextToken"]; ok {
				t.Errorf("first call should not pass NextToken: %v", body)
			}
			return map[string]any{
				"Users": []map[string]any{
					{"Id": "u1", "Email": "a@example.com", "State": "ENABLED", "UserRole": "USER"},
				},
				"NextToken": "tok-2",
			}
		case 2:
			if body["NextToken"] != "tok-2" {
				t.Errorf("second call NextToken = %v", body["NextToken"])
			}
			return map[string]any{
				"Users": []map[string]any{
					{"Id": "u2", "Email": "b@example.com", "State": "ENABLED", "UserRole": "USER"},
				},
			}
		}
		t.Fatalf("unexpected third call")
		return nil
	})
	dc, _ := NewDirectoryClient(DirectoryClientConfig{Client: c})
	users, err := dc.ListUsers(context.Background(), "")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}
}

func TestDirectoryClient_ListGroups_HappyPath(t *testing.T) {
	c := newWorkMailFake(t, func(operation string, _ map[string]any) any {
		if operation != "ListGroups" {
			t.Errorf("operation = %q", operation)
		}
		return map[string]any{
			"Groups": []map[string]any{
				{"Id": "g1", "Name": "Engineering", "Email": "eng@example.com", "State": "ENABLED"},
			},
		}
	})
	dc, _ := NewDirectoryClient(DirectoryClientConfig{Client: c})
	groups, err := dc.ListGroups(context.Background(), "")
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups) != 1 || groups[0].ID != "g1" {
		t.Fatalf("groups = %+v", groups)
	}
}

func TestClient_Invoke_SurfacesAPIErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"BadRequest","message":"missing OrganizationId"}`))
	}))
	t.Cleanup(srv.Close)
	signer, _ := NewSigner(SignerConfig{
		Region: "us-east-1", Service: "workmail",
		Credentials: StaticCredentials{Credentials: Credentials{AccessKeyID: "K", SecretAccessKey: "S"}},
	})
	c, _ := NewClient(ClientConfig{
		HTTPClient: srv.Client(),
		Signer:     signer,
		Endpoint:   srv.URL,
		Region:     "us-east-1",
		OrgID:      "m-abc",
	})
	err := c.Invoke(context.Background(), "ListUsers", map[string]any{"OrganizationId": "m-abc"}, &struct{}{})
	if err == nil {
		t.Fatal("expected error from 400 response")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("err type = %T, want *APIError", err)
	}
	if apiErr.Type != "BadRequest" || apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("apiErr = %+v", apiErr)
	}
}
