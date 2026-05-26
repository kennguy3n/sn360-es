package fastmail

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

func TestLabelProvider_Kind(t *testing.T) {
	c, _ := NewClient(ClientConfig{
		TokenSource: staticTokenSource("tok"),
		BaseURL:     "http://example.invalid",
		AccountID:   "acct-1",
	})
	lp, err := NewLabelProvider(LabelProviderConfig{Client: c})
	if err != nil {
		t.Fatalf("NewLabelProvider: %v", err)
	}
	if lp.Kind() != action.LabelProviderFastmail {
		t.Errorf("Kind = %q", lp.Kind())
	}
	// Compile-time guarantee.
	var _ action.LabelProvider = lp
}

func TestLabelProvider_EnsureLabel_ReusesExistingMailbox(t *testing.T) {
	var (
		mailboxGetCalls int
		mailboxSetCalls int
	)
	srv := newFakeFastmail(t, func(method string, _ json.RawMessage, _ string) (string, any) {
		switch method {
		case "Mailbox/get":
			mailboxGetCalls++
			return "Mailbox/get", map[string]any{
				"accountId": "acct-1",
				"state":     "s1",
				"list": []map[string]any{
					{"id": "mb-1", "name": "SN360-Tier1", "role": nil},
				},
			}
		case "Mailbox/set":
			mailboxSetCalls++
			return "Mailbox/set", map[string]any{"created": map[string]any{}}
		default:
			t.Errorf("unexpected method %q", method)
			return method, map[string]any{}
		}
	})
	c, _ := NewClient(ClientConfig{
		TokenSource: staticTokenSource("tok"),
		BaseURL:     srv.URL,
		AccountID:   "acct-1",
	})
	lp, _ := NewLabelProvider(LabelProviderConfig{Client: c})
	id, err := lp.EnsureLabel(context.Background(), "alice@example.com", "sn360-tier1", action.LabelColor{Background: "#000"})
	if err != nil {
		t.Fatalf("EnsureLabel: %v", err)
	}
	if id != "mb-1" {
		t.Errorf("EnsureLabel = %q", id)
	}
	if mailboxSetCalls != 0 {
		t.Errorf("Mailbox/set called %d times, expected 0", mailboxSetCalls)
	}
	if mailboxGetCalls != 1 {
		t.Errorf("Mailbox/get calls = %d", mailboxGetCalls)
	}
}

func TestLabelProvider_EnsureLabel_CreatesWhenMissing(t *testing.T) {
	var createPayload json.RawMessage
	srv := newFakeFastmail(t, func(method string, args json.RawMessage, _ string) (string, any) {
		switch method {
		case "Mailbox/get":
			return "Mailbox/get", map[string]any{"list": []any{}}
		case "Mailbox/set":
			createPayload = args
			return "Mailbox/set", map[string]any{
				"created": map[string]any{
					"new": map[string]any{"id": "mb-new"},
				},
			}
		default:
			t.Errorf("unexpected method %q", method)
			return method, map[string]any{}
		}
	})
	c, _ := NewClient(ClientConfig{
		TokenSource: staticTokenSource("tok"),
		BaseURL:     srv.URL,
		AccountID:   "acct-1",
	})
	lp, _ := NewLabelProvider(LabelProviderConfig{Client: c})
	id, err := lp.EnsureLabel(context.Background(), "alice@example.com", "Quarantine", action.LabelColor{})
	if err != nil {
		t.Fatalf("EnsureLabel: %v", err)
	}
	if id != "mb-new" {
		t.Errorf("EnsureLabel = %q", id)
	}
	// Verify the Mailbox/set payload referenced the configured account.
	if !strings.Contains(string(createPayload), `"accountId":"acct-1"`) {
		t.Errorf("create payload missing accountId: %s", string(createPayload))
	}
}

func TestLabelProvider_ApplyAndRemove_SetMailboxIds(t *testing.T) {
	var lastArgs json.RawMessage
	srv := newFakeFastmail(t, func(method string, args json.RawMessage, _ string) (string, any) {
		switch method {
		case "Mailbox/get":
			return "Mailbox/get", map[string]any{"list": []any{}}
		case "Email/set":
			lastArgs = args
			return "Email/set", map[string]any{"updated": map[string]any{"msg-1": map[string]any{}}}
		}
		return method, map[string]any{}
	})
	c, _ := NewClient(ClientConfig{
		TokenSource: staticTokenSource("tok"),
		BaseURL:     srv.URL,
		AccountID:   "acct-1",
	})
	lp, _ := NewLabelProvider(LabelProviderConfig{Client: c})

	if err := lp.ApplyLabel(context.Background(), "alice@example.com", "msg-1", "mb-1"); err != nil {
		t.Fatalf("ApplyLabel: %v", err)
	}
	if !strings.Contains(string(lastArgs), `"mailboxIds/mb-1":true`) {
		t.Errorf("apply payload missing mailboxIds add: %s", string(lastArgs))
	}

	if err := lp.RemoveLabel(context.Background(), "alice@example.com", "msg-1", "mb-1"); err != nil {
		t.Fatalf("RemoveLabel: %v", err)
	}
	if !strings.Contains(string(lastArgs), `"mailboxIds/mb-1":null`) {
		t.Errorf("remove payload missing mailboxIds remove: %s", string(lastArgs))
	}
}
