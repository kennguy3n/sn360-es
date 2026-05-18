package outlook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
)

type outlookMboxFake struct {
	srv    *httptest.Server
	users  []graphUser
	msgs   []graphMessage
	calls  int
}

func newOutlookMboxFake(t *testing.T) *outlookMboxFake {
	t.Helper()
	f := &outlookMboxFake{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *outlookMboxFake) URL() string { return f.srv.URL }

func (f *outlookMboxFake) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.calls++
	switch {
	case strings.HasPrefix(r.URL.Path, "/users") && !strings.Contains(r.URL.Path, "/messages"):
		_ = json.NewEncoder(w).Encode(graphUserList{Value: f.users})
	case strings.Contains(r.URL.Path, "/messages"):
		_ = json.NewEncoder(w).Encode(graphMessageList{Value: f.msgs})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestNewMailboxProvider_Validates(t *testing.T) {
	if _, err := NewMailboxProvider(MailboxProviderConfig{}); err == nil {
		t.Fatal("token source required")
	}
	if _, err := NewMailboxProvider(MailboxProviderConfig{TokenSource: staticToken("t")}); err == nil {
		t.Fatal("tenant id required")
	}
	p, err := NewMailboxProvider(MailboxProviderConfig{TokenSource: staticToken("t"), TenantID: "t-1"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if p.Kind() != "outlook" {
		t.Errorf("kind: %q", p.Kind())
	}
}

func TestListMailboxes_ManualFallback(t *testing.T) {
	p, _ := NewMailboxProvider(MailboxProviderConfig{
		TokenSource:     staticToken("tok"),
		TenantID:        "t-1",
		ManualMailboxes: []string{"User@Corp.Example", " ", ""},
	})
	mboxes, err := p.ListMailboxes(context.Background(), "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(mboxes) != 1 || mboxes[0].Address != "user@corp.example" {
		t.Errorf("manual list: %+v", mboxes)
	}
}

func TestListMailboxes_GraphEnumeration(t *testing.T) {
	fake := newOutlookMboxFake(t)
	fake.users = []graphUser{
		{ID: "1", Mail: "alice@corp.example", AccountEnabled: true},
		{ID: "2", UserPrincipalName: "bob@corp.example", AccountEnabled: true},
		{ID: "3", Mail: "carol@corp.example", AccountEnabled: false},
		{ID: "4", AccountEnabled: true}, // no email - skipped
	}
	p, _ := NewMailboxProvider(MailboxProviderConfig{
		TokenSource:    staticToken("tok"),
		TenantID:       "t-1",
		BaseURL:        fake.URL(),
		EnumerateUsers: true,
	})
	mboxes, err := p.ListMailboxes(context.Background(), "t-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(mboxes) != 2 {
		t.Fatalf("expected 2 (disabled + missing skipped): %+v", mboxes)
	}
	if mboxes[0].UserID != "1" || mboxes[1].UserID != "2" {
		t.Errorf("user ids: %+v", mboxes)
	}
}

func TestFetchNew_PopulatesEverything(t *testing.T) {
	fake := newOutlookMboxFake(t)
	rcv := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	fake.msgs = []graphMessage{{
		ID: "m-1", Subject: "Hello",
		Body: graphItemBody{ContentType: "html", Content: "<p>hi</p>"},
		BodyPreview: "hi",
		ReceivedDateTime: rcv,
		From: graphRecipient{EmailAddress: graphEmailAddress{Address: "alice@x.com"}},
		ToRecipients:   []graphRecipient{{EmailAddress: graphEmailAddress{Address: "bob@corp.example"}}},
		CcRecipients:   []graphRecipient{{EmailAddress: graphEmailAddress{Address: "carol@corp.example"}}},
		InternetMessageHeaders: []graphHeader{
			{Name: "Authentication-Results", Value: "spf=pass dkim=pass dmarc=pass"},
		},
		HasAttachments: true,
	}}
	p, _ := NewMailboxProvider(MailboxProviderConfig{
		TokenSource: staticToken("tok"), TenantID: "t-1", BaseURL: fake.URL(),
	})
	emails, err := p.FetchNew(context.Background(), ingestion.Mailbox{Address: "bob@corp.example"}, time.Time{}, 10)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(emails) != 1 {
		t.Fatalf("expected 1 email: %+v", emails)
	}
	e := emails[0]
	if e.Sender != "alice@x.com" {
		t.Errorf("sender: %q", e.Sender)
	}
	if len(e.Recipients) != 1 || len(e.CC) != 1 {
		t.Errorf("rcpts/cc: %+v", e)
	}
	if e.HTMLBody != "<p>hi</p>" {
		t.Errorf("html: %q", e.HTMLBody)
	}
	if e.Headers["Authentication-Results"] == "" {
		t.Errorf("headers: %+v", e.Headers)
	}
	if e.Headers["Content-Type"] != "multipart/mixed" {
		t.Errorf("attachment hint missing: %q", e.Headers["Content-Type"])
	}
}

func TestFetchNew_FiltersByCheckpoint(t *testing.T) {
	fake := newOutlookMboxFake(t)
	cp := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	fake.msgs = []graphMessage{
		{ID: "old", ReceivedDateTime: cp.Add(-time.Minute), Body: graphItemBody{ContentType: "text"}},
		{ID: "new", ReceivedDateTime: cp.Add(time.Minute), Body: graphItemBody{ContentType: "text"}},
	}
	p, _ := NewMailboxProvider(MailboxProviderConfig{
		TokenSource: staticToken("tok"), TenantID: "t-1", BaseURL: fake.URL(),
	})
	emails, err := p.FetchNew(context.Background(), ingestion.Mailbox{Address: "u@x.com"}, cp, 10)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(emails) != 1 || emails[0].ProviderMessageID != "new" {
		t.Errorf("checkpoint filter: %+v", emails)
	}
}

func TestFetchNew_RequiresMailboxAddress(t *testing.T) {
	p, _ := NewMailboxProvider(MailboxProviderConfig{TokenSource: staticToken("t"), TenantID: "t-1"})
	if _, err := p.FetchNew(context.Background(), ingestion.Mailbox{}, time.Time{}, 0); err == nil {
		t.Fatal("expected error for empty mailbox")
	}
}
