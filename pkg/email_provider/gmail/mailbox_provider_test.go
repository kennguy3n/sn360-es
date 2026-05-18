package gmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
)

// gmailMboxFake stands in for both the Admin SDK Directory API and
// the Gmail REST API. The test selects which surface to exercise via
// the request method + path.
type gmailMboxFake struct {
	srv      *httptest.Server
	users    []adminUser
	listMsgs []struct {
		ID         string
		Sender     string
		Subject    string
		HTMLBody   string
		PlainBody  string
		InternalMS int64
		Headers    []gmailMessageHeader
	}
	listCount int
	getCount  int
}

func (f *gmailMboxFake) URL() string { return f.srv.URL }

func newGmailMboxFake(t *testing.T) *gmailMboxFake {
	t.Helper()
	f := &gmailMboxFake{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *gmailMboxFake) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/admin/directory/v1/users"):
		_ = json.NewEncoder(w).Encode(adminUserList{Users: f.users})
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/messages") && r.URL.Query().Get("format") != "full":
		// list endpoint
		f.listCount++
		out := gmailMessageList{}
		for _, m := range f.listMsgs {
			out.Messages = append(out.Messages, struct {
				ID       string `json:"id"`
				ThreadID string `json:"threadId,omitempty"`
			}{ID: m.ID})
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/messages/") && r.URL.Query().Get("format") == "full":
		f.getCount++
		segs := strings.Split(r.URL.Path, "/")
		id := segs[len(segs)-1]
		for _, m := range f.listMsgs {
			if m.ID != id {
				continue
			}
			payload := gmailMessagePayload{
				MimeType: "multipart/alternative",
				Headers:  m.Headers,
				Parts: []gmailMessagePayload{
					{MimeType: "text/plain", Body: gmailMessagePart{Data: base64.URLEncoding.EncodeToString([]byte(m.PlainBody))}},
					{MimeType: "text/html", Body: gmailMessagePart{Data: base64.URLEncoding.EncodeToString([]byte(m.HTMLBody))}},
				},
			}
			_ = json.NewEncoder(w).Encode(gmailMessage{
				ID:           m.ID,
				InternalDate: jsonInt(m.InternalMS),
				Payload:      payload,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func jsonInt(v int64) string {
	if v == 0 {
		return ""
	}
	return strings.TrimSpace(strings.Repeat(" ", 0)) + itoa(v)
}

func itoa(v int64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	return string(buf[i:])
}

func TestNewMailboxProvider_Validates(t *testing.T) {
	if _, err := NewMailboxProvider(MailboxProviderConfig{}); err == nil {
		t.Fatal("expected error without token source")
	}
	if _, err := NewMailboxProvider(MailboxProviderConfig{TokenSource: staticToken("x")}); err == nil {
		t.Fatal("expected error without tenant id")
	}
	p, err := NewMailboxProvider(MailboxProviderConfig{TokenSource: staticToken("x"), TenantID: "t-1"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if p.Kind() != "gmail" {
		t.Errorf("kind: %q", p.Kind())
	}
}

func TestListMailboxes_FallsBackToManualWhenNoAdminSource(t *testing.T) {
	p, _ := NewMailboxProvider(MailboxProviderConfig{
		TokenSource:     staticToken("tok"),
		TenantID:        "t-1",
		ManualMailboxes: []string{"  Alice@Corp.example  ", ""},
	})
	mboxes, err := p.ListMailboxes(context.Background(), "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(mboxes) != 1 || mboxes[0].Address != "alice@corp.example" || mboxes[0].TenantID != "t-1" {
		t.Errorf("manual fallback: %+v", mboxes)
	}
}

func TestListMailboxes_UsesAdminSDK(t *testing.T) {
	fake := newGmailMboxFake(t)
	fake.users = []adminUser{
		{PrimaryEmail: "Alice@Corp.example", ID: "u1"},
		{PrimaryEmail: "bob@corp.example", ID: "u2", Suspended: true},
		{PrimaryEmail: "carol@corp.example", ID: "u3"},
	}
	p, _ := NewMailboxProvider(MailboxProviderConfig{
		TokenSource:      staticToken("gmail"),
		AdminTokenSource: staticToken("admin"),
		TenantID:         "t-1",
		AdminBaseURL:     fake.URL(),
	})
	mboxes, err := p.ListMailboxes(context.Background(), "t-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(mboxes) != 2 {
		t.Fatalf("expected 2 (suspended filtered): %+v", mboxes)
	}
	if mboxes[0].Address != "alice@corp.example" {
		t.Errorf("lowercasing: %q", mboxes[0].Address)
	}
}

func TestFetchNew_HydratesMessages(t *testing.T) {
	fake := newGmailMboxFake(t)
	rcvMS := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC).UnixMilli()
	fake.listMsgs = []struct {
		ID         string
		Sender     string
		Subject    string
		HTMLBody   string
		PlainBody  string
		InternalMS int64
		Headers    []gmailMessageHeader
	}{
		{
			ID: "m-1", PlainBody: "hello", HTMLBody: "<p>hello</p>", InternalMS: rcvMS,
			Headers: []gmailMessageHeader{
				{Name: "From", Value: "Alice <alice@x.com>"},
				{Name: "To", Value: "bob@corp.example, carol@corp.example"},
				{Name: "Cc", Value: "dan@corp.example"},
				{Name: "Subject", Value: "Hi"},
				{Name: "Authentication-Results", Value: "spf=pass dkim=pass"},
			},
		},
	}
	p, _ := NewMailboxProvider(MailboxProviderConfig{
		TokenSource: staticToken("tok"),
		TenantID:    "t-1",
		BaseURL:     fake.URL(),
	})
	emails, err := p.FetchNew(context.Background(), ingestion.Mailbox{Address: "bob@corp.example", TenantID: "t-1"}, time.Time{}, 10)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(emails) != 1 {
		t.Fatalf("expected 1 email: %+v", emails)
	}
	e := emails[0]
	if e.Sender == "" || e.Subject != "Hi" {
		t.Errorf("headers: %+v", e)
	}
	if len(e.Recipients) != 2 {
		t.Errorf("recipients: %v", e.Recipients)
	}
	if len(e.CC) != 1 {
		t.Errorf("cc: %v", e.CC)
	}
	if e.Body == "" || e.HTMLBody == "" {
		t.Errorf("bodies: %q / %q", e.Body, e.HTMLBody)
	}
	if e.ReceivedAt.UnixMilli() != rcvMS {
		t.Errorf("received_at: %s", e.ReceivedAt)
	}
}

func TestFetchNew_FiltersByCheckpoint(t *testing.T) {
	fake := newGmailMboxFake(t)
	cp := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	fake.listMsgs = []struct {
		ID         string
		Sender     string
		Subject    string
		HTMLBody   string
		PlainBody  string
		InternalMS int64
		Headers    []gmailMessageHeader
	}{
		{ID: "old", InternalMS: cp.Add(-time.Minute).UnixMilli()},
		{ID: "new", InternalMS: cp.Add(time.Minute).UnixMilli()},
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

func TestExtractBodies_WalksMultipart(t *testing.T) {
	payload := gmailMessagePayload{
		MimeType: "multipart/mixed",
		Parts: []gmailMessagePayload{
			{MimeType: "text/plain", Body: gmailMessagePart{Data: base64.URLEncoding.EncodeToString([]byte("text"))}},
			{MimeType: "multipart/alternative", Parts: []gmailMessagePayload{
				{MimeType: "text/html", Body: gmailMessagePart{Data: base64.URLEncoding.EncodeToString([]byte("<p>html</p>"))}},
			}},
		},
	}
	plain, html := extractBodies(payload)
	if plain != "text" || html != "<p>html</p>" {
		t.Errorf("bodies: %q / %q", plain, html)
	}
}

func TestSplitAddresses(t *testing.T) {
	got := splitAddresses("a@x.com, b@y.com, , c@z.com")
	if len(got) != 3 || got[2] != "c@z.com" {
		t.Errorf("split: %v", got)
	}
	if splitAddresses("") != nil {
		t.Errorf("empty should be nil")
	}
}

func TestFetchNew_RequiresMailboxAddress(t *testing.T) {
	p, _ := NewMailboxProvider(MailboxProviderConfig{TokenSource: staticToken("t"), TenantID: "t-1"})
	if _, err := p.FetchNew(context.Background(), ingestion.Mailbox{}, time.Time{}, 0); err == nil {
		t.Fatal("expected error for empty mailbox address")
	}
}
