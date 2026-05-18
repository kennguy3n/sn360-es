package gmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// gmailFake captures the requests the BannerInjector makes so the
// test can assert the import + trash pattern executes in the right
// order with the modified raw RFC2822.
type gmailFake struct {
	srv          *httptest.Server
	t            *testing.T
	rawMessage   []byte
	threadID     string
	imported     atomic.Pointer[string] // base64url(raw) submitted on import
	importThread atomic.Pointer[string]
	trashed      atomic.Int32
	getCount     atomic.Int32
	importStatus int
	trashStatus  int
	getStatus    int
}

func newGmailFake(t *testing.T, rawMessage []byte, threadID string) *gmailFake {
	t.Helper()
	f := &gmailFake{
		t:            t,
		rawMessage:   rawMessage,
		threadID:     threadID,
		importStatus: http.StatusOK,
		trashStatus:  http.StatusOK,
		getStatus:    http.StatusOK,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *gmailFake) URL() string { return f.srv.URL }

func (f *gmailFake) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages/m-1") && r.URL.Query().Get("format") == "raw":
		f.getCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if f.getStatus != http.StatusOK {
			w.WriteHeader(f.getStatus)
			return
		}
		enc := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(f.rawMessage)
		_ = json.NewEncoder(w).Encode(gmailGetMessageResponse{
			ID:       "m-1",
			ThreadID: f.threadID,
			Raw:      enc,
		})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/messages/import"):
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Raw      string `json:"raw"`
			ThreadID string `json:"threadId"`
		}
		_ = json.Unmarshal(body, &req)
		f.imported.Store(&req.Raw)
		f.importThread.Store(&req.ThreadID)
		if f.importStatus != http.StatusOK {
			w.WriteHeader(f.importStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"shadow-1"}`))
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/messages/m-1/trash"):
		f.trashed.Add(1)
		if f.trashStatus != http.StatusOK {
			w.WriteHeader(f.trashStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"m-1"}`))
	default:
		f.t.Logf("unexpected gmail request: %s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *gmailFake) importedRaw() []byte {
	enc := f.imported.Load()
	if enc == nil {
		return nil
	}
	dec, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(*enc)
	if err != nil {
		dec, _ = base64.URLEncoding.DecodeString(*enc)
	}
	return dec
}

func TestInjectBanner_SinglePartHTML_InjectsBeforeBody(t *testing.T) {
	raw := []byte("From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: hi\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><p>Hello</p></body></html>\r\n")
	fake := newGmailFake(t, raw, "thread-1")

	b, err := NewBannerInjector(BannerInjectorConfig{
		BaseURL:     fake.URL(),
		TokenSource: staticToken("tok"),
	})
	if err != nil {
		t.Fatalf("NewBannerInjector: %v", err)
	}

	err = b.InjectBanner(context.Background(), action.BannerInjectRequest{
		Tenant:    "t-1",
		Provider:  action.LabelProviderGmail,
		Email:     "rcpt@example.com",
		MessageID: "m-1",
		HTML:      []byte("<div id=\"sn360-banner\">SN360</div>"),
	})
	if err != nil {
		t.Fatalf("InjectBanner: %v", err)
	}

	if fake.trashed.Load() != 1 {
		t.Fatalf("expected exactly one trash call, got %d", fake.trashed.Load())
	}
	imported := fake.importedRaw()
	if !strings.Contains(string(imported), "<body><div id=\"sn360-banner\">SN360</div>") {
		t.Fatalf("banner not inserted after <body>: %q", string(imported))
	}
	if !strings.Contains(string(imported), "<p>Hello</p>") {
		t.Fatalf("original body lost: %q", string(imported))
	}
	if tid := fake.importThread.Load(); tid == nil || *tid != "thread-1" {
		t.Fatalf("threadId not preserved on import: %v", tid)
	}
}

func TestInjectBanner_MultipartAlternative_HTMLPartGetsBanner(t *testing.T) {
	boundary := "BOUNDARY"
	raw := []byte("From: s@x\r\nTo: r@x\r\nSubject: hi\r\n" +
		"Content-Type: multipart/alternative; boundary=" + boundary + "\r\n" +
		"\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"plain only\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n\r\n" +
		"<html><body>html only</body></html>\r\n" +
		"--" + boundary + "--\r\n")
	fake := newGmailFake(t, raw, "thread-1")
	b, _ := NewBannerInjector(BannerInjectorConfig{BaseURL: fake.URL(), TokenSource: staticToken("tok")})

	if err := b.InjectBanner(context.Background(), action.BannerInjectRequest{
		Tenant: "t", Provider: action.LabelProviderGmail, Email: "r@x",
		MessageID: "m-1", HTML: []byte("<b>BANNER</b>"),
	}); err != nil {
		t.Fatalf("InjectBanner: %v", err)
	}
	imported := string(fake.importedRaw())
	if !strings.Contains(imported, "<body><b>BANNER</b>html only") {
		t.Fatalf("banner not spliced into html part: %q", imported)
	}
	if !strings.Contains(imported, "plain only") {
		t.Fatalf("plain alternative dropped: %q", imported)
	}
}

func TestInjectBanner_PlainOnly_PromotedToNotice(t *testing.T) {
	raw := []byte("Subject: hi\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nplaintext body\r\n")
	fake := newGmailFake(t, raw, "")
	b, _ := NewBannerInjector(BannerInjectorConfig{BaseURL: fake.URL(), TokenSource: staticToken("tok")})
	if err := b.InjectBanner(context.Background(), action.BannerInjectRequest{
		Tenant: "t", Provider: action.LabelProviderGmail, Email: "r@x",
		MessageID: "m-1", HTML: []byte("<b>BANNER</b>"),
	}); err != nil {
		t.Fatalf("InjectBanner: %v", err)
	}
	imported := string(fake.importedRaw())
	if !strings.Contains(imported, "[SN360 SECURITY NOTICE]") {
		t.Fatalf("text/plain notice missing: %q", imported)
	}
	if !strings.Contains(imported, "plaintext body") {
		t.Fatalf("original plain body lost: %q", imported)
	}
}

func TestInjectBanner_QuotedPrintableHTMLPart(t *testing.T) {
	boundary := "QP"
	// "Hello" with quoted-printable encoding (no special chars =
	// identity for ASCII, useful to verify the decode/re-encode
	// round-trip does not corrupt the message).
	raw := []byte("From: s\r\nTo: r\r\n" +
		"Content-Type: multipart/alternative; boundary=" + boundary + "\r\n" +
		"\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
		"<html><body>Hello</body></html>\r\n" +
		"--" + boundary + "--\r\n")
	fake := newGmailFake(t, raw, "")
	b, _ := NewBannerInjector(BannerInjectorConfig{BaseURL: fake.URL(), TokenSource: staticToken("tok")})
	if err := b.InjectBanner(context.Background(), action.BannerInjectRequest{
		Tenant: "t", Provider: action.LabelProviderGmail, Email: "r@x",
		MessageID: "m-1", HTML: []byte("<b>BANNER</b>"),
	}); err != nil {
		t.Fatalf("InjectBanner: %v", err)
	}
	imported := string(fake.importedRaw())
	if !strings.Contains(imported, "<body><b>BANNER</b>Hello") {
		t.Fatalf("banner not spliced after decode+re-encode: %q", imported)
	}
}

func TestInjectBanner_TrashFailure_BubblesError(t *testing.T) {
	raw := []byte("Content-Type: text/html\r\n\r\n<body>hi</body>\r\n")
	fake := newGmailFake(t, raw, "")
	fake.trashStatus = http.StatusInternalServerError
	b, _ := NewBannerInjector(BannerInjectorConfig{BaseURL: fake.URL(), TokenSource: staticToken("tok")})
	err := b.InjectBanner(context.Background(), action.BannerInjectRequest{
		Tenant: "t", Provider: action.LabelProviderGmail, Email: "r@x",
		MessageID: "m-1", HTML: []byte("<b>BANNER</b>"),
	})
	if err == nil {
		t.Fatalf("expected trash failure to surface")
	}
	if !strings.Contains(err.Error(), "trash original") {
		t.Fatalf("error not annotated as trash failure: %v", err)
	}
	// Shadow copy must still have been imported.
	if fake.imported.Load() == nil {
		t.Fatalf("import never executed despite trash failure")
	}
}

func TestInjectBanner_Validate(t *testing.T) {
	b, _ := NewBannerInjector(BannerInjectorConfig{TokenSource: staticToken("tok")})
	tests := []struct {
		name string
		req  action.BannerInjectRequest
	}{
		{"missing tenant", action.BannerInjectRequest{MessageID: "m", HTML: []byte("x")}},
		{"missing message_id", action.BannerInjectRequest{Tenant: "t", HTML: []byte("x")}},
		{"missing html", action.BannerInjectRequest{Tenant: "t", MessageID: "m"}},
		{"missing email", action.BannerInjectRequest{Tenant: "t", MessageID: "m", HTML: []byte("x")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := b.InjectBanner(context.Background(), tc.req); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestNewBannerInjector_RequiresTokenSource(t *testing.T) {
	if _, err := NewBannerInjector(BannerInjectorConfig{}); err == nil {
		t.Fatalf("expected error on missing token source")
	}
}

func TestInjectBanner_NoBodyTag_PrependedToDocument(t *testing.T) {
	raw := []byte("Content-Type: text/html; charset=utf-8\r\n\r\n<p>orphan paragraph</p>\r\n")
	fake := newGmailFake(t, raw, "")
	b, _ := NewBannerInjector(BannerInjectorConfig{BaseURL: fake.URL(), TokenSource: staticToken("tok")})
	if err := b.InjectBanner(context.Background(), action.BannerInjectRequest{
		Tenant: "t", Provider: action.LabelProviderGmail, Email: "r@x",
		MessageID: "m-1", HTML: []byte("<div>BAN</div>"),
	}); err != nil {
		t.Fatalf("InjectBanner: %v", err)
	}
	imported := string(fake.importedRaw())
	if !strings.HasSuffix(strings.TrimSpace(imported)[len(strings.TrimSpace(imported))-len("</p>"):], "</p>") {
		t.Fatalf("expected document tail to remain <p>: %q", imported)
	}
	if !strings.Contains(imported, "<div>BAN</div><p>orphan paragraph</p>") {
		t.Fatalf("banner not prepended when no <body>: %q", imported)
	}
}
