package outlook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

type outlookFake struct {
	srv         *httptest.Server
	t           *testing.T
	body        outlookMessageBody
	patchedBody atomic.Pointer[outlookMessageBody]
	getStatus   int
	patchStatus int
	getCount    atomic.Int32
	patchCount  atomic.Int32
}

func newOutlookFake(t *testing.T, body outlookMessageBody) *outlookFake {
	t.Helper()
	f := &outlookFake{t: t, body: body, getStatus: http.StatusOK, patchStatus: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *outlookFake) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		f.getCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if f.getStatus != http.StatusOK {
			w.WriteHeader(f.getStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(outlookMessageBodyEnvelope{ID: "m-1", Body: f.body})
	case http.MethodPatch:
		f.patchCount.Add(1)
		body, _ := io.ReadAll(r.Body)
		var env outlookMessageBodyEnvelope
		_ = json.Unmarshal(body, &env)
		f.patchedBody.Store(&env.Body)
		if f.patchStatus != http.StatusOK {
			w.WriteHeader(f.patchStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"m-1"}`))
	default:
		f.t.Logf("unexpected outlook request: %s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusNotFound)
	}
}

func newOutlookBI(t *testing.T, srvURL string) *BannerInjector {
	t.Helper()
	b, err := NewBannerInjector(BannerInjectorConfig{
		BaseURL:     srvURL,
		TokenSource: TokenSourceFunc(func(_ context.Context) (string, error) { return "tok", nil }),
	})
	if err != nil {
		t.Fatalf("NewBannerInjector: %v", err)
	}
	return b
}

func TestOutlookInjectBanner_HTMLBody_SplicedAfterBody(t *testing.T) {
	fake := newOutlookFake(t, outlookMessageBody{
		ContentType: "html",
		Content:     "<html><body><p>Hello</p></body></html>",
	})
	b := newOutlookBI(t, fake.srv.URL)
	err := b.InjectBanner(context.Background(), action.BannerInjectRequest{
		Tenant: "t-1", Provider: action.LabelProviderOutlook,
		Email: "rcpt@example.com", MessageID: "m-1",
		HTML: []byte("<div>BAN</div>"),
	})
	if err != nil {
		t.Fatalf("InjectBanner: %v", err)
	}
	patched := fake.patchedBody.Load()
	if patched == nil {
		t.Fatalf("no PATCH observed")
	}
	if patched.ContentType != "html" {
		t.Fatalf("contentType = %q, want html", patched.ContentType)
	}
	if !strings.Contains(patched.Content, "<body><div>BAN</div><p>Hello</p>") {
		t.Fatalf("banner not inserted after <body>: %q", patched.Content)
	}
}

func TestOutlookInjectBanner_TextBody_PromotedToHTML(t *testing.T) {
	fake := newOutlookFake(t, outlookMessageBody{
		ContentType: "text",
		Content:     "Hello <world> & friends",
	})
	b := newOutlookBI(t, fake.srv.URL)
	if err := b.InjectBanner(context.Background(), action.BannerInjectRequest{
		Tenant: "t", Provider: action.LabelProviderOutlook,
		Email: "r@x", MessageID: "m-1",
		HTML: []byte("<b>BAN</b>"),
	}); err != nil {
		t.Fatalf("InjectBanner: %v", err)
	}
	patched := fake.patchedBody.Load()
	if patched == nil {
		t.Fatalf("no PATCH observed")
	}
	if patched.ContentType != "html" {
		t.Fatalf("text body should be promoted to html, got %q", patched.ContentType)
	}
	if !strings.HasPrefix(patched.Content, "<b>BAN</b>") {
		t.Fatalf("banner should lead promoted body: %q", patched.Content)
	}
	if !strings.Contains(patched.Content, "Hello &lt;world&gt; &amp; friends") {
		t.Fatalf("original text not html-escaped: %q", patched.Content)
	}
}

func TestOutlookInjectBanner_NoBodyTag_PrependsToDocument(t *testing.T) {
	fake := newOutlookFake(t, outlookMessageBody{
		ContentType: "html",
		Content:     "<p>orphan</p>",
	})
	b := newOutlookBI(t, fake.srv.URL)
	if err := b.InjectBanner(context.Background(), action.BannerInjectRequest{
		Tenant: "t", Provider: action.LabelProviderOutlook,
		Email: "r@x", MessageID: "m-1",
		HTML: []byte("<i>BAN</i>"),
	}); err != nil {
		t.Fatalf("InjectBanner: %v", err)
	}
	patched := fake.patchedBody.Load()
	if patched == nil {
		t.Fatalf("no PATCH observed")
	}
	if patched.Content != "<i>BAN</i><p>orphan</p>" {
		t.Fatalf("banner not prepended when no <body>: %q", patched.Content)
	}
}

func TestOutlookInjectBanner_PatchFailure_BubblesError(t *testing.T) {
	fake := newOutlookFake(t, outlookMessageBody{ContentType: "html", Content: "<body>hi</body>"})
	fake.patchStatus = http.StatusInternalServerError
	b := newOutlookBI(t, fake.srv.URL)
	err := b.InjectBanner(context.Background(), action.BannerInjectRequest{
		Tenant: "t", Provider: action.LabelProviderOutlook,
		Email: "r@x", MessageID: "m-1",
		HTML: []byte("<b>BAN</b>"),
	})
	if err == nil {
		t.Fatalf("expected error from 500")
	}
	if !strings.Contains(err.Error(), "patch body") {
		t.Fatalf("error not annotated as patch failure: %v", err)
	}
}

func TestOutlookInjectBanner_Validate(t *testing.T) {
	b := newOutlookBI(t, "http://does.not.matter")
	tests := []struct {
		name string
		req  action.BannerInjectRequest
	}{
		{"missing tenant", action.BannerInjectRequest{MessageID: "m", HTML: []byte("x"), Email: "e"}},
		{"missing message_id", action.BannerInjectRequest{Tenant: "t", HTML: []byte("x"), Email: "e"}},
		{"missing html", action.BannerInjectRequest{Tenant: "t", MessageID: "m", Email: "e"}},
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

func TestNewOutlookBannerInjector_RequiresTokenSource(t *testing.T) {
	if _, err := NewBannerInjector(BannerInjectorConfig{}); err == nil {
		t.Fatalf("expected error on missing token source")
	}
}

func TestSpliceHTMLBanner_LowercaseBodyTagMatching(t *testing.T) {
	got := spliceHTMLBanner("<BODY class=foo>hi</BODY>", "<i>X</i>")
	if got != "<BODY class=foo><i>X</i>hi</BODY>" {
		t.Fatalf("uppercase <BODY> not handled: %q", got)
	}
}
