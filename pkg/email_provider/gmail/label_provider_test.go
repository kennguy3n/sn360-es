package gmail

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

func staticToken(tok string) TokenSource {
	return TokenSourceFunc(func(_ context.Context) (string, error) { return tok, nil })
}

func newTestProvider(t *testing.T, h http.Handler) *LabelProvider {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	p, err := New(Config{
		BaseURL:     srv.URL,
		HTTPClient:  srv.Client(),
		TokenSource: staticToken("test-bearer"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestNew_RequiresTokenSource(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatalf("expected error when token source is nil")
	}
}

func TestKind_ReturnsGmail(t *testing.T) {
	p := newTestProvider(t, http.NewServeMux())
	if got := p.Kind(); got != action.LabelProviderGmail {
		t.Fatalf("Kind = %q, want gmail", got)
	}
}

func TestEnsureLabel_ExistingLabelReturnsCachedID(t *testing.T) {
	var calls []string
	mux := http.NewServeMux()
	mux.HandleFunc("/gmail/v1/users/user@example.com/labels", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodGet {
			t.Errorf("expected GET for label lookup, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-bearer" {
			t.Errorf("Authorization = %q, want Bearer test-bearer", got)
		}
		_ = json.NewEncoder(w).Encode(gmailLabelList{Labels: []gmailLabel{
			{ID: "Label_1", Name: "SN360 / Warning"},
			{ID: "Label_2", Name: "SN360 / High Risk"},
		}})
	})
	p := newTestProvider(t, mux)

	id, err := p.EnsureLabel(context.Background(), "user@example.com", "SN360 / Warning", action.ColorFor("warning"))
	if err != nil {
		t.Fatalf("EnsureLabel: %v", err)
	}
	if id != "Label_1" {
		t.Fatalf("EnsureLabel id = %q, want Label_1", id)
	}
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 list call, got %v", calls)
	}
}

func TestEnsureLabel_CreatesWhenMissing(t *testing.T) {
	var bodies []gmailLabel
	mux := http.NewServeMux()
	mux.HandleFunc("/gmail/v1/users/user@example.com/labels", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(gmailLabelList{Labels: nil})
		case http.MethodPost:
			var in gmailLabel
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Fatalf("decode create body: %v", err)
			}
			bodies = append(bodies, in)
			_ = json.NewEncoder(w).Encode(gmailLabel{ID: "Label_99", Name: in.Name})
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})
	p := newTestProvider(t, mux)

	id, err := p.EnsureLabel(context.Background(), "user@example.com", "SN360 / Warning",
		action.LabelColor{Background: "#cc3a21", Foreground: "#ffffff"})
	if err != nil {
		t.Fatalf("EnsureLabel: %v", err)
	}
	if id != "Label_99" {
		t.Fatalf("EnsureLabel id = %q, want Label_99", id)
	}
	if len(bodies) != 1 {
		t.Fatalf("expected exactly 1 create body, got %d", len(bodies))
	}
	body := bodies[0]
	if body.Name != "SN360 / Warning" {
		t.Errorf("body.Name = %q, want SN360 / Warning", body.Name)
	}
	if body.LabelListVisibility != "labelShow" {
		t.Errorf("body.LabelListVisibility = %q, want labelShow", body.LabelListVisibility)
	}
	if body.MessageListVisibility != "show" {
		t.Errorf("body.MessageListVisibility = %q, want show", body.MessageListVisibility)
	}
	if body.Color == nil || body.Color.BackgroundColor != "#cc3a21" {
		t.Errorf("body.Color = %+v, want background #cc3a21", body.Color)
	}
}

func TestEnsureLabel_RejectsEmptyInputs(t *testing.T) {
	p := newTestProvider(t, http.NewServeMux())
	if _, err := p.EnsureLabel(context.Background(), "", "name", action.LabelColor{}); err == nil {
		t.Errorf("expected error for empty email")
	}
	if _, err := p.EnsureLabel(context.Background(), "u@x", "", action.LabelColor{}); err == nil {
		t.Errorf("expected error for empty name")
	}
}

func TestApplyLabel_PostsModifyEnvelope(t *testing.T) {
	var got gmailModifyRequest
	mux := http.NewServeMux()
	mux.HandleFunc("/gmail/v1/users/user@example.com/messages/m1/modify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	p := newTestProvider(t, mux)
	if err := p.ApplyLabel(context.Background(), "user@example.com", "m1", "Label_1"); err != nil {
		t.Fatalf("ApplyLabel: %v", err)
	}
	if len(got.AddLabelIDs) != 1 || got.AddLabelIDs[0] != "Label_1" {
		t.Errorf("AddLabelIDs = %v, want [Label_1]", got.AddLabelIDs)
	}
	if len(got.RemoveLabelIDs) != 0 {
		t.Errorf("RemoveLabelIDs = %v, want empty", got.RemoveLabelIDs)
	}
}

func TestRemoveLabel_PostsRemoveEnvelope(t *testing.T) {
	var got gmailModifyRequest
	mux := http.NewServeMux()
	mux.HandleFunc("/gmail/v1/users/user@example.com/messages/m1/modify", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		_, _ = w.Write([]byte(`{}`))
	})
	p := newTestProvider(t, mux)
	if err := p.RemoveLabel(context.Background(), "user@example.com", "m1", "Label_42"); err != nil {
		t.Fatalf("RemoveLabel: %v", err)
	}
	if len(got.AddLabelIDs) != 0 {
		t.Errorf("AddLabelIDs = %v, want empty", got.AddLabelIDs)
	}
	if len(got.RemoveLabelIDs) != 1 || got.RemoveLabelIDs[0] != "Label_42" {
		t.Errorf("RemoveLabelIDs = %v, want [Label_42]", got.RemoveLabelIDs)
	}
}

func TestModify_RejectsEmptyInputs(t *testing.T) {
	p := newTestProvider(t, http.NewServeMux())
	if err := p.ApplyLabel(context.Background(), "", "m1", "Label_1"); err == nil {
		t.Errorf("expected error for empty email")
	}
	if err := p.ApplyLabel(context.Background(), "u@x", "", "Label_1"); err == nil {
		t.Errorf("expected error for empty message id")
	}
}

func TestDo_PropagatesAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/gmail/v1/users/user@example.com/labels", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":403,"message":"insufficient permissions"}}`))
	})
	p := newTestProvider(t, mux)
	_, err := p.EnsureLabel(context.Background(), "user@example.com", "name", action.LabelColor{})
	if err == nil {
		t.Fatalf("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T (%v)", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Body, "insufficient permissions") {
		t.Errorf("Body = %q, want substring 'insufficient permissions'", apiErr.Body)
	}
}

func TestDo_TokenError_Propagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("server should not be called when token errors")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	p, err := New(Config{
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
		TokenSource: TokenSourceFunc(func(_ context.Context) (string, error) {
			return "", errors.New("boom")
		}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.ApplyLabel(context.Background(), "u@x", "m", "L"); err == nil {
		t.Fatalf("expected error from token source")
	}
}

func TestDo_EmptyToken_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("server should not be called when token is empty")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	p, err := New(Config{
		BaseURL:     srv.URL,
		HTTPClient:  srv.Client(),
		TokenSource: staticToken(""),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.ApplyLabel(context.Background(), "u@x", "m", "L"); err == nil {
		t.Fatalf("expected error for empty bearer token")
	}
}

func TestSnapToGmailPalette(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"exact match", "#cc3a21", "#cc3a21"},
		{"case insensitive", "#CC3A21", "#cc3a21"},
		{"unknown falls back to neutral", "#abcdef", "#666666"},
		{"empty falls back to neutral", "", "#666666"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := snapToGmailPalette(tt.in, gmailBackgroundPalette); got != tt.want {
				t.Errorf("snap(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMapColor_EmptyBackgroundReturnsNil(t *testing.T) {
	if got := mapColor(action.LabelColor{}); got != nil {
		t.Fatalf("mapColor empty = %+v, want nil", got)
	}
}

func TestAPIError_Error(t *testing.T) {
	e := &APIError{StatusCode: 500, Body: strings.Repeat("x", 300), Endpoint: "/foo"}
	msg := e.Error()
	if !strings.Contains(msg, "500") {
		t.Errorf("expected status in error: %s", msg)
	}
	if !strings.Contains(msg, "/foo") {
		t.Errorf("expected endpoint in error: %s", msg)
	}
	if !strings.HasSuffix(msg, "…") {
		t.Errorf("expected truncated body, got %q", msg)
	}
}
