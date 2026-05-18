package outlook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestKind_ReturnsOutlook(t *testing.T) {
	p := newTestProvider(t, http.NewServeMux())
	if got := p.Kind(); got != action.LabelProviderOutlook {
		t.Fatalf("Kind = %q, want outlook", got)
	}
}

func TestEnsureLabel_ExistingCategoryShortCircuits(t *testing.T) {
	var calls []string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/users/user@example.com/outlook/masterCategories",
		func(w http.ResponseWriter, r *http.Request) {
			calls = append(calls, r.Method)
			if r.Method != http.MethodGet {
				t.Errorf("expected GET, got %s", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer test-bearer" {
				t.Errorf("Authorization = %q", got)
			}
			_ = json.NewEncoder(w).Encode(outlookCategoryList{Value: []outlookCategory{
				{DisplayName: "SN360 / Warning", Color: "preset0"},
			}})
		})
	p := newTestProvider(t, mux)
	id, err := p.EnsureLabel(context.Background(), "user@example.com",
		"SN360 / Warning", action.ColorFor("warning"))
	if err != nil {
		t.Fatalf("EnsureLabel: %v", err)
	}
	if id != "SN360 / Warning" {
		t.Fatalf("id = %q, want SN360 / Warning", id)
	}
	if len(calls) != 1 || calls[0] != http.MethodGet {
		t.Fatalf("expected single GET, got %v", calls)
	}
}

func TestEnsureLabel_CreatesWhenMissing(t *testing.T) {
	var (
		mu          sync.Mutex
		createCalls int
		body        outlookCategory
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/users/user@example.com/outlook/masterCategories",
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = json.NewEncoder(w).Encode(outlookCategoryList{Value: nil})
			case http.MethodPost:
				mu.Lock()
				createCalls++
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode: %v", err)
				}
				mu.Unlock()
				_ = json.NewEncoder(w).Encode(outlookCategory{
					ID:          "id-123",
					DisplayName: body.DisplayName,
					Color:       body.Color,
				})
			default:
				t.Errorf("unexpected method %s", r.Method)
			}
		})
	p := newTestProvider(t, mux)
	id, err := p.EnsureLabel(context.Background(), "user@example.com",
		"SN360 / High Risk", action.LabelColor{OutlookPreset: "preset3"})
	if err != nil {
		t.Fatalf("EnsureLabel: %v", err)
	}
	if id != "SN360 / High Risk" {
		t.Fatalf("id = %q, want SN360 / High Risk", id)
	}
	if createCalls != 1 {
		t.Fatalf("expected exactly one POST, got %d", createCalls)
	}
	if body.Color != "preset3" {
		t.Errorf("body.Color = %q, want preset3", body.Color)
	}
}

func TestEnsureLabel_TreatsConflictAsSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/users/user@example.com/outlook/masterCategories",
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				// Race: the GET response says "not yet present"
				_ = json.NewEncoder(w).Encode(outlookCategoryList{Value: nil})
			case http.MethodPost:
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":{"code":"ObjectAlreadyExists"}}`))
			default:
				t.Errorf("unexpected method %s", r.Method)
			}
		})
	p := newTestProvider(t, mux)
	id, err := p.EnsureLabel(context.Background(), "user@example.com",
		"SN360 / Warning", action.ColorFor("warning"))
	if err != nil {
		t.Fatalf("EnsureLabel: %v", err)
	}
	if id != "SN360 / Warning" {
		t.Fatalf("id = %q, want SN360 / Warning", id)
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

func TestApplyLabel_MergesIntoExistingCategories(t *testing.T) {
	var patchEnv messageEnvelope
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/users/user@example.com/messages/m1",
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = json.NewEncoder(w).Encode(messageEnvelope{
					Categories: []string{"Other Category"},
				})
			case http.MethodPatch:
				b, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(b, &patchEnv); err != nil {
					t.Fatalf("decode patch: %v", err)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			default:
				t.Errorf("unexpected method %s", r.Method)
			}
		})
	p := newTestProvider(t, mux)
	if err := p.ApplyLabel(context.Background(), "user@example.com", "m1", "SN360 / Warning"); err != nil {
		t.Fatalf("ApplyLabel: %v", err)
	}
	got := patchEnv.Categories
	if len(got) != 2 || got[0] != "Other Category" || got[1] != "SN360 / Warning" {
		t.Fatalf("Categories = %v, want [Other Category, SN360 / Warning]", got)
	}
}

func TestApplyLabel_IsIdempotent(t *testing.T) {
	var patchEnv messageEnvelope
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/users/user@example.com/messages/m1",
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = json.NewEncoder(w).Encode(messageEnvelope{
					Categories: []string{"SN360 / Warning"},
				})
			case http.MethodPatch:
				_ = json.NewDecoder(r.Body).Decode(&patchEnv)
				_, _ = w.Write([]byte(`{}`))
			}
		})
	p := newTestProvider(t, mux)
	if err := p.ApplyLabel(context.Background(), "user@example.com", "m1", "SN360 / Warning"); err != nil {
		t.Fatalf("ApplyLabel: %v", err)
	}
	if got := patchEnv.Categories; len(got) != 1 || got[0] != "SN360 / Warning" {
		t.Fatalf("Categories = %v, want [SN360 / Warning]", got)
	}
}

func TestRemoveLabel_DropsCategory(t *testing.T) {
	var patchEnv messageEnvelope
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/users/user@example.com/messages/m1",
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = json.NewEncoder(w).Encode(messageEnvelope{
					Categories: []string{"Other", "SN360 / Warning"},
				})
			case http.MethodPatch:
				_ = json.NewDecoder(r.Body).Decode(&patchEnv)
				_, _ = w.Write([]byte(`{}`))
			}
		})
	p := newTestProvider(t, mux)
	if err := p.RemoveLabel(context.Background(), "user@example.com", "m1", "SN360 / Warning"); err != nil {
		t.Fatalf("RemoveLabel: %v", err)
	}
	if got := patchEnv.Categories; len(got) != 1 || got[0] != "Other" {
		t.Fatalf("Categories = %v, want [Other]", got)
	}
}

func TestRemoveLabel_EmptySendsExplicitEmptyArray(t *testing.T) {
	var raw []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/users/user@example.com/messages/m1",
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = json.NewEncoder(w).Encode(messageEnvelope{Categories: []string{"SN360 / Warning"}})
			case http.MethodPatch:
				raw, _ = io.ReadAll(r.Body)
				_, _ = w.Write([]byte(`{}`))
			}
		})
	p := newTestProvider(t, mux)
	if err := p.RemoveLabel(context.Background(), "user@example.com", "m1", "SN360 / Warning"); err != nil {
		t.Fatalf("RemoveLabel: %v", err)
	}
	if !strings.Contains(string(raw), `"categories":[]`) {
		t.Fatalf("expected explicit empty array in PATCH body, got %s", string(raw))
	}
}

func TestApplyLabel_RejectsEmptyInputs(t *testing.T) {
	p := newTestProvider(t, http.NewServeMux())
	if err := p.ApplyLabel(context.Background(), "", "m1", "L"); err == nil {
		t.Errorf("expected error for empty email")
	}
	if err := p.ApplyLabel(context.Background(), "u@x", "", "L"); err == nil {
		t.Errorf("expected error for empty message id")
	}
}

func TestDo_PropagatesAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/users/user@example.com/outlook/masterCategories",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"InvalidAuthenticationToken"}}`))
		})
	p := newTestProvider(t, mux)
	_, err := p.EnsureLabel(context.Background(), "user@example.com", "name", action.LabelColor{})
	if err == nil {
		t.Fatalf("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", apiErr.StatusCode)
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
		t.Fatalf("expected token error")
	}
}

func TestMergeCategory(t *testing.T) {
	tests := []struct {
		name     string
		existing []string
		input    string
		mode     op
		want     []string
	}{
		{"add new", []string{"A"}, "B", addOp, []string{"A", "B"}},
		{"add duplicate", []string{"A"}, "A", addOp, []string{"A"}},
		{"add case duplicate", []string{"sn360 / warning"}, "SN360 / Warning", addOp, []string{"sn360 / warning"}},
		{"remove existing", []string{"A", "B"}, "B", removeOp, []string{"A"}},
		{"remove case insensitive", []string{"sn360 / warning"}, "SN360 / Warning", removeOp, []string{}},
		{"remove missing", []string{"A"}, "B", removeOp, []string{"A"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeCategory(tt.existing, tt.input, tt.mode)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v want %v", got, tt.want)
				}
			}
		})
	}
}

func TestMapPreset_DefaultsToPreset0(t *testing.T) {
	if got := mapPreset(action.LabelColor{}); got != "preset0" {
		t.Fatalf("mapPreset empty = %q, want preset0", got)
	}
	if got := mapPreset(action.LabelColor{OutlookPreset: "preset3"}); got != "preset3" {
		t.Fatalf("mapPreset preset3 = %q, want preset3", got)
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
