package llamaserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/inference/slm"
)

// stringPtr returns a pointer to s; used to populate *string
// Config fields where the zero value is meaningful (e.g.
// AuthScheme="" means "send the APIKey verbatim", distinct
// from AuthScheme=nil = "apply DefaultAuthScheme on the default
// AuthHeader").
func stringPtr(s string) *string { return &s }

func TestEvaluate_PathShapedModelNameIsTrimmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payload := map[string]any{
			"model": "/models/llama-3-8b-instruct.Q4_K_M.gguf",
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": `{"score": 17, "confidence": 0.42}`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	c, err := NewClient(Config{URL: srv.URL, Model: "configured-model", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	out, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	want := "llama-3-8b-instruct.Q4_K_M"
	if out.ModelName != want {
		t.Errorf("ModelName = %q, want %q", out.ModelName, want)
	}
	if out.Score != 17 {
		t.Errorf("Score = %d, want 17", out.Score)
	}
}

func TestEvaluate_FallsBackToConfiguredModelWhenResponseEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payload := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": `{"score": 0}`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	c, err := NewClient(Config{URL: srv.URL, Model: "my-llama"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	out, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.ModelName != "my-llama" {
		t.Errorf("ModelName = %q, want my-llama", out.ModelName)
	}
}

func TestEvaluate_TolerantToMissingUsage(t *testing.T) {
	// llama-server <= b30xx omits the usage object entirely.
	// Our adapter must NOT treat that as an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-1","model":"llama-3-8b","choices":[{"index":0,"message":{"role":"assistant","content":"{\"score\":33}"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()

	c, err := NewClient(Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	out, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Score != 33 {
		t.Errorf("Score = %d, want 33", out.Score)
	}
}

func TestEvaluate_CustomAuthHeader(t *testing.T) {
	const apiKey = "abcd1234"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("Authorization header set; expected only X-API-Key, got %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-API-Key") != apiKey {
			t.Errorf("X-API-Key = %q, want %q", r.Header.Get("X-API-Key"), apiKey)
		}
		payload := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": `{"score": 1}`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	c, err := NewClient(Config{
		URL:        srv.URL,
		APIKey:     apiKey,
		AuthHeader: "X-API-Key",
		AuthScheme: stringPtr(""),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
}

func TestPickModelName(t *testing.T) {
	cases := []struct {
		name         string
		responseName string
		configured   string
		want         string
	}{
		{"path with extension", "/models/llama-3-8b-instruct.Q4_K_M.gguf", "fallback", "llama-3-8b-instruct.Q4_K_M"},
		{"plain name", "llama-3-8b", "fallback", "llama-3-8b"},
		{"empty falls back", "", "fallback", "fallback"},
		{"whitespace falls back", "  \t ", "fallback", "fallback"},
		{"deep path", "/var/models/mistral-7b.gguf", "fallback", "mistral-7b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pickModelName(tc.responseName, tc.configured)
			if got != tc.want {
				t.Errorf("pickModelName(%q, %q) = %q, want %q", tc.responseName, tc.configured, got, tc.want)
			}
		})
	}
}

func TestFactory_HonoursAuthHeaderOpts(t *testing.T) {
	c, err := slm.New(slm.ProviderConfig{
		Name:   Name,
		URL:    "http://stub",
		APIKey: "k",
		ProviderOpts: map[string]string{
			"auth_header_name":   "X-API-Key",
			"auth_header_scheme": "",
		},
	})
	if err != nil {
		t.Fatalf("slm.New: %v", err)
	}
	if c == nil {
		t.Fatal("slm.New returned nil")
	}
}

// TestEvaluate_AuthSchemeExplicitEmptyOnDefaultHeader pins the
// *string sentinel contract: a caller saying AuthScheme: stringPtr("")
// on the default Authorization header gets the APIKey verbatim
// (no "Bearer " prefix). The plain-string previous generation
// silently coerced this to "Bearer " because it could not
// distinguish nil from "".
func TestEvaluate_AuthSchemeExplicitEmptyOnDefaultHeader(t *testing.T) {
	const apiKey = "abcd1234"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != apiKey {
			t.Errorf("Authorization = %q, want %q (no Bearer prefix)", got, apiKey)
		}
		payload := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": `{"score": 1}`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	c, err := NewClient(Config{
		URL:        srv.URL,
		APIKey:     apiKey,
		AuthScheme: stringPtr(""),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
}

// TestEvaluate_AuthSchemeNilOnDefaultHeader pins the historical
// ergonomics: unset AuthScheme + default AuthHeader → "Bearer "
// prefix. This is the path the vast majority of deployments hit.
func TestEvaluate_AuthSchemeNilOnDefaultHeader(t *testing.T) {
	const apiKey = "abcd1234"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+apiKey {
			t.Errorf("Authorization = %q, want %q", got, "Bearer "+apiKey)
		}
		payload := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": `{"score": 1}`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	c, err := NewClient(Config{URL: srv.URL, APIKey: apiKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
}

// TestEvaluate_AuthSchemeNilOnCustomHeader pins the historical
// ergonomics for the X-API-Key idiom: unset AuthScheme + custom
// AuthHeader → "" prefix (verbatim API key on the custom
// header). Operators expect this without having to also set
// auth_header_scheme to "".
func TestEvaluate_AuthSchemeNilOnCustomHeader(t *testing.T) {
	const apiKey = "abcd1234"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-API-Key"); got != apiKey {
			t.Errorf("X-API-Key = %q, want %q", got, apiKey)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want empty", got)
		}
		payload := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": `{"score": 1}`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	c, err := NewClient(Config{
		URL:        srv.URL,
		APIKey:     apiKey,
		AuthHeader: "X-API-Key",
		// AuthScheme intentionally nil: contract says default to
		// "" because AuthHeader is non-default.
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
}

// TestFactory_AuthSchemeOmittedDefaultsByHeader confirms the
// Factory path: when auth_header_scheme is omitted entirely, the
// AuthScheme stays nil and NewClient applies the right default
// based on auth_header_name.
func TestFactory_AuthSchemeOmittedDefaultsByHeader(t *testing.T) {
	const apiKey = "abcd1234"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-API-Key"); got != apiKey {
			t.Errorf("X-API-Key = %q, want %q", got, apiKey)
		}
		payload := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": `{"score": 1}`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	c, err := slm.New(slm.ProviderConfig{
		Name:   Name,
		URL:    srv.URL,
		APIKey: apiKey,
		ProviderOpts: map[string]string{
			"auth_header_name": "X-API-Key",
			// auth_header_scheme intentionally omitted.
		},
	})
	if err != nil {
		t.Fatalf("slm.New: %v", err)
	}
	if _, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
}

func TestNewClient_RejectsEmptyURL(t *testing.T) {
	if _, err := NewClient(Config{}); err == nil {
		t.Fatal("NewClient(empty) err = nil, want non-nil")
	}
}
