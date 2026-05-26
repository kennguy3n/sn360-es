package zoho

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestAccountsBaseURL_DataCenters(t *testing.T) {
	cases := map[string]string{
		"":         "https://accounts.zoho.com",
		"com":      "https://accounts.zoho.com",
		"COM":      "https://accounts.zoho.com",
		" eu ":     "https://accounts.zoho.eu",
		"in":       "https://accounts.zoho.in",
		"com.au":   "https://accounts.zoho.com.au",
		"au":       "https://accounts.zoho.com.au",
		"com.cn":   "https://accounts.zoho.com.cn",
		"cn":       "https://accounts.zoho.com.cn",
		"jp":       "https://accounts.zoho.jp",
		"unknown":  "https://accounts.zoho.com", // unknown DC falls back to US
		"bogus_dc": "https://accounts.zoho.com",
	}
	for dc, want := range cases {
		if got := AccountsBaseURL(dc); got != want {
			t.Errorf("AccountsBaseURL(%q) = %q, want %q", dc, got, want)
		}
	}
}

func TestMailBaseURL_DataCenters(t *testing.T) {
	cases := map[string]string{
		"":     "https://mail.zoho.com/api",
		"eu":   "https://mail.zoho.eu/api",
		"in":   "https://mail.zoho.in/api",
		"jp":   "https://mail.zoho.jp/api",
		"bad":  "https://mail.zoho.com/api",
		"COM":  "https://mail.zoho.com/api",
		"  EU": "https://mail.zoho.eu/api",
	}
	for dc, want := range cases {
		if got := MailBaseURL(dc); got != want {
			t.Errorf("MailBaseURL(%q) = %q, want %q", dc, got, want)
		}
	}
}

func TestNewRefreshTokenSource_Validation(t *testing.T) {
	cases := []RefreshTokenConfig{
		{ClientSecret: "s", RefreshToken: "r"},
		{ClientID: "c", RefreshToken: "r"},
		{ClientID: "c", ClientSecret: "s"},
	}
	for i, cfg := range cases {
		if _, err := NewRefreshTokenSource(cfg); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestRefreshTokenSource_TokenCachesUntilNearExpiry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/oauth/v2/token" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %q", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.Form.Get("refresh_token"); got != "rt-xyz" {
			t.Errorf("refresh_token = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-1",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	t.Cleanup(srv.Close)

	now := time.Unix(1_700_000_000, 0)
	ts, err := NewRefreshTokenSource(RefreshTokenConfig{
		ClientID:     "c",
		ClientSecret: "s",
		RefreshToken: "rt-xyz",
		AccountsURL:  srv.URL,
		HTTPClient:   srv.Client(),
		Clock:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewRefreshTokenSource: %v", err)
	}

	// First call refreshes.
	got, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token #1: %v", err)
	}
	if got != "at-1" {
		t.Errorf("Token #1 = %q", got)
	}
	// Second call reuses the cached token because TTL is still 3600s.
	got2, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token #2: %v", err)
	}
	if got2 != "at-1" {
		t.Errorf("Token #2 = %q", got2)
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 refresh call, got %d", calls.Load())
	}

	// Advance clock past the 60s safety margin and verify a second refresh fires.
	now = now.Add(3600 * time.Second)
	got3, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token #3: %v", err)
	}
	if got3 != "at-1" {
		t.Errorf("Token #3 = %q", got3)
	}
	if calls.Load() != 2 {
		t.Errorf("expected 2 refresh calls after expiry, got %d", calls.Load())
	}
}

func TestRefreshTokenSource_SurfacesNon2xxAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	t.Cleanup(srv.Close)
	ts, err := NewRefreshTokenSource(RefreshTokenConfig{
		ClientID: "c", ClientSecret: "s", RefreshToken: "rt",
		AccountsURL: srv.URL, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := ts.Token(context.Background()); err == nil {
		t.Fatal("expected error for 400 response")
	}
}

func TestRefreshTokenSource_SurfacesEmbeddedError(t *testing.T) {
	// Zoho sometimes returns HTTP 200 with an "error" field. Verify
	// the source treats that as an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"invalid_code"}`))
	}))
	t.Cleanup(srv.Close)
	ts, err := NewRefreshTokenSource(RefreshTokenConfig{
		ClientID: "c", ClientSecret: "s", RefreshToken: "rt",
		AccountsURL: srv.URL, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := ts.Token(context.Background()); err == nil {
		t.Fatal("expected error for body containing error field")
	}
}

func TestStaticTokenSource(t *testing.T) {
	if _, err := (StaticTokenSource{}).Token(context.Background()); err == nil {
		t.Fatal("empty access token must error")
	}
	got, err := (StaticTokenSource{AccessToken: "abc"}).Token(context.Background())
	if err != nil || got != "abc" {
		t.Fatalf("Token = %q, %v", got, err)
	}
}
