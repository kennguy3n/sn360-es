package main

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/onboarding"
)

// quietLogger returns a logger that discards all output so the test
// log isn't cluttered with provider-init noise.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestBuildProviderRegistry_Empty verifies the registry is non-nil
// when no providers are configured. This is the canonical "degraded
// mode" boot path — the action consumers must still come up cleanly
// when the operator has not yet wired any provider.
func TestBuildProviderRegistry_Empty(t *testing.T) {
	cfg := &config.Config{}
	reg := buildProviderRegistry(context.Background(), cfg, quietLogger())
	if reg == nil {
		t.Fatal("expected non-nil registry")
	}
	if reg.hasAny() {
		t.Error("expected hasAny() = false on empty config")
	}
	if got := reg.labelProviders(); len(got) != 0 {
		t.Errorf("labelProviders = %d, want 0", len(got))
	}
	if got := reg.quarantineProviders(); len(got) != 0 {
		t.Errorf("quarantineProviders = %d, want 0", len(got))
	}
}

// TestBuildProviderRegistry_RegistersNewProviders boots the registry
// with valid configs for Zoho, Fastmail, and WorkMail simultaneously
// and verifies all three entries land under the correct per-provider
// tenant id. Gmail and Outlook are intentionally not exercised here:
// they require a real RSA service-account JSON / client-credentials
// flow respectively, which is tested in pkg/email_provider/gmail and
// pkg/email_provider/outlook. The wiring-level invariant we want to
// pin down is "the new HasZoho/HasFastmail/HasWorkMail branches
// register entries under the correct tenant keys".
func TestBuildProviderRegistry_RegistersNewProviders(t *testing.T) {
	cfg := &config.Config{
		Zoho: config.Zoho{
			ClientID:     "zc",
			ClientSecret: "zs",
			RefreshToken: "zr",
			OrgID:        "100200300",
			Domain:       "example.com",
			DataCenter:   "com",
		},
		Fastmail: config.Fastmail{
			APIToken:  "fm-token",
			AccountID: "fm-acct",
		},
		WorkMail: config.WorkMail{
			OrganizationID:  "m-abcdef",
			Region:          "us-east-1",
			AccessKeyID:     "AKIA",
			SecretAccessKey: "secret",
		},
	}
	reg := buildProviderRegistry(context.Background(), cfg, quietLogger())
	if reg == nil {
		t.Fatal("expected non-nil registry")
	}
	if !reg.hasAny() {
		t.Fatal("expected hasAny() = true with three providers configured")
	}

	// Each provider key must resolve to its declared LabelProviderKind.
	cases := []struct {
		tenant string
		want   action.LabelProviderKind
	}{
		{"example.com", action.LabelProviderZoho},
		{"fm-acct", action.LabelProviderFastmail},
		{"m-abcdef", action.LabelProviderWorkmail},
	}
	for _, tc := range cases {
		e := reg.lookup(tc.tenant)
		if e == nil {
			t.Errorf("lookup(%q) returned nil", tc.tenant)
			continue
		}
		if e.kind != tc.want {
			t.Errorf("lookup(%q).kind = %q, want %q", tc.tenant, e.kind, tc.want)
		}
		if e.labelProvider == nil {
			t.Errorf("entry(%q).labelProvider is nil", tc.tenant)
		}
		if e.bannerInjector == nil {
			t.Errorf("entry(%q).bannerInjector is nil", tc.tenant)
		}
		if e.quarantineProvider == nil {
			t.Errorf("entry(%q).quarantineProvider is nil", tc.tenant)
		}
		if e.bodyRewriter == nil {
			t.Errorf("entry(%q).bodyRewriter is nil", tc.tenant)
		}
		if got := reg.resolveKind(tc.tenant); got != tc.want {
			t.Errorf("resolveKind(%q) = %q, want %q", tc.tenant, got, tc.want)
		}
	}

	// LabelProviders and QuarantineProviders are aggregations across
	// every registered entry; each new provider should contribute one.
	if got := len(reg.labelProviders()); got != 3 {
		t.Errorf("labelProviders count = %d, want 3", got)
	}
	if got := len(reg.quarantineProviders()); got != 3 {
		t.Errorf("quarantineProviders count = %d, want 3", got)
	}
}

// TestBuildProviderRegistry_ZohoTenantIsDomain verifies that Zoho's
// registry key is the operator-supplied Domain (HasZoho() requires
// Domain to be non-empty, and OrgID is intentionally not used as a
// fallback). This is the invariant the package comment on
// zohoProviderTenant promises.
func TestBuildProviderRegistry_ZohoTenantIsDomain(t *testing.T) {
	cfg := &config.Config{
		Zoho: config.Zoho{
			ClientID:     "zc",
			ClientSecret: "zs",
			RefreshToken: "zr",
			OrgID:        "100200300",
			Domain:       "primary.example.com",
			DataCenter:   "com",
		},
	}
	reg := buildProviderRegistry(context.Background(), cfg, quietLogger())
	if e := reg.lookup("primary.example.com"); e == nil {
		t.Fatal("expected Zoho entry keyed by Domain to be present")
	}
	if e := reg.lookup("100200300"); e != nil {
		t.Errorf("did not expect Zoho entry keyed by OrgID: got kind=%q", e.kind)
	}
}

// TestBuildOAuthProviderConfigs_ZohoRegistration verifies that Zoho
// ClientID + ClientSecret alone are enough to register a Zoho OAuth
// provider config (the refresh token is produced by the consent flow
// itself, so we must NOT require it here — chicken-and-egg). Without
// this entry, calling AuthURL(ProviderZoho, …) would error with
// "unknown provider" and the entire Zoho onboarding flow would be
// dead code.
func TestBuildOAuthProviderConfigs_ZohoRegistration(t *testing.T) {
	cfg := &config.Config{
		Onboarding: config.Onboarding{CallbackURL: "https://app.example/v1/onboarding/callback"},
		Zoho: config.Zoho{
			ClientID:     "zc",
			ClientSecret: "zs",
			DataCenter:   "eu",
			// RefreshToken intentionally empty: this is what the
			// consent flow produces. Registering must NOT depend on
			// it being present.
		},
	}
	providers := buildOAuthProviderConfigs(cfg)
	got, ok := providers[onboarding.ProviderZoho]
	if !ok {
		t.Fatal("ProviderZoho not registered")
	}
	if got.ClientID != "zc" || got.ClientSecret != "zs" {
		t.Errorf("ClientID/Secret = %q/%q, want zc/zs", got.ClientID, got.ClientSecret)
	}
	// EU data centre must route AuthURL/TokenURL to accounts.zoho.eu.
	if !strings.HasPrefix(got.AuthURL, "https://accounts.zoho.eu/oauth/v2/auth") {
		t.Errorf("AuthURL = %q, want EU regional endpoint", got.AuthURL)
	}
	if !strings.HasPrefix(got.TokenURL, "https://accounts.zoho.eu/oauth/v2/token") {
		t.Errorf("TokenURL = %q, want EU regional endpoint", got.TokenURL)
	}
	if got.RedirectURL != cfg.Onboarding.CallbackURL {
		t.Errorf("RedirectURL = %q, want %q", got.RedirectURL, cfg.Onboarding.CallbackURL)
	}
	wantScopes := []string{
		"ZohoMail.messages.ALL",
		"ZohoMail.folders.ALL",
		"ZohoMail.tags.ALL",
		"ZohoMail.accounts.READ",
		"ZohoMail.organization.READ",
	}
	if !reflect.DeepEqual(got.Scopes, wantScopes) {
		t.Errorf("Scopes = %v, want %v", got.Scopes, wantScopes)
	}
}

// TestBuildOAuthProviderConfigs_ZohoEmptyWithoutCredentials verifies
// that Zoho is NOT registered when its OAuth credentials are absent.
// (Fastmail/WorkMail are similarly never registered here — they use
// non-OAuth auth, so this also serves as a regression for that.)
func TestBuildOAuthProviderConfigs_ZohoEmptyWithoutCredentials(t *testing.T) {
	cfg := &config.Config{
		Fastmail: config.Fastmail{APIToken: "fm-token", AccountID: "fm-acct"},
		WorkMail: config.WorkMail{OrganizationID: "m-x", Region: "us-east-1"},
	}
	providers := buildOAuthProviderConfigs(cfg)
	if _, ok := providers[onboarding.ProviderZoho]; ok {
		t.Error("ProviderZoho should not be registered without Zoho OAuth credentials")
	}
	if _, ok := providers[onboarding.ProviderFastmail]; ok {
		t.Error("ProviderFastmail must not be registered (non-OAuth auth)")
	}
	if _, ok := providers[onboarding.ProviderWorkmail]; ok {
		t.Error("ProviderWorkmail must not be registered (AWS IAM auth)")
	}
}
