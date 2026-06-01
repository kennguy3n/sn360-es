package selfrelease

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// newTestIssuer constructs a JWTIssuer suitable for banner tests:
// a deterministic HS256 secret, "sn360-es" issuer, and the WS-1d
// 24h default TTL (overrideable per-call).
func newTestIssuer(t *testing.T) *privacy.JWTIssuer {
	t.Helper()
	iss, err := privacy.NewJWTIssuer(privacy.JWTConfig{
		Secret: bytes.Repeat([]byte{0x42}, 32),
		Issuer: "sn360-es",
		TTL:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWTIssuer: %v", err)
	}
	return iss
}

// TestBannerRenderer_RejectsBadConfig checks the constructor and
// Render input-validation gates.
func TestBannerRenderer_RejectsBadConfig(t *testing.T) {
	if _, err := NewBannerRenderer(BannerRendererConfig{}); err == nil {
		t.Fatal("expected error with nil issuer")
	}

	r, err := NewBannerRenderer(BannerRendererConfig{Issuer: newTestIssuer(t)})
	if err != nil {
		t.Fatalf("NewBannerRenderer: %v", err)
	}

	cases := []BannerInput{
		{PseudoMessageID: "p", RecipientUserHash: []byte("h"), ReleaseEndpoint: "https://x/y"},
		{TenantID: "t", RecipientUserHash: []byte("h"), ReleaseEndpoint: "https://x/y"},
		{TenantID: "t", PseudoMessageID: "p", ReleaseEndpoint: "https://x/y"},
		{TenantID: "t", PseudoMessageID: "p", RecipientUserHash: []byte("h")},
	}
	for i, in := range cases {
		if _, err := r.Render(in); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

// TestBannerRenderer_RendersTokenAndForm exercises the happy path:
// the output is a <form method="POST"> containing a signed
// scp="quarantine_release" token, and the token round-trips
// through Verify with the right claims.
func TestBannerRenderer_RendersTokenAndForm(t *testing.T) {
	iss := newTestIssuer(t)
	r, err := NewBannerRenderer(BannerRendererConfig{Issuer: iss})
	if err != nil {
		t.Fatalf("NewBannerRenderer: %v", err)
	}

	out, err := r.Render(BannerInput{
		TenantID:          "acme",
		PseudoMessageID:   "pmid-1",
		RecipientUserHash: []byte{0xde, 0xad, 0xbe, 0xef},
		SubjectExcerpt:    "Invoice for review",
		SenderDisplay:     "AP team <ap@example.com>",
		ReleaseEndpoint:   "https://es.acme.sn360.example/v1/quarantine/release",
		Now:               time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := string(out)

	// Form posts to the release endpoint.
	if !strings.Contains(html, `action="https://es.acme.sn360.example/v1/quarantine/release"`) {
		t.Fatalf("output missing form action: %s", html)
	}
	if !strings.Contains(strings.ToLower(html), `method="post"`) {
		t.Fatalf("output missing method=POST: %s", html)
	}
	// Token field is present.
	tokenIdx := strings.Index(html, `name="token" value="`)
	if tokenIdx < 0 {
		t.Fatalf("output missing token field: %s", html)
	}
	tokenStart := tokenIdx + len(`name="token" value="`)
	tokenEnd := strings.IndexByte(html[tokenStart:], '"')
	if tokenEnd < 0 {
		t.Fatalf("token field not closed: %s", html)
	}
	token := html[tokenStart : tokenStart+tokenEnd]
	// Token must verify back to the expected claims.
	claims, err := iss.Verify(token)
	if err != nil {
		t.Fatalf("Verify minted token: %v", err)
	}
	if claims.TenantID != "acme" {
		t.Fatalf("tenant=%q", claims.TenantID)
	}
	if claims.PseudonymizedMessage != "pmid-1" {
		t.Fatalf("pmid=%q", claims.PseudonymizedMessage)
	}
	if claims.Scope != privacy.ScopeQuarantineRelease {
		t.Fatalf("scope=%q", claims.Scope)
	}
	if claims.RecipientUserHash != "deadbeef" {
		t.Fatalf("recipient_user_hash=%q", claims.RecipientUserHash)
	}
	// Subject and sender escaped + present.
	if !strings.Contains(html, "Invoice for review") {
		t.Fatalf("missing subject: %s", html)
	}
	if !strings.Contains(html, "AP team") || strings.Contains(html, `<ap@example.com>`) {
		t.Fatalf("sender display not properly escaped: %s", html)
	}
	// Accessibility attributes.
	if !strings.Contains(html, `role="region"`) {
		t.Fatalf("missing role=region: %s", html)
	}
}

// TestBannerRenderer_EscapesHTMLInjection ensures malicious
// subject / sender values can't break out of the inline div.
func TestBannerRenderer_EscapesHTMLInjection(t *testing.T) {
	iss := newTestIssuer(t)
	r, err := NewBannerRenderer(BannerRendererConfig{Issuer: iss})
	if err != nil {
		t.Fatalf("NewBannerRenderer: %v", err)
	}
	out, err := r.Render(BannerInput{
		TenantID:          "acme",
		PseudoMessageID:   "pmid-1",
		RecipientUserHash: []byte{0x01},
		SubjectExcerpt:    `</div><script>alert(1)</script>`,
		SenderDisplay:     `"><img src=x onerror=alert(1)>`,
		ReleaseEndpoint:   "https://es.acme.sn360.example/v1/quarantine/release",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := string(out)
	if strings.Contains(html, "<script>") {
		t.Fatalf("subject script not escaped: %s", html)
	}
	// onerror is allowed only inside an escaped representation;
	// the raw "<img" / live "onerror" handler combination would
	// fire if any of the angle brackets or quotes remained
	// unescaped. We check for the structural escape:
	if strings.Contains(html, `<img src=x onerror=alert(1)>`) {
		t.Fatalf("sender img/onerror not escaped (raw tag survived): %s", html)
	}
	// Double-quote in injection payload must be HTML-entity
	// escaped so it cannot terminate an attribute value.
	if strings.Contains(html, `value=""><img`) {
		t.Fatalf("sender quote escape failed: %s", html)
	}
}

// TestBannerRenderer_LocaleSelectsRTL ensures the dir="rtl"
// attribute is emitted for known RTL locales and omitted for
// LTR locales.
func TestBannerRenderer_LocaleSelectsRTL(t *testing.T) {
	iss := newTestIssuer(t)
	r, err := NewBannerRenderer(BannerRendererConfig{Issuer: iss})
	if err != nil {
		t.Fatalf("NewBannerRenderer: %v", err)
	}
	in := BannerInput{
		TenantID:          "acme",
		PseudoMessageID:   "pmid-1",
		RecipientUserHash: []byte{0x01},
		ReleaseEndpoint:   "https://es.acme.sn360.example/v1/quarantine/release",
	}

	in.Locale = "ar-EG"
	rtl, _ := r.Render(in)
	if !strings.Contains(string(rtl), `dir="rtl"`) {
		t.Fatalf("expected dir=rtl for ar-EG: %s", rtl)
	}
	in.Locale = "en-US"
	ltr, _ := r.Render(in)
	if strings.Contains(string(ltr), `dir="rtl"`) {
		t.Fatalf("unexpected dir=rtl for en-US: %s", ltr)
	}
}

// TestBannerRenderer_TokenTTLDefaultIs24h ensures the WS-1d
// default applies when TokenTTL is unset.
func TestBannerRenderer_TokenTTLDefaultIs24h(t *testing.T) {
	r, err := NewBannerRenderer(BannerRendererConfig{Issuer: newTestIssuer(t)})
	if err != nil {
		t.Fatalf("NewBannerRenderer: %v", err)
	}
	if r.tokenTTL != 24*time.Hour {
		t.Fatalf("tokenTTL=%v want=24h", r.tokenTTL)
	}
}

// TestBannerRenderer_TokenTTLOverride confirms the override path.
func TestBannerRenderer_TokenTTLOverride(t *testing.T) {
	r, err := NewBannerRenderer(BannerRendererConfig{
		Issuer:   newTestIssuer(t),
		TokenTTL: 90 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewBannerRenderer: %v", err)
	}
	if r.tokenTTL != 90*time.Minute {
		t.Fatalf("tokenTTL=%v want=90m", r.tokenTTL)
	}
}
