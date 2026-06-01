package selfrelease

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// BannerInput is the structured input to BannerRenderer.Render. The
// renderer expects the caller to have already authenticated /
// scoped the message to a recipient — no fields here are validated
// for authorisation; the caller must only call Render for messages
// the recipient is permitted to self-release.
type BannerInput struct {
	// TenantID, PseudoMessageID, RecipientUserHash identify the
	// (tenant, message, recipient) tuple for which the release
	// token is minted. The renderer hex-encodes RecipientUserHash
	// into the token's `ruh` claim.
	TenantID          string
	PseudoMessageID   string
	RecipientUserHash []byte
	// SubjectExcerpt is a short, already-truncated rendering of
	// the original subject. May be empty. The renderer escapes
	// it before inlining into the HTML so a malicious subject
	// cannot inject markup.
	SubjectExcerpt string
	// SenderDisplay is the rendered sender. Same escaping rules
	// as SubjectExcerpt.
	SenderDisplay string
	// Locale is BCP-47; rendered banners fall back to "en" if
	// missing. Used only for the user-visible copy; the URL
	// itself is locale-independent.
	Locale string
	// ReleaseEndpoint is the absolute URL the "Release" button
	// posts to (typically "https://es.<tenant>.sn360.example/v1/quarantine/release").
	// The renderer appends the token as a query string so the
	// recipient's click is a GET that becomes a POST via a tiny
	// inline form — easier for mail clients than fetch() and
	// works without JS.
	ReleaseEndpoint string
	// Now is injectable for deterministic golden-file tests.
	// Defaults to time.Now().UTC() in production.
	Now time.Time
}

// BannerRenderer produces the self-service release HTML snippet.
// The snippet is suitable for both an in-message banner (above the
// quarantine stub body) and a recipient digest entry — the
// rendered output is a self-contained <div> with inline styles for
// mail-client compatibility.
type BannerRenderer struct {
	issuer *privacy.JWTIssuer
	tpl    *template.Template
	// TokenTTL is the action-token TTL; defaults to 24h per
	// WS-1d's banner-token default.
	tokenTTL time.Duration
}

// BannerRendererConfig wires the renderer's dependencies.
type BannerRendererConfig struct {
	// Issuer mints the signed action token. Required.
	Issuer *privacy.JWTIssuer
	// TokenTTL is the lifetime of the issued token. Defaults to
	// 24h when zero (the WS-1d default).
	TokenTTL time.Duration
}

// NewBannerRenderer constructs a renderer. Issuer is required; ttl
// defaults to 24h.
func NewBannerRenderer(cfg BannerRendererConfig) (*BannerRenderer, error) {
	if cfg.Issuer == nil {
		return nil, errors.New("selfrelease/banner: issuer is required")
	}
	ttl := cfg.TokenTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	tpl, err := template.New("self_release").Parse(bannerTemplate)
	if err != nil {
		return nil, fmt.Errorf("selfrelease/banner: parse template: %w", err)
	}
	return &BannerRenderer{issuer: cfg.Issuer, tpl: tpl, tokenTTL: ttl}, nil
}

// Render produces the banner HTML. Errors come from token minting
// (issuer's keys not configured) or from required-field validation.
// The output is a single HTML <div> with inline styles; the caller
// concatenates it into the larger banner or digest document.
func (r *BannerRenderer) Render(in BannerInput) ([]byte, error) {
	if in.TenantID == "" {
		return nil, errors.New("selfrelease/banner: tenant_id is required")
	}
	if in.PseudoMessageID == "" {
		return nil, errors.New("selfrelease/banner: pseudo_message_id is required")
	}
	if len(in.RecipientUserHash) == 0 {
		return nil, errors.New("selfrelease/banner: recipient_user_hash is required")
	}
	if in.ReleaseEndpoint == "" {
		return nil, errors.New("selfrelease/banner: release_endpoint is required")
	}
	if _, err := url.Parse(in.ReleaseEndpoint); err != nil {
		return nil, fmt.Errorf("selfrelease/banner: release_endpoint not parseable: %w", err)
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// hexEncode the recipient hash into the `ruh` claim. The
	// pseudonymiser produces a fixed 64-byte hex digest, so we
	// hex-encode the byte slice as-is — the audit layer reverses
	// it back to BYTEA on the way into Postgres.
	token, err := r.issuer.Issue(in.TenantID, in.PseudoMessageID, privacy.IssueOptions{
		TTL:               r.tokenTTL,
		Scope:             privacy.ScopeQuarantineRelease,
		RecipientUserHash: hexEncode(in.RecipientUserHash),
	})
	if err != nil {
		return nil, fmt.Errorf("selfrelease/banner: issue token: %w", err)
	}
	locale := in.Locale
	if locale == "" {
		locale = "en"
	}
	data := struct {
		Token     string
		Endpoint  string
		Subject   string
		Sender    string
		Locale    string
		ExpiresAt string
		IsRTL     bool
	}{
		Token:     token,
		Endpoint:  in.ReleaseEndpoint,
		Subject:   in.SubjectExcerpt,
		Sender:    in.SenderDisplay,
		Locale:    locale,
		ExpiresAt: now.Add(r.tokenTTL).UTC().Format(time.RFC3339),
		IsRTL:     isRTLLocale(locale),
	}
	var buf bytes.Buffer
	if err := r.tpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("selfrelease/banner: execute template: %w", err)
	}
	return buf.Bytes(), nil
}

// hexEncode is a tiny helper to make the call site self-documenting.
// We don't reach for `encoding/hex` here to keep the import surface
// small; the inline form is fine for 32-byte BLAKE2b digests.
func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}

// isRTLLocale defers to the canonical RTL-locale list maintained by
// internal/service/action.IsRTLLocale so adding a new RTL language
// (e.g. "yi") in one place propagates here automatically. Previously
// this file carried a hand-mirrored copy of the locale map kept in
// sync by a comment, which is exactly the silent-divergence shape
// Devin Review flagged in WS-3a round 4 — promoted from a comment-
// kept-in-sync arrangement to an actual code-level shared
// definition.
func isRTLLocale(locale string) bool { return action.IsRTLLocale(locale) }

// bannerTemplate is the self-contained HTML for the self-service
// release banner. It renders as a single <div> with inline styles
// and a <form> that POSTs the token. We use a <form method="POST">
// instead of an anchor or a fetch() call because:
//   - Mail clients reliably handle <form action=URL method=POST>
//     when a button-style input is inside it; many strip JS and
//     mangle anchor-driven URL state.
//   - GET-encoded tokens in the address bar are persisted by the
//     browser's history / referrer; POSTing the token keeps it out
//     of those side-channels.
//   - The endpoint already only accepts POST (existing
//     QuarantineHandler.ServeHTTP enforces method == POST).
//
// The accessibility attributes (role, aria-label, aria-live) match
// the canonical banner renderer's conventions so screen readers
// announce the banner with the same vocabulary as the other tiers'
// banners.
const bannerTemplate = `<div role="region" aria-label="SN360 quarantined message"
     lang="{{.Locale}}"{{if .IsRTL}} dir="rtl"{{end}}
     style="border:1px solid #6e4d00;background:#fff8e1;color:#3d2c00;padding:14px 16px;border-radius:4px;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.4;margin:8px 0;">
    <div style="font-weight:bold;margin-bottom:6px;">SN360 held this message for review.</div>
    {{if .Subject}}<div style="margin-bottom:4px;"><strong>Subject:</strong> {{.Subject}}</div>{{end}}
    {{if .Sender}}<div style="margin-bottom:8px;"><strong>From:</strong> {{.Sender}}</div>{{end}}
    <div style="margin-bottom:10px;">If you recognise this sender and trust this message, you can release it to your inbox.</div>
    <form action="{{.Endpoint}}" method="POST" enctype="application/x-www-form-urlencoded"
          style="margin:0;padding:0;">
        <input type="hidden" name="token" value="{{.Token}}">
        <button type="submit"
                aria-label="Release this message to my inbox"
                style="background:#6e4d00;color:#ffffff;border:none;padding:8px 14px;border-radius:3px;font-weight:bold;cursor:pointer;font-size:13px;">
            Release to my inbox
        </button>
    </form>
    <div aria-live="polite" style="margin-top:8px;color:#5e4900;font-size:11px;">
        Link expires {{.ExpiresAt}}. If you are unsure, leave the message in quarantine and contact your IT team.
    </div>
</div>
`
