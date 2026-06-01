package handler

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// ThreatIntel is the contract the interstitial handler needs to make
// a final decision about an outbound click. Implementations may
// consult a feed, a cache, or a synchronous Tier 0 + Rspamd recheck.
type ThreatIntel interface {
	// CheckURL returns (safe, reason). When safe == true the
	// interstitial redirects; otherwise the block page is rendered.
	CheckURL(ctx context.Context, original string) (safe bool, reason string)
}

// AnonymousClickLogger records that a click was decided. It must not
// receive any PII — the implementation is expected to keep only the
// tenant ID + verdict + timestamp.
type AnonymousClickLogger interface {
	LogClick(ctx context.Context, tenantID, urlHash, verdict string, at time.Time)
}

// InterstitialHandler serves GET /{token} for the interstitial flow.
// It verifies the token, decrypts the URL pre-image, optionally
// re-checks against threat intel, then either redirects or renders
// a block page.
type InterstitialHandler struct {
	logger     *slog.Logger
	rewriter   *action.URLRewriter
	intel      ThreatIntel
	clickLog   AnonymousClickLogger
	blockTmpl  *template.Template
	tokenParam string
}

// InterstitialConfig optional knobs for the handler.
type InterstitialConfig struct {
	// TokenParam is the path / query param holding the token.
	// Default "token".
	TokenParam string
}

// NewInterstitialHandler wires up the handler. intel may be nil; in
// that case verified URLs always redirect (no recheck). clickLog may
// also be nil.
func NewInterstitialHandler(logger *slog.Logger, rewriter *action.URLRewriter, intel ThreatIntel, clickLog AnonymousClickLogger, cfg InterstitialConfig) *InterstitialHandler {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.TokenParam == "" {
		cfg.TokenParam = "token"
	}
	tmpl := template.Must(template.New("block").Parse(blockHTML))
	return &InterstitialHandler{
		logger:     logger,
		rewriter:   rewriter,
		intel:      intel,
		clickLog:   clickLog,
		blockTmpl:  tmpl,
		tokenParam: cfg.TokenParam,
	}
}

// ServeHTTP implements http.Handler.
func (h *InterstitialHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Defense-in-depth security headers for the interstitial page.
	// Set before any branch so success, error, block, and redirect
	// responses all carry them — Go's net/http freezes headers on
	// the first WriteHeader/Write, so they have to land first.
	setInterstitialSecurityHeaders(w)
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token := h.extractToken(r)
	if token == "" {
		writeError(w, http.StatusBadRequest, "missing token")
		return
	}
	original, claims, err := h.rewriter.Resolve(r.Context(), token)
	if err != nil {
		h.logger.WarnContext(r.Context(), "interstitial: resolve",
			slog.Any("error", err))
		h.renderBlock(w, "link_expired", "")
		return
	}
	verdict := "safe"
	reason := ""
	if h.intel != nil {
		safe, intelReason := h.intel.CheckURL(r.Context(), original)
		if !safe {
			verdict = "blocked"
			reason = intelReason
		}
	}
	if h.clickLog != nil {
		h.clickLog.LogClick(r.Context(), claims.TenantID, claims.OriginalURLHash, verdict, time.Now().UTC())
	}
	if verdict == "blocked" {
		h.renderBlock(w, "policy_block", reason)
		return
	}
	// Validate before redirecting so we never bounce into something
	// the parser can't understand.
	if _, err := url.Parse(original); err != nil {
		h.renderBlock(w, "malformed_url", "")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, original, http.StatusFound)
}

// setInterstitialSecurityHeaders applies the WS-7d defense-in-depth
// header set on every response from the interstitial handler. Kept
// per-handler (not in a generic middleware) because other endpoints
// — dashboard plugin iframe views, action-token banners — need
// looser CSP / framing rules; tightening them globally would break
// those surfaces.
//
//	Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'
//	X-Frame-Options:         DENY
//	X-Content-Type-Options:  nosniff
//
// `style-src 'unsafe-inline'` is required because blockHTML embeds
// its CSS in a <style> block to stay a self-contained document with
// no external asset hosting. If that ever changes, drop
// 'unsafe-inline' before relaxing anything else.
func setInterstitialSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
}

// extractToken pulls the token from either the path (last segment) or
// the query string (?token=...). Path form is preferred so the URL is
// short and shareable.
func (h *InterstitialHandler) extractToken(r *http.Request) string {
	if q := strings.TrimSpace(r.URL.Query().Get(h.tokenParam)); q != "" {
		return q
	}
	// Trim a trailing slash so /l/ABC and /l/ABC/ both resolve.
	p := strings.TrimRight(r.URL.Path, "/")
	if idx := strings.LastIndex(p, "/"); idx >= 0 && idx < len(p)-1 {
		return p[idx+1:]
	}
	return ""
}

func (h *InterstitialHandler) renderBlock(w http.ResponseWriter, code, reason string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	data := struct {
		Code   string
		Reason string
	}{Code: code, Reason: reason}
	if err := h.blockTmpl.Execute(w, data); err != nil {
		h.logger.Warn("interstitial: render", slog.Any("error", err))
	}
}

// blockHTML is the inline block-page rendered when the URL is unsafe,
// expired, or malformed. Self-contained so the interstitial does not
// depend on static asset hosting.
const blockHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SN360 — Link Blocked</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:#fce8e6;color:#5a0014;margin:0;padding:48px 16px;display:flex;justify-content:center}
.card{background:#fff;max-width:480px;border-radius:12px;padding:24px;border:1px solid #b00020;box-shadow:0 4px 12px rgba(0,0,0,.05)}
h1{font-size:18px;margin:0 0 12px}
p{margin:0 0 8px;font-size:14px}
.code{font-family:ui-monospace,monospace;font-size:12px;color:#7a7a7a;margin-top:16px}
</style>
</head>
<body>
<div class="card">
<h1>Link blocked by SN360</h1>
<p>This link was rewritten by SN360-ES because the original message was flagged as high risk. The interstitial check determined the destination should not be opened.</p>
{{ if .Reason }}<p><strong>Reason:</strong> {{ .Reason }}</p>{{ end }}
<p class="code">{{ .Code }}</p>
</div>
</body>
</html>`
