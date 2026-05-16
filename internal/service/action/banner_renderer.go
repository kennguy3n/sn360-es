package action

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// BannerInput is the structured input to BannerRenderer.Render. Every
// field is plain data (no pointers to mutable state) so the renderer
// produces byte-identical output given identical input.
type BannerInput struct {
	Tier        constant.Tier
	Primary     constant.Category
	Secondary   []constant.Category
	ReasonCodes []string
	// SenderAuth is the aggregate result of SPF / DKIM / DMARC.
	SenderAuth AuthVerdict
	// SenderDisplay is the rendered sender ("Name <email>"); used for
	// the auth chip subtext.
	SenderDisplay string
	// SenderDomain is the parsed sending domain.
	SenderDomain string
	// Locale is BCP-47; rendered banners fall back to "en" if missing.
	Locale string
	// ActionToken is the short-lived signed JWT used to post feedback.
	// Required for any tier that exposes user actions.
	ActionToken string
	// MicroLessonURL is an optional anchor to an in-product micro-lesson.
	MicroLessonURL string
	// Degraded is true when one or more detection services were down
	// during evaluation; surfaces as a small notice on the banner.
	Degraded bool
}

// Validate sanity-checks the input.
func (b BannerInput) Validate() error {
	if !b.Tier.Valid() {
		return errors.New("banner: invalid tier")
	}
	if b.Tier.AllowsMarkSafe() && b.ActionToken == "" {
		return errors.New("banner: action token required for interactive tier")
	}
	return nil
}

// Translator is the minimal i18n surface used by the renderer. The
// default implementation is JSONCatalog (banner_i18n.go).
type Translator interface {
	Translate(locale, key string) string
}

// BannerRenderer renders self-contained HTML for the six banner tiers.
type BannerRenderer struct {
	tmpl *template.Template
	tr   Translator
}

// NewBannerRenderer parses the templates and returns a renderer. The
// argument is required so callers can inject mock translators in tests.
func NewBannerRenderer(tr Translator) (*BannerRenderer, error) {
	if tr == nil {
		return nil, errors.New("banner: translator required")
	}
	tmpl, err := template.New("banner").Funcs(template.FuncMap{
		"hasClass":  hasClass,
		"chipClass": chipClassFor,
		"safeCSS":   func(s string) template.CSS { return template.CSS(s) },
	}).Parse(bannerTemplate)
	if err != nil {
		return nil, fmt.Errorf("banner: parse template: %w", err)
	}
	return &BannerRenderer{tmpl: tmpl, tr: tr}, nil
}

// Render returns the HTML byte slice for in.
func (r *BannerRenderer) Render(in BannerInput) ([]byte, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	locale := in.Locale
	if locale == "" {
		locale = "en"
	}
	view := bannerView{
		Tier:          in.Tier,
		TierClass:     tierClassFor(in.Tier),
		Title:         r.tr.Translate(locale, "tier."+string(in.Tier)+".title"),
		Body:          r.tr.Translate(locale, "tier."+string(in.Tier)+".body"),
		Primary:       in.Primary,
		PrimaryCopy:   r.tr.Translate(locale, in.Primary.CopyKey()),
		Secondary:     in.Secondary,
		ReasonCodes:   in.ReasonCodes,
		AuthVerdict:   in.SenderAuth,
		AuthLabel:     r.tr.Translate(locale, "auth."+string(in.SenderAuth)),
		SenderDisplay: in.SenderDisplay,
		SenderDomain:  in.SenderDomain,
		Locale:        locale,
		ActionToken:   in.ActionToken,
		ShowReport:    in.Tier.Severity() >= constant.TierInformational.Severity(),
		ShowMarkSafe:  in.Tier.AllowsMarkSafe(),
		ShowTrust:     in.Tier.AllowsMarkSafe(),
		MicroLesson:   in.MicroLessonURL,
		Degraded:      in.Degraded,
		ReportLabel:   r.tr.Translate(locale, "action.report"),
		MarkSafeLabel: r.tr.Translate(locale, "action.mark_safe"),
		TrustLabel:    r.tr.Translate(locale, "action.trust_sender"),
		LearnLabel:    r.tr.Translate(locale, "action.learn_more"),
		DegradedLabel: r.tr.Translate(locale, "banner.degraded"),
	}

	for _, sec := range in.Secondary {
		view.SecondaryCopy = append(view.SecondaryCopy, r.tr.Translate(locale, sec.CopyKey()))
	}

	var buf bytes.Buffer
	if err := r.tmpl.Execute(&buf, view); err != nil {
		return nil, fmt.Errorf("banner: render: %w", err)
	}
	return buf.Bytes(), nil
}

// bannerView is the template's input struct.
type bannerView struct {
	Tier          constant.Tier
	TierClass     string
	Title         string
	Body          string
	Primary       constant.Category
	PrimaryCopy   string
	Secondary     []constant.Category
	SecondaryCopy []string
	ReasonCodes   []string
	AuthVerdict   AuthVerdict
	AuthLabel     string
	SenderDisplay string
	SenderDomain  string
	Locale        string
	ActionToken   string
	ShowReport    bool
	ShowMarkSafe  bool
	ShowTrust     bool
	MicroLesson   string
	Degraded      bool
	ReportLabel   string
	MarkSafeLabel string
	TrustLabel    string
	LearnLabel    string
	DegradedLabel string
}

func tierClassFor(t constant.Tier) string {
	switch t {
	case constant.TierBlocked:
		return "sn360-banner sn360-blocked"
	case constant.TierHighRisk:
		return "sn360-banner sn360-high"
	case constant.TierWarning:
		return "sn360-banner sn360-warning"
	case constant.TierCaution:
		return "sn360-banner sn360-caution"
	case constant.TierInformational:
		return "sn360-banner sn360-info"
	case constant.TierTrusted:
		return "sn360-banner sn360-trusted"
	default:
		return "sn360-banner"
	}
}

func chipClassFor(v AuthVerdict) string {
	switch v {
	case AuthVerified:
		return "sn360-chip sn360-chip-verified"
	case AuthFailed:
		return "sn360-chip sn360-chip-failed"
	case AuthUnverified:
		return "sn360-chip sn360-chip-unverified"
	default:
		return "sn360-chip"
	}
}

func hasClass(class string, classes ...string) bool {
	for _, c := range classes {
		if strings.EqualFold(c, class) {
			return true
		}
	}
	return false
}

// bannerCSS is the inline stylesheet shared by all banner tiers. It is
// declared separately so the Go file can use a single backtick-quoted
// string without nesting (Go does not allow nested backtick literals).
const bannerCSS = `.sn360-banner{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;font-size:14px;line-height:1.4;border-radius:8px;padding:12px 16px;margin:8px 0;border:1px solid transparent;color:#111;background:#f5f5f5}
.sn360-banner h1{font-size:14px;font-weight:600;margin:0 0 4px 0;letter-spacing:0.01em}
.sn360-banner p{margin:0 0 6px 0}
.sn360-banner .sn360-secondary{color:#555;font-size:12px;margin-top:4px}
.sn360-banner .sn360-reasons{color:#666;font-size:12px;margin-top:4px;font-style:italic}
.sn360-banner .sn360-actions{margin-top:8px;display:flex;flex-wrap:wrap;gap:8px}
.sn360-banner .sn360-actions a{display:inline-block;padding:6px 12px;border-radius:6px;text-decoration:none;font-weight:500;font-size:12px;color:#fff;background:#444}
.sn360-banner .sn360-chip{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;margin-right:6px;vertical-align:middle}
.sn360-banner .sn360-chip-verified{background:#0a7a3d;color:#fff}
.sn360-banner .sn360-chip-failed{background:#b00020;color:#fff}
.sn360-banner .sn360-chip-unverified{background:#7a7a7a;color:#fff}
.sn360-blocked{background:#fce8e6;border-color:#b00020;color:#5a0014}
.sn360-blocked .sn360-actions a{background:#b00020}
.sn360-high{background:#fff1e5;border-color:#cc5500;color:#5a2400}
.sn360-high .sn360-actions a{background:#cc5500}
.sn360-warning{background:#fff8e1;border-color:#b58a00;color:#5a4400}
.sn360-warning .sn360-actions a{background:#7a5a00}
.sn360-caution{background:#eef6ff;border-color:#1565c0;color:#0a3a78}
.sn360-caution .sn360-actions a{background:#1565c0}
.sn360-info{background:#f1f5f9;border-color:#5a6b80;color:#1f2a36}
.sn360-info .sn360-actions a{background:#5a6b80}
.sn360-trusted{background:#e6f4ea;border-color:#0a7a3d;color:#1f4a2c}
.sn360-trusted .sn360-actions a{background:#0a7a3d}
.sn360-degraded{color:#666;font-size:11px;margin-top:6px;font-style:italic}
@media (prefers-color-scheme:dark){.sn360-banner{color:#f5f5f5;background:#222}.sn360-banner .sn360-secondary,.sn360-banner .sn360-reasons,.sn360-degraded{color:#bbb}}`

// bannerTemplate is the single self-contained template used for all
// tiers. Variants are switched purely via CSS class. The template
// intentionally inlines all CSS so the banner survives provider HTML
// sanitisers.
var bannerTemplate = `<style>` + bannerCSS + `</style>
<div class="{{ .TierClass }}" data-sn360-tier="{{ .Tier }}" data-sn360-locale="{{ .Locale }}">
  <h1>{{ .Title }}</h1>
  <p>{{ .Body }}</p>
  {{ if .PrimaryCopy }}<p><strong>{{ .PrimaryCopy }}</strong></p>{{ end }}
  {{ if .SecondaryCopy }}<p class="sn360-secondary">{{ range $i, $s := .SecondaryCopy }}{{ if $i }} · {{ end }}{{ $s }}{{ end }}</p>{{ end }}
  {{ if .ReasonCodes }}<p class="sn360-reasons">{{ range $i, $r := .ReasonCodes }}{{ if $i }} · {{ end }}{{ $r }}{{ end }}</p>{{ end }}
  {{ if .AuthLabel }}<p><span class="{{ chipClass .AuthVerdict }}">{{ .AuthLabel }}</span>{{ if .SenderDomain }} <span class="sn360-secondary">{{ .SenderDomain }}</span>{{ end }}</p>{{ end }}
  <div class="sn360-actions">
    {{ if .ShowReport }}<a href="https://l.sn360.io/action/report_phishing?token={{ .ActionToken }}">{{ .ReportLabel }}</a>{{ end }}
    {{ if .ShowMarkSafe }}<a href="https://l.sn360.io/action/mark_safe?token={{ .ActionToken }}">{{ .MarkSafeLabel }}</a>{{ end }}
    {{ if .ShowTrust }}<a href="https://l.sn360.io/action/trust_sender?token={{ .ActionToken }}">{{ .TrustLabel }}</a>{{ end }}
    {{ if .MicroLesson }}<a href="{{ .MicroLesson }}">{{ .LearnLabel }}</a>{{ end }}
  </div>
  {{ if .Degraded }}<p class="sn360-degraded">{{ .DegradedLabel }}</p>{{ end }}
</div>
`
