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
	// Optional: when empty, the renderer suppresses the interactive
	// CTAs (Report / Mark Safe / Trust Sender) and produces an
	// informational-only banner. Callers that want the user to be able
	// to act on the verdict from the banner must mint a token and pass
	// it here; deployments without a feedback token issuer still get a
	// readable banner.
	ActionToken string
	// MicroLessonURL is an optional anchor to an in-product micro-lesson.
	MicroLessonURL string
	// Degraded is true when one or more detection services were down
	// during evaluation; surfaces as a small notice on the banner.
	Degraded bool
}

// rtlLocales is the set of BCP-47 language codes that render right-to-left.
// Used to inject dir="rtl" on the banner root for accessibility.
var rtlLocales = map[string]struct{}{
	"ar": {},
	"he": {},
	"fa": {},
	"ur": {},
}

// isRTLLocale reports whether locale renders right-to-left. The
// language-only prefix is consulted (e.g. "ar-EG" -> "ar").
func isRTLLocale(locale string) bool {
	if locale == "" {
		return false
	}
	lang := locale
	if dash := strings.IndexByte(locale, '-'); dash > 0 {
		lang = locale[:dash]
	}
	_, ok := rtlLocales[strings.ToLower(lang)]
	return ok
}

// tierColors mirrors the per-tier palette baked into bannerCSS so the
// renderer can also emit equivalent inline `style="..."` attributes.
// Modern clients honour the <style> block; Outlook 2016/2019/2021
// desktop (Word HTML engine) strips most rules in <style> and only
// respects inline style attributes. Keeping both representations in
// sync — the CSS rules in bannerCSS and the inline-style maps here —
// is what lets the same banner render correctly across Gmail web,
// Outlook web, Outlook desktop, Apple Mail and Thunderbird without a
// provider switch in the renderer.
//
// Background / Border / Text mirror the .sn360-{tier} CSS rules.
// Button / ButtonText mirror the .sn360-{tier} .sn360-actions a rule.
type tierColors struct {
	Background string
	Border     string
	Text       string
	Button     string
	ButtonText string
}

func tierColorsFor(t constant.Tier) tierColors {
	switch t {
	case constant.TierBlocked:
		return tierColors{"#fce8e6", "#9b0019", "#3d0010", "#9b0019", "#ffffff"}
	case constant.TierHighRisk:
		return tierColors{"#fff1e5", "#a64600", "#3d1900", "#a64600", "#ffffff"}
	case constant.TierWarning:
		return tierColors{"#fff8e1", "#6e4d00", "#3d2c00", "#6e4d00", "#ffffff"}
	case constant.TierCaution:
		return tierColors{"#eef6ff", "#0d4ea0", "#062a59", "#0d4ea0", "#ffffff"}
	case constant.TierInformational:
		return tierColors{"#f1f5f9", "#4a566a", "#16202c", "#4a566a", "#ffffff"}
	case constant.TierTrusted:
		return tierColors{"#e6f4ea", "#08642f", "#143d24", "#08642f", "#ffffff"}
	}
	return tierColors{"#f5f5f5", "transparent", "#0a0a0a", "#262626", "#ffffff"}
}

// chipInlineStyle returns the inline background colour mirror of the
// .sn360-chip-* CSS classes in bannerCSS. Used so Outlook desktop
// renders the auth-verdict chip with the correct colour even when the
// <style> block is stripped. The default branch must produce the same
// colour as the .sn360-chip-unknown CSS rule so AuthUnknown chips look
// the same on modern clients (which read the class rule) and Outlook
// desktop (which only sees this inline attribute).
func chipInlineStyle(v AuthVerdict) string {
	switch v {
	case AuthVerified:
		return "background:#08642f;color:#ffffff"
	case AuthFailed:
		return "background:#9b0019;color:#ffffff"
	case AuthUnverified:
		return "background:#595959;color:#ffffff"
	}
	// Default case mirrors .sn360-chip-unknown. The colour is the same
	// neutral grey we use for Unverified, because AuthUnknown means "we
	// have no rspamd outcome at all" which is functionally weaker than
	// Unverified but should not be visually alarming.
	return "background:#595959;color:#ffffff"
}

// tierIcon returns a short text glyph that conveys severity
// independently of color. Falls back to an empty string for unknown
// tiers so the template renders no icon span.
func tierIcon(t constant.Tier) string {
	switch t {
	case constant.TierBlocked:
		return "\u26d4" // no-entry
	case constant.TierHighRisk:
		return "\u26a0" // warning sign
	case constant.TierWarning:
		return "!"
	case constant.TierCaution:
		return "\u24d8" // circled i
	case constant.TierInformational:
		return "\u2139" // information source
	case constant.TierTrusted:
		return "\u2713" // check mark
	}
	return ""
}

// ariaRoleFor returns the ARIA live-region role for the tier. High-
// severity tiers use "alert" (assertive, immediate); softer tiers use
// "status" (polite, queued).
func ariaRoleFor(t constant.Tier) string {
	switch t {
	case constant.TierBlocked, constant.TierHighRisk:
		return "alert"
	default:
		return "status"
	}
}

// Validate sanity-checks the structural invariants on the input. A
// missing ActionToken is no longer fatal: Render() simply suppresses
// the interactive CTAs in that case so the informational portion of
// the banner still surfaces. This avoids silent banner loss in
// deployments that haven't wired a JWT feedback issuer.
func (b BannerInput) Validate() error {
	if !b.Tier.Valid() {
		return errors.New("banner: invalid tier")
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
		// safeCSS unconditionally trusts its input — but the only
		// callers in bannerTemplate feed it the tier slug
		// (constant.TierBlocked et al) and the constant chip class
		// names returned by chipClassFor. Neither is attacker-
		// controlled. The G203 finding is therefore a false positive.
		"safeCSS": func(s string) template.CSS { return template.CSS(s) }, //nolint:gosec
		// safeHTML is used solely to emit the four hardcoded Microsoft
		// Outlook conditional-comment delimiters (`<!--[if mso]>`,
		// `<![endif]-->`, `<!--[if !mso]><!-->`, `<!--<![endif]-->`)
		// that bracket the Outlook-desktop fallback table. Go's
		// html/template package strips HTML comments by default, which
		// would silently drop the entire fallback path. Every caller
		// in bannerTemplate passes a string literal that comes from
		// this file — none of the input is attacker-controlled.
		"safeHTML": func(s string) template.HTML { return template.HTML(s) }, //nolint:gosec
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
	title := r.tr.Translate(locale, "tier."+string(in.Tier)+".title")
	// Interactive CTAs (Report / Mark Safe / Trust Sender) all post to
	// l.sn360.io with `?token={ActionToken}`. Without a token the
	// resulting URL is broken and the click would surface as a feedback
	// 401 on the server, so suppress them when no token is supplied.
	// The micro-lesson link is unrelated to feedback and stays visible.
	hasToken := in.ActionToken != ""
	colors := tierColorsFor(in.Tier)
	view := bannerView{
		Tier:           in.Tier,
		TierClass:      tierClassFor(in.Tier),
		WrapperStyle:   wrapperInlineStyle(colors),
		ButtonStyle:    buttonInlineStyle(colors, false),
		ButtonStyleMSO: buttonInlineStyle(colors, true),
		ChipStyle:      chipInlineStyle(in.SenderAuth),
		Title:          title,
		Body:           r.tr.Translate(locale, "tier."+string(in.Tier)+".body"),
		Primary:        in.Primary,
		PrimaryCopy:    r.tr.Translate(locale, in.Primary.CopyKey()),
		Secondary:      in.Secondary,
		ReasonCodes:    in.ReasonCodes,
		AuthVerdict:    in.SenderAuth,
		AuthLabel:      r.tr.Translate(locale, "auth."+string(in.SenderAuth)),
		SenderDisplay:  in.SenderDisplay,
		SenderDomain:   in.SenderDomain,
		Locale:         locale,
		Dir:            dirFor(locale),
		AriaRole:       ariaRoleFor(in.Tier),
		AriaLabel:      title,
		IconGlyph:      tierIcon(in.Tier),
		ActionToken:    in.ActionToken,
		ShowReport:     hasToken && in.Tier.Severity() >= constant.TierInformational.Severity(),
		ShowMarkSafe:   hasToken && in.Tier.AllowsMarkSafe(),
		ShowTrust:      hasToken && in.Tier.AllowsMarkSafe(),
		MicroLesson:    in.MicroLessonURL,
		Degraded:       in.Degraded,
		ReportLabel:    r.tr.Translate(locale, "action.report"),
		MarkSafeLabel:  r.tr.Translate(locale, "action.mark_safe"),
		TrustLabel:     r.tr.Translate(locale, "action.trust_sender"),
		LearnLabel:     r.tr.Translate(locale, "action.learn_more"),
		DegradedLabel:  r.tr.Translate(locale, "banner.degraded"),
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
	Tier           constant.Tier
	TierClass      string
	WrapperStyle   string
	ButtonStyle    string
	ButtonStyleMSO string
	ChipStyle      string
	Title          string
	Body           string
	Primary        constant.Category
	PrimaryCopy    string
	Secondary      []constant.Category
	SecondaryCopy  []string
	ReasonCodes    []string
	AuthVerdict    AuthVerdict
	AuthLabel      string
	SenderDisplay  string
	SenderDomain   string
	Locale         string
	Dir            string
	AriaRole       string
	AriaLabel      string
	IconGlyph      string
	ActionToken    string
	ShowReport     bool
	ShowMarkSafe   bool
	ShowTrust      bool
	MicroLesson    string
	Degraded       bool
	ReportLabel    string
	MarkSafeLabel  string
	TrustLabel     string
	LearnLabel     string
	DegradedLabel  string
}

// wrapperInlineStyle composes the wrapper-element inline style that
// mirrors the tier-specific CSS rule in bannerCSS. Emitted on the
// outer <div> so Outlook desktop renders the tier colour even though
// the Word HTML engine ignores most rules inside the embedded <style>
// block. The font-family and base typography are repeated here so the
// banner still looks like a banner if the <style> block is stripped
// outright by a strict sanitiser.
func wrapperInlineStyle(c tierColors) string {
	return "font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;" +
		"font-size:14px;line-height:1.4;padding:12px 16px;margin:8px 0;" +
		"border-radius:8px;border:1px solid " + c.Border + ";" +
		"color:" + c.Text + ";background:" + c.Background
}

// buttonInlineStyle composes the inline style applied to action <a>
// elements. The mso=true variant omits border-radius (the Word HTML
// engine ignores it and would render as a square corner anyway) and
// adds mso-padding-alt:0 — an Outlook-specific declaration that tells
// the Word engine not to layer its own implicit cell padding on top of
// the padding we already supplied, which would otherwise inflate the
// button height and break vertical alignment with adjacent buttons.
// The border colour is set to match the background (rather than the
// CSS rule's `transparent`) because the Word engine sometimes collapses
// transparent borders to zero height, shrinking the button; a matching
// solid border is visually identical and stays a stable size.
func buttonInlineStyle(c tierColors, mso bool) string {
	base := "display:inline-block;padding:6px 12px;text-decoration:none;" +
		"font-weight:600;font-size:12px;" +
		"font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;" +
		"color:" + c.ButtonText + ";background:" + c.Button + ";" +
		"border:1px solid " + c.Button + ";"
	if !mso {
		base += "border-radius:6px;"
	} else {
		base += "mso-padding-alt:0;"
	}
	return base
}

// dirFor returns "rtl" for RTL locales and "ltr" otherwise. Always
// emits an explicit direction so screen readers and CSS layout do not
// need to infer from content.
func dirFor(locale string) string {
	if isRTLLocale(locale) {
		return "rtl"
	}
	return "ltr"
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
	case AuthUnknown:
		return "sn360-chip sn360-chip-unknown"
	default:
		return "sn360-chip sn360-chip-unknown"
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
//
// All color combinations satisfy WCAG 2.1 AA contrast (4.5:1 for normal
// text, 3:1 for large text and graphical objects). Text colors are
// darkened relative to the v1 palette so the contrast targets are met
// in both light and dark modes.
const bannerCSS = `.sn360-banner{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;font-size:14px;line-height:1.4;border-radius:8px;padding:12px 16px;margin:8px 0;border:1px solid transparent;color:#0a0a0a;background:#f5f5f5}
.sn360-banner h1{font-size:14px;font-weight:700;margin:0 0 4px 0;letter-spacing:0.01em}
.sn360-banner p{margin:0 0 6px 0}
.sn360-banner .sn360-icon{display:inline-block;margin-right:6px;font-size:16px;line-height:1;vertical-align:middle;font-weight:700}
.sn360-banner[dir="rtl"] .sn360-icon{margin-right:0;margin-left:6px}
.sn360-banner .sn360-secondary{color:#3a3a3a;font-size:12px;margin-top:4px}
.sn360-banner .sn360-reasons{color:#3a3a3a;font-size:12px;margin-top:4px;font-style:italic}
.sn360-banner .sn360-actions{margin-top:8px;display:flex;flex-wrap:wrap;gap:8px}
.sn360-banner .sn360-actions a{display:inline-block;padding:6px 12px;border-radius:6px;text-decoration:none;font-weight:600;font-size:12px;color:#fff;background:#262626;border:1px solid transparent}
.sn360-banner .sn360-actions a:focus{outline:2px solid #0050b3;outline-offset:2px}
.sn360-banner .sn360-actions a:hover{text-decoration:underline}
.sn360-banner .sn360-chip{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700;margin-right:6px;vertical-align:middle;color:#fff}
.sn360-banner[dir="rtl"] .sn360-chip{margin-right:0;margin-left:6px}
.sn360-banner .sn360-chip-verified{background:#08642f}
.sn360-banner .sn360-chip-failed{background:#9b0019}
.sn360-banner .sn360-chip-unverified{background:#595959}
.sn360-banner .sn360-chip-unknown{background:#595959}
.sn360-blocked{background:#fce8e6;border-color:#9b0019;color:#3d0010}
.sn360-blocked .sn360-actions a{background:#9b0019}
.sn360-high{background:#fff1e5;border-color:#a64600;color:#3d1900}
.sn360-high .sn360-actions a{background:#a64600}
.sn360-warning{background:#fff8e1;border-color:#6e4d00;color:#3d2c00}
.sn360-warning .sn360-actions a{background:#6e4d00}
.sn360-caution{background:#eef6ff;border-color:#0d4ea0;color:#062a59}
.sn360-caution .sn360-actions a{background:#0d4ea0}
.sn360-info{background:#f1f5f9;border-color:#4a566a;color:#16202c}
.sn360-info .sn360-actions a{background:#4a566a}
.sn360-trusted{background:#e6f4ea;border-color:#08642f;color:#143d24}
.sn360-trusted .sn360-actions a{background:#08642f}
.sn360-degraded{color:#3a3a3a;font-size:11px;margin-top:6px;font-style:italic}
.sn360-sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media (prefers-color-scheme:dark){.sn360-banner{color:#f5f5f5;background:#1a1a1a}.sn360-banner .sn360-secondary,.sn360-banner .sn360-reasons,.sn360-degraded{color:#cfcfcf}}`

// bannerTemplate is the single self-contained template used for all
// tiers. Variants are switched purely via CSS class. The template
// intentionally inlines all CSS so the banner survives provider HTML
// sanitisers.
//
// Cross-client rendering strategy:
//   - The full bannerCSS block is emitted in a <style> tag for modern
//     clients (Gmail web/mobile, Outlook web, Apple Mail, Thunderbird)
//     that honour stylesheet rules in embedded <style> blocks.
//   - Every visible element ALSO carries an inline style="..." attribute
//     mirroring the same rule, because Outlook 2016 / 2019 / 2021 desktop
//     (Word HTML rendering engine) strips most rules from <style> and
//     only honours inline style attributes. Without the mirror, Outlook
//     desktop would render the banner as default-styled black text on a
//     white background.
//   - The action buttons are emitted twice: once inside an
//     <!--[if !mso]><!--> / <!--<![endif]--> guard (the modern flexbox
//     <div> seen by every non-Outlook-desktop client), and once inside
//     an <!--[if mso]> / <![endif]--> guard (the Outlook-desktop-only
//     <table> fallback so the buttons render as a proper row of tap
//     targets instead of stacking flat). MSO conditional comments are
//     ignored by every client other than Outlook desktop, so a single
//     HTML body cleanly serves heterogeneous reading clients without a
//     provider switch in the renderer.
//
// Accessibility:
//   - role attribute is "alert" for Blocked/HighRisk and "status" for
//     softer tiers so assistive tech announces severity immediately.
//     We intentionally do NOT set aria-live: role="alert" has an
//     implicit aria-live="assertive" + aria-atomic="true" and
//     role="status" has an implicit aria-live="polite", so the implicit
//     behavior is exactly what we want. Setting aria-live="polite"
//     explicitly would override the assertive behavior of "alert" and
//     cause Blocked/HighRisk banners to be queued instead of
//     interrupting screen readers.
//   - aria-label on the root mirrors the visible severity headline.
//   - aria-hidden on the icon glyph so screen readers don't speak it.
//   - dir attribute is set explicitly for RTL locales.
//   - Focus order follows reading order: title -> body -> reasons ->
//     auth chip -> action buttons.
//   - The Outlook-only <table> fallback duplicates the action links but
//     is unreachable by every other client (conditional comments hide
//     it from the DOM), so screen readers only encounter the modern
//     flexbox <div role="group"> path. No duplicate-announcement risk.
var bannerTemplate = `<style>` + bannerCSS + `</style>
<div class="{{ .TierClass }}" style="{{ safeCSS .WrapperStyle }}" role="{{ .AriaRole }}" aria-label="{{ .AriaLabel }}" dir="{{ .Dir }}" data-sn360-tier="{{ .Tier }}" data-sn360-locale="{{ .Locale }}">
  <h1 style="font-size:14px;font-weight:700;margin:0 0 4px 0;letter-spacing:0.01em">{{ if .IconGlyph }}<span class="sn360-icon" aria-hidden="true" style="display:inline-block;margin-right:6px;font-size:16px;line-height:1;vertical-align:middle;font-weight:700">{{ .IconGlyph }}</span>{{ end }}<span class="sn360-sr-only" style="position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0">{{ .AriaLabel }}: </span>{{ .Title }}</h1>
  <p style="margin:0 0 6px 0">{{ .Body }}</p>
  {{ if .PrimaryCopy }}<p style="margin:0 0 6px 0"><strong>{{ .PrimaryCopy }}</strong></p>{{ end }}
  {{ if .SecondaryCopy }}<p class="sn360-secondary" style="color:#3a3a3a;font-size:12px;margin-top:4px">{{ range $i, $s := .SecondaryCopy }}{{ if $i }} · {{ end }}{{ $s }}{{ end }}</p>{{ end }}
  {{ if .ReasonCodes }}<p class="sn360-reasons" style="color:#3a3a3a;font-size:12px;margin-top:4px;font-style:italic">{{ range $i, $r := .ReasonCodes }}{{ if $i }} · {{ end }}{{ $r }}{{ end }}</p>{{ end }}
  {{ if .AuthLabel }}<p style="margin:0 0 6px 0"><span class="{{ chipClass .AuthVerdict }}" style="display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700;margin-right:6px;vertical-align:middle;{{ safeCSS .ChipStyle }}" role="img" aria-label="{{ .AuthLabel }}">{{ .AuthLabel }}</span>{{ if .SenderDomain }} <span class="sn360-secondary" style="color:#3a3a3a;font-size:12px">{{ .SenderDomain }}</span>{{ end }}</p>{{ end }}
  {{ if or .ShowReport .ShowMarkSafe .ShowTrust .MicroLesson }}
  {{ safeHTML "<!--[if !mso]><!-->" }}
  <div class="sn360-actions" role="group" aria-label="{{ .AriaLabel }}" style="margin-top:8px;display:flex;flex-wrap:wrap;gap:8px">
    {{ if .ShowReport }}<a href="https://l.sn360.io/action/report_phishing?token={{ .ActionToken }}" aria-label="{{ .ReportLabel }}" style="{{ safeCSS .ButtonStyle }}">{{ .ReportLabel }}</a>{{ end }}
    {{ if .ShowMarkSafe }}<a href="https://l.sn360.io/action/mark_safe?token={{ .ActionToken }}" aria-label="{{ .MarkSafeLabel }}" style="{{ safeCSS .ButtonStyle }}">{{ .MarkSafeLabel }}</a>{{ end }}
    {{ if .ShowTrust }}<a href="https://l.sn360.io/action/trust_sender?token={{ .ActionToken }}" aria-label="{{ .TrustLabel }}" style="{{ safeCSS .ButtonStyle }}">{{ .TrustLabel }}</a>{{ end }}
    {{ if .MicroLesson }}<a href="{{ .MicroLesson }}" aria-label="{{ .LearnLabel }}" style="{{ safeCSS .ButtonStyle }}">{{ .LearnLabel }}</a>{{ end }}
  </div>
  {{ safeHTML "<!--<![endif]-->" }}
  {{ safeHTML "<!--[if mso]>" }}
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin-top:8px;border-collapse:collapse" aria-hidden="true"><tr>
    {{ if .ShowReport }}<td style="padding-right:8px"><a href="https://l.sn360.io/action/report_phishing?token={{ .ActionToken }}" style="{{ safeCSS .ButtonStyleMSO }}">{{ .ReportLabel }}</a></td>{{ end }}
    {{ if .ShowMarkSafe }}<td style="padding-right:8px"><a href="https://l.sn360.io/action/mark_safe?token={{ .ActionToken }}" style="{{ safeCSS .ButtonStyleMSO }}">{{ .MarkSafeLabel }}</a></td>{{ end }}
    {{ if .ShowTrust }}<td style="padding-right:8px"><a href="https://l.sn360.io/action/trust_sender?token={{ .ActionToken }}" style="{{ safeCSS .ButtonStyleMSO }}">{{ .TrustLabel }}</a></td>{{ end }}
    {{ if .MicroLesson }}<td style="padding-right:8px"><a href="{{ .MicroLesson }}" style="{{ safeCSS .ButtonStyleMSO }}">{{ .LearnLabel }}</a></td>{{ end }}
  </tr></table>
  {{ safeHTML "<![endif]-->" }}
  {{ end }}
  {{ if .Degraded }}<p class="sn360-degraded" style="color:#3a3a3a;font-size:11px;margin-top:6px;font-style:italic">{{ .DegradedLabel }}</p>{{ end }}
</div>
`
