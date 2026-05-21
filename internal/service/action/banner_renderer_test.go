package action

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

func mustRenderer(t *testing.T) *BannerRenderer {
	t.Helper()
	cat, err := DefaultBannerCatalog()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	r, err := NewBannerRenderer(cat)
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	return r
}

func TestBannerRendererRejectsNilTranslator(t *testing.T) {
	if _, err := NewBannerRenderer(nil); err == nil {
		t.Fatal("expected error when translator is nil")
	}
}

// TestBannerRendererSuppressesCTAsWhenTokenMissing pins the relaxed
// contract: a banner with no ActionToken still renders (so deployments
// without a feedback-token issuer still surface the warning), but the
// interactive CTAs are suppressed because their URLs would otherwise
// embed an empty token. The structural copy (title, body, primary,
// reasons, auth chip) must still be present.
func TestBannerRendererSuppressesCTAsWhenTokenMissing(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:    constant.TierWarning,
		Primary: constant.CategoryLikelyPhishing,
		Locale:  "en",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	if !strings.Contains(s, `data-sn360-tier="Warning"`) {
		t.Errorf("output should still mark Warning tier, got: %s", s)
	}
	for _, banned := range []string{"report_phishing", "mark_safe", "trust_sender"} {
		if strings.Contains(s, banned) {
			t.Errorf("interactive CTA %q must be suppressed when no token is supplied\n%s", banned, s)
		}
	}
	if strings.Contains(s, "token=\"") || strings.Contains(s, "token=&") || strings.Contains(s, "?token= ") {
		t.Errorf("output exposes empty-token URL: %s", s)
	}
}

func TestBannerRendererRendersTrustedWithoutToken(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:    constant.TierTrusted,
		Primary: constant.CategoryInternalTrusted,
		Locale:  "en",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	if !strings.Contains(s, `data-sn360-tier="Trusted"`) {
		t.Errorf("output should include trusted tier marker, got: %s", s)
	}
	if strings.Contains(s, "mark_safe") {
		t.Error("trusted banner should not surface mark_safe action")
	}
}

func TestBannerRendererDeterministicOutput(t *testing.T) {
	r := mustRenderer(t)
	in := BannerInput{
		Tier:        constant.TierHighRisk,
		Primary:     constant.CategoryLikelyPhishing,
		Secondary:   []constant.Category{constant.CategoryCredentialHarvesting},
		ReasonCodes: []string{"lookalike-domain", "credential-harvest"},
		SenderAuth:  AuthFailed,
		Locale:      "en",
		ActionToken: "tok-abc",
	}
	first, err := r.Render(in)
	if err != nil {
		t.Fatalf("first render: %v", err)
	}
	for i := 0; i < 3; i++ {
		out, err := r.Render(in)
		if err != nil {
			t.Fatalf("render %d: %v", i, err)
		}
		if !bytes.Equal(first, out) {
			t.Fatal("renderer produced non-deterministic output for identical input")
		}
	}
}

func TestBannerRendererIncludesActions(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:        constant.TierWarning,
		Primary:     constant.CategoryLookalikeDomain,
		Locale:      "en",
		ActionToken: "tok-xyz",
		SenderAuth:  AuthVerified,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	for _, want := range []string{"report_phishing", "mark_safe", "trust_sender", "tok-xyz"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n%s", want, s)
		}
	}
}

func TestBannerRendererVietnameseLocale(t *testing.T) {
	r := mustRenderer(t)
	enHTML, err := r.Render(BannerInput{
		Tier:        constant.TierBlocked,
		Primary:     constant.CategoryLikelyPhishing,
		Locale:      "en",
		ActionToken: "tok-en",
	})
	if err != nil {
		t.Fatal(err)
	}
	viHTML, err := r.Render(BannerInput{
		Tier:        constant.TierBlocked,
		Primary:     constant.CategoryLikelyPhishing,
		Locale:      "vi",
		ActionToken: "tok-vi",
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enHTML, viHTML) {
		t.Fatal("English and Vietnamese banners should not be byte-identical")
	}
	if !strings.Contains(string(viHTML), `data-sn360-locale="vi"`) {
		t.Errorf("VI banner missing locale marker:\n%s", viHTML)
	}
}

func TestBannerRendererInjectsDegradedNotice(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:        constant.TierCaution,
		Primary:     constant.CategoryFirstContactExternal,
		Locale:      "en",
		ActionToken: "tok-x",
		Degraded:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "sn360-degraded") {
		t.Errorf("expected degraded notice in HTML:\n%s", html)
	}
}

// TestBannerRendererAccessibility verifies WCAG 2.1 AA hooks:
//   - role="alert" on Blocked / HighRisk, "status" on softer tiers.
//   - aria-label mirrors the localised severity headline.
//   - icon glyph is aria-hidden (decorative) but conveys severity.
//   - dir attribute is rendered explicitly (defaults to ltr).
//   - aria-live is NOT set explicitly: role="alert" has an implicit
//     aria-live="assertive" and role="status" has an implicit
//     aria-live="polite", so an explicit attribute would override
//     the assertive behaviour we want on Blocked / HighRisk. The
//     negative assertion below locks this in.
func TestBannerRendererAccessibility(t *testing.T) {
	r := mustRenderer(t)
	cases := []struct {
		name      string
		tier      constant.Tier
		wantRole  string
		wantIcon  string
		showIcon  bool
		showToken bool
	}{
		{"blocked uses alert role", constant.TierBlocked, "alert", "\u26d4", true, true},
		{"high risk uses alert role", constant.TierHighRisk, "alert", "\u26a0", true, true},
		{"warning uses status role", constant.TierWarning, "status", "!", true, true},
		{"caution uses status role", constant.TierCaution, "status", "\u24d8", true, true},
		{"informational uses status role", constant.TierInformational, "status", "\u2139", true, true},
		{"trusted uses status role", constant.TierTrusted, "status", "\u2713", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := BannerInput{
				Tier:    tc.tier,
				Primary: constant.CategoryFirstContactExternal,
				Locale:  "en",
			}
			if tc.showToken {
				in.ActionToken = "tok"
			}
			html, err := r.Render(in)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			s := string(html)
			if !strings.Contains(s, `role="`+tc.wantRole+`"`) {
				t.Errorf("missing role=%q\n%s", tc.wantRole, s)
			}
			if !strings.Contains(s, `aria-label="`) {
				t.Errorf("missing aria-label on root\n%s", s)
			}
			// Negative assertion: aria-live must NOT be set explicitly.
			// role="alert" implies aria-live="assertive" and
			// role="status" implies aria-live="polite"; setting either
			// explicitly overrides the implicit behaviour. The previous
			// template hardcoded aria-live="polite" which silently
			// downgraded Blocked / HighRisk banners.
			if strings.Contains(s, "aria-live") {
				t.Errorf("aria-live should not be set explicitly (role=%q implies it)\n%s", tc.wantRole, s)
			}
			if !strings.Contains(s, `dir="ltr"`) {
				t.Errorf("missing dir=ltr on root\n%s", s)
			}
			if tc.showIcon {
				if !strings.Contains(s, tc.wantIcon) {
					t.Errorf("missing icon glyph %q\n%s", tc.wantIcon, s)
				}
				if !strings.Contains(s, `aria-hidden="true"`) {
					t.Errorf("icon glyph should be aria-hidden\n%s", s)
				}
			}
			if !strings.Contains(s, "sn360-sr-only") {
				t.Errorf("missing screen-reader-only severity prefix\n%s", s)
			}
		})
	}
}

// TestBannerRendererRTL verifies that the renderer emits dir="rtl"
// for locales whose primary language is RTL even if the locale string
// is region-qualified.
func TestBannerRendererRTL(t *testing.T) {
	// The "ar" catalog is the only locale provided; we use "ar" as
	// the fallback so the constructor's fallback-presence check
	// passes. Missing English strings then layer in via stackedCatalog
	// below.
	cat, err := NewJSONCatalog(map[string]map[string]string{
		"ar": {
			"tier.HighRisk.title":        "خطر مرتفع",
			"tier.HighRisk.body":         "لا تتفاعل مع هذه الرسالة.",
			"category.BEC_IMPERSONATION": "احتيال انتحال شخصية",
			"auth.failed":                "فشل التحقق",
			"action.report":              "إبلاغ",
			"action.mark_safe":           "آمن",
			"action.trust_sender":        "ثقة",
			"action.learn_more":          "اعرف المزيد",
			"banner.degraded":            "تدهور",
		},
	}, "ar")
	if err != nil {
		t.Fatalf("new catalog: %v", err)
	}
	// Layer onto the default English catalog so missing keys still resolve.
	def, err := DefaultBannerCatalog()
	if err != nil {
		t.Fatalf("default catalog: %v", err)
	}
	r, err := NewBannerRenderer(stackedCatalog{primary: cat, fallback: def})
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	html, err := r.Render(BannerInput{
		Tier:        constant.TierHighRisk,
		Primary:     constant.CategoryBECImpersonation,
		Locale:      "ar-EG",
		ActionToken: "tok",
		SenderAuth:  AuthFailed,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	if !strings.Contains(s, `dir="rtl"`) {
		t.Errorf("expected dir=rtl for ar-EG\n%s", s)
	}
}

// stackedCatalog is a tiny test helper that consults a primary
// catalog then falls back to a secondary one when the primary returns
// the key unchanged (the i18n catalog's missing-key behaviour).
type stackedCatalog struct {
	primary  Translator
	fallback Translator
}

func (s stackedCatalog) Translate(locale, key string) string {
	v := s.primary.Translate(locale, key)
	if v == "" || v == key {
		return s.fallback.Translate(locale, key)
	}
	return v
}

// TestBannerRendererNewLocales renders banners in every newly added
// locale and checks the output is non-empty and carries the locale
// marker.
func TestBannerRendererNewLocales(t *testing.T) {
	r := mustRenderer(t)
	cases := []string{"th", "ja", "ko", "zh", "de", "fr", "it", "ar", "fil", "ms"}
	for _, loc := range cases {
		t.Run(loc, func(t *testing.T) {
			html, err := r.Render(BannerInput{
				Tier:        constant.TierWarning,
				Primary:     constant.CategoryLikelyPhishing,
				Locale:      loc,
				ActionToken: "tok",
			})
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			s := string(html)
			if !strings.Contains(s, `data-sn360-locale="`+loc+`"`) {
				t.Errorf("missing locale marker for %q\n%s", loc, s)
			}
			if !strings.Contains(s, `data-sn360-tier="Warning"`) {
				t.Errorf("missing tier marker for %q\n%s", loc, s)
			}
			// Ensure we are not echoing the i18n key back.
			if strings.Contains(s, "tier.Warning.title") {
				t.Errorf("untranslated key leaked for %q\n%s", loc, s)
			}
		})
	}
}

// TestBannerRendererArabicRTLProductionCatalog verifies that the production
// ar.json catalog (not the test-only stackedCatalog) correctly triggers
// dir="rtl" output.
func TestBannerRendererArabicRTLProductionCatalog(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:        constant.TierHighRisk,
		Primary:     constant.CategoryBECImpersonation,
		Locale:      "ar",
		ActionToken: "tok",
		SenderAuth:  AuthFailed,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	if !strings.Contains(s, `dir="rtl"`) {
		t.Errorf("expected dir=rtl for ar locale with production catalog\n%s", s)
	}
	if !strings.Contains(s, `data-sn360-locale="ar"`) {
		t.Errorf("missing locale marker for ar\n%s", s)
	}
}

// TestBannerRendererInlineWrapperStyle locks in the contract that the
// renderer emits a per-tier inline style="..." attribute on the wrapper
// <div>. Outlook 2016 / 2019 / 2021 desktop uses the Word HTML engine,
// which strips most rules from the embedded <style> block and only
// honours inline style attributes — so without this attribute the
// banner renders as default-styled black text on white in those clients,
// losing the severity colour cue that the design relies on.
func TestBannerRendererInlineWrapperStyle(t *testing.T) {
	r := mustRenderer(t)
	cases := []struct {
		name      string
		tier      constant.Tier
		wantBG    string
		wantText  string
		wantBordr string
	}{
		// Backgrounds + text colours mirror the .sn360-{tier} CSS rules
		// in bannerCSS. If you change one, change the other.
		{"blocked", constant.TierBlocked, "background:#fce8e6", "color:#3d0010", "border:1px solid #9b0019"},
		{"high risk", constant.TierHighRisk, "background:#fff1e5", "color:#3d1900", "border:1px solid #a64600"},
		{"warning", constant.TierWarning, "background:#fff8e1", "color:#3d2c00", "border:1px solid #6e4d00"},
		{"caution", constant.TierCaution, "background:#eef6ff", "color:#062a59", "border:1px solid #0d4ea0"},
		{"informational", constant.TierInformational, "background:#f1f5f9", "color:#16202c", "border:1px solid #4a566a"},
		{"trusted", constant.TierTrusted, "background:#e6f4ea", "color:#143d24", "border:1px solid #08642f"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			html, err := r.Render(BannerInput{
				Tier:        tc.tier,
				Primary:     constant.CategoryFirstContactExternal,
				Locale:      "en",
				ActionToken: "tok",
			})
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			s := string(html)
			for _, want := range []string{tc.wantBG, tc.wantText, tc.wantBordr} {
				if !strings.Contains(s, want) {
					t.Errorf("wrapper missing inline %q (tier=%s)\n%s", want, tc.tier, s)
				}
			}
		})
	}
}

// TestBannerRendererEmitsMSOConditionalFallback locks in the contract
// that the renderer emits the Outlook-desktop-only MSO conditional
// fallback alongside the modern flexbox path. Without these comments,
// Outlook 2016 / 2019 / 2021 desktop would see only the flexbox <div>
// whose `display:flex` rule is stripped by the Word HTML engine,
// causing the action buttons to stack flat without spacing. The MSO
// fallback wraps a <table> of <a> elements that the Word engine
// renders as a proper row of tap-targets.
//
// The negative assertion guards that the modern path is also wrapped
// in `<!--[if !mso]><!-->` so Outlook desktop does not see it twice
// and end up with two banners stacked on top of each other.
func TestBannerRendererEmitsMSOConditionalFallback(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:        constant.TierWarning,
		Primary:     constant.CategoryLookalikeDomain,
		Locale:      "en",
		ActionToken: "tok-xyz",
		SenderAuth:  AuthFailed,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	for _, want := range []string{
		"<!--[if !mso]><!-->",
		"<!--<![endif]-->",
		"<!--[if mso]>",
		"<![endif]-->",
		// MSO branch uses a <table> for the action buttons.
		`<table role="presentation"`,
		`cellpadding="0"`,
		`cellspacing="0"`,
		// The fallback table must be marked aria-hidden so screen
		// readers do not announce the buttons twice (the modern
		// flexbox <div role="group"> already handles announcement).
		`aria-hidden="true"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("MSO fallback missing %q\n%s", want, s)
		}
	}
}

// TestBannerRendererMSOFallbackRespectsCTAVisibility verifies that the
// suppression logic for missing ActionTokens also flows through to the
// Outlook fallback table. Without this, an Outlook-desktop reader
// could see Report/Mark-safe/Trust buttons with broken `token=` URLs
// that 401 when clicked, while every other client correctly suppresses
// them. The fallback path uses the same {{ if .ShowReport }} guard so
// the two paths cannot drift.
func TestBannerRendererMSOFallbackRespectsCTAVisibility(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:    constant.TierWarning,
		Primary: constant.CategoryLikelyPhishing,
		Locale:  "en",
		// No ActionToken — both paths must suppress CTAs.
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	for _, banned := range []string{"report_phishing", "mark_safe", "trust_sender"} {
		if strings.Contains(s, banned) {
			t.Errorf("interactive CTA %q leaked into output (modern or MSO path) when no token was supplied\n%s", banned, s)
		}
	}
}

// TestBannerRendererInlineActionButtonStyle verifies that the per-tier
// background colour of the action <a> elements is emitted as an inline
// style attribute in both the modern and MSO branches. Without this,
// Outlook desktop would render the buttons with the default colour
// only because the .sn360-{tier} .sn360-actions a CSS rule lives in
// the stripped <style> block.
func TestBannerRendererInlineActionButtonStyle(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:        constant.TierBlocked,
		Primary:     constant.CategoryLikelyPhishing,
		Locale:      "en",
		ActionToken: "tok",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	// .sn360-blocked .sn360-actions a uses background:#9b0019.
	if strings.Count(s, "background:#9b0019") < 2 {
		t.Errorf("blocked-tier button colour should appear inline in BOTH the modern and MSO paths (>=2 hits), got\n%s", s)
	}
	// Buttons must also carry text-decoration:none so Outlook does
	// not render them as underlined links.
	if !strings.Contains(s, "text-decoration:none") {
		t.Errorf("action <a> elements missing inline text-decoration:none\n%s", s)
	}
}

// TestBannerRendererInlineChipStyle verifies the auth-verdict chip
// carries the inline colour that mirrors .sn360-chip-verified /
// .sn360-chip-failed / .sn360-chip-unverified in bannerCSS. The same
// argument applies as for the wrapper and action buttons: Outlook
// desktop strips the chip-class rules, so the inline mirror is what
// keeps the chip rendering as a coloured pill instead of plain text.
func TestBannerRendererInlineChipStyle(t *testing.T) {
	r := mustRenderer(t)
	cases := []struct {
		name string
		verd AuthVerdict
		want string
	}{
		{"verified -> green", AuthVerified, "background:#08642f"},
		{"failed -> red", AuthFailed, "background:#9b0019"},
		{"unverified -> gray", AuthUnverified, "background:#595959"},
		// AuthUnknown maps to the same neutral gray as Unverified.
		// The chip class (sn360-chip-unknown) and inline style must
		// agree so the modern-CSS and Outlook-desktop paths render
		// the chip identically. See chipClassFor + bannerCSS.
		{"unknown -> gray", AuthUnknown, "background:#595959"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			html, err := r.Render(BannerInput{
				Tier:        constant.TierCaution,
				Primary:     constant.CategoryFirstContactExternal,
				Locale:      "en",
				SenderAuth:  tc.verd,
				ActionToken: "tok",
			})
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if !strings.Contains(string(html), tc.want) {
				t.Errorf("missing inline chip style %q for verdict=%s\n%s", tc.want, tc.verd, html)
			}
		})
	}
}

// TestBannerRendererAuthUnknownChipClassIsConsistent locks in that the
// chip class for AuthUnknown is sn360-chip-unknown — matching a real
// CSS rule in bannerCSS — rather than the bare sn360-chip class (which
// has no background rule and would render as white text on the banner
// background in modern clients while the inline-style mirror still
// emitted a gray background, creating a visual divergence between the
// two render paths).
func TestBannerRendererAuthUnknownChipClassIsConsistent(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:        constant.TierCaution,
		Primary:     constant.CategoryFirstContactExternal,
		Locale:      "en",
		SenderAuth:  AuthUnknown,
		ActionToken: "tok",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	if !strings.Contains(s, `class="sn360-chip sn360-chip-unknown"`) {
		t.Errorf("AuthUnknown chip should carry the sn360-chip-unknown CSS class so the modern-CSS path matches the inline-style mirror\n%s", s)
	}
	if !strings.Contains(s, ".sn360-chip-unknown{background:#595959}") {
		t.Errorf("bannerCSS must include the .sn360-chip-unknown rule so modern clients also paint the chip gray\n%s", s)
	}
}

// TestBannerRendererInlineRTLEndSide locks in that the icon margin,
// chip margin, and MSO-fallback <td> padding flip from the right side
// to the left side in RTL locales. Inline style attributes win over
// the .sn360-banner[dir="rtl"] CSS overrides, and Outlook desktop's
// Word HTML engine has no CSS-logical-property support — meaning the
// only way to express "end-side margin/padding" portably is to compute
// the physical side in Go. Without this, RTL deployments (Arabic,
// Hebrew, Farsi) would render the icon + chip + MSO-button gap on the
// wrong side in Outlook desktop while looking correct in every other
// client (because non-Outlook clients still get the CSS override).
//
// We assert the RTL output:
//   - contains margin-left:6px (for icon + chip)
//   - contains padding-left:8px (for MSO <td>)
//   - does NOT contain hardcoded margin-right:6px or padding-right:8px
//     in the inline-style attributes (the CSS string in <style> still
//     legitimately has margin-right rules for the LTR default — we
//     only check the inline-style attributes by anchoring on the
//     surrounding inline-only context).
func TestBannerRendererInlineRTLEndSide(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:        constant.TierWarning,
		Primary:     constant.CategoryLikelyPhishing,
		Locale:      "ar",
		SenderAuth:  AuthFailed,
		ActionToken: "tok",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	if !strings.Contains(s, `dir="rtl"`) {
		t.Fatalf("expected dir=rtl on root for ar locale\n%s", s)
	}
	// Icon inline style: must use margin-left.
	if !strings.Contains(s, `<span class="sn360-icon" aria-hidden="true" style="display:inline-block;margin-left:6px;`) {
		t.Errorf("RTL: icon inline style should use margin-left:6px instead of margin-right:6px\n%s", s)
	}
	// Chip inline style: must use margin-left after font-weight:700.
	if !strings.Contains(s, `font-weight:700;margin-left:6px;vertical-align:middle;`) {
		t.Errorf("RTL: chip inline style should use margin-left:6px instead of margin-right:6px\n%s", s)
	}
	// MSO fallback <td> elements: must use padding-left:8px instead of
	// padding-right:8px so the inter-button gap appears on the correct
	// side in Outlook desktop's Word engine (which has no CSS logical
	// property support and no [dir="rtl"] selector inheritance through
	// the conditional-comment fallback table).
	if !strings.Contains(s, `<td style="padding-left:8px">`) {
		t.Errorf("RTL: MSO fallback <td> should use padding-left:8px instead of padding-right:8px\n%s", s)
	}
	if strings.Contains(s, `<td style="padding-right:8px">`) {
		t.Errorf("RTL: stray padding-right:8px <td> attribute should not appear in RTL output\n%s", s)
	}
}

// TestBannerRendererInlineLTREndSide is the LTR counterpart to the
// RTL test above and exists so a future refactor cannot accidentally
// flip the LTR default by treating the RTL path as the only branch.
func TestBannerRendererInlineLTREndSide(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:        constant.TierWarning,
		Primary:     constant.CategoryLikelyPhishing,
		Locale:      "en",
		SenderAuth:  AuthFailed,
		ActionToken: "tok",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	if !strings.Contains(s, `dir="ltr"`) {
		t.Fatalf("expected dir=ltr on root for en locale\n%s", s)
	}
	if !strings.Contains(s, `<span class="sn360-icon" aria-hidden="true" style="display:inline-block;margin-right:6px;`) {
		t.Errorf("LTR: icon inline style should use margin-right:6px\n%s", s)
	}
	if !strings.Contains(s, `font-weight:700;margin-right:6px;vertical-align:middle;`) {
		t.Errorf("LTR: chip inline style should use margin-right:6px\n%s", s)
	}
	if !strings.Contains(s, `<td style="padding-right:8px">`) {
		t.Errorf("LTR: MSO fallback <td> should use padding-right:8px\n%s", s)
	}
}

// TestBannerRendererSuppressesEmptyActionContainers verifies that
// when no interactive CTAs are visible (no ActionToken supplied AND
// no MicroLessonURL), neither the modern <div class="sn360-actions">
// nor the MSO <table> fallback is emitted. Without this guard the
// banner would carry 8 + 8 = 16px of dead vertical space (one per
// path) — visually broken in clients that strip the comments and
// see both containers anyway, and wasteful even when only one
// container is rendered.
func TestBannerRendererSuppressesEmptyActionContainers(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:    constant.TierWarning,
		Primary: constant.CategoryLikelyPhishing,
		Locale:  "en",
		// No ActionToken, no MicroLessonURL — no CTAs are visible.
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	// Modern path: <div class="sn360-actions"> must not appear.
	if strings.Contains(s, `class="sn360-actions"`) {
		t.Errorf("modern .sn360-actions container should not render when no CTAs are visible\n%s", s)
	}
	// MSO path: <table role="presentation" ...> for the fallback
	// must not appear either (it is the only such table in the
	// template).
	if strings.Contains(s, `role="presentation"`) {
		t.Errorf("MSO fallback <table role=presentation> should not render when no CTAs are visible\n%s", s)
	}
}

// TestBannerRendererDarkModeRulesWinOverInlineStyles locks in the
// contract that the `@media (prefers-color-scheme:dark)` block in
// bannerCSS uses !important on every property so the dark-mode
// overrides win against the per-element inline `style="..."` mirror
// that exists for Outlook desktop compatibility.
//
// Why this matters: CSS specificity ordering puts inline `style="..."`
// above author stylesheet rules, EXCEPT when the stylesheet rule
// carries `!important`. The renderer emits inline tier colours (e.g.
// `background:#fce8e6` for Blocked) on the wrapper <div> so Outlook
// desktop — which strips the entire <style> block — still gets tier-
// themed banners. Without !important on the dark-mode rules, those
// same inline colours would lock in light-mode appearance even on
// clients that DO support the media query (Apple Mail, Thunderbird,
// Outlook iOS), defeating the dark-mode design entirely.
//
// The test does NOT verify that the dark-mode override actually
// renders correctly (that requires a browser); it verifies the CSS
// source contract that future edits cannot accidentally remove.
func TestBannerRendererDarkModeRulesWinOverInlineStyles(t *testing.T) {
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:    constant.TierBlocked,
		Primary: constant.CategoryLikelyPhishing,
		Locale:  "en",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	// Every property inside the dark-mode block must carry
	// !important. We assert the exact pattern that appears in the
	// constant so a future edit that removes the marker (e.g. by
	// dropping !important on background:#1a1a1a) breaks the test.
	for _, want := range []string{
		// Wrapper light-text + dark-bg override on .sn360-banner.
		"color:#f5f5f5!important",
		"background:#1a1a1a!important",
		// Secondary text override (covers .sn360-secondary,
		// .sn360-reasons, and .sn360-degraded — all three share
		// the same selector group).
		"color:#cfcfcf!important",
		// The selector group itself must include all three
		// descendant selectors, otherwise .sn360-degraded would
		// still inherit the inline #3a3a3a colour.
		".sn360-banner .sn360-secondary,.sn360-banner .sn360-reasons,.sn360-banner .sn360-degraded",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("dark-mode @media block missing required marker %q — inline styles will lock the banner to light mode\n%s", want, s)
		}
	}
	// Defensive: the @media block itself must still be present —
	// catches a refactor that accidentally drops the wrapper.
	if !strings.Contains(s, "@media (prefers-color-scheme:dark)") {
		t.Errorf("@media (prefers-color-scheme:dark) block missing entirely from bannerCSS")
	}
}

// TestBannerRendererMSOCommentsUseNamedHelpers verifies that the four
// Microsoft Outlook conditional-comment delimiters are emitted via
// the dedicated no-arg FuncMap helpers (msoIfStart / msoIfEnd /
// msoIfNotStart / msoIfNotEnd) rather than the older generic
// `safeHTML(string) template.HTML` function.
//
// The two paths are observationally identical in HTML output — both
// emit the same four byte sequences — so the test instead asserts
// the renderer-source contract by checking that the FuncMap entries
// exist and that the package-level template.HTML constants carry the
// exact expected byte sequences. This protects against:
//
//  1. A future edit that re-introduces a generic safeHTML helper
//     accepting arbitrary string input, which would re-widen the XSS
//     blast radius.
//  2. A future edit that changes one of the four comment delimiters
//     to a non-MSO sequence (e.g. dropping the `<!--` or `-->`),
//     which would cause Outlook desktop to either render the entire
//     fallback table as a literal HTML comment OR to render BOTH the
//     modern and MSO action containers, doubling up the buttons.
func TestBannerRendererMSOCommentsUseNamedHelpers(t *testing.T) {
	// Contract 1: the four hardcoded constants carry the exact
	// expected byte sequences. The Outlook Word HTML engine is
	// strict about these — any whitespace or character variation
	// causes the conditional to fail open.
	cases := []struct {
		name string
		got  template.HTML
		want string
	}{
		{"msoIfStartHTML", msoIfStartHTML, "<!--[if mso]>"},
		{"msoIfEndHTML", msoIfEndHTML, "<![endif]-->"},
		{"msoIfNotStartHTML", msoIfNotStartHTML, "<!--[if !mso]><!-->"},
		{"msoIfNotEndHTML", msoIfNotEndHTML, "<!--<![endif]-->"},
	}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}

	// Contract 2: the renderer must actually emit all four
	// sequences in the output. This is also covered by
	// TestBannerRendererEmitsMSOConditionalFallback but is asserted
	// here too so a future regression of the named-helper FuncMap
	// wiring fails this test specifically (clearer signal than a
	// generic fallback-missing failure).
	r := mustRenderer(t)
	html, err := r.Render(BannerInput{
		Tier:        constant.TierWarning,
		Primary:     constant.CategoryLookalikeDomain,
		Locale:      "en",
		ActionToken: "tok",
		SenderAuth:  AuthFailed,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	for _, c := range cases {
		if !strings.Contains(s, string(c.got)) {
			t.Errorf("rendered banner missing MSO delimiter %s (%q)", c.name, c.got)
		}
	}

	// Contract 3: the legacy `safeHTML` and `safeCSS` FuncMap
	// entries must NOT exist any more. We probe by parsing a tiny
	// template against the REAL renderer's *template.Template (not a
	// mirrored FuncMap), because template.Template.New() inherits
	// the FuncMap of its parent. If either `safeHTML` or `safeCSS`
	// is re-introduced to NewBannerRenderer's FuncMap in the future,
	// the corresponding probe will succeed and this test will fail.
	//
	// Inline CSS in bannerView is now expressed via template.CSS
	// typed fields (WrapperStyle, ButtonStyle, ButtonStyleMSO,
	// ChipStyle, IconChipEnd, MSOButtonGap), so neither `safeHTML`
	// nor `safeCSS` is needed any more. The type system is the trust
	// boundary, not a FuncMap helper.
	for _, badFn := range []string{
		"{{ safeHTML \"x\" }}",
		"{{ safeCSS \"x\" }}",
	} {
		if _, err := r.tmpl.New("probe").Parse(badFn); err == nil {
			t.Errorf("renderer FuncMap should NOT contain a generic trust-bypass helper, but parsing %q succeeded — a future edit re-introduced the helper", badFn)
		}
	}
}

// TestBannerRendererInlineMirrorMatchesCSS locks in the contract that
// the per-tier colours emitted as inline style attributes (via the
// `tierColorsFor` lookup table) are an exact mirror of the same
// colours used in the `bannerCSS` constant. The Outlook-desktop
// rendering path depends on inline styles because the Word HTML
// engine strips the embedded <style> block; modern clients depend on
// the <style> block because they render off classes alone. If the
// two sources of truth drift apart, modern clients and Outlook
// desktop will show different tier colours — a visual divergence
// that's hard to catch without per-client visual-regression testing.
//
// This test enumerates every concrete tier and asserts that each of
// its `tierColors` hex values appears somewhere in bannerCSS. It does
// NOT assert the exact CSS rule shape (selector + property), because
// future refactors may legitimately reorganise the CSS — it only
// asserts that the same hex literal exists in both places. That's the
// minimal contract: if you change a colour in `tierColorsFor` without
// also updating bannerCSS (or vice versa), this test fails.
func TestBannerRendererInlineMirrorMatchesCSS(t *testing.T) {
	cases := []struct {
		name string
		tier constant.Tier
	}{
		{"blocked", constant.TierBlocked},
		{"high risk", constant.TierHighRisk},
		{"warning", constant.TierWarning},
		{"caution", constant.TierCaution},
		{"informational", constant.TierInformational},
		{"trusted", constant.TierTrusted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tierColorsFor(tc.tier)
			// Background, Border, Text, and Button must all appear
			// verbatim in bannerCSS. The CSS rules are:
			//   .sn360-{tier}{background:Background;border-color:Border;color:Text}
			//   .sn360-{tier} .sn360-actions a{background:Button}
			// If any of these hex values is missing from bannerCSS,
			// the inline-style mirror has drifted from the CSS rule
			// and modern clients will render a different colour from
			// Outlook desktop for that tier.
			//
			// ButtonText is intentionally omitted from this check
			// because it is invariant across every tier
			// (`tierColorsFor(*).ButtonText == "#ffffff"`) and the
			// CSS rule expresses it as `#fff` (3-digit shorthand) on
			// the shared `.sn360-banner .sn360-actions a{color:#fff}`
			// selector — so a byte-equal match would always fail
			// even though the two are semantically identical. Drift
			// risk on a constant white text colour is negligible.
			for _, want := range []string{c.Background, c.Border, c.Text, c.Button} {
				if !strings.Contains(bannerCSS, want) {
					t.Errorf("tier=%s: bannerCSS missing colour %q from tierColorsFor() — inline-style mirror and CSS rule have drifted; modern clients will paint this tier differently from Outlook desktop", tc.tier, want)
				}
			}
		})
	}

	// The chip colours (.sn360-chip-verified / -failed / -unverified
	// / -unknown) also have an inline mirror in chipInlineStyle. Lock
	// the same contract: every chip-colour hex used by
	// chipInlineStyle must appear in bannerCSS.
	chipCases := []struct {
		name string
		v    AuthVerdict
	}{
		{"verified", AuthVerified},
		{"failed", AuthFailed},
		{"unverified", AuthUnverified},
		{"unknown", AuthUnknown},
	}
	for _, cc := range chipCases {
		t.Run("chip_"+cc.name, func(t *testing.T) {
			inline := string(chipInlineStyle(cc.v))
			// chipInlineStyle always returns "background:#XXXXXX;color:#YYYYYY".
			// Extract the hex literals (one for background, one for
			// color) and assert each is present in bannerCSS.
			//
			// `#ffffff` is filtered out for the same reason ButtonText
			// is filtered out above: every chip uses white text and
			// the CSS expresses it as `#fff` (3-digit shorthand) on
			// the shared `.sn360-banner .sn360-chip{color:#fff}`
			// selector. A byte-equal contains check would always
			// fail on the constant white text colour.
			for _, want := range hexLiteralsIn(inline) {
				if want == "#ffffff" {
					continue
				}
				if !strings.Contains(bannerCSS, want) {
					t.Errorf("chip verdict=%s: bannerCSS missing colour %q from chipInlineStyle() — modern-CSS chip will paint differently from Outlook desktop inline chip", cc.v, want)
				}
			}
		})
	}
}

// hexLiteralsIn extracts CSS hex colour literals (#rrggbb form) from
// an inline-style declaration string. Used by
// TestBannerRendererInlineMirrorMatchesCSS to assert that every hex
// emitted by chipInlineStyle also exists in bannerCSS without having
// to hardcode the chip palette in two places.
func hexLiteralsIn(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if s[i] != '#' {
			continue
		}
		// A CSS hex literal is # followed by exactly 6 hex digits
		// in our renderer (we don't use 3-digit shorthand or 8-digit
		// alpha form). Anything shorter or longer is not a valid
		// banner palette literal and we skip it.
		if i+7 > len(s) {
			continue
		}
		hex := s[i : i+7]
		ok := true
		for _, c := range hex[1:] {
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, hex)
			i += 6
		}
	}
	return out
}
