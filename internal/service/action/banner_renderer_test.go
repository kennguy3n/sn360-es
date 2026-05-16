package action

import (
	"bytes"
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

func TestBannerRendererRequiresActionTokenForInteractiveTiers(t *testing.T) {
	r := mustRenderer(t)
	in := BannerInput{
		Tier:    constant.TierWarning,
		Primary: constant.CategoryLikelyPhishing,
		Locale:  "en",
		// No ActionToken — Warning tier exposes Mark Safe so this should fail.
	}
	if _, err := r.Render(in); err == nil {
		t.Fatal("expected error when token missing on interactive tier")
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
			"tier.HighRisk.title":              "خطر مرتفع",
			"tier.HighRisk.body":               "لا تتفاعل مع هذه الرسالة.",
			"category.BEC_IMPERSONATION":       "احتيال انتحال شخصية",
			"auth.failed":                      "فشل التحقق",
			"action.report":                    "إبلاغ",
			"action.mark_safe":                 "آمن",
			"action.trust_sender":              "ثقة",
			"action.learn_more":                "اعرف المزيد",
			"banner.degraded":                  "تدهور",
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
	cases := []string{"th", "ja", "ko", "zh"}
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
