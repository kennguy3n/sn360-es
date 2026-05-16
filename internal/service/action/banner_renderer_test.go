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
