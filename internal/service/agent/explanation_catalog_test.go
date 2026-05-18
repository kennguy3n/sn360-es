package agent

import (
	"sort"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

var allExplanationLocales = []string{"en", "vi", "th", "ja", "ko", "zh", "de", "fr", "it", "ar", "fil", "ms"}

func TestExplanationCatalog_LoadsAllLocales(t *testing.T) {
	cat, err := DefaultExplanationCatalog()
	if err != nil {
		t.Fatalf("DefaultExplanationCatalog: %v", err)
	}
	locales := cat.Locales()
	sort.Strings(locales)
	for _, want := range allExplanationLocales {
		found := false
		for _, got := range locales {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing locale %q in catalog (have: %v)", want, locales)
		}
	}
}

func TestExplanationCatalog_AllTiersPresent(t *testing.T) {
	cat, err := DefaultExplanationCatalog()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, locale := range allExplanationLocales {
		t.Run(locale, func(t *testing.T) {
			for _, tier := range constant.AllTiers {
				exp := cat.TierExplanation(tier, locale)
				if exp == "" {
					t.Errorf("locale %q tier %q: empty explanation", locale, tier)
				}
				sug := cat.TierSuggestion(tier, locale)
				if sug == "" {
					t.Errorf("locale %q tier %q: empty suggestion", locale, tier)
				}
			}
		})
	}
}

func TestExplanationCatalog_AllCategoryNamesPresent(t *testing.T) {
	cat, err := DefaultExplanationCatalog()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, locale := range allExplanationLocales {
		t.Run(locale, func(t *testing.T) {
			for _, c := range constant.AllCategories {
				name := cat.CategoryName(c, locale)
				if name == "" || name == string(c) {
					t.Errorf("locale %q category %q: untranslated or empty name %q", locale, c, name)
				}
			}
		})
	}
}

func TestExplanationCatalog_FallbackToEnglish(t *testing.T) {
	cat, err := DefaultExplanationCatalog()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Unknown locale should return English text.
	exp := cat.TierExplanation(constant.TierBlocked, "xx-unknown")
	enExp := cat.TierExplanation(constant.TierBlocked, "en")
	if exp != enExp {
		t.Errorf("expected fallback to en, got %q vs %q", exp, enExp)
	}
}

func TestExplanationCatalog_LocaleSpecificText(t *testing.T) {
	cat, err := DefaultExplanationCatalog()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	enText := cat.TierExplanation(constant.TierBlocked, "en")
	deText := cat.TierExplanation(constant.TierBlocked, "de")
	if enText == deText {
		t.Error("de and en should have different Blocked explanations")
	}
	viText := cat.TierExplanation(constant.TierBlocked, "vi")
	if enText == viText {
		t.Error("vi and en should have different Blocked explanations")
	}
}

func TestExplanationCatalog_HelperMethods(t *testing.T) {
	cat, err := DefaultExplanationCatalog()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, locale := range allExplanationLocales {
		if s := cat.PrimarySignalLabel(locale); s == "" {
			t.Errorf("locale %q: empty PrimarySignalLabel", locale)
		}
		if s := cat.ContributingFactorsLabel(locale); s == "" {
			t.Errorf("locale %q: empty ContributingFactorsLabel", locale)
		}
		if s := cat.DegradedNotice(locale); s == "" {
			t.Errorf("locale %q: empty DegradedNotice", locale)
		}
		if s := cat.VerdictPending(locale); s == "" {
			t.Errorf("locale %q: empty VerdictPending", locale)
		}
		if s := cat.EscalatedSuggestion(locale); s == "" {
			t.Errorf("locale %q: empty EscalatedSuggestion", locale)
		}
		if s := cat.ReleaseSuggestion(locale); s == "" {
			t.Errorf("locale %q: empty ReleaseSuggestion", locale)
		}
	}
}

func TestExplainVerdict_UsesLocale(t *testing.T) {
	cat, err := DefaultExplanationCatalog()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	en := ExplainVerdictWith(cat, sampleVerdict(), "en")
	de := ExplainVerdictWith(cat, sampleVerdict(), "de")
	if en == de {
		t.Error("en and de verdicts should differ")
	}
	if en == "" || de == "" {
		t.Error("verdicts should not be empty")
	}
}

func TestDefaultSuggestionLocale_UsesLocale(t *testing.T) {
	en := DefaultSuggestionLocale(constant.TierBlocked, "en")
	de := DefaultSuggestionLocale(constant.TierBlocked, "de")
	if en == de {
		t.Error("en and de suggestions should differ")
	}
}

func sampleVerdict() dto.EvaluateResult {
	return dto.EvaluateResult{
		Tier:        constant.TierBlocked,
		Primary:     constant.CategoryLikelyPhishing,
		ReasonCodes: []string{"lookalike-domain"},
		Degraded:    true,
	}
}
