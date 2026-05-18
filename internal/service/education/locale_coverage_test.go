package education

import (
	"sort"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// allLocales is the full set of 12 supported locales.
var allLocales = []string{"en", "vi", "th", "ja", "ko", "zh", "de", "fr", "it", "ar", "fil", "ms"}

// TestLessonCatalog_AllLocalesAllCategories verifies every locale has
// lessons for all 16 threat categories.
func TestLessonCatalog_AllLocalesAllCategories(t *testing.T) {
	store, err := DefaultLessonStore()
	if err != nil {
		t.Fatalf("DefaultLessonStore: %v", err)
	}
	for _, locale := range allLocales {
		t.Run(locale, func(t *testing.T) {
			lessons, ok := store.Lookup(locale)
			if !ok {
				t.Fatalf("no lessons found for locale %q", locale)
			}
			for _, cat := range constant.AllCategories {
				if _, exists := lessons[cat]; !exists {
					t.Errorf("locale %q missing lesson for category %q", locale, cat)
				}
			}
		})
	}
}

// TestLessonCatalog_LessonFieldsNonEmpty verifies that every lesson has
// non-empty required fields.
func TestLessonCatalog_LessonFieldsNonEmpty(t *testing.T) {
	store, err := DefaultLessonStore()
	if err != nil {
		t.Fatalf("DefaultLessonStore: %v", err)
	}
	for _, locale := range allLocales {
		lessons, ok := store.Lookup(locale)
		if !ok {
			t.Errorf("locale %q: not found", locale)
			continue
		}
		for cat, lesson := range lessons {
			if lesson.LessonID == "" {
				t.Errorf("locale %q category %q: empty LessonID", locale, cat)
			}
			if lesson.Title == "" {
				t.Errorf("locale %q category %q: empty Title", locale, cat)
			}
			if lesson.BodyHTML == "" {
				t.Errorf("locale %q category %q: empty BodyHTML", locale, cat)
			}
			if lesson.EstimatedSeconds <= 0 {
				t.Errorf("locale %q category %q: EstimatedSeconds=%d", locale, cat, lesson.EstimatedSeconds)
			}
		}
	}
}

// TestTemplateLibrary_PerLocaleTemplatesExist verifies that the embedded
// template library contains templates for every supported locale.
func TestTemplateLibrary_PerLocaleTemplatesExist(t *testing.T) {
	lib, err := LoadDefaultTemplates()
	if err != nil {
		t.Fatalf("LoadDefaultTemplates: %v", err)
	}
	locales := lib.Locales()
	sort.Strings(locales)

	for _, locale := range allLocales {
		t.Run(locale, func(t *testing.T) {
			templates := lib.ListByLocale("", "", locale)
			if len(templates) == 0 {
				t.Fatalf("no templates found for locale %q", locale)
			}
			// Each locale should have at least one template.
			for _, tmpl := range templates {
				if tmpl.TemplateID == "" {
					t.Errorf("template with empty ID in locale %q", locale)
				}
				if tmpl.SubjectTemplate == "" {
					t.Errorf("template %q: empty subject", tmpl.TemplateID)
				}
				if tmpl.BodyTemplate == "" {
					t.Errorf("template %q: empty body", tmpl.TemplateID)
				}
			}
		})
	}
}

// TestTemplateLibrary_LocaleFallbackToEn verifies that requesting
// templates for an unknown locale falls back to "en" templates.
func TestTemplateLibrary_LocaleFallbackToEn(t *testing.T) {
	lib, err := LoadDefaultTemplates()
	if err != nil {
		t.Fatalf("LoadDefaultTemplates: %v", err)
	}
	enTemplates := lib.ListByLocale("", "", "en")
	unknownTemplates := lib.ListByLocale("", "", "xx-unknown")
	if len(unknownTemplates) == 0 {
		t.Fatal("expected fallback to en for unknown locale")
	}
	if len(unknownTemplates) != len(enTemplates) {
		t.Errorf("unknown locale got %d templates, en has %d", len(unknownTemplates), len(enTemplates))
	}
}

// TestTemplateLibrary_PickForLocale verifies locale-aware template picking.
func TestTemplateLibrary_PickForLocale(t *testing.T) {
	lib, err := LoadDefaultTemplates()
	if err != nil {
		t.Fatalf("LoadDefaultTemplates: %v", err)
	}
	// Pick from a known non-en locale.
	tmpl, ok := lib.PickForLocale(dto.AttackTypeBEC, dto.DifficultyEasy, "de")
	if !ok {
		t.Fatal("expected to pick a template for de/bec/easy")
	}
	if tmpl.Locale != "de" {
		t.Errorf("expected locale=de, got %q", tmpl.Locale)
	}
}

// TestTemplateLibrary_PickForLocale_Fallback verifies fallback when locale
// has no template for a specific attack/difficulty combo.
func TestTemplateLibrary_PickForLocale_Fallback(t *testing.T) {
	lib, err := LoadDefaultTemplates()
	if err != nil {
		t.Fatalf("LoadDefaultTemplates: %v", err)
	}
	// Use an attack type that likely only en has.
	enTemplates := lib.ListByLocale("", "", "en")
	if len(enTemplates) == 0 {
		t.Skip("no en templates found")
	}
	// Pick a combo from en that de might not have.
	for _, et := range enTemplates {
		deTemplates := lib.ListByLocale(et.AttackType, et.Difficulty, "de")
		if len(deTemplates) > 0 {
			continue
		}
		// This combo only exists in en; de should fallback.
		tmpl, ok := lib.PickForLocale(et.AttackType, et.Difficulty, "de")
		if !ok {
			t.Errorf("expected fallback to en for %s/%s when de has none", et.AttackType, et.Difficulty)
			continue
		}
		if tmpl.Locale != "en" {
			t.Errorf("expected fallback locale=en, got %q", tmpl.Locale)
		}
		return // One successful check is enough.
	}
}

// TestTemplateLibrary_RegisterWithLocale tests that registering a template
// with a locale field indexes it correctly.
func TestTemplateLibrary_RegisterWithLocale(t *testing.T) {
	lib := NewTemplateLibrary()
	err := lib.Register(dto.SimulationTemplate{
		TemplateID:            "test.bec.easy.de",
		AttackType:            dto.AttackTypeBEC,
		Difficulty:            dto.DifficultyEasy,
		Locale:                "de",
		SubjectTemplate:       "Dringende Überweisung",
		BodyTemplate:          "<p>Test</p>",
		SenderDisplayTemplate: "CEO",
		SenderDomainTemplate:  "example.com",
		LandingPageType:       "none",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Should be findable via ListByLocale.
	templates := lib.ListByLocale(dto.AttackTypeBEC, dto.DifficultyEasy, "de")
	if len(templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(templates))
	}
	if templates[0].Locale != "de" {
		t.Errorf("expected locale=de, got %q", templates[0].Locale)
	}
	// Should NOT be returned for "fr".
	frTemplates := lib.ListByLocale(dto.AttackTypeBEC, dto.DifficultyEasy, "fr")
	if len(frTemplates) != 0 {
		t.Errorf("expected 0 templates for fr, got %d", len(frTemplates))
	}
}
