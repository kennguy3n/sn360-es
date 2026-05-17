package translation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestLoadEmbeddedBanners(t *testing.T) {
	c, err := LoadEmbeddedBanners()
	if err != nil {
		t.Fatalf("LoadEmbeddedBanners: %v", err)
	}
	got := c.Locales()
	want := []string{"en", "ja", "ko", "th", "vi", "zh"}
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("locales mismatch: got=%v want=%v", got, want)
	}
}

func TestTranslate_PrimarySubtagFallback(t *testing.T) {
	c, err := LoadEmbeddedBanners()
	if err != nil {
		t.Fatalf("LoadEmbeddedBanners: %v", err)
	}
	en := c.T("en", "tier.Warning.title")
	if en == "tier.Warning.title" {
		t.Fatalf("en lookup returned key: %q", en)
	}
	// zh-Hant should fall back to zh, which is loaded.
	val := c.T("zh-Hant", "tier.Warning.title")
	if val == "tier.Warning.title" {
		t.Fatalf("zh-Hant fallback missing: %q", val)
	}
}

func TestTranslate_DefaultLocaleFallback(t *testing.T) {
	c, err := LoadEmbeddedBanners()
	if err != nil {
		t.Fatal(err)
	}
	val, ok := c.Translate("ja", "tier.Blocked.title")
	if val == "tier.Blocked.title" || !ok {
		t.Fatalf("expected ja translation, got %q (ok=%v)", val, ok)
	}
	// Unknown locale -> en fallback.
	val, ok = c.Translate("xx", "tier.Blocked.title")
	if ok {
		t.Fatal("expected ok=false for fallback")
	}
	if val == "tier.Blocked.title" {
		t.Fatalf("expected en fallback value, got key: %q", val)
	}
}

func TestTranslate_UnknownKeyReturnsKey(t *testing.T) {
	c, err := LoadEmbeddedBanners()
	if err != nil {
		t.Fatal(err)
	}
	val, ok := c.Translate("en", "does.not.exist")
	if val != "does.not.exist" || ok {
		t.Fatalf("expected key passthrough, got %q ok=%v", val, ok)
	}
}

func TestLoadFromDir_RejectsMissingDefault(t *testing.T) {
	dir := t.TempDir()
	bundle := map[string]string{"k": "v"}
	data, _ := json.Marshal(bundle)
	if err := os.WriteFile(filepath.Join(dir, "ja.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.LoadFromDir(dir); err == nil {
		t.Fatal("expected error when default locale missing")
	}
}

func TestLoadFromDir_LoadsValidBundles(t *testing.T) {
	dir := t.TempDir()
	en := map[string]string{"hello": "Hello"}
	jp := map[string]string{"hello": "こんにちは"}
	for code, b := range map[string]map[string]string{"en": en, "ja": jp} {
		data, _ := json.Marshal(b)
		if err := os.WriteFile(filepath.Join(dir, code+".json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c := New()
	if err := c.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	if got := c.T("ja", "hello"); got != "こんにちは" {
		t.Fatalf("ja lookup: %q", got)
	}
	if !c.Has("ja", "hello") || c.Has("ja", "missing") {
		t.Fatal("Has() reports wrong state")
	}
}
