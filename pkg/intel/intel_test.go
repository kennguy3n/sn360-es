package intel

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestCanonicalise_DomainNormalises(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
	}{
		{"trailing dot", "Example.COM."},
		{"www prefix", "www.example.com"},
		{"mixed case", "ExAmPlE.com"},
		{"whitespace", "  example.com  "},
	}
	want := sha256.Sum256([]byte("example.com"))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Canonicalise(Indicator{Indicator: tc.in, Type: IndicatorDomain})
			if err != nil {
				t.Fatalf("Canonicalise(%q): %v", tc.in, err)
			}
			if got.Indicator != "example.com" {
				t.Errorf("canonical = %q; want example.com", got.Indicator)
			}
			if string(got.Hash) != string(want[:]) {
				t.Errorf("hash mismatch")
			}
		})
	}
}

func TestCanonicalise_IDN(t *testing.T) {
	t.Parallel()
	// "münchen.de" → "xn--mnchen-3ya.de"
	got, err := Canonicalise(Indicator{Indicator: "münchen.de", Type: IndicatorDomain})
	if err != nil {
		t.Fatalf("Canonicalise: %v", err)
	}
	if got.Indicator != "xn--mnchen-3ya.de" {
		t.Errorf("idn canonical = %q; want xn--mnchen-3ya.de", got.Indicator)
	}
}

func TestCanonicalise_URLDropsFragment(t *testing.T) {
	t.Parallel()
	got, err := Canonicalise(Indicator{
		Indicator: "HTTPS://Example.COM:443/foo?x=1#abc",
		Type:      IndicatorURL,
	})
	if err != nil {
		t.Fatalf("Canonicalise: %v", err)
	}
	if got.Indicator != "https://example.com/foo?x=1" {
		t.Errorf("canonical = %q; want https://example.com/foo?x=1", got.Indicator)
	}
}

func TestCanonicalise_URLBareHostTrailingSlash(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"http://example.com", "http://example.com"},
		{"http://example.com/", "http://example.com"},
		{"http://example.com/foo", "http://example.com/foo"},
	}
	for _, tc := range cases {
		got, err := Canonicalise(Indicator{Indicator: tc.in, Type: IndicatorURL})
		if err != nil {
			t.Fatalf("Canonicalise(%q): %v", tc.in, err)
		}
		if got.Indicator != tc.want {
			t.Errorf("%q → %q; want %q", tc.in, got.Indicator, tc.want)
		}
	}
}

func TestCanonicalise_SHA256(t *testing.T) {
	t.Parallel()
	good := strings.Repeat("A", 64)
	got, err := Canonicalise(Indicator{Indicator: good, Type: IndicatorSHA256})
	if err != nil {
		t.Fatalf("Canonicalise: %v", err)
	}
	if got.Indicator != strings.Repeat("a", 64) {
		t.Errorf("sha256 not lowercased: %q", got.Indicator)
	}

	bad := []string{"", "abc", strings.Repeat("z", 64), strings.Repeat("a", 63)}
	for _, b := range bad {
		_, err := Canonicalise(Indicator{Indicator: b, Type: IndicatorSHA256})
		if !errors.Is(err, ErrIndicatorMalformed) {
			t.Errorf("Canonicalise(sha256=%q) err = %v; want ErrIndicatorMalformed", b, err)
		}
	}
}

func TestCanonicalise_ClampSeverity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   int
		want int
	}{
		{-5, 0},
		{0, 0},
		{50, 50},
		{100, 100},
		{200, 100},
	}
	for _, tc := range cases {
		got, err := Canonicalise(Indicator{Indicator: "example.com", Type: IndicatorDomain, Severity: tc.in})
		if err != nil {
			t.Fatalf("Canonicalise: %v", err)
		}
		if got.Severity != tc.want {
			t.Errorf("Severity(%d) → %d; want %d", tc.in, got.Severity, tc.want)
		}
	}
}

func TestCanonicalise_DropEmptyAndDuplicateTags(t *testing.T) {
	t.Parallel()
	got, err := Canonicalise(Indicator{
		Indicator: "example.com",
		Type:      IndicatorDomain,
		Tags:      []string{"a", " ", "a", "b", ""},
	})
	if err != nil {
		t.Fatalf("Canonicalise: %v", err)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "a" || got.Tags[1] != "b" {
		t.Errorf("Tags = %v; want [a b]", got.Tags)
	}
}

func TestCanonicalise_RejectsUnknownType(t *testing.T) {
	t.Parallel()
	_, err := Canonicalise(Indicator{Indicator: "x", Type: IndicatorType("totally-bogus")})
	if err == nil {
		t.Fatalf("expected error for bogus type")
	}
}

func TestHashIndicator_MatchesCanonicalise(t *testing.T) {
	t.Parallel()
	h1, err := HashIndicator(IndicatorDomain, "WWW.Example.COM")
	if err != nil {
		t.Fatalf("HashIndicator: %v", err)
	}
	want, _ := Canonicalise(Indicator{Indicator: "example.com", Type: IndicatorDomain})
	if string(h1) != string(want.Hash) {
		t.Errorf("hash mismatch: HashIndicator and Canonicalise disagree")
	}
}

func TestRegistry_RegisterAndBuild(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	called := false
	err := r.Register("test", func(cfg FeedConfig) (Poller, error) {
		called = true
		return stubPoller{provider: "test"}, nil
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if dup := r.Register("test", func(FeedConfig) (Poller, error) { return nil, nil }); dup == nil {
		t.Errorf("expected dup error on second Register")
	}
	p, err := r.Build(FeedConfig{Provider: "test", URL: "https://x/"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !called {
		t.Error("constructor not called")
	}
	if p.Provider() != "test" {
		t.Errorf("provider = %q; want test", p.Provider())
	}
}

func TestRegistry_BuildUnknownProvider(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	_, err := r.Build(FeedConfig{Provider: "missing"})
	if !errors.Is(err, ErrUnknownProvider) {
		t.Errorf("err = %v; want ErrUnknownProvider", err)
	}
}

type stubPoller struct {
	provider string
}

func (s stubPoller) Provider() string                          { return s.provider }
func (s stubPoller) Poll(_ context.Context) (Result, error)    { return Result{}, nil }
