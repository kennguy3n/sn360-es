package action

import (
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

func TestSubjectTagger_DisabledByDefault(t *testing.T) {
	tagger, err := NewSubjectTagger(SubjectTagConfig{})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if tagger.Enabled() {
		t.Fatal("default config should be disabled")
	}
	got, added := tagger.Tag("Hello", constant.TierWarning)
	if added || got != "Hello" {
		t.Fatalf("disabled tagger must passthrough; got %q added=%v", got, added)
	}
}

func TestSubjectTagger_AppliesAtWarningAndAbove(t *testing.T) {
	tagger, err := NewSubjectTagger(SubjectTagConfig{Enabled: true})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	cases := []struct {
		tier   constant.Tier
		expect string
	}{
		{constant.TierWarning, "[SN360: WARN] Hello"},
		{constant.TierHighRisk, "[SN360: RISK] Hello"},
		{constant.TierBlocked, "[SN360: BLOCK] Hello"},
	}
	for _, tc := range cases {
		got, added := tagger.Tag("Hello", tc.tier)
		if !added {
			t.Errorf("%s: expected tag to be added", tc.tier)
		}
		if got != tc.expect {
			t.Errorf("%s: got %q want %q", tc.tier, got, tc.expect)
		}
	}
}

func TestSubjectTagger_BelowFloorPassthrough(t *testing.T) {
	tagger, _ := NewSubjectTagger(SubjectTagConfig{Enabled: true})
	below := []constant.Tier{
		constant.TierTrusted,
		constant.TierInformational,
		constant.TierCaution,
	}
	for _, tier := range below {
		got, added := tagger.Tag("Hello", tier)
		if added || got != "Hello" {
			t.Errorf("%s: expected passthrough, got %q added=%v", tier, got, added)
		}
	}
}

func TestSubjectTagger_Idempotent(t *testing.T) {
	tagger, _ := NewSubjectTagger(SubjectTagConfig{Enabled: true})
	first, added := tagger.Tag("Wire transfer ASAP", constant.TierHighRisk)
	if !added {
		t.Fatal("first call must add tag")
	}
	second, added := tagger.Tag(first, constant.TierHighRisk)
	if added {
		t.Fatal("second call must not add tag")
	}
	if second != first {
		t.Fatalf("tag must be idempotent:\nfirst=%q\nsecond=%q", first, second)
	}
}

func TestSubjectTagger_CustomPrefixAndLabels(t *testing.T) {
	tagger, err := NewSubjectTagger(SubjectTagConfig{
		Enabled: true,
		Prefix:  "ACME-SEC",
		Labels: map[constant.Tier]string{
			constant.TierWarning: "ALERT",
		},
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	got, added := tagger.Tag("RFP", constant.TierWarning)
	if !added || got != "[ACME-SEC: ALERT] RFP" {
		t.Fatalf("custom prefix/label not applied: %q (added=%v)", got, added)
	}
}

func TestSubjectTagger_HigherMinTier(t *testing.T) {
	tagger, _ := NewSubjectTagger(SubjectTagConfig{
		Enabled: true,
		MinTier: constant.TierBlocked,
	})
	if got, added := tagger.Tag("X", constant.TierWarning); added {
		t.Fatalf("warning below blocked floor must passthrough, got %q", got)
	}
	if got, added := tagger.Tag("X", constant.TierBlocked); !added || !strings.HasPrefix(got, "[SN360:") {
		t.Fatalf("blocked tier should be tagged, got %q added=%v", got, added)
	}
}

func TestSubjectTagger_EmptySubject(t *testing.T) {
	tagger, _ := NewSubjectTagger(SubjectTagConfig{Enabled: true})
	got, added := tagger.Tag("", constant.TierWarning)
	if !added || got != "[SN360: WARN] " {
		t.Fatalf("empty subject: got %q added=%v", got, added)
	}
}

func TestSubjectTagger_Untag(t *testing.T) {
	tagger, _ := NewSubjectTagger(SubjectTagConfig{Enabled: true})
	tagged, _ := tagger.Tag("Quarterly report", constant.TierWarning)
	clean, stripped := tagger.Untag(tagged)
	if !stripped || clean != "Quarterly report" {
		t.Fatalf("untag failed: got %q stripped=%v", clean, stripped)
	}
	// Untagged input is passed through.
	clean, stripped = tagger.Untag("Plain subject")
	if stripped || clean != "Plain subject" {
		t.Fatalf("untag of plain subject: got %q stripped=%v", clean, stripped)
	}
	// Malformed (missing closing bracket) is passed through.
	clean, stripped = tagger.Untag("[SN360: WARN missing close")
	if stripped {
		t.Fatalf("malformed tag should not be stripped: %q", clean)
	}
}

func TestSubjectTagger_InvalidTierPassthrough(t *testing.T) {
	tagger, _ := NewSubjectTagger(SubjectTagConfig{Enabled: true})
	got, added := tagger.Tag("Hi", constant.Tier("BOGUS"))
	if added || got != "Hi" {
		t.Fatalf("invalid tier must passthrough: got %q added=%v", got, added)
	}
}

func TestNewSubjectTagger_RejectsBadConfig(t *testing.T) {
	if _, err := NewSubjectTagger(SubjectTagConfig{MinTier: "GARBAGE"}); err == nil {
		t.Fatal("expected error for invalid min tier")
	}
	if _, err := NewSubjectTagger(SubjectTagConfig{
		Enabled: true,
		Labels: map[constant.Tier]string{
			constant.TierWarning: "   ",
		},
	}); err == nil {
		t.Fatal("expected error for whitespace label")
	}
	if _, err := NewSubjectTagger(SubjectTagConfig{
		Enabled: true,
		MinTier: constant.TierBlocked,
		Labels: map[constant.Tier]string{
			constant.TierWarning: "WARN",
		},
	}); err == nil {
		t.Fatal("expected error when no label is at or above min tier")
	}
}
