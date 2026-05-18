package evaluate

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

func TestScoreClampsAndAggregates(t *testing.T) {
	cases := []struct {
		name string
		comp Components
		w    Weights
		want int
	}{
		{"defaults_ai_heavy", Components{AI: 80, Rspamd: 10}, DefaultWeights(), 49},
		{"defaults_pure_ai", Components{AI: 50}, DefaultWeights(), 30},
		{"defaults_pure_rspamd", Components{Rspamd: 60}, DefaultWeights(), 6},
		{"clamp_high", Components{AI: 200}, Weights{AI: 1}, 100},
		{"clamp_low", Components{AI: -10}, Weights{AI: 1}, 0},
		{"zero_weights_returns_ai", Components{AI: 73}, Weights{}, 73},
		{"all_weights_equal", Components{AI: 40, Rspamd: 40, Attachments: 40, Links: 40}, Weights{AI: 1, Rspamd: 1, Attachments: 1, Links: 1}, 40},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Score(tc.comp, tc.w)
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestFromResultPicksMaxAI(t *testing.T) {
	r := &dto.EvaluateResult{
		Tier1:  &dto.Tier1Outcome{Score: 40},
		Tier2:  &dto.Tier2Outcome{Score: 75},
		Rspamd: &dto.RspamdOutcome{Score: 15, Threshold: 15},
	}
	c := FromResult(r)
	if c.AI != 75 {
		t.Errorf("AI = %d, want 75 (Tier2 max)", c.AI)
	}
	if c.Rspamd != 50 {
		t.Errorf("Rspamd normalised = %d, want 50 (threshold midpoint)", c.Rspamd)
	}
}

func TestFromResultNilSafe(t *testing.T) {
	c := FromResult(nil)
	if (c != Components{}) {
		t.Errorf("FromResult(nil) should be zero, got %+v", c)
	}
}

func TestFromResultIncludesLinkAndAttachment(t *testing.T) {
	linkScore := 80
	attachScore := 60
	r := &dto.EvaluateResult{
		Tier1:           &dto.Tier1Outcome{Score: 50},
		LinkScore:       &linkScore,
		AttachmentScore: &attachScore,
	}
	c := FromResult(r)
	if c.Links != 80 {
		t.Errorf("Links = %d, want 80", c.Links)
	}
	if c.Attachments != 60 {
		t.Errorf("Attachments = %d, want 60", c.Attachments)
	}
	if c.AI != 50 {
		t.Errorf("AI = %d, want 50", c.AI)
	}
}

func TestScoreWithLinkAndAttachment(t *testing.T) {
	comp := Components{AI: 60, Rspamd: 40, Links: 80, Attachments: 70}
	w := DefaultWeights()
	got := Score(comp, w)
	// Expected: (60*0.60 + 40*0.10 + 70*0.15 + 80*0.15) / 1.0
	// = 36 + 4 + 10.5 + 12 = 62.5 → 63
	if got != 63 {
		t.Errorf("got %d, want 63", got)
	}
}

func TestNormaliseRspamdBands(t *testing.T) {
	cases := []struct {
		score, threshold float64
		want             int
	}{
		{0, 15, 0},
		{15, 15, 50},
		{30, 15, 100},
		{45, 15, 100},
		{10, 15, 33},
		{5, 0, 17},
	}
	for _, tc := range cases {
		if got := normaliseRspamd(tc.score, tc.threshold); got != tc.want {
			t.Errorf("normaliseRspamd(%v, %v) = %d, want %d", tc.score, tc.threshold, got, tc.want)
		}
	}
}

func TestSortedReasonCodesDeterministic(t *testing.T) {
	in := []string{"c", "a", "b"}
	got := SortedReasonCodes(in)
	if got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("not sorted: %v", got)
	}
	if in[0] != "c" {
		t.Error("input should not be mutated")
	}
}
