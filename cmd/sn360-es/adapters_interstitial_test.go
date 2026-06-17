package main

import (
	"context"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
	"github.com/kennguy3n/sn360-es/pkg/intel"
)

// TestInterstitialThreatIntel_CheckURL wires the adapter over a real
// in-memory intel store and asserts the block-decision logic:
// block/quarantine-tier matches (severity >= 50) block the click,
// flag-only matches (severity < 50) still redirect.
func TestInterstitialThreatIntel_CheckURL(t *testing.T) {
	ctx := context.Background()
	store := repository.NewMemoryIntelStore()
	feed, err := store.CreateFeed(ctx, intel.Feed{Name: "test-feed", Provider: "csv", URL: "http://feed.example", Enabled: true})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}
	seed := func(typ intel.IndicatorType, value string, severity int) {
		ind, cerr := intel.Canonicalise(intel.Indicator{Indicator: value, Type: typ, Severity: severity})
		if cerr != nil {
			t.Fatalf("Canonicalise %q: %v", value, cerr)
		}
		if _, uerr := store.UpsertIndicators(ctx, feed.ID, []intel.Indicator{ind}); uerr != nil {
			t.Fatalf("UpsertIndicators: %v", uerr)
		}
	}
	seed(intel.IndicatorURL, "http://phish.example/login", 90) // block tier
	seed(intel.IndicatorDomain, "suspicious.example", 60)      // quarantine tier
	seed(intel.IndicatorURL, "http://lowsev.example/x", 30)    // flag-only

	adapter := interstitialThreatIntel{checker: &tier0.StoreTIChecker{Store: store}}

	cases := []struct {
		name      string
		url       string
		wantSafe  bool
		reasonHas string
	}{
		{"phishing-blocked", "http://phish.example/login", false, "phishing"},
		{"suspicious-domain-blocked", "https://suspicious.example/anything", false, "suspicious"},
		{"low-severity-allowed", "http://lowsev.example/x", true, ""},
		{"clean-allowed", "https://good.example/", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			safe, reason := adapter.CheckURL(ctx, tc.url)
			if safe != tc.wantSafe {
				t.Fatalf("safe = %v, want %v (reason %q)", safe, tc.wantSafe, reason)
			}
			if tc.reasonHas != "" && !strings.Contains(strings.ToLower(reason), tc.reasonHas) {
				t.Errorf("reason %q does not contain %q", reason, tc.reasonHas)
			}
			if tc.wantSafe && reason != "" {
				t.Errorf("safe verdict must carry empty reason, got %q", reason)
			}
		})
	}
}

// TestInterstitialThreatIntel_FailOpen verifies the adapter allows the
// click when no checker is wired (dev configs without an intel store).
func TestInterstitialThreatIntel_FailOpen(t *testing.T) {
	var adapter interstitialThreatIntel // nil checker
	if safe, reason := adapter.CheckURL(context.Background(), "http://phish.example/login"); !safe || reason != "" {
		t.Fatalf("nil-checker should allow; got safe=%v reason=%q", safe, reason)
	}
}
