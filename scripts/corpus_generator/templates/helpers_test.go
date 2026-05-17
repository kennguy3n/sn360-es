package templates

import (
	"math/rand"
	"strings"
	"testing"
)

// TestLookalikeDomainNeverReturnsOriginal fuzzes lookalikeDomain
// against a representative set of vendor and tenant domains and
// asserts the function never returns a string equal to the
// lower-cased input. Previously the function would silently return
// the original domain whenever the randomly-chosen character swap
// was a no-op (e.g. swapping "m"→"rn" on "apple.com") AND the
// randomly-chosen TLD happened to also be ".com", which silently
// invalidated ~8-12% of "lookalike" test emails.
func TestLookalikeDomainNeverReturnsOriginal(t *testing.T) {
	targets := []string{
		// .com vendors with at least one swap target letter.
		"alpha-supply.com", "beta-logistics.com", "gamma-print.com",
		"dropbox.com", "paypal.com", "apple.com", "google.com",
		// Non-.com domains where TrimSuffix is a no-op.
		"acme.example", "tenant.local", "vendor.io", "supplier.co",
		// Worst case: short domain with NONE of o/l/m so every char
		// swap is a no-op and the function MUST hit the suffix
		// fallback to differ from the input.
		"acme", "ace", "xyz",
	}

	const iterationsPerTarget = 5000
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			r := rand.New(rand.NewSource(1))
			lower := strings.ToLower(target)
			for i := 0; i < iterationsPerTarget; i++ {
				got := lookalikeDomain(r, target)
				if got == lower {
					t.Fatalf("lookalikeDomain(%q) returned the original domain unchanged on iter %d", target, i)
				}
				if got == "" {
					t.Fatalf("lookalikeDomain(%q) returned empty string on iter %d", target, i)
				}
			}
		})
	}
}

// TestLookalikeDomainStability ensures lookalikeDomain is deterministic
// for a given seed: two seeded RNGs starting from the same value must
// produce the same sequence of outputs. The generator's caller relies
// on this so that `--seed 42` re-runs produce byte-identical corpora.
func TestLookalikeDomainStability(t *testing.T) {
	const seed = 42
	const target = "alpha-supply.com"
	const iterations = 500

	r1 := rand.New(rand.NewSource(seed))
	r2 := rand.New(rand.NewSource(seed))
	for i := 0; i < iterations; i++ {
		a := lookalikeDomain(r1, target)
		b := lookalikeDomain(r2, target)
		if a != b {
			t.Fatalf("lookalikeDomain non-deterministic on iter %d: %q vs %q", i, a, b)
		}
	}
}
