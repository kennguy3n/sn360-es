package corpus

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestSynthetic_GeneratorIsDeterministic pins the contract WS-4b
// requires: same seed + same size → byte-identical corpus. A
// regression here breaks every committed baseline downstream, so
// the test is the canary for accidental changes to the template
// list, RNG draw order, or fixture-ID format.
func TestSynthetic_GeneratorIsDeterministic(t *testing.T) {
	a := GenerateSyntheticN(DefaultSyntheticSeed, 40)
	b := GenerateSyntheticN(DefaultSyntheticSeed, 40)
	if len(a) != len(b) {
		t.Fatalf("expected same length, got %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("id mismatch at %d: %s vs %s", i, a[i].ID, b[i].ID)
		}
		if a[i].RFC822 != b[i].RFC822 {
			t.Errorf("rfc822 mismatch at %d (%s)", i, a[i].ID)
		}
	}
}

func TestSynthetic_HasFiftyPerLabel(t *testing.T) {
	fx := GenerateSyntheticN(DefaultSyntheticSeed, DefaultSyntheticSize)
	if len(fx) != DefaultSyntheticSize {
		t.Fatalf("expected %d fixtures, got %d", DefaultSyntheticSize, len(fx))
	}
	counts := map[Label]int{}
	for _, f := range fx {
		counts[f.Label]++
	}
	for _, l := range AllLabels {
		if counts[l] != 50 {
			t.Errorf("label %s: expected 50 fixtures, got %d", l, counts[l])
		}
	}
}

func TestSynthetic_EveryFixtureCarriesSyntheticMarker(t *testing.T) {
	fx := GenerateSyntheticN(DefaultSyntheticSeed, DefaultSyntheticSize)
	for _, f := range fx {
		src := f.Metadata["source"]
		if !strings.HasPrefix(src, "ws4b-synthetic-") {
			t.Errorf("%s: expected synthetic source marker, got %q", f.ID, src)
		}
	}
}

func TestSynthetic_WriteJSONLProducesValidLines(t *testing.T) {
	fx := GenerateSyntheticN(DefaultSyntheticSeed, 8)
	var buf bytes.Buffer
	if err := WriteJSONL(&buf, fx); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}
	// Drop comment / blank lines, JSON-decode each fixture line.
	lineNum := 0
	for _, line := range strings.Split(buf.String(), "\n") {
		ln := strings.TrimSpace(line)
		if ln == "" || strings.HasPrefix(ln, "//") {
			continue
		}
		var got Fixture
		if err := json.Unmarshal([]byte(ln), &got); err != nil {
			t.Errorf("line %d (%q): %v", lineNum, ln, err)
		}
		lineNum++
	}
	if lineNum != len(fx) {
		t.Errorf("expected %d JSON lines, decoded %d", len(fx), lineNum)
	}
}

func TestSynthetic_FixtureValidatePasses(t *testing.T) {
	for _, f := range GenerateSyntheticN(DefaultSyntheticSeed, DefaultSyntheticSize) {
		if err := f.Validate(); err != nil {
			t.Errorf("synthetic fixture %s failed Validate: %v", f.ID, err)
		}
	}
}

func TestSynthetic_BuildRequestRoundTripsEveryFixture(t *testing.T) {
	for _, f := range GenerateSyntheticN(DefaultSyntheticSeed, DefaultSyntheticSize) {
		req, err := BuildRequest(t.Context(), f, BuildOpts{})
		if err != nil {
			t.Errorf("BuildRequest %s: %v", f.ID, err)
			continue
		}
		if req.Subject == "" {
			t.Errorf("%s: empty subject", f.ID)
		}
		if req.Body == "" {
			t.Errorf("%s: empty body", f.ID)
		}
	}
}
