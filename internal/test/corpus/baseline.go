package corpus

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
)

// DefaultRegressionTolerance is the per-label F1 drop the CI gate
// treats as a regression. A 5-point drop on a 200-fixture corpus
// corresponds to ~10 newly-misclassified fixtures for a label with
// 50 support — well outside the noise floor a deterministic
// synthetic generator can produce without an actual change to the
// evaluator.
const DefaultRegressionTolerance = 0.05

// Regression carries one entry per label whose F1 regressed by more
// than the tolerance compared to the baseline.
type Regression struct {
	Label        Label   `json:"label"`
	BaselineF1   float64 `json:"baseline_f1"`
	CurrentF1    float64 `json:"current_f1"`
	Delta        float64 `json:"delta"`
	Catastrophic bool    `json:"catastrophic"`
}

// CompareToBaseline diffs a current Report against a baseline Report.
// Returns the list of label-level regressions exceeding tolerance.
// A regression is marked catastrophic when the F1 dropped to 0
// (the corresponding label is completely missed) or the delta is
// > 0.25 (a >25-point drop is qualitatively different from a model
// drift); the harness treats catastrophic regressions as blocking
// even on PRs.
func CompareToBaseline(current, baseline Report, tolerance float64) []Regression {
	var out []Regression
	for _, l := range AllLabels {
		base, ok := baseline.PerLabel[l]
		if !ok {
			continue
		}
		cur, ok := current.PerLabel[l]
		if !ok {
			continue
		}
		delta := base.F1 - cur.F1
		if delta <= tolerance+1e-9 {
			continue
		}
		out = append(out, Regression{
			Label:        l,
			BaselineF1:   base.F1,
			CurrentF1:    cur.F1,
			Delta:        delta,
			Catastrophic: math.Abs(cur.F1) < 1e-9 || delta > 0.25,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Label < out[j].Label
	})
	return out
}

// WriteJSON serialises a Report to w with stable formatting (2-space
// indent, sorted keys). The output is byte-deterministic for a given
// Report, so two harness runs against the same corpus + evaluator
// produce identical baseline files.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}

// WriteFile is the file-backed form of WriteJSON. The parent
// directory is NOT created automatically — callers must mkdir first
// — so the caller can decide whether the report belongs in a
// gitignored reports/ directory or in the committed baseline path.
func WriteFile(path string, r Report) error {
	f, err := os.Create(path) // #nosec G304 -- caller-controlled report path
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return WriteJSON(f, r)
}

// LoadReport parses a JSON report previously written by WriteFile.
// Used by the CI gate to compare against the committed baseline.
func LoadReport(path string) (Report, error) {
	f, err := os.Open(path) // #nosec G304 -- caller-controlled report path
	if err != nil {
		return Report{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	var r Report
	if err := json.NewDecoder(f).Decode(&r); err != nil {
		return Report{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return r, nil
}
