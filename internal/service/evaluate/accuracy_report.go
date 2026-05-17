package evaluate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// ClassificationMetrics holds the per-class confusion totals plus the
// derived rates (precision, recall, F1, accuracy). Zero values are
// safe: rate accessors return 0 when no positive predictions or
// positive ground-truths have been recorded yet.
//
// Conventions:
//
//   - TP: predicted == class AND actual == class
//   - FP: predicted == class AND actual != class
//   - FN: predicted != class AND actual == class
//   - TN: predicted != class AND actual != class
//
// Precision = TP / (TP+FP), Recall = TP / (TP+FN),
// F1 = 2PR / (P+R), Accuracy = (TP+TN) / total.
type ClassificationMetrics struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	TN        int     `json:"tn"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	Accuracy  float64 `json:"accuracy"`
}

// Total returns the population this row of metrics was computed
// against. Useful for sanity checking that all per-class confusion
// rows agree on the corpus size.
func (m ClassificationMetrics) Total() int {
	return m.TP + m.FP + m.TN + m.FN
}

// Recompute rebuilds the derived rates from TP/FP/TN/FN. The
// AccuracyReport.Recompute method calls this for every cell so the
// accumulator path doesn't have to maintain rolling averages.
func (m *ClassificationMetrics) Recompute() {
	if m.TP+m.FP > 0 {
		m.Precision = float64(m.TP) / float64(m.TP+m.FP)
	} else {
		m.Precision = 0
	}
	if m.TP+m.FN > 0 {
		m.Recall = float64(m.TP) / float64(m.TP+m.FN)
	} else {
		m.Recall = 0
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	} else {
		m.F1 = 0
	}
	if total := m.Total(); total > 0 {
		m.Accuracy = float64(m.TP+m.TN) / float64(total)
	} else {
		m.Accuracy = 0
	}
}

// AccuracyReport is the structured output of the accuracy harness. It
// is intentionally serialisable to JSON so CI can post the report as a
// PR comment and dashboards can ingest the time-series.
type AccuracyReport struct {
	// Timestamp is the wall-clock time the report was produced.
	Timestamp time.Time `json:"timestamp"`
	// CorpusSize is the number of evaluations performed.
	CorpusSize int `json:"corpus_size"`
	// Seed is the corpus generator seed; pin so reruns are reproducible.
	Seed int64 `json:"seed"`

	// Overall is the micro-averaged confusion (sum of per-class TP/FP/…
	// across the whole corpus). Useful when comparing accuracy across
	// rebalancings of the corpus.
	Overall ClassificationMetrics `json:"overall"`

	// PerCategory is the per-category confusion. Keys are the 16
	// constant.Category values.
	PerCategory map[constant.Category]ClassificationMetrics `json:"per_category"`

	// PerTier is the per-tier confusion, including the trusted /
	// informational tiers.
	PerTier map[constant.Tier]ClassificationMetrics `json:"per_tier"`

	// ConfusionMatrix is a predicted×actual matrix of tier counts. The
	// outer key is the predicted tier; the inner key is the actual.
	ConfusionMatrix map[constant.Tier]map[constant.Tier]int `json:"confusion_matrix"`

	// PerDifficulty is the breakdown by corpus difficulty bucket. The
	// keys mirror corpus.Difficulty values ("easy", "medium", "hard").
	PerDifficulty map[string]ClassificationMetrics `json:"per_difficulty,omitempty"`

	// FalsePositiveRate is the fraction of benign emails that escalated
	// above Trusted/Informational. PROPOSAL.md target: <5%.
	FalsePositiveRate float64 `json:"false_positive_rate"`
	// FalseNegativeRate is the fraction of threat emails classified as
	// Trusted. PROPOSAL.md target: <2%.
	FalseNegativeRate float64 `json:"false_negative_rate"`
}

// NewAccuracyReport constructs an empty report scaffold.
func NewAccuracyReport(corpusSize int, seed int64) *AccuracyReport {
	return &AccuracyReport{
		Timestamp:       time.Now().UTC(),
		CorpusSize:      corpusSize,
		Seed:            seed,
		PerCategory:     map[constant.Category]ClassificationMetrics{},
		PerTier:         map[constant.Tier]ClassificationMetrics{},
		ConfusionMatrix: map[constant.Tier]map[constant.Tier]int{},
		PerDifficulty:   map[string]ClassificationMetrics{},
	}
}

// AddObservation folds one (predicted, expected) pair into the
// per-category and per-tier confusion tables and into the confusion
// matrix. Call AccuracyReport.Recompute once after all observations
// have been added.
func (r *AccuracyReport) AddObservation(predictedCat, expectedCat constant.Category, predictedTier, expectedTier constant.Tier, difficulty string, threat bool) {
	for _, c := range constant.AllCategories {
		m := r.PerCategory[c]
		switch {
		case predictedCat == c && expectedCat == c:
			m.TP++
		case predictedCat == c && expectedCat != c:
			m.FP++
		case predictedCat != c && expectedCat == c:
			m.FN++
		default:
			m.TN++
		}
		r.PerCategory[c] = m
	}
	for _, t := range constant.AllTiers {
		m := r.PerTier[t]
		switch {
		case predictedTier == t && expectedTier == t:
			m.TP++
		case predictedTier == t && expectedTier != t:
			m.FP++
		case predictedTier != t && expectedTier == t:
			m.FN++
		default:
			m.TN++
		}
		r.PerTier[t] = m
	}
	if r.ConfusionMatrix[predictedTier] == nil {
		r.ConfusionMatrix[predictedTier] = map[constant.Tier]int{}
	}
	r.ConfusionMatrix[predictedTier][expectedTier]++

	// Difficulty rollup uses a single "correct" predicate per row.
	if difficulty != "" {
		d := r.PerDifficulty[difficulty]
		if predictedCat == expectedCat {
			d.TP++
		} else {
			d.FN++
		}
		r.PerDifficulty[difficulty] = d
	}

	// Track FP / FN rates against benign / threat ground truth. We
	// classify a verdict as "raised" when the predicted tier is
	// Warning or higher; a verdict as "trusted" when it lands at
	// Trusted.
	predRaised := predictedTier.Severity() >= constant.TierWarning.Severity()
	predTrusted := predictedTier == constant.TierTrusted
	overall := r.Overall
	if threat {
		if predTrusted {
			overall.FN++
		} else {
			overall.TP++
		}
	} else {
		if predRaised {
			overall.FP++
		} else {
			overall.TN++
		}
	}
	r.Overall = overall
}

// Recompute walks the per-class accumulators and refreshes the derived
// rates. After this call every ClassificationMetrics in the report
// has fresh Precision/Recall/F1/Accuracy values.
func (r *AccuracyReport) Recompute() {
	r.Overall.Recompute()
	for c, m := range r.PerCategory {
		m.Recompute()
		r.PerCategory[c] = m
	}
	for t, m := range r.PerTier {
		m.Recompute()
		r.PerTier[t] = m
	}
	for d, m := range r.PerDifficulty {
		m.Recompute()
		r.PerDifficulty[d] = m
	}
	// FP/FN rates against the population. We extract from Overall's
	// accumulator counts: total threats = TP+FN; total benign = FP+TN.
	if threats := r.Overall.TP + r.Overall.FN; threats > 0 {
		r.FalseNegativeRate = float64(r.Overall.FN) / float64(threats)
	}
	if benign := r.Overall.FP + r.Overall.TN; benign > 0 {
		r.FalsePositiveRate = float64(r.Overall.FP) / float64(benign)
	}
}

// FormatMarkdown renders the report as a Markdown document suitable
// for committing under benchmarks/. The output is deterministic given
// the same metric values: maps are iterated in canonical order.
func (r *AccuracyReport) FormatMarkdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Accuracy Report\n\n")
	fmt.Fprintf(&b, "- Timestamp: `%s`\n", r.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "- Corpus size: `%d`\n", r.CorpusSize)
	fmt.Fprintf(&b, "- Seed: `%d`\n", r.Seed)
	fmt.Fprintf(&b, "- False-positive rate (benign → raised): `%.4f` (target <0.05)\n", r.FalsePositiveRate)
	fmt.Fprintf(&b, "- False-negative rate (threat → trusted): `%.4f` (target <0.02)\n\n", r.FalseNegativeRate)

	fmt.Fprintf(&b, "## Overall (threat vs benign)\n\n")
	writeMetricsTable(&b, "Class", []row{{Label: "overall", Metrics: r.Overall}})

	fmt.Fprintf(&b, "## Per-category\n\n")
	catRows := make([]row, 0, len(constant.AllCategories))
	for _, c := range constant.AllCategories {
		catRows = append(catRows, row{Label: string(c), Metrics: r.PerCategory[c]})
	}
	writeMetricsTable(&b, "Category", catRows)

	fmt.Fprintf(&b, "## Per-tier\n\n")
	tierRows := make([]row, 0, len(constant.AllTiers))
	for _, t := range constant.AllTiers {
		tierRows = append(tierRows, row{Label: string(t), Metrics: r.PerTier[t]})
	}
	writeMetricsTable(&b, "Tier", tierRows)

	if len(r.PerDifficulty) > 0 {
		fmt.Fprintf(&b, "## Per-difficulty (top-1 accuracy)\n\n")
		diffRows := make([]row, 0, len(r.PerDifficulty))
		keys := make([]string, 0, len(r.PerDifficulty))
		for k := range r.PerDifficulty {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			diffRows = append(diffRows, row{Label: k, Metrics: r.PerDifficulty[k]})
		}
		writeMetricsTable(&b, "Difficulty", diffRows)
	}

	fmt.Fprintf(&b, "## Confusion matrix (predicted rows × actual columns)\n\n")
	b.WriteString("| Predicted \\ Actual |")
	for _, t := range constant.AllTiers {
		fmt.Fprintf(&b, " %s |", t)
	}
	b.WriteString("\n|")
	for i := 0; i <= len(constant.AllTiers); i++ {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	for _, pred := range constant.AllTiers {
		fmt.Fprintf(&b, "| **%s** |", pred)
		row := r.ConfusionMatrix[pred]
		for _, actual := range constant.AllTiers {
			fmt.Fprintf(&b, " %d |", row[actual])
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	return b.String()
}

// row is one rendered row in a per-class Markdown table.
type row struct {
	Label   string
	Metrics ClassificationMetrics
}

// writeMetricsTable writes a standard Markdown table with the columns
// Label | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy.
func writeMetricsTable(b *strings.Builder, labelHeader string, rows []row) {
	fmt.Fprintf(b, "| %s | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |\n", labelHeader)
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range rows {
		fmt.Fprintf(b, "| %s | %d | %d | %d | %d | %.4f | %.4f | %.4f | %.4f |\n",
			r.Label, r.Metrics.TP, r.Metrics.FP, r.Metrics.FN, r.Metrics.TN,
			r.Metrics.Precision, r.Metrics.Recall, r.Metrics.F1, r.Metrics.Accuracy)
	}
	b.WriteString("\n")
}

// ConfusionTotal returns the sum of every cell in the predicted×actual
// confusion matrix; used in tests to verify the matrix preserves the
// corpus size.
func (r *AccuracyReport) ConfusionTotal() int {
	total := 0
	for _, row := range r.ConfusionMatrix {
		for _, v := range row {
			total += v
		}
	}
	return total
}
