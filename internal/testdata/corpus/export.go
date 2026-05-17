package corpus

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// ExportRecord is the persisted shape of a LabeledEmail. We export the
// EvaluateRequest fields explicitly so the JSON file is human-readable
// and consumable by external tools (the dto.EvaluateRequest JSON tags
// nest the signals one level deep, which is exactly what we want).
type ExportRecord struct {
	TestID             string            `json:"test_id"`
	MessageID          string            `json:"message_id"`
	TenantID           string            `json:"tenant_id"`
	CorrelationID      string            `json:"correlation_id"`
	Sender             string            `json:"sender"`
	Recipient          string            `json:"recipient"`
	Subject            string            `json:"subject"`
	Body               string            `json:"body"`
	Locale             string            `json:"locale"`
	Signals            json.RawMessage   `json:"signals"`
	ExpectedTier       constant.Tier     `json:"expected_tier"`
	ExpectedPrimary    constant.Category `json:"expected_primary"`
	ExpectedScoreRange [2]int            `json:"expected_score_range"`
	Difficulty         Difficulty        `json:"difficulty"`
	AttackType         string            `json:"attack_type"`
	IsThreat           bool              `json:"is_threat"`
}

// ToExportRecords converts a corpus slice into ExportRecord values.
func ToExportRecords(c []LabeledEmail) ([]ExportRecord, error) {
	out := make([]ExportRecord, 0, len(c))
	for i, e := range c {
		sig, err := json.Marshal(e.Request.Signals)
		if err != nil {
			return nil, fmt.Errorf("corpus: marshal signals row %d: %w", i, err)
		}
		out = append(out, ExportRecord{
			TestID:             fmt.Sprintf("corpus-%05d", i),
			MessageID:          e.Request.MessageID,
			TenantID:           e.Request.TenantID,
			CorrelationID:      e.Request.CorrelationID,
			Sender:             e.Request.Sender,
			Recipient:          e.Request.Recipient,
			Subject:            e.Request.Subject,
			Body:               e.Request.Body,
			Locale:             e.Locale,
			Signals:            sig,
			ExpectedTier:       e.ExpectedTier,
			ExpectedPrimary:    e.ExpectedPrimary,
			ExpectedScoreRange: e.ExpectedScoreRange,
			Difficulty:         e.Difficulty,
			AttackType:         e.AttackType,
			IsThreat:           e.IsThreat,
		})
	}
	return out, nil
}

// WriteJSON serialises c as an indented JSON array to w.
func WriteJSON(w io.Writer, c []LabeledEmail) error {
	recs, err := ToExportRecords(c)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(recs); err != nil {
		return fmt.Errorf("corpus: encode json: %w", err)
	}
	return nil
}

// WriteCSV serialises c as a flat CSV to w. Signals are inlined as a
// JSON blob so the round-trip is lossless without exploding the column
// count.
func WriteCSV(w io.Writer, c []LabeledEmail) error {
	recs, err := ToExportRecords(c)
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	defer cw.Flush()
	header := []string{
		"test_id", "message_id", "tenant_id", "correlation_id",
		"sender", "recipient", "subject", "body", "locale",
		"expected_tier", "expected_primary", "expected_score_lo",
		"expected_score_hi", "difficulty", "attack_type", "is_threat",
		"signals_json",
	}
	if err := cw.Write(header); err != nil {
		return fmt.Errorf("corpus: write csv header: %w", err)
	}
	for _, r := range recs {
		row := []string{
			r.TestID, r.MessageID, r.TenantID, r.CorrelationID,
			r.Sender, r.Recipient, r.Subject, r.Body, r.Locale,
			string(r.ExpectedTier), string(r.ExpectedPrimary),
			strconv.Itoa(r.ExpectedScoreRange[0]),
			strconv.Itoa(r.ExpectedScoreRange[1]),
			string(r.Difficulty), r.AttackType, strconv.FormatBool(r.IsThreat),
			string(r.Signals),
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("corpus: write csv row: %w", err)
		}
	}
	if err := cw.Error(); err != nil {
		return fmt.Errorf("corpus: flush csv: %w", err)
	}
	return nil
}

// WriteFile serialises c to a file at path. The format is inferred
// from the path suffix (.json / .csv). Any other suffix defaults to
// JSON to stay close to the principle of least surprise.
func WriteFile(path string, c []LabeledEmail, format string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("corpus: create %s: %w", path, err)
	}
	defer f.Close()
	switch format {
	case "csv":
		return WriteCSV(f, c)
	default:
		return WriteJSON(f, c)
	}
}
