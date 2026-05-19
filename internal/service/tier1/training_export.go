package tier1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/storage/s3"
)

// TrainingLabel represents the human-confirmed verdict.
type TrainingLabel string

const (
	LabelFalsePositive TrainingLabel = "false_positive"
	LabelFalseNegative TrainingLabel = "false_negative"
	LabelTruePositive  TrainingLabel = "true_positive"
	LabelTrueNegative  TrainingLabel = "true_negative"
)

// TrainingSample is a single pseudonymized training record exported
// for model fine-tuning. No raw email bodies are included (privacy
// architecture compliance).
type TrainingSample struct {
	// Pseudonymized fields only.
	MessageHash   string        `json:"message_hash"`
	SubjectTokens []string      `json:"subject_tokens"`
	SenderDomain  string        `json:"sender_domain"`
	EncoderScore  int           `json:"encoder_score"`
	FinalScore    int           `json:"final_score"`
	FinalTier     string        `json:"final_tier"`
	Category      string        `json:"category"`
	ReasonCodes   []string      `json:"reason_codes,omitempty"`
	SignalFlags   SignalFlags   `json:"signal_flags"`
	HumanLabel    TrainingLabel `json:"human_label"`
	FeedbackAt    time.Time     `json:"feedback_at"`
	Language      string        `json:"language,omitempty"`
	ModelTag      string        `json:"model_tag,omitempty"`
}

// SignalFlags are the boolean risk signals for training.
type SignalFlags struct {
	HasLinks       bool `json:"has_links"`
	HasAttachments bool `json:"has_attachments"`
	IsInternal     bool `json:"is_internal"`
	AuthPassed     bool `json:"auth_passed"`
	SPFPass        bool `json:"spf_pass"`
	DKIMPass       bool `json:"dkim_pass"`
	DMARCPass      bool `json:"dmarc_pass"`
	IsReply        bool `json:"is_reply"`
	HasUrgentTone  bool `json:"has_urgent_tone"`
}

// FeedbackRecord is the input from the feedback store that the
// exporter queries for confirmed FP/FN verdicts.
type FeedbackRecord struct {
	TenantID           string
	PseudonymizedMsgID string
	Subject            string
	SenderDomain       string
	EncoderScore       int
	FinalScore         int
	FinalTier          string
	Category           string
	ReasonCodes        []string
	Signals            SignalFlags
	Language           string
	ModelTag           string
	Action             string // "report_phishing" or "mark_safe"
	FeedbackAt         time.Time
}

// FeedbackSource is the query interface for confirmed verdicts.
type FeedbackSource interface {
	// QueryConfirmedFeedback returns all confirmed FP/FN feedback
	// records within the given time range.
	QueryConfirmedFeedback(ctx context.Context, since, until time.Time) ([]FeedbackRecord, error)
}

// TrainingExportConfig wires the training export pipeline.
type TrainingExportConfig struct {
	Source FeedbackSource
	Store  s3.ObjectStore
	Logger *slog.Logger
	// Bucket prefix for S3 storage. Defaults to "training".
	Prefix string
	// Clock for deterministic testing.
	Clock func() time.Time
}

// TrainingExporter is the periodic job that queries confirmed
// FP/FN verdicts and exports pseudonymized training samples as JSONL
// to S3.
type TrainingExporter struct {
	source FeedbackSource
	store  s3.ObjectStore
	log    *slog.Logger
	prefix string
	now    func() time.Time
}

// NewTrainingExporter constructs the exporter.
func NewTrainingExporter(cfg TrainingExportConfig) (*TrainingExporter, error) {
	if cfg.Source == nil {
		return nil, fmt.Errorf("training_export: feedback source is required")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("training_export: object store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "training"
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &TrainingExporter{
		source: cfg.Source,
		store:  cfg.Store,
		log:    cfg.Logger,
		prefix: cfg.Prefix,
		now:    cfg.Clock,
	}, nil
}

// ExportResult summarises the outcome.
type ExportResult struct {
	RecordsExported int
	S3Key           string
	Duration        time.Duration
}

// Export runs a single export cycle: queries feedback since the last
// export window and writes a JSONL file to S3.
func (e *TrainingExporter) Export(ctx context.Context, since, until time.Time) (ExportResult, error) {
	start := e.now()
	records, err := e.source.QueryConfirmedFeedback(ctx, since, until)
	if err != nil {
		return ExportResult{}, fmt.Errorf("training_export: query: %w", err)
	}
	if len(records) == 0 {
		e.log.InfoContext(ctx, "training_export: no records to export",
			slog.Time("since", since),
			slog.Time("until", until))
		return ExportResult{}, nil
	}

	var buf strings.Builder
	for _, rec := range records {
		sample := pseudonymize(rec)
		line, jerr := json.Marshal(sample)
		if jerr != nil {
			e.log.WarnContext(ctx, "training_export: marshal failed", slog.Any("error", jerr))
			continue
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	key := fmt.Sprintf("%s/%s/feedback.jsonl", e.prefix, until.Format("2006-01-02"))
	if err := e.store.Put(ctx, key, []byte(buf.String()),
		s3.WithContentType("application/x-ndjson"),
		s3.WithMetadata(map[string]string{
			"records":     fmt.Sprintf("%d", len(records)),
			"since":       since.Format(time.RFC3339),
			"until":       until.Format(time.RFC3339),
			"exported_at": e.now().Format(time.RFC3339),
		}),
	); err != nil {
		return ExportResult{}, fmt.Errorf("training_export: upload: %w", err)
	}

	result := ExportResult{
		RecordsExported: len(records),
		S3Key:           key,
		Duration:        e.now().Sub(start),
	}
	e.log.InfoContext(ctx, "training_export: exported",
		slog.Int("records", result.RecordsExported),
		slog.String("key", result.S3Key),
		slog.Duration("duration", result.Duration))
	return result, nil
}

// ExportDaily is a convenience that exports yesterday's feedback window.
func (e *TrainingExporter) ExportDaily(ctx context.Context) (ExportResult, error) {
	now := e.now()
	until := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	since := until.Add(-24 * time.Hour)
	return e.Export(ctx, since, until)
}

// pseudonymize converts a FeedbackRecord into a TrainingSample,
// stripping PII and pseudonymizing identifiers.
func pseudonymize(rec FeedbackRecord) TrainingSample {
	label := LabelTruePositive
	switch rec.Action {
	case "mark_safe":
		label = LabelFalsePositive
	case "report_phishing":
		label = LabelFalseNegative
	}

	return TrainingSample{
		MessageHash:   hashID(rec.TenantID + ":" + rec.PseudonymizedMsgID),
		SubjectTokens: tokenizeSubject(rec.Subject),
		SenderDomain:  rec.SenderDomain,
		EncoderScore:  rec.EncoderScore,
		FinalScore:    rec.FinalScore,
		FinalTier:     rec.FinalTier,
		Category:      rec.Category,
		ReasonCodes:   rec.ReasonCodes,
		SignalFlags:   rec.Signals,
		HumanLabel:    label,
		FeedbackAt:    rec.FeedbackAt,
		Language:      rec.Language,
		ModelTag:      rec.ModelTag,
	}
}

// hashID produces a deterministic pseudonym from a plaintext ID.
func hashID(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:16])
}

// tokenizeSubject splits a subject into lowered tokens, stripping
// common prefixes (Re:, Fwd:). No PII is leaked because subject
// tokens are individual words, not the full phrase.
func tokenizeSubject(subject string) []string {
	s := strings.ToLower(subject)
	// Strip common reply/forward prefixes.
	for _, prefix := range []string{"re:", "fwd:", "fw:", "re: ", "fwd: ", "fw: "} {
		if strings.HasPrefix(s, prefix) {
			s = s[len(prefix):]
			break
		}
	}
	parts := strings.Fields(s)
	if len(parts) > 20 {
		parts = parts[:20]
	}
	return parts
}
