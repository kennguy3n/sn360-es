package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// ForcedReEvaluator triggers a re-evaluation pass with Tier 1 + Tier 2
// forced (per PROPOSAL.md §8 "User-Reported Phishing Workflow"). When
// the second pass confirms phishing the report workflow auto-quarantines
// all copies of the message in the tenant.
type ForcedReEvaluator interface {
	ReEvaluateForced(ctx context.Context, tenantID, pseudoMessageID string) (ReportVerdict, error)
}

// TenantRecipientLookup returns the list of pseudonymised recipients
// who received the same message across the tenant. The workflow uses
// it to fan-out the auto-quarantine after a confirmed report.
type TenantRecipientLookup interface {
	Recipients(ctx context.Context, tenantID, pseudoMessageID string) ([]string, error)
}

// MultiQuarantiner is the surface the report workflow needs from the
// quarantine service. It is satisfied by *QuarantineService.
type MultiQuarantiner interface {
	Quarantine(ctx context.Context, tenantID, pseudoMessageID, recipientHash string, providerMessageID string) error
}

// ReportVerdict is the outcome of the forced re-evaluation pass.
type ReportVerdict struct {
	Confirmed bool    `json:"confirmed"`
	Tier      string  `json:"tier"`
	Reason    string  `json:"reason"`
	Score     float64 `json:"score"`
}

// ReportStore aggregates user reports for the same message so the
// workflow can scale confidence with the number of reporters.
type ReportStore interface {
	Add(ctx context.Context, tenantID, pseudoMessageID, reporterHash string) (count int, err error)
	Get(ctx context.Context, tenantID, pseudoMessageID string) (count int, err error)
}

// ReportEvent is the canonical payload published to
// `es.action.feedback.report_confirmed` or `report_dismissed`.
type ReportEvent struct {
	TenantID             string    `json:"tenant_id"`
	PseudonymizedMessage string    `json:"pseudonymized_message_id"`
	ReporterHash         string    `json:"reporter_hash"`
	Reporters            int       `json:"reporters"`
	Confirmed            bool      `json:"confirmed"`
	Tier                 string    `json:"tier,omitempty"`
	OccurredAt           time.Time `json:"occurred_at"`
	CorrelationID        string    `json:"correlation_id,omitempty"`
}

// ReportWorkflowConfig wires the workflow.
type ReportWorkflowConfig struct {
	Publisher        FeedbackPublisher
	ReEvaluator      ForcedReEvaluator
	Recipients       TenantRecipientLookup
	Quarantiner      MultiQuarantiner
	Reports          ReportStore
	Logger           *slog.Logger
	Clock            func() time.Time
	AutoConfirmCount int
}

// ReportWorkflow implements the user-reported phishing workflow.
type ReportWorkflow struct {
	pub        FeedbackPublisher
	reEval     ForcedReEvaluator
	recipients TenantRecipientLookup
	quar       MultiQuarantiner
	reports    ReportStore
	log        *slog.Logger
	now        func() time.Time
	autoCount  int
}

// NewReportWorkflow constructs the workflow.
func NewReportWorkflow(cfg ReportWorkflowConfig) (*ReportWorkflow, error) {
	if cfg.Publisher == nil {
		return nil, errors.New("report: publisher is required")
	}
	if cfg.Reports == nil {
		cfg.Reports = NewMemoryReportStore()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.AutoConfirmCount <= 0 {
		cfg.AutoConfirmCount = 3
	}
	return &ReportWorkflow{
		pub:        cfg.Publisher,
		reEval:     cfg.ReEvaluator,
		recipients: cfg.Recipients,
		quar:       cfg.Quarantiner,
		reports:    cfg.Reports,
		log:        cfg.Logger,
		now:        cfg.Clock,
		autoCount:  cfg.AutoConfirmCount,
	}, nil
}

// HandleReport ingests one user "report phishing" click. It:
//
//  1. Increments the per-message report counter.
//  2. Triggers a forced re-evaluation (Tier 1 + Tier 2).
//  3. If the re-evaluation confirms phishing OR the cumulative report
//     count crosses AutoConfirmCount, fan-out auto-quarantine across
//     all recipients in the tenant who received the same message.
//  4. Publishes report_confirmed / report_dismissed on the bus.
func (w *ReportWorkflow) HandleReport(ctx context.Context, tenantID, pseudoMessageID, reporterHash, correlationID string) (ReportEvent, error) {
	if tenantID == "" || pseudoMessageID == "" || reporterHash == "" {
		return ReportEvent{}, errors.New("report: tenant_id, pseudo_message_id and reporter_hash are required")
	}
	count, err := w.reports.Add(ctx, tenantID, pseudoMessageID, reporterHash)
	if err != nil {
		return ReportEvent{}, fmt.Errorf("report: store add: %w", err)
	}
	verdict := ReportVerdict{}
	if w.reEval != nil {
		v, err := w.reEval.ReEvaluateForced(ctx, tenantID, pseudoMessageID)
		if err != nil {
			w.log.WarnContext(ctx, "report: forced re-evaluate failed",
				slog.String("tenant_id", tenantID),
				slog.Any("error", err),
			)
		} else {
			verdict = v
		}
	}
	confirmed := verdict.Confirmed || count >= w.autoCount
	if confirmed {
		if err := w.fanoutQuarantine(ctx, tenantID, pseudoMessageID); err != nil {
			w.log.WarnContext(ctx, "report: fanout quarantine failed",
				slog.String("tenant_id", tenantID),
				slog.Any("error", err),
			)
		}
	}
	evt := ReportEvent{
		TenantID:             tenantID,
		PseudonymizedMessage: pseudoMessageID,
		ReporterHash:         reporterHash,
		Reporters:            count,
		Confirmed:            confirmed,
		Tier:                 verdict.Tier,
		OccurredAt:           w.now(),
		CorrelationID:        correlationID,
	}
	subject := "es.action.feedback.report_dismissed"
	if confirmed {
		subject = "es.action.feedback.report_confirmed"
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		return ReportEvent{}, fmt.Errorf("report: marshal: %w", err)
	}
	if err := w.pub.Publish(ctx, subject, payload,
		events.WithEventType(subject),
		events.WithTenantID(tenantID),
		events.WithMessageID(pseudoMessageID),
		events.WithCorrelationID(correlationID),
	); err != nil {
		return ReportEvent{}, fmt.Errorf("report: publish: %w", err)
	}
	return evt, nil
}

func (w *ReportWorkflow) fanoutQuarantine(ctx context.Context, tenantID, pseudoMessageID string) error {
	if w.quar == nil || w.recipients == nil {
		return nil
	}
	recipients, err := w.recipients.Recipients(ctx, tenantID, pseudoMessageID)
	if err != nil {
		return fmt.Errorf("recipients lookup: %w", err)
	}
	for _, r := range recipients {
		if err := w.quar.Quarantine(ctx, tenantID, pseudoMessageID, r, ""); err != nil {
			w.log.WarnContext(ctx, "report: quarantine one recipient failed",
				slog.String("tenant_id", tenantID),
				slog.String("recipient_hash", r),
				slog.Any("error", err),
			)
			continue
		}
	}
	return nil
}

// --- In-memory report store ---

// MemoryReportStore is a goroutine-safe in-memory ReportStore.
type MemoryReportStore struct {
	mu     sync.Mutex
	counts map[string]map[string]int // tenant -> message -> count
	seen   map[string]map[string]map[string]struct{}
}

// NewMemoryReportStore returns an empty store.
func NewMemoryReportStore() *MemoryReportStore {
	return &MemoryReportStore{
		counts: map[string]map[string]int{},
		seen:   map[string]map[string]map[string]struct{}{},
	}
}

// Add implements ReportStore.
func (m *MemoryReportStore) Add(_ context.Context, tenantID, pseudoMessageID, reporterHash string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.counts[tenantID]; !ok {
		m.counts[tenantID] = map[string]int{}
		m.seen[tenantID] = map[string]map[string]struct{}{}
	}
	if _, ok := m.seen[tenantID][pseudoMessageID]; !ok {
		m.seen[tenantID][pseudoMessageID] = map[string]struct{}{}
	}
	if _, dup := m.seen[tenantID][pseudoMessageID][reporterHash]; dup {
		return m.counts[tenantID][pseudoMessageID], nil
	}
	m.seen[tenantID][pseudoMessageID][reporterHash] = struct{}{}
	m.counts[tenantID][pseudoMessageID]++
	return m.counts[tenantID][pseudoMessageID], nil
}

// Get implements ReportStore.
func (m *MemoryReportStore) Get(_ context.Context, tenantID, pseudoMessageID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.counts[tenantID]; !ok {
		return 0, nil
	}
	return m.counts[tenantID][pseudoMessageID], nil
}
