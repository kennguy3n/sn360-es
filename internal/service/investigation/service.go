// Package investigation backs the WS-3b operator-facing
// investigation API:
//
//	GET /v1/investigation/message/{pseudo_id}
//	GET /v1/investigation/sender/{sender_hash}
//
// The endpoints let a SOC operator pivot from a dashboard / incident
// detail into the per-message verdict context and the per-sender
// activity pattern without writing ad-hoc Postgres queries against
// the management replica.
//
// The service is intentionally a thin read-only orchestrator: every
// data shape it returns lives in one of the underlying repositories
// (evaluation_results, communication_histories). The service joins
// them in process so the HTTP layer never sees raw repository row
// shapes — it also lets the tenant-isolation invariant be enforced
// in exactly one place per query (the service-side WHERE tenant_id
// clause that every repository call carries) rather than scattered
// across multiple handler functions.
package investigation

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
)

// ErrTenantIDRequired is returned whenever a Service method is
// invoked with an empty tenantID. The service refuses to query the
// repositories without a tenant scope because every underlying
// table is tenant-partitioned and a blank tenantID would either
// return no rows (defense-in-depth misses) or — for the in-memory
// fixture used in tests — silently match the first row whose
// tenant_id field is also blank. Exported as a sentinel so callers
// can `errors.Is` instead of matching the message string.
var ErrTenantIDRequired = errors.New("investigation: tenant_id is required")

// ErrMessageIDRequired / ErrSenderHashRequired guard the path
// parameters at the service boundary. The handler validates them at
// the HTTP layer too — both layers refuse the request — but
// duplicating the check here means a future non-HTTP caller
// (event-bus drill-down, CLI debug command, internal cron) cannot
// accidentally bypass the validation.
var (
	ErrMessageIDRequired  = errors.New("investigation: pseudo_message_id is required")
	ErrSenderHashRequired = errors.New("investigation: sender_hash is required")
)

// ErrNotFound is returned by MessageTrail when no evaluation result
// matches the (tenant, pseudo_message_id) pair. The HTTP layer
// translates this into a 404 indistinguishable from the cross-tenant
// case so the response surface cannot fingerprint which message IDs
// exist in which tenant. The sentinel is exposed so handler tests
// can `errors.Is` against it.
var ErrNotFound = errors.New("investigation: not found")

// senderTrailDefaultWindow is the look-back applied to SenderTrail
// when the caller does not specify one. 30 days matches the
// communication_histories rolling Count30d window so a sender that
// has gone quiet for more than a month is reported as "no recent
// activity" rather than confusingly carrying a stale verdict.
const senderTrailDefaultWindow = 30 * 24 * time.Hour

// senderTrailDefaultLimit caps the per-sender evaluation result set
// returned to the caller. The repository hard-caps at
// repository.EvalListBySenderMaxLimit; this default is intentionally
// smaller so a typical operator-facing call returns a focused trail
// rather than a deep history dump. Callers that want more must
// request explicitly via Options.Limit.
const senderTrailDefaultLimit = 100

// ServiceConfig wires the investigation service. The two repository
// fields are required: a partially-wired deployment (no
// evaluation_results, no communication_histories) cannot serve a
// useful response and the constructor refuses to return a non-nil
// Service in that case so the composition root can fail loudly
// rather than silently route requests into a no-op surface.
type ServiceConfig struct {
	EvaluationResults      repository.EvaluationResultRepository
	CommunicationHistories repository.CommunicationHistoryRepository
	Logger                 *slog.Logger
	// Clock lets tests fix a deterministic "now" so the default
	// 30-day look-back window in SenderTrail is reproducible. The
	// constructor substitutes time.Now when this is nil.
	Clock func() time.Time
}

// Service backs the WS-3b read-only investigation endpoints. Every
// method takes tenantID as the first argument; that value MUST come
// from the verified middleware-supplied claim, never from a path
// parameter or request body.
type Service struct {
	evalRepo repository.EvaluationResultRepository
	histRepo repository.CommunicationHistoryRepository
	log      *slog.Logger
	now      func() time.Time
}

// NewService validates the wiring and returns an investigation
// service. Returns a non-nil error when either repository is
// missing — the service has no fall-back for "no rows to query" and
// would otherwise pretend to be wired while always returning empty
// results.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.EvaluationResults == nil {
		return nil, errors.New("investigation: evaluation_results repository is required")
	}
	if cfg.CommunicationHistories == nil {
		return nil, errors.New("investigation: communication_histories repository is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &Service{
		evalRepo: cfg.EvaluationResults,
		histRepo: cfg.CommunicationHistories,
		log:      cfg.Logger,
		now:      cfg.Clock,
	}, nil
}

// MessageTrail is the per-message investigation lookup. It returns
// the persisted EvaluationResult for the (tenant, pseudo message id)
// pair plus, when available, the CommunicationHistory row for the
// (sender, recipient) pair the result references. Both lookups are
// tenant-scoped at the repository level.
//
// Returns ErrNotFound when no evaluation result matches. The handler
// translates this into a 404 that is indistinguishable from the
// cross-tenant case — see the handler's own docstring for the
// fingerprinting rationale.
func (s *Service) MessageTrail(ctx context.Context, tenantID, pseudoMessageID string) (MessageTrail, error) {
	if tenantID == "" {
		return MessageTrail{}, ErrTenantIDRequired
	}
	if pseudoMessageID == "" {
		return MessageTrail{}, ErrMessageIDRequired
	}
	// The evaluation_results table stores the pseudonymised
	// message ID as the BYTEA message_id_hash column; the wire
	// pseudoMessageID is the same bytes encoded as a string by
	// the writer (see cmd/sn360-es/consumers_evaluate.go
	// evaluateResultRow). Mirror that contract on the read side.
	res, err := s.evalRepo.GetByMessageHash(ctx, tenantID, []byte(pseudoMessageID))
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return MessageTrail{}, ErrNotFound
		}
		return MessageTrail{}, err
	}
	// Defense-in-depth: even though GetByMessageHash filters by
	// tenant_id, refuse a row whose persisted tenant doesn't
	// match the caller. A future repository implementation that
	// loosens the filter would otherwise leak verdicts across
	// tenants through this service.
	if res.TenantID != tenantID {
		return MessageTrail{}, ErrNotFound
	}
	trail := MessageTrail{Result: *res}
	// CommunicationHistory join is best-effort: legacy rows have
	// no persisted sender_hash so the Get below returns
	// ErrNotFound. The investigation UI degrades gracefully when
	// CommHistory is nil — the per-message verdict is still
	// useful on its own.
	if len(res.SenderHash) > 0 && len(res.RecipientHash) > 0 {
		hist, herr := s.histRepo.Get(ctx, tenantID, res.SenderHash, res.RecipientHash)
		switch {
		case herr == nil:
			if hist.TenantID == tenantID {
				trail.CommunicationHistory = hist
			}
		case errors.Is(herr, repository.ErrNotFound):
			// no-op: handler will render an absent commHistory field
		default:
			// Log and continue. A transient repository error on
			// the join lookup must NOT mask the primary verdict;
			// the operator's investigation view degrades to "no
			// recent activity for this pair" instead of failing
			// the whole request.
			s.log.WarnContext(ctx, "investigation: comm_history join failed",
				slog.String("tenant_id", tenantID),
				slog.Any("error", herr))
		}
	}
	return trail, nil
}

// SenderTrailOptions tunes the SenderTrail response. Zero-value
// fields select the documented defaults; the service is strict
// about clamping ranges so an upstream caller cannot accidentally
// request an unbounded scan.
type SenderTrailOptions struct {
	// Limit caps the number of evaluation_results rows returned.
	// Zero (default) selects senderTrailDefaultLimit. Values
	// above repository.EvalListBySenderMaxLimit are clamped to
	// that cap by the repository layer.
	Limit int
	// Since is the look-back applied to the recipient-fan-out
	// aggregation. Zero (default) selects 30 days. Future values
	// are accepted but the aggregation treats them as "since
	// now" — there is no future-events case to surface.
	Since time.Duration
}

// SenderTrail returns the per-sender investigation view: the most
// recent evaluation verdicts the sender produced for any recipient
// in the tenant, the recipient fan-out (CommunicationHistory rows
// keyed by senderHash), and a small aggregate envelope the
// dashboard renders without a second round-trip.
func (s *Service) SenderTrail(ctx context.Context, tenantID string, senderHash []byte, opts SenderTrailOptions) (SenderTrail, error) {
	if tenantID == "" {
		return SenderTrail{}, ErrTenantIDRequired
	}
	if len(senderHash) == 0 {
		return SenderTrail{}, ErrSenderHashRequired
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = senderTrailDefaultLimit
	}
	since := opts.Since
	if since <= 0 {
		since = senderTrailDefaultWindow
	}
	verdicts, err := s.evalRepo.ListBySender(ctx, tenantID, senderHash, limit)
	if err != nil {
		return SenderTrail{}, err
	}
	// Defense-in-depth: drop any row whose persisted tenant or
	// sender doesn't match the request scope. The repository
	// filters on both, but a future bug in either implementation
	// would otherwise let stale rows leak through this endpoint.
	verdicts = filterVerdicts(verdicts, tenantID, senderHash)

	recipients, err := s.histRepo.ListBySender(ctx, tenantID, senderHash, repository.CommHistoryListByTenantMaxLimit)
	if err != nil {
		return SenderTrail{}, err
	}
	recipients = filterCommHistories(recipients, tenantID, senderHash)

	now := s.now().UTC()
	agg := aggregate(verdicts, recipients, now, since)

	return SenderTrail{
		SenderHash:             append([]byte(nil), senderHash...),
		Verdicts:               verdicts,
		CommunicationHistories: recipients,
		Aggregate:              agg,
	}, nil
}

// MessageTrail is the per-message view the investigation API
// returns. The CommunicationHistory pointer is nil when the
// (tenant, sender, recipient) join lookup turned up no row — either
// because the evaluation result predates WS-3b's persisted hashes
// or because the relationship has not been recorded yet.
type MessageTrail struct {
	Result               repository.EvaluationResult
	CommunicationHistory *repository.CommunicationHistory
}

// SenderTrail is the per-sender view: the recent verdicts the
// sender produced, the recipient fan-out across the tenant, and an
// aggregate envelope summarising both.
type SenderTrail struct {
	SenderHash             []byte
	Verdicts               []repository.EvaluationResult
	CommunicationHistories []repository.CommunicationHistory
	Aggregate              SenderTrailAggregate
}

// SenderTrailAggregate is a small derived envelope the dashboard
// uses to render headline metrics without paging through the full
// slice. Every field is computed from the slices above; no
// additional repository round-trip is performed.
type SenderTrailAggregate struct {
	// TotalVerdicts is len(Verdicts). Exposed explicitly so the
	// dashboard can render a "showing N of M" footer without
	// re-counting.
	TotalVerdicts int
	// HighRiskVerdicts is the count of Verdicts whose Tier is
	// "blocked" or "high". Matches the tier values
	// internal/constant.Tier emits so the dashboard's category
	// filter stays consistent.
	HighRiskVerdicts int
	// MaxScore is the highest Score across Verdicts (0-100). 0
	// when Verdicts is empty.
	MaxScore int
	// LastVerdictAt is the EvaluatedAt of the most recent
	// verdict. Zero when Verdicts is empty.
	LastVerdictAt time.Time
	// DistinctRecipients is len(CommunicationHistories) filtered
	// to rows whose LastSeenAt is within `since` of now. Used by
	// the dashboard's "active recipient fan-out" widget.
	DistinctRecipients int
	// TotalSightingsWindow is the sum of Count30d across the
	// recipient rows in DistinctRecipients. Approximates the
	// sender's rolling message volume in the look-back window.
	TotalSightingsWindow int
}

// aggregate is a pure helper so it can be exhaustively tested
// without spinning up the surrounding Service / repositories.
func aggregate(
	verdicts []repository.EvaluationResult,
	recipients []repository.CommunicationHistory,
	now time.Time,
	since time.Duration,
) SenderTrailAggregate {
	agg := SenderTrailAggregate{TotalVerdicts: len(verdicts)}
	for _, v := range verdicts {
		if v.Score > agg.MaxScore {
			agg.MaxScore = v.Score
		}
		if v.EvaluatedAt.After(agg.LastVerdictAt) {
			agg.LastVerdictAt = v.EvaluatedAt
		}
		switch v.Tier {
		case "blocked", "high":
			agg.HighRiskVerdicts++
		}
	}
	cutoff := now.Add(-since)
	for _, r := range recipients {
		if r.LastSeenAt.Before(cutoff) {
			continue
		}
		agg.DistinctRecipients++
		agg.TotalSightingsWindow += r.Count30d
	}
	return agg
}

// filterVerdicts is a tenant-isolation defense-in-depth filter
// applied at the service boundary. The repository already filters
// by tenant_id + sender_hash; this layer drops anything that
// somehow slipped through so a future repository bug cannot leak
// rows across tenants via this read path.
func filterVerdicts(rows []repository.EvaluationResult, tenantID string, senderHash []byte) []repository.EvaluationResult {
	out := rows[:0]
	for _, r := range rows {
		if r.TenantID != tenantID {
			continue
		}
		if !bytes.Equal(r.SenderHash, senderHash) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// filterCommHistories mirrors filterVerdicts for the recipient
// fan-out slice. Same defense-in-depth rationale.
func filterCommHistories(rows []repository.CommunicationHistory, tenantID string, senderHash []byte) []repository.CommunicationHistory {
	out := rows[:0]
	for _, r := range rows {
		if r.TenantID != tenantID {
			continue
		}
		if !bytes.Equal(r.SenderHash, senderHash) {
			continue
		}
		out = append(out, r)
	}
	return out
}
