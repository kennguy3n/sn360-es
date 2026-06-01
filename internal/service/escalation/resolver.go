// Copyright 2024-2026 SN360. All rights reserved.
// Use of this source code is governed by the proprietary license
// that can be found in the LICENSE file.

package escalation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/repository"
)

// BannerReopener is the narrow interface the resolver depends
// on for the WS-5A.6 banner-reopen path. The consumer-side
// wiring (cmd/sn360-es) implements it on top of the existing
// BannerInjector / publisher pair so the resolver doesn't have
// to know about NATS subjects or provider clients.
//
// Reopen MUST be a no-op when banner_state.delivered_at IS
// NULL — that gating happens in the resolver before calling
// the implementation, but implementations should also defend
// at their boundary so a stale resolver can never bypass the
// invariant.
type BannerReopener interface {
	// ReopenBanner re-renders the banner with the supplied
	// reason and re-injects it for (tenant, messageID). The
	// implementation is responsible for the
	// banner_state.MarkReopened bookkeeping; the resolver
	// passes reason as the audit-trail-visible disposition
	// (e.g. "Updated by SOC analyst: confirmed_threat").
	ReopenBanner(ctx context.Context, tenantID, messageID, reason string) error
}

// Resolver is the WS-5A.6 reconciler. Constructed once at
// consumer startup with concrete repositories + a banner
// reopener and called per-message from the NATS handler.
//
// The struct holds no per-message state; concurrent
// invocations are safe.
type Resolver struct {
	evalResults repository.EvaluationResultRepository
	audits      repository.EmailVerdictAuditRepository
	banners     repository.BannerStateRepository
	reopener    BannerReopener
	logger      *slog.Logger
}

// New constructs a Resolver. logger may be nil; a discard
// handler is substituted so the resolver methods are free of
// nil-logger guards. The other dependencies are required —
// the WS-5A.6 contract has no nil-friendly behaviour for them
// (the resolver's job IS to write through those repositories).
func New(
	evalResults repository.EvaluationResultRepository,
	audits repository.EmailVerdictAuditRepository,
	banners repository.BannerStateRepository,
	reopener BannerReopener,
	logger *slog.Logger,
) (*Resolver, error) {
	if evalResults == nil {
		return nil, errors.New("escalation: eval results repository required")
	}
	if audits == nil {
		return nil, errors.New("escalation: audits repository required")
	}
	if banners == nil {
		return nil, errors.New("escalation: banner state repository required")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return &Resolver{
		evalResults: evalResults,
		audits:      audits,
		banners:     banners,
		reopener:    reopener,
		logger:      logger,
	}, nil
}

// discardWriter is a sink for the nil-logger fallback. Avoids
// pulling io/ioutil's Discard into the package's import set
// for a sink the production path never hits.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// Reconcile is the WS-5A.6 hot path.
//
// Invariants:
//
//   - Exactly ONE audit row per invocation (success or
//     skip-with-reason). Never zero, never two. The
//     INSERT-ON-CONFLICT path counts as one logical row even
//     when a previous invocation wrote it.
//   - Tenant isolation: payload.tenant_id MUST match the
//     EvaluationResult.TenantID loaded for the
//     pseudo_message_id. A mismatch is dropped with an audit
//     row carrying the rationale — never silent.
//   - Banner reopen: gated on banner_state.delivered_at IS
//     NOT NULL. A reopen on an undelivered banner is silently
//     suppressed (no error, no banner row) because the
//     business invariant is "don't surprise a user with a
//     banner they never saw the first version of".
//   - Idempotency: re-deliveries within the JetStream 600s
//     dedup window are dropped broker-side; re-deliveries
//     beyond the window collide on (tenant_id, dedup_id) and
//     return OutcomeDuplicate without re-applying the verdict
//     flip or reopen.
func (r *Resolver) Reconcile(ctx context.Context, ev IncidentResolved) (Outcome, error) {
	if err := validateInput(ev); err != nil {
		return Outcome{}, err
	}
	// Idempotency check FIRST. If the audit row exists, the
	// resolver short-circuits without touching
	// evaluation_results or banner_state — the previous
	// invocation already did that work and a second pass
	// risks double-firing the banner reopen.
	if existing, err := r.audits.GetByDedupID(ctx, ev.TenantID, ev.DedupID); err == nil && existing != nil {
		r.logger.DebugContext(ctx, "escalation: duplicate delivery short-circuit",
			slog.String("tenant_id", ev.TenantID),
			slog.String("dedup_id", ev.DedupID),
			slog.String("audit_id", existing.ID),
		)
		return Outcome{
			Kind:            OutcomeDuplicate,
			AuditID:         existing.ID,
			OriginalVerdict: existing.OriginalVerdict,
			NewVerdict:      existing.NewVerdict,
			Reason:          existing.Reason,
		}, nil
	} else if err != nil && !errors.Is(err, repository.ErrNotFound) {
		// A transient DB error on the dedup probe: surface
		// it so JetStream retries. If we ploughed on past
		// the error, we'd risk double-applying the verdict
		// flip on a delivery that has already landed.
		return Outcome{}, fmt.Errorf("escalation: dedup probe: %w", err)
	}

	// Locate the EvaluationResult. The producer guarantees
	// HasIdentifier() == true before publishing, so at least
	// one of pseudo_message_id / correlation_id will be set
	// here. Prefer pseudo_message_id because it indexes
	// directly into evaluation_results.message_id_hash;
	// correlation_id is a secondary index.
	messageIDHash, evalRow, lookupReason, err := r.locateEvaluation(ctx, ev)
	if err != nil {
		return Outcome{}, err
	}
	if evalRow == nil {
		// No row found. Persist an audit-skip row so the
		// invocation is observable.
		return r.persistSkip(ctx, ev, messageIDHash, lookupReason)
	}

	// Tenant isolation invariant. A mismatch could mean
	// either (a) a misrouted soc-triage incident or (b) a
	// pseudo_message_id collision (extraordinarily
	// unlikely with 256-bit hashes). Either way, the
	// resolver must not reach across the tenant boundary;
	// drop with audit log.
	if evalRow.TenantID != ev.TenantID {
		r.logger.WarnContext(ctx, "escalation: cross-tenant payload dropped",
			slog.String("payload_tenant", ev.TenantID),
			slog.String("row_tenant", evalRow.TenantID),
			slog.String("dedup_id", ev.DedupID),
		)
		reason := fmt.Sprintf("cross-tenant: payload tenant=%s row tenant=%s", ev.TenantID, evalRow.TenantID)
		return r.persistSkip(ctx, ev, messageIDHash, reason)
	}

	original := automatedVerdict(evalRow)
	newVerdict, flip := flipFor(ev.Resolution, original)

	out := Outcome{
		OriginalVerdict: original,
		Reason:          composeReason(ev.AnalystNotes, ev.Resolution),
	}

	if !flip {
		// Telemetry-only: analyst confirmed the platform's
		// automated verdict. Audit row records the
		// confirmation; no verdict UPDATE / banner reopen.
		out.Kind = OutcomeNoop
	} else {
		if err := r.evalResults.SetFinalVerdict(ctx, evalRow.TenantID, messageIDHash, newVerdict); err != nil {
			return Outcome{}, fmt.Errorf("escalation: SetFinalVerdict: %w", err)
		}
		out.Kind = OutcomeFlipped
		out.NewVerdict = newVerdict
	}

	// Banner-reopen path. Gated on:
	//   1. The verdict actually flipped (otherwise nothing
	//      to communicate to the user).
	//   2. The new verdict is "malicious" (a downgrade to
	//      benign should suppress the existing banner, not
	//      re-render it — that's a separate clawback path
	//      out of scope for the WS-5A.6 reopen contract).
	//   3. banner_state.delivered_at IS NOT NULL — the user
	//      observed the original banner and so SHOULD see
	//      the updated reason.
	if flip && newVerdict == verdictMalicious && r.reopener != nil {
		bs, err := r.banners.Get(ctx, evalRow.TenantID, messageIDHash)
		switch {
		case errors.Is(err, repository.ErrNotFound):
			// No banner was ever rendered for this email
			// (probably Trusted/Informational tier on the
			// automated verdict). Suppress reopen per
			// invariant.
			r.logger.DebugContext(ctx, "escalation: banner-reopen suppressed (no banner_state row)",
				slog.String("tenant_id", evalRow.TenantID),
			)
		case err != nil:
			// Transient DB error on the gate check. We
			// already wrote final_verdict, so we can't
			// roll the invocation back. Surface as warn
			// and continue; ops can manually reopen via
			// the admin path if needed.
			r.logger.WarnContext(ctx, "escalation: banner-state probe failed",
				slog.Any("error", err),
				slog.String("tenant_id", evalRow.TenantID),
			)
		case bs.DeliveredAt == nil:
			// Banner was rendered but the user has not
			// observed it (provider failure, race).
			// Suppress reopen.
			r.logger.DebugContext(ctx, "escalation: banner-reopen suppressed (delivered_at NULL)",
				slog.String("tenant_id", evalRow.TenantID),
			)
		default:
			reopenReason := composeBannerReason(ev.Resolution, ev.AnalystNotes)
			// MessageID for the reopener is the producer-stamped
			// pseudonym (or the row's stored CorrelationID when
			// the pseudo is empty). The reopener implementation
			// is responsible for resolving the pseudonym back to
			// the provider-side mailbox identifier; see
			// cmd/sn360-es/banner_reopener.go.
			reopenMessageID := pseudoMessageIDFor(ev)
			if reopenMessageID == "" {
				reopenMessageID = evalRow.CorrelationID
			}
			if rerr := r.reopener.ReopenBanner(ctx, evalRow.TenantID, reopenMessageID, reopenReason); rerr != nil {
				// Non-fatal: the audit row + verdict flip
				// already landed. Operator can manually
				// re-trigger if necessary.
				r.logger.WarnContext(ctx, "escalation: ReopenBanner failed (non-fatal)",
					slog.Any("error", rerr),
					slog.String("tenant_id", evalRow.TenantID),
				)
			} else {
				out.BannerReopened = true
			}
		}
	}

	// Persist the audit row LAST so it reflects the final
	// committed disposition. On INSERT-ON-CONFLICT (the
	// dedup probe above missed because of a TOCTOU race
	// with a parallel consumer), inserted=false and we
	// promote the result to OutcomeDuplicate so the caller
	// can ack the broker-side delivery without a metric
	// blip.
	row := &repository.EmailVerdictAudit{
		TenantID:         ev.TenantID,
		DedupID:          ev.DedupID,
		PseudoMessageID:  pseudoMessageIDFor(ev),
		OriginalVerdict:  out.OriginalVerdict,
		NewVerdict:       out.NewVerdict,
		Resolution:       ev.Resolution,
		ResolvedBy:       ev.ResolvedBy,
		ResolvedAt:       ev.ResolvedAt,
		SourceIncidentID: ev.IncidentID,
		Reason:           out.Reason,
	}
	inserted, err := r.audits.Insert(ctx, row)
	if err != nil {
		return Outcome{}, fmt.Errorf("escalation: audit insert: %w", err)
	}
	out.AuditID = row.ID
	if !inserted {
		// TOCTOU race with a parallel consumer or DLQ
		// drain — the audit row was already written
		// between our dedup probe and this insert. Promote
		// to Duplicate so metrics / DEBUG logs label the
		// outcome correctly.
		out.Kind = OutcomeDuplicate
	}
	return out, nil
}

// pseudoMessageIDFor returns the consumer's preferred
// pseudo_message_id string for the audit row. Prefers the
// producer's explicit value, falls back to the CorrelationID
// when the producer didn't stamp one (e.g. legacy playbook
// shapes that only stamp correlation_id). Empty when the
// payload had no link at all (cross-tenant / skip paths).
func pseudoMessageIDFor(ev IncidentResolved) string {
	if ev.RelatedEmail == nil {
		return ""
	}
	if s := strings.TrimSpace(ev.RelatedEmail.PseudoMessageID); s != "" {
		return s
	}
	return strings.TrimSpace(ev.RelatedEmail.CorrelationID)
}

func validateInput(ev IncidentResolved) error {
	if ev.IncidentID == "" {
		return errors.New("escalation: incident_id required")
	}
	if ev.TenantID == "" {
		return errors.New("escalation: tenant_id required")
	}
	if !IsValidResolution(ev.Resolution) {
		return fmt.Errorf("escalation: invalid resolution %q", ev.Resolution)
	}
	if ev.ResolvedAt.IsZero() {
		return errors.New("escalation: resolved_at required")
	}
	if ev.DedupID == "" {
		return errors.New("escalation: dedup_id required")
	}
	return nil
}

// locateEvaluation tries the pseudo_message_id path first,
// falls back to correlation_id. Returns the bytes the row was
// keyed by (so the caller can pass them to SetFinalVerdict
// without re-deriving), the row itself (nil if no match), and
// a "lookup reason" string the persistSkip path stamps onto
// the audit row when nothing was found.
func (r *Resolver) locateEvaluation(
	ctx context.Context,
	ev IncidentResolved,
) (messageIDHash []byte, row *repository.EvaluationResult, lookupReason string, err error) {
	if ev.RelatedEmail == nil {
		// Producer guarantees this is non-nil for findable
		// events, but defend at the boundary so a
		// mis-stamped payload becomes an observable skip
		// rather than a nil dereference.
		return nil, nil, "payload missing related_email", nil
	}
	pseudo := strings.TrimSpace(ev.RelatedEmail.PseudoMessageID)
	corr := strings.TrimSpace(ev.RelatedEmail.CorrelationID)

	if pseudo != "" {
		// pseudo_message_id is the same opaque identifier
		// the evaluate pipeline stamps into
		// evaluation_results.message_id_hash as raw bytes.
		// Today the upstream evaluate consumer writes the
		// plaintext provider message-id directly to the
		// BYTEA column; tomorrow it may switch to a hashed
		// representation. Either way the consumer keys on
		// the bytes the producer sends, which preserves
		// the consumer/producer contract independently of
		// the hashing convention.
		h := []byte(pseudo)
		row, err = r.evalResults.GetByMessageHash(ctx, ev.TenantID, h)
		if err == nil {
			return h, row, "", nil
		}
		if !errors.Is(err, repository.ErrNotFound) {
			return nil, nil, "", fmt.Errorf("escalation: GetByMessageHash: %w", err)
		}
		// Not found by pseudo_message_id — try
		// correlation_id below if available.
		messageIDHash = h
	}

	if corr != "" {
		// correlation_id is plain text (UUID-shaped, but
		// the schema is TEXT). Fall back to listing recent
		// evals and filtering, since evaluation_results
		// has no direct lookup-by-correlation API today.
		// Bounded to a small recent window so we don't
		// scan unbounded history.
		// The WS-3b investigation API already pages
		// evaluation_results by tenant + correlation_id;
		// the resolver doesn't depend on it here so the
		// consumer can boot before WS-3b is wired, but
		// the in-memory + Postgres scan path below stays
		// O(recent) instead of O(table).
		recents, listErr := r.evalResults.ListRecent(ctx, ev.TenantID, evalListLookbackForCorrelation)
		if listErr != nil {
			return messageIDHash, nil, "", fmt.Errorf("escalation: ListRecent for correlation: %w", listErr)
		}
		for i := range recents {
			if strings.EqualFold(recents[i].CorrelationID, corr) {
				return recents[i].MessageIDHash, &recents[i], "", nil
			}
		}
		return messageIDHash, nil, fmt.Sprintf("no evaluation_results row for correlation_id=%s within recent window", corr), nil
	}

	if pseudo != "" {
		return messageIDHash, nil, fmt.Sprintf("no evaluation_results row for pseudo_message_id=%s", pseudo), nil
	}
	return nil, nil, "payload related_email had no identifiers", nil
}

// evalListLookbackForCorrelation caps the recents window the
// correlation-id fallback scans. The WS-5A.6 producer-side
// timing analysis says incidents close within the 24h MaxAge
// of the platform stream, so 500 recents is well above the
// expected per-tenant rate during that window. Larger windows
// trade latency for completeness; smaller windows risk
// missing legitimate matches during a backlog drain.
const evalListLookbackForCorrelation = 500

// Platform verdict labels — kept in lockstep with the schema's
// CHECK constraint on evaluation_results.final_verdict.
const (
	verdictMalicious  = "malicious"
	verdictSuspicious = "suspicious"
	verdictBenign     = "benign"
)

// automatedVerdict maps the evaluation_results row's tier +
// primary_category to one of {malicious, suspicious, benign}.
// This is the platform's automated call; the WS-5A.6 resolver
// compares the analyst's resolution to this value and decides
// whether to flip.
//
// If the row already carries a non-empty FinalVerdict (a prior
// analyst flip), that takes precedence — the resolver
// compares against the most-recent authoritative call, not the
// stale automated baseline.
//
// Mapping (mirrors the banner-renderer's tier palette
// semantics):
//
//   - Blocked / HighRisk      → malicious
//   - Warning / Caution       → suspicious
//   - Informational / Trusted → benign
//
// "quarantine" is an action, not a verdict (see migration
// 0021 doc block) and is enforced at the tier-decider; not
// part of the analyst-overridable verdict set.
func automatedVerdict(r *repository.EvaluationResult) string {
	if r == nil {
		return ""
	}
	if r.FinalVerdict != "" {
		return r.FinalVerdict
	}
	switch constant.Tier(r.Tier) {
	case constant.TierBlocked, constant.TierHighRisk:
		return verdictMalicious
	case constant.TierWarning, constant.TierCaution:
		return verdictSuspicious
	case constant.TierInformational, constant.TierTrusted:
		return verdictBenign
	}
	return ""
}

// flipFor decides whether to issue a final_verdict UPDATE and
// what the new value should be. Returns the (newVerdict, flip)
// pair; flip == false means the resolver takes the noop path
// (audit row records confirmation, no DB UPDATE, no banner).
//
// Mapping per WS-5A.6 spec section "Scope" bullet 2:
//
//   - confirmed_threat + automated ∈ {benign, suspicious}
//     → reclassify to malicious, flip = true.
//   - confirmed_threat + automated == malicious
//     → confirmation; noop.
//   - false_positive  + automated ∈ {malicious, suspicious}
//     → reclassify to benign, flip = true.
//   - false_positive  + automated == benign
//     → confirmation; noop.
//   - benign         + automated == benign / suspicious
//     → confirmation; noop (telemetry).
//   - benign         + automated == malicious
//     → DOWNGRADE to benign, flip = true (the analyst is
//     overruling the platform; treat as false_positive).
//   - inconclusive   + anything
//     → noop. The analyst couldn't decide; we don't override.
func flipFor(resolution, automated string) (string, bool) {
	switch resolution {
	case ResolutionConfirmedThreat:
		if automated == verdictMalicious {
			return "", false
		}
		return verdictMalicious, true
	case ResolutionFalsePositive:
		if automated == verdictBenign {
			return "", false
		}
		return verdictBenign, true
	case ResolutionBenign:
		if automated == verdictMalicious {
			return verdictBenign, true
		}
		return "", false
	case ResolutionInconclusive:
		return "", false
	}
	return "", false
}

// composeReason builds the audit-row `reason` field from
// the analyst notes + the resolution token. Format keeps the
// resolution at the front so a fan-out search (SELECT … LIKE
// 'confirmed_threat%') stays cheap.
func composeReason(notes, resolution string) string {
	notes = strings.TrimSpace(notes)
	if notes == "" {
		return resolution
	}
	return resolution + ": " + notes
}

// composeBannerReason builds the user-visible banner copy for
// the reopen path. Mirrors the banner-renderer's "what
// changed" microcopy style. Truncates to a sane length so the
// recipient mailbox doesn't render a wall of text.
func composeBannerReason(resolution, notes string) string {
	notes = strings.TrimSpace(notes)
	prefix := "Updated by SOC analyst: " + resolution
	if notes == "" {
		return prefix
	}
	// Mirror the producer-side MaxAnalystNotesBytes cap so a
	// pathological note can't bloat the banner HTML. 256
	// chars is comfortably above the rendered-in-a-banner
	// length budget and below any wire / cell-format ceiling.
	const maxBannerNoteChars = 256
	if len(notes) > maxBannerNoteChars {
		notes = notes[:maxBannerNoteChars-1] + "…"
	}
	return prefix + " — " + notes
}

// persistSkip is the unhappy-path helper. Builds an audit row
// recording why the resolver could not reconcile, persists it
// (still via INSERT-ON-CONFLICT so a re-delivery doesn't
// double-stamp), and returns an OutcomeSkipped envelope.
//
// `messageIDHash` may be empty when the resolver could not
// derive one (no email link); that's fine — the audit row's
// pseudo_message_id column is non-empty when we did derive
// one but no row matched, empty otherwise.
func (r *Resolver) persistSkip(ctx context.Context, ev IncidentResolved, _ []byte, reason string) (Outcome, error) {
	if reason == "" {
		reason = "no findable evaluation row"
	}
	full := composeReason(ev.AnalystNotes, ev.Resolution) + " [skip: " + reason + "]"
	row := &repository.EmailVerdictAudit{
		TenantID:         ev.TenantID,
		DedupID:          ev.DedupID,
		PseudoMessageID:  pseudoMessageIDFor(ev),
		Resolution:       ev.Resolution,
		ResolvedBy:       ev.ResolvedBy,
		ResolvedAt:       ev.ResolvedAt,
		SourceIncidentID: ev.IncidentID,
		Reason:           full,
	}
	inserted, err := r.audits.Insert(ctx, row)
	if err != nil {
		return Outcome{}, fmt.Errorf("escalation: audit insert (skip): %w", err)
	}
	out := Outcome{
		Kind:    OutcomeSkipped,
		AuditID: row.ID,
		Reason:  full,
	}
	if !inserted {
		out.Kind = OutcomeDuplicate
	}
	return out, nil
}
