package action

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// stubReevaluator returns a canned EvaluateResult or error.
type stubReevaluator struct {
	verdict dto.EvaluateResult
	err     error
}

func (s stubReevaluator) Reevaluate(_ context.Context, _ string, _ string) (dto.EvaluateResult, error) {
	return s.verdict, s.err
}

func mustQuarantine(t *testing.T, svc *QuarantineService) {
	t.Helper()
	ctx := context.Background()
	if _, err := svc.Quarantine(ctx, QuarantineRequest{
		Tenant:               "acme",
		PseudonymizedMessage: "msg-1",
		Provider:             LabelProviderGmail,
		Email:                "user@acme.com",
		MessageID:            "raw-1",
		Tier:                 constant.TierBlocked,
		Primary:              constant.CategoryLikelyPhishing,
	}); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}
}

func TestRelease_AllowedRestoresMessage(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "Label_99")
	pub := &recordingPublisher{}
	qsvc, _ := newQuarantineForTest(t, prov, pub)
	mustQuarantine(t, qsvc)

	reev := stubReevaluator{
		verdict: dto.EvaluateResult{
			Tier:    constant.TierInformational,
			Primary: constant.CategoryFirstContactExternal,
		},
	}
	rsvc, err := NewReleaseService(ReleaseConfig{
		Quarantine:  qsvc,
		Reevaluator: reev,
		Publisher:   pub,
	})
	if err != nil {
		t.Fatalf("NewReleaseService: %v", err)
	}
	outcome, err := rsvc.Release(ctx, ReleaseRequest{
		TenantID:             "acme",
		PseudonymizedMessage: "msg-1",
		RequestedBy:          "user-hash",
	})
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if outcome.Reason != ReleaseAllowed {
		t.Fatalf("reason: got %q want allowed", outcome.Reason)
	}
	if !outcome.Restored {
		t.Fatal("expected Restored=true")
	}
	if len(prov.restoreCalls) != 1 {
		t.Fatalf("expected 1 restore call, got %d", len(prov.restoreCalls))
	}
	// Reference should be cleared after restoration.
	if _, found, _ := qsvc.LookupReference(ctx, "acme", "msg-1"); found {
		t.Fatal("expected reference cleared")
	}
	// Two events published: applied + release.
	if got := pub.lastSubject(); got != "es.action.quarantine.release" {
		t.Fatalf("last subject: got %q", got)
	}
}

func TestRelease_RefusedKeepsQuarantine(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "Label_99")
	pub := &recordingPublisher{}
	qsvc, _ := newQuarantineForTest(t, prov, pub)
	mustQuarantine(t, qsvc)

	reev := stubReevaluator{
		verdict: dto.EvaluateResult{
			Tier:        constant.TierBlocked,
			Primary:     constant.CategoryBECImpersonation,
			Secondary:   []constant.Category{constant.CategoryLookalikeDomain},
			ReasonCodes: []string{"lookalike_domain"},
		},
	}
	rsvc, err := NewReleaseService(ReleaseConfig{
		Quarantine:  qsvc,
		Reevaluator: reev,
		Publisher:   pub,
	})
	if err != nil {
		t.Fatalf("NewReleaseService: %v", err)
	}
	outcome, err := rsvc.Release(ctx, ReleaseRequest{
		TenantID:             "acme",
		PseudonymizedMessage: "msg-1",
	})
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if outcome.Reason != ReleaseRefused {
		t.Fatalf("reason: got %q want refused", outcome.Reason)
	}
	if outcome.Restored {
		t.Fatal("expected Restored=false")
	}
	if len(prov.restoreCalls) != 0 {
		t.Fatalf("expected no restore calls, got %d", len(prov.restoreCalls))
	}
	if _, found, _ := qsvc.LookupReference(ctx, "acme", "msg-1"); !found {
		t.Fatal("expected reference preserved")
	}
	if len(outcome.Explanations) == 0 {
		t.Fatal("expected explanations on refusal")
	}
	if outcome.ReportPath == "" {
		t.Fatal("expected report path on refusal")
	}
}

func TestRelease_NotFoundDoesNotRestore(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "Label_99")
	pub := &recordingPublisher{}
	qsvc, _ := newQuarantineForTest(t, prov, pub)

	rsvc, err := NewReleaseService(ReleaseConfig{
		Quarantine:  qsvc,
		Reevaluator: stubReevaluator{},
		Publisher:   pub,
	})
	if err != nil {
		t.Fatalf("NewReleaseService: %v", err)
	}
	outcome, err := rsvc.Release(ctx, ReleaseRequest{
		TenantID:             "acme",
		PseudonymizedMessage: "missing",
	})
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if outcome.Reason != ReleaseNotFound {
		t.Fatalf("reason: got %q want not_found", outcome.Reason)
	}
	if len(prov.restoreCalls) != 0 {
		t.Fatal("expected no provider calls")
	}
}

func TestRelease_PropagatesReevaluatorError(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "Label_99")
	qsvc, _ := newQuarantineForTest(t, prov, &recordingPublisher{})
	mustQuarantine(t, qsvc)

	rsvc, err := NewReleaseService(ReleaseConfig{
		Quarantine:  qsvc,
		Reevaluator: stubReevaluator{err: errors.New("boom")},
	})
	if err != nil {
		t.Fatalf("NewReleaseService: %v", err)
	}
	if _, err := rsvc.Release(ctx, ReleaseRequest{
		TenantID:             "acme",
		PseudonymizedMessage: "msg-1",
	}); err == nil {
		t.Fatal("expected reevaluator error")
	}
}

func TestRelease_EventEnvelopeHasReason(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "Label_99")
	pub := &recordingPublisher{}
	qsvc, _ := newQuarantineForTest(t, prov, pub)
	mustQuarantine(t, qsvc)

	rsvc, err := NewReleaseService(ReleaseConfig{
		Quarantine: qsvc,
		Reevaluator: stubReevaluator{
			verdict: dto.EvaluateResult{Tier: constant.TierCaution},
		},
		Publisher: pub,
	})
	if err != nil {
		t.Fatalf("NewReleaseService: %v", err)
	}
	if _, err := rsvc.Release(ctx, ReleaseRequest{
		TenantID:             "acme",
		PseudonymizedMessage: "msg-1",
	}); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// Find the release event in the publisher recording.
	var releaseEnv map[string]any
	for _, e := range pub.events {
		if e.subject == "es.action.quarantine.release" {
			if err := json.Unmarshal(e.data, &releaseEnv); err != nil {
				t.Fatalf("unmarshal release event: %v", err)
			}
		}
	}
	if releaseEnv == nil {
		t.Fatal("expected release event published")
	}
	if releaseEnv["reason"] != "allowed" {
		t.Fatalf("reason in event: %v", releaseEnv["reason"])
	}
}

// TestRelease_ConcurrentClaimsDeduplicate proves the
// ClaimReference-based fencing path: when two release flows run
// concurrently against the same (tenant, pseudoMessage), exactly
// one wins the atomic GETDEL and calls RestoreFromQuarantine; the
// loser observes the missing reference and returns
// ReleaseAlreadyDone. This is the application-layer guarantee that
// defends against split-brain Redis lock failures.
func TestRelease_ConcurrentClaimsDeduplicate(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "Label_99")
	pub := &recordingPublisher{}
	qsvc, _ := newQuarantineForTest(t, prov, pub)
	mustQuarantine(t, qsvc)

	rsvc, err := NewReleaseService(ReleaseConfig{
		Quarantine: qsvc,
		Reevaluator: stubReevaluator{
			verdict: dto.EvaluateResult{
				Tier:    constant.TierInformational,
				Primary: constant.CategoryFirstContactExternal,
			},
		},
		Publisher: pub,
	})
	if err != nil {
		t.Fatalf("NewReleaseService: %v", err)
	}

	type result struct {
		outcome ReleaseOutcome
		err     error
	}
	const replicas = 8
	results := make(chan result, replicas)
	start := make(chan struct{})
	for i := 0; i < replicas; i++ {
		go func() {
			<-start
			o, e := rsvc.Release(ctx, ReleaseRequest{
				TenantID:             "acme",
				PseudonymizedMessage: "msg-1",
			})
			results <- result{outcome: o, err: e}
		}()
	}
	close(start)

	// Losers can show up as either ReleaseAlreadyDone (their
	// LookupReference saw the record, their ClaimReference lost
	// the race) or ReleaseNotFound (their LookupReference happened
	// AFTER the winner's claim cleared the record). Both are
	// "no-op, no second restore" outcomes and equally valid — the
	// fencing guarantee under test is that exactly one replica
	// reaches RestoreFromQuarantine, not which return code the
	// other replicas surface.
	var allowed, noop int
	for i := 0; i < replicas; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("Release: %v", r.err)
		}
		switch r.outcome.Reason {
		case ReleaseAllowed:
			allowed++
		case ReleaseAlreadyDone, ReleaseNotFound:
			noop++
		default:
			t.Fatalf("unexpected reason: %v", r.outcome.Reason)
		}
	}
	if allowed != 1 {
		t.Fatalf("expected exactly 1 ReleaseAllowed, got %d (noop=%d)", allowed, noop)
	}
	if noop != replicas-1 {
		t.Fatalf("expected %d no-op outcomes, got %d", replicas-1, noop)
	}
	if len(prov.restoreCalls) != 1 {
		t.Fatalf("expected exactly 1 RestoreFromQuarantine call, got %d", len(prov.restoreCalls))
	}
}

// TestRelease_RestoreFailureRepersistsRecord proves the recovery
// invariant: if the provider RestoreFromQuarantine call fails AFTER
// ClaimReference removed the encrypted blob, the release service
// must re-persist so a subsequent attempt can retry. A naive
// claim-and-restore implementation would lose the record on
// transient provider outages.
func TestRelease_RestoreFailureRepersistsRecord(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "Label_99")
	prov.restoreErr = errors.New("provider 503")
	pub := &recordingPublisher{}
	qsvc, _ := newQuarantineForTest(t, prov, pub)
	mustQuarantine(t, qsvc)

	rsvc, err := NewReleaseService(ReleaseConfig{
		Quarantine: qsvc,
		Reevaluator: stubReevaluator{
			verdict: dto.EvaluateResult{
				Tier:    constant.TierInformational,
				Primary: constant.CategoryFirstContactExternal,
			},
		},
		Publisher: pub,
	})
	if err != nil {
		t.Fatalf("NewReleaseService: %v", err)
	}
	if _, err := rsvc.Release(ctx, ReleaseRequest{
		TenantID:             "acme",
		PseudonymizedMessage: "msg-1",
	}); err == nil {
		t.Fatal("expected restore failure error")
	}
	if _, found, lerr := qsvc.LookupReference(ctx, "acme", "msg-1"); !found {
		t.Fatalf("expected reference re-persisted after restore failure; found=%v err=%v", found, lerr)
	}
}
