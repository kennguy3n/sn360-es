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
