package selfrelease

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// fakeQuarantine implements QuarantineLookup. The map is keyed by
// (tenant, pseudoMessage). A missing key returns found=false; an
// entry with an error returns it.
type fakeQuarantine struct {
	mu      sync.Mutex
	records map[string]action.QuarantineRecord
	err     error
}

func newFakeQuarantine() *fakeQuarantine {
	return &fakeQuarantine{records: map[string]action.QuarantineRecord{}}
}

func (f *fakeQuarantine) key(t, p string) string { return t + "|" + p }

// put stores rec under (tenant, pmid). The QuarantineRecord type
// itself does not carry the pseudonymised id (it's the lookup key),
// so we accept it as an explicit argument here.
func (f *fakeQuarantine) put(tenant, pmid string, rec action.QuarantineRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec.Tenant = tenant
	f.records[f.key(tenant, pmid)] = rec
}

func (f *fakeQuarantine) LookupReference(_ context.Context, tenant, pmid string) (action.QuarantineRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return action.QuarantineRecord{}, false, f.err
	}
	rec, ok := f.records[f.key(tenant, pmid)]
	return rec, ok, nil
}

// fakeRunner satisfies ReleaseRunner. The next-up outcomes are
// returned in order; if there are no queued outcomes, the static
// default applies. Tests that want a single response can use the
// default; tests that exercise a sequence (e.g. release-then-
// already-done) push multiple.
type fakeRunner struct {
	mu       sync.Mutex
	calls    int
	queue    []action.ReleaseOutcome
	queueErr []error
	def      action.ReleaseOutcome
	defErr   error
}

func (f *fakeRunner) push(out action.ReleaseOutcome, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, out)
	f.queueErr = append(f.queueErr, err)
}

func (f *fakeRunner) Release(_ context.Context, req action.ReleaseRequest) (action.ReleaseOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if len(f.queue) > 0 {
		out := f.queue[0]
		err := f.queueErr[0]
		f.queue = f.queue[1:]
		f.queueErr = f.queueErr[1:]
		return out, err
	}
	if f.defErr != nil {
		return action.ReleaseOutcome{}, f.defErr
	}
	// Default success outcome — restored=true so we can
	// detect inadvertent direct-runner calls in tests that
	// expected to short-circuit earlier.
	_ = req
	return f.def, nil
}

func newServiceUnderTest(t *testing.T, opts ...func(*Config)) (*Service, *fakeQuarantine, *fakeRunner, repository.QuarantineReleaseAuditRepository, repository.TenantReleasePolicyRepository) {
	t.Helper()
	q := newFakeQuarantine()
	r := &fakeRunner{def: action.ReleaseOutcome{
		Reason:   action.ReleaseAllowed,
		Restored: true,
		Verdict:  dto.EvaluateResult{Tier: constant.TierInformational},
	}}
	audit := repository.NewMemoryQuarantineReleaseAudit()
	policies := repository.NewMemoryTenantReleasePolicy()
	cfg := Config{
		Quarantine:      q,
		Runner:          r,
		Audit:           audit,
		Policies:        policies,
		RateLimitWindow: time.Hour,
		Clock:           func() time.Time { return time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	for _, o := range opts {
		o(&cfg)
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, q, r, audit, policies
}

// TestService_RejectsInvalidInputs covers the upfront input
// validation in Release: missing tenant_id, missing
// pseudo_message_id, missing recipient_user_hash. Each must error
// without writing an audit row or touching the quarantine
// repository (we audit-failure-only when the handler called us
// post-token-decode).
func TestService_RejectsInvalidInputs(t *testing.T) {
	svc, _, runner, audit, _ := newServiceUnderTest(t)
	ctx := context.Background()
	hash := []byte("recipient-hash")

	cases := []Request{
		{TenantID: "", PseudoMessageID: "p", RecipientUserHash: hash},
		{TenantID: "t", PseudoMessageID: "", RecipientUserHash: hash},
		{TenantID: "t", PseudoMessageID: "p", RecipientUserHash: nil},
	}
	for i, req := range cases {
		_, err := svc.Release(ctx, req)
		if err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
	if runner.calls != 0 {
		t.Fatalf("runner unexpectedly called %d times", runner.calls)
	}
	entries, err := audit.ListByMessage(ctx, "t", "p", 10)
	if err != nil {
		t.Fatalf("ListByMessage: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("audit row written on bad input: %+v", entries)
	}
}

// TestService_NotFound is the cross-tenant indistinguishability
// path: lookup returns not-found, service writes a not_found
// audit row, no runner call.
func TestService_NotFound(t *testing.T) {
	svc, _, runner, audit, _ := newServiceUnderTest(t)
	ctx := context.Background()

	res, err := svc.Release(ctx, Request{
		TenantID:          "acme",
		PseudoMessageID:   "pmid-does-not-exist",
		RecipientUserHash: []byte("rh"),
	})
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if res.Outcome != repository.QuarantineReleaseOutcomeNotFound {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	if res.Restored {
		t.Fatal("Restored should be false on not_found")
	}
	if runner.calls != 0 {
		t.Fatalf("runner called on not_found path: %d", runner.calls)
	}
	entries, _ := audit.ListByMessage(ctx, "acme", "pmid-does-not-exist", 10)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one audit row, got %d", len(entries))
	}
	if entries[0].Outcome != repository.QuarantineReleaseOutcomeNotFound {
		t.Fatalf("audit outcome=%q", entries[0].Outcome)
	}
}

// TestService_Tier2BlockedIsUnconditional verifies the tier-2
// gate fires BEFORE the rate-limit gate and BEFORE the runner.
// We deliberately set a generous per-hour cap so a stuck gate
// would have let this through.
func TestService_Tier2BlockedIsUnconditional(t *testing.T) {
	svc, q, runner, audit, policies := newServiceUnderTest(t)
	ctx := context.Background()
	_ = policies.Upsert(ctx, repository.TenantReleasePolicy{
		TenantID:                     "acme",
		QuarantineSelfReleasePerHour: 1000,
	})
	q.put("acme", "pmid-1", action.QuarantineRecord{Tier2Malicious: true})

	res, err := svc.Release(ctx, Request{
		TenantID:          "acme",
		PseudoMessageID:   "pmid-1",
		RecipientUserHash: []byte("rh"),
	})
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if res.Outcome != repository.QuarantineReleaseOutcomeTier2Blocked {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	if runner.calls != 0 {
		t.Fatalf("runner called on tier-2 block path: %d", runner.calls)
	}
	entries, _ := audit.ListByMessage(ctx, "acme", "pmid-1", 10)
	if len(entries) != 1 || entries[0].Outcome != repository.QuarantineReleaseOutcomeTier2Blocked {
		t.Fatalf("audit entries=%+v", entries)
	}
}

// TestService_RateLimited covers both the explicit "tenant
// disabled" (per_hour=0) and the "exceeded cap" branches.
// Audited as rate_limited in both cases, reason field
// distinguishes them.
func TestService_RateLimited(t *testing.T) {
	t.Run("tenant disabled", func(t *testing.T) {
		svc, q, runner, audit, policies := newServiceUnderTest(t)
		ctx := context.Background()
		_ = policies.Upsert(ctx, repository.TenantReleasePolicy{
			TenantID:                     "acme",
			QuarantineSelfReleasePerHour: 0, // explicit disable
		})
		q.put("acme", "pmid-1", action.QuarantineRecord{})

		res, err := svc.Release(ctx, Request{
			TenantID: "acme", PseudoMessageID: "pmid-1", RecipientUserHash: []byte("rh"),
		})
		if err != nil {
			t.Fatalf("Release: %v", err)
		}
		if res.Outcome != repository.QuarantineReleaseOutcomeRateLimited {
			t.Fatalf("outcome=%q", res.Outcome)
		}
		if runner.calls != 0 {
			t.Fatalf("runner called on rate-limit path: %d", runner.calls)
		}
		if !strings.Contains(res.Reason, "disabled") {
			t.Fatalf("expected disabled reason, got %q", res.Reason)
		}
		entries, _ := audit.ListByMessage(ctx, "acme", "pmid-1", 10)
		if len(entries) != 1 {
			t.Fatalf("expected one audit row, got %d", len(entries))
		}
	})

	t.Run("exceeded cap", func(t *testing.T) {
		svc, q, runner, audit, policies := newServiceUnderTest(t)
		ctx := context.Background()
		// Cap of 2 → third attempt is rate-limited. Seed two
		// pre-existing audit entries inside the window.
		_ = policies.Upsert(ctx, repository.TenantReleasePolicy{
			TenantID:                     "acme",
			QuarantineSelfReleasePerHour: 2,
		})
		q.put("acme", "pmid-1", action.QuarantineRecord{})

		recHash := []byte("rh")
		for i := 0; i < 2; i++ {
			_, err := audit.Record(ctx, repository.QuarantineReleaseAuditEntry{
				TenantID:          "acme",
				PseudoMessageID:   "pmid-other",
				RecipientUserHash: recHash,
				Outcome:           repository.QuarantineReleaseOutcomeReleased,
				Reason:            "seed",
				RequestedAt:       time.Date(2025, 1, 2, 3, 0, 0, 0, time.UTC),
			})
			if err != nil {
				t.Fatalf("seed audit %d: %v", i, err)
			}
		}

		res, err := svc.Release(ctx, Request{
			TenantID: "acme", PseudoMessageID: "pmid-1", RecipientUserHash: recHash,
		})
		if err != nil {
			t.Fatalf("Release: %v", err)
		}
		if res.Outcome != repository.QuarantineReleaseOutcomeRateLimited {
			t.Fatalf("outcome=%q", res.Outcome)
		}
		if runner.calls != 0 {
			t.Fatalf("runner called on rate-limit path: %d", runner.calls)
		}
		if !strings.Contains(res.Reason, "exceeded") {
			t.Fatalf("expected exceeded reason, got %q", res.Reason)
		}
	})
}

// TestService_RateLimit_PerRecipientNotPerTenant verifies the
// bucket key is the recipient_user_hash, not the tenant: a noisy
// recipient cannot burn another recipient's quota.
func TestService_RateLimit_PerRecipientNotPerTenant(t *testing.T) {
	svc, q, _, audit, policies := newServiceUnderTest(t)
	ctx := context.Background()
	_ = policies.Upsert(ctx, repository.TenantReleasePolicy{
		TenantID:                     "acme",
		QuarantineSelfReleasePerHour: 1, // cap of 1 per recipient
	})
	q.put("acme", "pmid-1", action.QuarantineRecord{})

	noisyHash := []byte("noisy")
	quietHash := []byte("quiet")
	// Seed: noisy already used their one allowance.
	_, _ = audit.Record(ctx, repository.QuarantineReleaseAuditEntry{
		TenantID:          "acme",
		PseudoMessageID:   "pmid-other",
		RecipientUserHash: noisyHash,
		Outcome:           repository.QuarantineReleaseOutcomeReleased,
		RequestedAt:       time.Date(2025, 1, 2, 3, 0, 0, 0, time.UTC),
	})

	// Noisy is blocked
	res, err := svc.Release(ctx, Request{
		TenantID: "acme", PseudoMessageID: "pmid-1", RecipientUserHash: noisyHash,
	})
	if err != nil || res.Outcome != repository.QuarantineReleaseOutcomeRateLimited {
		t.Fatalf("noisy: outcome=%q err=%v", res.Outcome, err)
	}
	// Quiet is allowed (the noisy recipient's entry doesn't
	// affect the quiet bucket).
	res, err = svc.Release(ctx, Request{
		TenantID: "acme", PseudoMessageID: "pmid-1", RecipientUserHash: quietHash,
	})
	if err != nil || res.Outcome != repository.QuarantineReleaseOutcomeReleased {
		t.Fatalf("quiet: outcome=%q err=%v", res.Outcome, err)
	}
}

// TestService_Released_HappyPath exercises the full release path
// through the runner. Default runner returns ReleaseAllowed.
func TestService_Released_HappyPath(t *testing.T) {
	svc, q, runner, audit, policies := newServiceUnderTest(t)
	ctx := context.Background()
	_ = policies.Upsert(ctx, repository.TenantReleasePolicy{
		TenantID:                     "acme",
		QuarantineSelfReleasePerHour: 5,
	})
	q.put("acme", "pmid-1", action.QuarantineRecord{})

	res, err := svc.Release(ctx, Request{
		TenantID:          "acme",
		PseudoMessageID:   "pmid-1",
		RecipientUserHash: []byte{0xde, 0xad},
		CorrelationID:     "corr-1",
	})
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if res.Outcome != repository.QuarantineReleaseOutcomeReleased {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	if !res.Restored {
		t.Fatal("expected Restored=true")
	}
	if runner.calls != 1 {
		t.Fatalf("runner.calls=%d", runner.calls)
	}
	entries, _ := audit.ListByMessage(ctx, "acme", "pmid-1", 10)
	if len(entries) != 1 || entries[0].Outcome != repository.QuarantineReleaseOutcomeReleased {
		t.Fatalf("audit=%+v", entries)
	}
	if entries[0].CorrelationID != "corr-1" {
		t.Fatalf("correlation_id not threaded: %q", entries[0].CorrelationID)
	}
}

// TestService_RunnerOutcomeMapping covers each ReleaseReason →
// Outcome translation in fromRunnerOutcome.
func TestService_RunnerOutcomeMapping(t *testing.T) {
	cases := []struct {
		name    string
		runOut  action.ReleaseOutcome
		runErr  error
		want    repository.QuarantineReleaseOutcome
		wantErr bool
	}{
		{
			name:   "allowed -> released",
			runOut: action.ReleaseOutcome{Reason: action.ReleaseAllowed, Restored: true},
			want:   repository.QuarantineReleaseOutcomeReleased,
		},
		{
			name:   "already_done -> already_released",
			runOut: action.ReleaseOutcome{Reason: action.ReleaseAlreadyDone},
			want:   repository.QuarantineReleaseOutcomeAlreadyReleased,
		},
		{
			name:   "not_found -> not_found (race)",
			runOut: action.ReleaseOutcome{Reason: action.ReleaseNotFound},
			want:   repository.QuarantineReleaseOutcomeNotFound,
		},
		{
			name: "refused -> release_refused (NOT tier2_blocked: runner refusal can be any safety-stack reason, not just tier-2)",
			runOut: action.ReleaseOutcome{
				Reason:       action.ReleaseRefused,
				Explanations: []string{"reeval said no"},
			},
			want: repository.QuarantineReleaseOutcomeReleaseRefused,
		},
		{
			name:   "unknown -> not_found (fallback)",
			runOut: action.ReleaseOutcome{Reason: action.ReleaseReason("mystery")},
			want:   repository.QuarantineReleaseOutcomeNotFound,
		},
		{
			name:    "runner error bubbles up",
			runErr:  errors.New("boom"),
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, q, runner, _, policies := newServiceUnderTest(t)
			ctx := context.Background()
			_ = policies.Upsert(ctx, repository.TenantReleasePolicy{
				TenantID:                     "acme",
				QuarantineSelfReleasePerHour: 5,
			})
			q.put("acme", "pmid-1", action.QuarantineRecord{})
			runner.push(tc.runOut, tc.runErr)

			res, err := svc.Release(ctx, Request{
				TenantID: "acme", PseudoMessageID: "pmid-1", RecipientUserHash: []byte("rh"),
			})
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Release: %v", err)
			}
			if res.Outcome != tc.want {
				t.Fatalf("outcome=%q want=%q", res.Outcome, tc.want)
			}
		})
	}
}

// TestService_AuditAuthFailure covers the handler-driven audit
// path for token-expired / invalid-token outcomes.
func TestService_AuditAuthFailure(t *testing.T) {
	svc, _, _, audit, _ := newServiceUnderTest(t)
	ctx := context.Background()

	t.Run("invalid_token writes a row", func(t *testing.T) {
		_, err := svc.AuditAuthFailure(ctx, "acme", "pmid-1", []byte{0xab}, "corr-1",
			repository.QuarantineReleaseOutcomeInvalidToken, "sig mismatch")
		if err != nil {
			t.Fatalf("AuditAuthFailure: %v", err)
		}
		entries, _ := audit.ListByMessage(ctx, "acme", "pmid-1", 10)
		if len(entries) != 1 || entries[0].Outcome != repository.QuarantineReleaseOutcomeInvalidToken {
			t.Fatalf("entries=%+v", entries)
		}
	})

	t.Run("expired writes a row", func(t *testing.T) {
		_, err := svc.AuditAuthFailure(ctx, "acme", "pmid-2", []byte{0xab}, "",
			repository.QuarantineReleaseOutcomeTokenExpired, "exp in past")
		if err != nil {
			t.Fatalf("AuditAuthFailure: %v", err)
		}
		entries, _ := audit.ListByMessage(ctx, "acme", "pmid-2", 10)
		if len(entries) != 1 || entries[0].Outcome != repository.QuarantineReleaseOutcomeTokenExpired {
			t.Fatalf("entries=%+v", entries)
		}
	})

	t.Run("missing tenant skips audit", func(t *testing.T) {
		entry, err := svc.AuditAuthFailure(ctx, "", "pmid-3", []byte{0xab}, "",
			repository.QuarantineReleaseOutcomeInvalidToken, "no tenant")
		if err != nil {
			t.Fatalf("AuditAuthFailure: %v", err)
		}
		if entry.TenantID != "" {
			t.Fatalf("unexpected audit row written for empty tenant")
		}
	})

	t.Run("coerces unknown outcome", func(t *testing.T) {
		entry, err := svc.AuditAuthFailure(ctx, "acme", "pmid-4", []byte{0xab}, "",
			repository.QuarantineReleaseOutcome("bogus"), "weird")
		if err != nil {
			t.Fatalf("AuditAuthFailure: %v", err)
		}
		if entry.Outcome != repository.QuarantineReleaseOutcomeInvalidToken {
			t.Fatalf("outcome=%q", entry.Outcome)
		}
		if !strings.Contains(entry.Reason, "coerced outcome") {
			t.Fatalf("reason=%q", entry.Reason)
		}
	})

	t.Run("empty recipient hash gets sentinel byte", func(t *testing.T) {
		entry, err := svc.AuditAuthFailure(ctx, "acme", "pmid-5", nil, "",
			repository.QuarantineReleaseOutcomeInvalidToken, "no hash")
		if err != nil {
			t.Fatalf("AuditAuthFailure: %v", err)
		}
		if len(entry.RecipientUserHash) != 1 || entry.RecipientUserHash[0] != 0x00 {
			t.Fatalf("recipient_user_hash=%v", entry.RecipientUserHash)
		}
	})
}

// TestService_LookupErrorBubbles ensures a quarantine-store
// outage surfaces as an error (the handler will 503), not as a
// silently-audited not_found row that would mask the outage.
func TestService_LookupErrorBubbles(t *testing.T) {
	svc, q, _, audit, _ := newServiceUnderTest(t)
	q.err = errors.New("redis down")

	_, err := svc.Release(context.Background(), Request{
		TenantID: "acme", PseudoMessageID: "pmid-1", RecipientUserHash: []byte("rh"),
	})
	if err == nil {
		t.Fatal("expected lookup error")
	}
	entries, _ := audit.ListByMessage(context.Background(), "acme", "pmid-1", 10)
	if len(entries) != 0 {
		t.Fatalf("audit row written on lookup error: %+v", entries)
	}
}

// TestService_NewService_RejectsMissingDeps protects the
// constructor contract.
func TestService_NewService_RejectsMissingDeps(t *testing.T) {
	q := newFakeQuarantine()
	r := &fakeRunner{}
	a := repository.NewMemoryQuarantineReleaseAudit()
	p := repository.NewMemoryTenantReleasePolicy()
	cases := []Config{
		{Runner: r, Audit: a, Policies: p},
		{Quarantine: q, Audit: a, Policies: p},
		{Quarantine: q, Runner: r, Policies: p},
		{Quarantine: q, Runner: r, Audit: a},
	}
	for i, c := range cases {
		if _, err := NewService(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}
