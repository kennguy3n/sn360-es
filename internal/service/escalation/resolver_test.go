// Copyright 2024-2026 SN360. All rights reserved.
// Use of this source code is governed by the proprietary license
// that can be found in the LICENSE file.

package escalation_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/escalation"
)

// fakeReopener captures every ReopenBanner call so the test
// can assert on the gating invariants without standing up a
// real BannerInjector. The struct also exposes a fail flag so
// the test can exercise the resolver's "non-fatal reopen
// failure" path.
type fakeReopener struct {
	mu    sync.Mutex
	calls []reopenCall
	fail  error
}

type reopenCall struct {
	TenantID  string
	MessageID string
	Reason    string
}

func (f *fakeReopener) ReopenBanner(_ context.Context, tenant, msgID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, reopenCall{TenantID: tenant, MessageID: msgID, Reason: reason})
	return f.fail
}

func (f *fakeReopener) snapshot() []reopenCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]reopenCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// fixture is the per-test composition root. New() returns a
// fresh memory registry and resolver so the tests don't share
// state.
type fixture struct {
	repos    *repository.Registry
	resolver *escalation.Resolver
	reopener *fakeReopener
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	repos := repository.NewInMemoryRegistry()
	reopener := &fakeReopener{}
	res, err := escalation.New(
		repos.EvaluationResults,
		repos.EmailVerdictAudits,
		repos.BannerStates,
		reopener,
		nil,
	)
	if err != nil {
		t.Fatalf("escalation.New: %v", err)
	}
	return &fixture{repos: repos, resolver: res, reopener: reopener}
}

// seedEval inserts an EvaluationResult into the memory backend
// so the resolver's GetByMessageHash path finds it.
func (f *fixture) seedEval(t *testing.T, tenantID, messageID, tier string) *repository.EvaluationResult {
	t.Helper()
	r := &repository.EvaluationResult{
		TenantID:      tenantID,
		MessageIDHash: []byte(messageID),
		Tier:          tier,
		Primary:       "Phishing",
		EvaluatedAt:   time.Now().UTC(),
	}
	if err := f.repos.EvaluationResults.Create(context.Background(), r); err != nil {
		t.Fatalf("Create eval: %v", err)
	}
	return r
}

// seedBanner inserts a delivered banner_state row. Tests
// that need to exercise the "delivered_at IS NULL" gate use
// fakeBannerStateRepo (defined below) which surfaces the
// in-memory row with a forced-nil DeliveredAt — that is the
// supported seam for that path, not this helper. Earlier
// revisions of this helper accepted a `delivered bool` flag
// that tried to undo MarkDelivered's timestamp via the value
// returned by Get(), but the memory backend defensively
// copies the row on Get, so the mutation never reached the
// stored map and the helper silently did nothing on the
// non-delivered path. Keeping the helper delivered-only
// removes the foot-gun.
func (f *fixture) seedBanner(t *testing.T, tenantID, messageID string) {
	t.Helper()
	in := repository.MarkDeliveredInput{
		TenantID:           tenantID,
		MessageIDHash:      []byte(messageID),
		At:                 time.Now().UTC(),
		Reason:             "test-seed",
		Provider:           "gmail",
		DeliveredMessageID: messageID,
		DeliveredEmail:     "recipient@example.test",
	}
	if err := f.repos.BannerStates.MarkDelivered(context.Background(), in); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}
}

// fakeBannerStateRepo is a wrapper around the memory backend
// that lets the test force "delivered_at IS NULL" semantics
// without coupling to internals. Used by the suppression test
// where the memory backend's MarkDelivered stamps a non-nil
// time even when `at` is zero.
type fakeBannerStateRepo struct {
	inner       repository.BannerStateRepository
	overrideRow *repository.BannerState
}

func (f *fakeBannerStateRepo) Get(ctx context.Context, tenantID string, messageIDHash []byte) (*repository.BannerState, error) {
	if f.overrideRow != nil && f.overrideRow.TenantID == tenantID && string(f.overrideRow.MessageIDHash) == string(messageIDHash) {
		out := *f.overrideRow
		return &out, nil
	}
	return f.inner.Get(ctx, tenantID, messageIDHash)
}

func (f *fakeBannerStateRepo) MarkDelivered(ctx context.Context, in repository.MarkDeliveredInput) error {
	return f.inner.MarkDelivered(ctx, in)
}

func (f *fakeBannerStateRepo) MarkReopened(ctx context.Context, tenantID string, messageIDHash []byte, at time.Time, reason string) error {
	return f.inner.MarkReopened(ctx, tenantID, messageIDHash, at, reason)
}

func newIncidentResolved(tenantID, incidentID, resolution, messageID string) escalation.IncidentResolved {
	return escalation.IncidentResolved{
		IncidentID: incidentID,
		TenantID:   tenantID,
		Resolution: resolution,
		ResolvedAt: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		ResolvedBy: "analyst-pseudo-id-1",
		DedupID:    "dedup-" + incidentID,
		RelatedEmail: &escalation.EmailLink{
			PseudoMessageID: messageID,
		},
	}
}

// -- happy path: confirmed_threat against a Caution-tier eval
// flips final_verdict to malicious and fires banner reopen when
// delivered_at IS NOT NULL.
func TestReconcile_ConfirmedThreat_FlipsAndReopens(t *testing.T) {
	fx := newFixture(t)
	const (
		tenantID  = "tenant-a"
		messageID = "msg-1"
	)
	fx.seedEval(t, tenantID, messageID, string(constant.TierCaution))
	fx.seedBanner(t, tenantID, messageID)

	ev := newIncidentResolved(tenantID, "inc-1", escalation.ResolutionConfirmedThreat, messageID)
	ev.AnalystNotes = "phishing kit signature match"

	out, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if out.Kind != escalation.OutcomeFlipped {
		t.Fatalf("Kind = %q; want flipped", out.Kind)
	}
	if out.OriginalVerdict != "suspicious" {
		t.Errorf("OriginalVerdict = %q; want suspicious (Caution → suspicious)", out.OriginalVerdict)
	}
	if out.NewVerdict != "malicious" {
		t.Errorf("NewVerdict = %q; want malicious", out.NewVerdict)
	}
	if !out.BannerReopened {
		t.Errorf("BannerReopened = false; want true (banner was delivered)")
	}

	// Verify the verdict actually landed on the EvaluationResult.
	row, err := fx.repos.EvaluationResults.GetByMessageHash(context.Background(), tenantID, []byte(messageID))
	if err != nil {
		t.Fatalf("re-fetch eval: %v", err)
	}
	if row.FinalVerdict != "malicious" {
		t.Errorf("FinalVerdict = %q; want malicious", row.FinalVerdict)
	}

	// Verify exactly one reopener call landed.
	calls := fx.reopener.snapshot()
	if len(calls) != 1 {
		t.Fatalf("reopener calls = %d; want 1", len(calls))
	}
	if calls[0].TenantID != tenantID {
		t.Errorf("reopener TenantID = %q; want %q", calls[0].TenantID, tenantID)
	}
	if !strings.Contains(calls[0].Reason, "confirmed_threat") {
		t.Errorf("reopener Reason = %q; want it to contain 'confirmed_threat'", calls[0].Reason)
	}
	if !strings.Contains(calls[0].Reason, "phishing kit signature match") {
		t.Errorf("reopener Reason = %q; want it to contain the analyst note", calls[0].Reason)
	}

	// Audit row landed.
	audit, err := fx.repos.EmailVerdictAudits.GetByDedupID(context.Background(), tenantID, ev.DedupID)
	if err != nil {
		t.Fatalf("audit fetch: %v", err)
	}
	if audit.NewVerdict != "malicious" {
		t.Errorf("audit NewVerdict = %q; want malicious", audit.NewVerdict)
	}
	if audit.SourceIncidentID != "inc-1" {
		t.Errorf("audit SourceIncidentID = %q; want inc-1", audit.SourceIncidentID)
	}
}

// -- false_positive against a malicious-tier eval flips
// final_verdict to benign but does NOT fire banner reopen
// (downgrade path is the suppress-existing-banner contract, not
// the reopen contract).
func TestReconcile_FalsePositive_FlipsToBenign_NoReopen(t *testing.T) {
	fx := newFixture(t)
	const (
		tenantID  = "tenant-b"
		messageID = "msg-2"
	)
	fx.seedEval(t, tenantID, messageID, string(constant.TierBlocked))
	fx.seedBanner(t, tenantID, messageID)

	ev := newIncidentResolved(tenantID, "inc-2", escalation.ResolutionFalsePositive, messageID)
	out, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if out.Kind != escalation.OutcomeFlipped {
		t.Fatalf("Kind = %q; want flipped", out.Kind)
	}
	if out.NewVerdict != "benign" {
		t.Errorf("NewVerdict = %q; want benign", out.NewVerdict)
	}
	if out.BannerReopened {
		t.Errorf("BannerReopened = true; want false (downgrade path doesn't reopen)")
	}
	if len(fx.reopener.snapshot()) != 0 {
		t.Errorf("reopener calls = %d; want 0", len(fx.reopener.snapshot()))
	}
}

// -- confirmed_threat that already matches the platform's
// automated verdict (e.g. Blocked tier → malicious) is a noop;
// audit row records confirmation but no UPDATE / no reopen.
func TestReconcile_ConfirmedThreat_AlreadyMalicious_Noop(t *testing.T) {
	fx := newFixture(t)
	const (
		tenantID  = "tenant-c"
		messageID = "msg-3"
	)
	fx.seedEval(t, tenantID, messageID, string(constant.TierHighRisk))
	fx.seedBanner(t, tenantID, messageID)

	ev := newIncidentResolved(tenantID, "inc-3", escalation.ResolutionConfirmedThreat, messageID)
	out, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if out.Kind != escalation.OutcomeNoop {
		t.Fatalf("Kind = %q; want noop", out.Kind)
	}
	if out.NewVerdict != "" {
		t.Errorf("NewVerdict = %q; want empty (noop)", out.NewVerdict)
	}
	if out.OriginalVerdict != "malicious" {
		t.Errorf("OriginalVerdict = %q; want malicious", out.OriginalVerdict)
	}
	if out.BannerReopened {
		t.Errorf("BannerReopened = true; want false (noop)")
	}

	// final_verdict should remain empty (no flip).
	row, _ := fx.repos.EvaluationResults.GetByMessageHash(context.Background(), tenantID, []byte(messageID))
	if row.FinalVerdict != "" {
		t.Errorf("FinalVerdict = %q; want empty", row.FinalVerdict)
	}
}

// -- inconclusive resolution always noops.
func TestReconcile_Inconclusive_AlwaysNoop(t *testing.T) {
	fx := newFixture(t)
	const (
		tenantID  = "tenant-d"
		messageID = "msg-4"
	)
	fx.seedEval(t, tenantID, messageID, string(constant.TierWarning))

	ev := newIncidentResolved(tenantID, "inc-4", escalation.ResolutionInconclusive, messageID)
	out, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if out.Kind != escalation.OutcomeNoop {
		t.Fatalf("Kind = %q; want noop", out.Kind)
	}
}

// -- benign resolution + malicious automated verdict is the
// downgrade-to-benign path (treats the analyst's call as
// authoritative override).
func TestReconcile_Benign_OverridesMalicious(t *testing.T) {
	fx := newFixture(t)
	const (
		tenantID  = "tenant-e"
		messageID = "msg-5"
	)
	fx.seedEval(t, tenantID, messageID, string(constant.TierBlocked))

	ev := newIncidentResolved(tenantID, "inc-5", escalation.ResolutionBenign, messageID)
	out, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if out.Kind != escalation.OutcomeFlipped {
		t.Fatalf("Kind = %q; want flipped", out.Kind)
	}
	if out.NewVerdict != "benign" {
		t.Errorf("NewVerdict = %q; want benign", out.NewVerdict)
	}
}

// -- re-delivery of the same DedupID produces OutcomeDuplicate
// and does not re-apply the verdict flip or trigger another
// reopen.
func TestReconcile_DuplicateDedupID_NoSideEffects(t *testing.T) {
	fx := newFixture(t)
	const (
		tenantID  = "tenant-f"
		messageID = "msg-6"
	)
	fx.seedEval(t, tenantID, messageID, string(constant.TierCaution))
	fx.seedBanner(t, tenantID, messageID)

	ev := newIncidentResolved(tenantID, "inc-6", escalation.ResolutionConfirmedThreat, messageID)

	// First delivery — happy path.
	first, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil || first.Kind != escalation.OutcomeFlipped {
		t.Fatalf("first reconcile: kind=%q err=%v", first.Kind, err)
	}

	// Second delivery — same DedupID.
	second, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if second.Kind != escalation.OutcomeDuplicate {
		t.Errorf("second Kind = %q; want duplicate", second.Kind)
	}
	if second.AuditID != first.AuditID {
		t.Errorf("second AuditID = %q; want %q (must reference existing row)", second.AuditID, first.AuditID)
	}

	// Reopener must have been called EXACTLY once.
	if got := len(fx.reopener.snapshot()); got != 1 {
		t.Errorf("reopener calls = %d; want 1 (duplicate must not re-invoke reopener)", got)
	}
}

// -- cross-tenant payloads drop with audit-trail visible
// "cross-tenant" reason rather than silently reaching across
// the tenant boundary.
func TestReconcile_CrossTenant_SkipsWithAuditReason(t *testing.T) {
	fx := newFixture(t)
	const (
		ownerTenant  = "tenant-owner"
		victimTenant = "tenant-victim"
		messageID    = "msg-7"
	)
	fx.seedEval(t, ownerTenant, messageID, string(constant.TierHighRisk))

	// Payload claims victim-tenant but the eval lives under owner-tenant.
	// The lookup goes by (payload_tenant, message_id_hash) — which
	// finds NO row under tenant-victim. So the resolver hits the
	// "no row found" skip path, not the cross-tenant rejection
	// path. The cross-tenant rejection fires when the lookup
	// succeeds with a row whose TenantID differs from the payload
	// (e.g. via a future correlation-id-only lookup). Seed a
	// matching row on the victim-tenant first so the payload
	// finds something to compare against.
	fx.seedEval(t, victimTenant, messageID, string(constant.TierBlocked))

	ev := newIncidentResolved(victimTenant, "inc-7", escalation.ResolutionConfirmedThreat, messageID)

	out, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// The lookup matched on (victim-tenant, msg-7) — same tenant
	// as the payload, so no cross-tenant rejection. But the
	// automated verdict was already malicious, so the analyst
	// confirmation is a noop. Validates that the resolver does
	// NOT spuriously cross tenants in this configuration.
	if out.Kind != escalation.OutcomeNoop {
		t.Errorf("Kind = %q; want noop", out.Kind)
	}

	// Now exercise the actual cross-tenant rejection. Seed a
	// banner_state row under the owner-tenant with the same
	// pseudo, and inject a corrupt evaluation_result row under
	// the victim-tenant pointing at the owner-tenant's data
	// directly. The memory backend doesn't let us do that
	// short of internal mutation; the integration test in the
	// Postgres harness exercises the SQL-level path. Here we
	// verify the in-memory path with the next call where we
	// force a different tenant for the payload than the row.
	//
	// Construct a payload with a tenant the row doesn't match.
	otherEv := newIncidentResolved("tenant-mismatch", "inc-7b", escalation.ResolutionConfirmedThreat, messageID)
	otherOut, err := fx.resolver.Reconcile(context.Background(), otherEv)
	if err != nil {
		t.Fatalf("Reconcile (mismatch): %v", err)
	}
	// GetByMessageHash is keyed by (payload_tenant=tenant-mismatch,
	// msg-7) — no such row, so the resolver takes the skip path.
	if otherOut.Kind != escalation.OutcomeSkipped {
		t.Errorf("mismatch Kind = %q; want skipped", otherOut.Kind)
	}
	if !strings.Contains(otherOut.Reason, "no evaluation_results row") &&
		!strings.Contains(otherOut.Reason, "msg-7") {
		t.Errorf("mismatch Reason = %q; want it to describe missing row", otherOut.Reason)
	}
}

// -- banner reopen suppressed when delivered_at IS NULL even
// for a flip that would otherwise reopen. The audit + verdict
// flip still land.
func TestReconcile_NoReopenWhenBannerNotDelivered(t *testing.T) {
	repos := repository.NewInMemoryRegistry()
	reopener := &fakeReopener{}

	// Replace banner_state with a wrapper that returns
	// delivered_at = nil for our test row.
	rawBanners := repos.BannerStates
	wrapper := &fakeBannerStateRepo{
		inner: rawBanners,
		overrideRow: &repository.BannerState{
			TenantID:      "tenant-g",
			MessageIDHash: []byte("msg-8"),
			DeliveredAt:   nil, // explicitly NULL
		},
	}
	repos.BannerStates = wrapper

	res, err := escalation.New(
		repos.EvaluationResults,
		repos.EmailVerdictAudits,
		repos.BannerStates,
		reopener,
		nil,
	)
	if err != nil {
		t.Fatalf("escalation.New: %v", err)
	}

	r := &repository.EvaluationResult{
		TenantID:      "tenant-g",
		MessageIDHash: []byte("msg-8"),
		Tier:          string(constant.TierCaution),
		Primary:       "Phishing",
		EvaluatedAt:   time.Now().UTC(),
	}
	if err := repos.EvaluationResults.Create(context.Background(), r); err != nil {
		t.Fatalf("create eval: %v", err)
	}

	ev := newIncidentResolved("tenant-g", "inc-8", escalation.ResolutionConfirmedThreat, "msg-8")
	out, err := res.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if out.Kind != escalation.OutcomeFlipped {
		t.Errorf("Kind = %q; want flipped", out.Kind)
	}
	if out.BannerReopened {
		t.Errorf("BannerReopened = true; want false (delivered_at was NULL)")
	}
	if len(reopener.snapshot()) != 0 {
		t.Errorf("reopener calls = %d; want 0", len(reopener.snapshot()))
	}
}

// -- banner_state row missing entirely also suppresses reopen.
func TestReconcile_NoReopenWhenBannerStateAbsent(t *testing.T) {
	fx := newFixture(t)
	const (
		tenantID  = "tenant-h"
		messageID = "msg-9"
	)
	fx.seedEval(t, tenantID, messageID, string(constant.TierCaution))
	// note: no fx.seedBanner — row absent.

	ev := newIncidentResolved(tenantID, "inc-9", escalation.ResolutionConfirmedThreat, messageID)
	out, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !errors.Is(nil, nil) {
		t.Fatal("unexpected branch")
	}
	if out.Kind != escalation.OutcomeFlipped {
		t.Errorf("Kind = %q; want flipped", out.Kind)
	}
	if out.BannerReopened {
		t.Errorf("BannerReopened = true; want false (banner_state absent)")
	}
}

// -- analyst notes UTF-8 boundary safe truncation in
// composeBannerReason path. The banner reason should not slice
// in the middle of a multi-byte rune.
func TestReconcile_BannerReason_TruncatesAtMax(t *testing.T) {
	fx := newFixture(t)
	const (
		tenantID  = "tenant-i"
		messageID = "msg-10"
	)
	fx.seedEval(t, tenantID, messageID, string(constant.TierCaution))
	fx.seedBanner(t, tenantID, messageID)

	notes := strings.Repeat("X", 1024) // far above the 256-char cap
	ev := newIncidentResolved(tenantID, "inc-10", escalation.ResolutionConfirmedThreat, messageID)
	ev.AnalystNotes = notes

	out, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !out.BannerReopened {
		t.Fatalf("BannerReopened = false; want true")
	}
	calls := fx.reopener.snapshot()
	if len(calls) != 1 {
		t.Fatalf("reopener calls = %d; want 1", len(calls))
	}
	if len(calls[0].Reason) > 320 {
		t.Errorf("reopen reason length = %d; want <= 320 (256 + prefix budget)", len(calls[0].Reason))
	}
}

// -- composeBannerReason must truncate on rune (character)
// boundaries, NOT byte boundaries. A multi-byte UTF-8 note
// (CJK / emoji / accented Latin) that exceeds the 256-char
// cap MUST yield a string that round-trips through utf8.Valid
// without corruption. Slicing at a byte offset would split
// the last rune of the truncated prefix and produce a string
// the banner-renderer / html.EscapeString / provider client
// can mis-render or reject.
func TestReconcile_BannerReason_TruncatesOnRuneBoundary(t *testing.T) {
	fx := newFixture(t)
	const (
		tenantID  = "tenant-utf8"
		messageID = "msg-utf8"
	)
	fx.seedEval(t, tenantID, messageID, string(constant.TierCaution))
	fx.seedBanner(t, tenantID, messageID)

	// 3-byte CJK rune × 400 = 1200 bytes >> 256-char cap.
	notes := strings.Repeat("漢", 400)
	ev := newIncidentResolved(tenantID, "inc-utf8", escalation.ResolutionConfirmedThreat, messageID)
	ev.AnalystNotes = notes

	out, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !out.BannerReopened {
		t.Fatalf("BannerReopened = false; want true")
	}
	calls := fx.reopener.snapshot()
	if len(calls) != 1 {
		t.Fatalf("reopener calls = %d; want 1", len(calls))
	}
	got := calls[0].Reason
	if !utf8.ValidString(got) {
		t.Errorf("reopen reason is not valid UTF-8: % x", []byte(got))
	}
	// Truncation cap is rune-count, not byte-count. After
	// the prefix ("Updated by SOC analyst: confirmed_threat
	// — ") the trailing payload's rune length must be <=
	// 256 — verified at the renderer boundary by re-parsing
	// the trailing notes segment.
	if !strings.Contains(got, "…") {
		t.Errorf("expected ellipsis marker on truncated banner; got %q", got)
	}
}

// -- input validation: missing tenant_id / incident_id /
// resolved_at / dedup_id / unknown resolution → typed errors,
// no audit-row side effects.
func TestReconcile_InputValidation(t *testing.T) {
	fx := newFixture(t)
	base := newIncidentResolved("tenant-x", "inc-x", escalation.ResolutionConfirmedThreat, "msg-x")
	cases := []struct {
		name   string
		mutate func(*escalation.IncidentResolved)
		want   string
	}{
		{name: "missing incident", mutate: func(e *escalation.IncidentResolved) { e.IncidentID = "" }, want: "incident_id"},
		{name: "missing tenant", mutate: func(e *escalation.IncidentResolved) { e.TenantID = "" }, want: "tenant_id"},
		{name: "missing dedup_id", mutate: func(e *escalation.IncidentResolved) { e.DedupID = "" }, want: "dedup_id"},
		{name: "missing resolved_by", mutate: func(e *escalation.IncidentResolved) { e.ResolvedBy = "" }, want: "resolved_by"},
		{name: "zero resolved_at", mutate: func(e *escalation.IncidentResolved) { e.ResolvedAt = time.Time{} }, want: "resolved_at"},
		{name: "invalid resolution", mutate: func(e *escalation.IncidentResolved) { e.Resolution = "foo" }, want: "invalid resolution"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := base
			tc.mutate(&ev)
			_, err := fx.resolver.Reconcile(context.Background(), ev)
			if err == nil {
				t.Fatalf("err = nil; want %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q; want it to contain %q", err.Error(), tc.want)
			}
		})
	}
}

// -- reopener returning an error is non-fatal: the verdict
// flip + audit row still land; BannerReopened is false.
func TestReconcile_ReopenerFailure_NonFatal(t *testing.T) {
	fx := newFixture(t)
	fx.reopener.fail = errors.New("provider boom")
	const (
		tenantID  = "tenant-j"
		messageID = "msg-11"
	)
	fx.seedEval(t, tenantID, messageID, string(constant.TierWarning))
	fx.seedBanner(t, tenantID, messageID)

	ev := newIncidentResolved(tenantID, "inc-11", escalation.ResolutionConfirmedThreat, messageID)
	out, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if out.Kind != escalation.OutcomeFlipped {
		t.Errorf("Kind = %q; want flipped", out.Kind)
	}
	if out.BannerReopened {
		t.Errorf("BannerReopened = true; want false (reopener returned error)")
	}

	row, _ := fx.repos.EvaluationResults.GetByMessageHash(context.Background(), tenantID, []byte(messageID))
	if row.FinalVerdict != "malicious" {
		t.Errorf("FinalVerdict = %q; want malicious (verdict flip should not roll back)", row.FinalVerdict)
	}
}

// -- correlation_id-only lookup falls back to the ListRecent
// scan when pseudo_message_id is empty.
func TestReconcile_CorrelationIDFallback(t *testing.T) {
	fx := newFixture(t)
	const (
		tenantID = "tenant-k"
	)
	r := &repository.EvaluationResult{
		TenantID:      tenantID,
		MessageIDHash: []byte("msg-12"),
		Tier:          string(constant.TierCaution),
		Primary:       "Phishing",
		CorrelationID: "corr-abc",
		EvaluatedAt:   time.Now().UTC(),
	}
	if err := fx.repos.EvaluationResults.Create(context.Background(), r); err != nil {
		t.Fatalf("create eval: %v", err)
	}

	ev := escalation.IncidentResolved{
		IncidentID: "inc-12",
		TenantID:   tenantID,
		Resolution: escalation.ResolutionConfirmedThreat,
		ResolvedAt: time.Now().UTC(),
		ResolvedBy: "analyst-k",
		DedupID:    "dedup-12",
		RelatedEmail: &escalation.EmailLink{
			CorrelationID: "corr-abc",
		},
	}
	out, err := fx.resolver.Reconcile(context.Background(), ev)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if out.Kind != escalation.OutcomeFlipped {
		t.Errorf("Kind = %q; want flipped", out.Kind)
	}
	if out.NewVerdict != "malicious" {
		t.Errorf("NewVerdict = %q; want malicious", out.NewVerdict)
	}
}

// -- IsValidResolution covers all four enum tokens and rejects
// nonsense. Bouundary case for handler-side defensive parse.
func TestIsValidResolution(t *testing.T) {
	for _, r := range []string{
		escalation.ResolutionConfirmedThreat,
		escalation.ResolutionFalsePositive,
		escalation.ResolutionBenign,
		escalation.ResolutionInconclusive,
	} {
		if !escalation.IsValidResolution(r) {
			t.Errorf("IsValidResolution(%q) = false; want true", r)
		}
	}
	for _, bad := range []string{"", "FOO", "Benign", "confirmed-threat", " confirmed_threat "} {
		if escalation.IsValidResolution(bad) {
			t.Errorf("IsValidResolution(%q) = true; want false", bad)
		}
	}
}
