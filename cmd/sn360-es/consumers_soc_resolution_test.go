// Copyright 2024-2026 SN360. All rights reserved.
// Use of this source code is governed by the proprietary license
// that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/escalation"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// headerMessage is a payloadMessage variant whose Headers()
// returns a configurable map. Used by bodyTenantHeaderShim
// tests to verify the producer-header pass-through vs
// body-derived fallback paths.
type headerMessage struct {
	payloadMessage
	headers map[string]string
}

func (m headerMessage) Headers() map[string]string { return m.headers }

// reopenerSpy is a hand-rolled escalation.BannerReopener that
// captures calls into a slice for assertion. Lives in the
// consumer-level test because the resolver-level test already
// has its own spy in internal/service/escalation; co-locating
// keeps each layer's test surface self-contained.
type reopenerSpy struct {
	calls []string // "tenant/messageID/reason" tuple
	err   error
}

func (r *reopenerSpy) ReopenBanner(_ context.Context, tenant, msgID, reason string) error {
	r.calls = append(r.calls, tenant+"/"+msgID+"/"+reason)
	return r.err
}

// buildEscalationApp wires the minimum slice of `application`
// needed to exercise handleSOCIncidentResolved end-to-end:
// repos + escalationResolver + a logger. No NATS, no provider
// registry — those are tested independently.
func buildEscalationApp(t *testing.T) (*application, *reopenerSpy) {
	t.Helper()
	app := newTestApp(t)
	repos := repository.NewInMemoryRegistry()
	app.repos = repos
	spy := &reopenerSpy{}
	res, err := escalation.New(
		repos.EvaluationResults,
		repos.EmailVerdictAudits,
		repos.BannerStates,
		spy,
		app.logger,
	)
	if err != nil {
		t.Fatalf("escalation.New: %v", err)
	}
	app.escalationResolver = res
	return app, spy
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// -- Happy path: a confirmed_threat against a Caution-tier eval
// flips the verdict to malicious and fires a reopen because
// the banner was delivered.
func TestHandleSOCIncidentResolved_HappyPath_FlipsAndReopens(t *testing.T) {
	app, spy := buildEscalationApp(t)

	const (
		tenantID  = "tenant-h1"
		messageID = "msg-h1"
	)
	// Seed evaluation_results row + banner_state delivered.
	if err := app.repos.EvaluationResults.Create(context.Background(), &repository.EvaluationResult{
		TenantID:      tenantID,
		MessageIDHash: []byte(messageID),
		Tier:          string(constant.TierCaution),
		Primary:       "Phishing",
		EvaluatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Create eval: %v", err)
	}
	if err := app.repos.BannerStates.MarkDelivered(context.Background(), repository.MarkDeliveredInput{
		TenantID:           tenantID,
		MessageIDHash:      []byte(messageID),
		At:                 time.Now().UTC(),
		Provider:           "gmail",
		DeliveredMessageID: messageID,
		DeliveredEmail:     "r@example.test",
	}); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}

	payload := escalation.IncidentResolved{
		IncidentID: "inc-h1",
		TenantID:   tenantID,
		Resolution: escalation.ResolutionConfirmedThreat,
		ResolvedAt: time.Now().UTC(),
		ResolvedBy: "analyst-h1",
		DedupID:    "dedup-h1",
		RelatedEmail: &escalation.EmailLink{
			PseudoMessageID: messageID,
		},
	}
	msg := payloadMessage{data: mustMarshal(t, payload), subject: socResolutionSubject}
	if err := app.handleSOCIncidentResolved(context.Background(), msg); err != nil {
		t.Fatalf("handleSOCIncidentResolved: %v", err)
	}

	// Reopener invoked exactly once.
	if len(spy.calls) != 1 {
		t.Fatalf("reopener calls = %d; want 1", len(spy.calls))
	}
	if !strings.HasPrefix(spy.calls[0], tenantID+"/"+messageID+"/") {
		t.Errorf("reopener call = %q; want tenant/message prefix", spy.calls[0])
	}

	// Verdict actually flipped on the eval row.
	row, err := app.repos.EvaluationResults.GetByMessageHash(context.Background(), tenantID, []byte(messageID))
	if err != nil {
		t.Fatalf("re-fetch eval: %v", err)
	}
	if row.FinalVerdict != "malicious" {
		t.Errorf("FinalVerdict = %q; want malicious", row.FinalVerdict)
	}

	// Audit row landed.
	audit, err := app.repos.EmailVerdictAudits.GetByDedupID(context.Background(), tenantID, "dedup-h1")
	if err != nil {
		t.Fatalf("audit fetch: %v", err)
	}
	if audit.NewVerdict != "malicious" {
		t.Errorf("audit NewVerdict = %q; want malicious", audit.NewVerdict)
	}
}

// -- malformed JSON drops at the unmarshal boundary with no
// resolver invocation and no return error (so JetStream
// advances past the poison pill).
func TestHandleSOCIncidentResolved_MalformedJSON_Drops(t *testing.T) {
	app, spy := buildEscalationApp(t)
	if err := app.handleSOCIncidentResolved(context.Background(), payloadMessage{
		data:    []byte("{not-json"),
		subject: socResolutionSubject,
	}); err != nil {
		t.Errorf("err = %v; want nil for poison-pill payload", err)
	}
	if len(spy.calls) != 0 {
		t.Errorf("reopener calls = %d; want 0 (resolver should not run on malformed JSON)", len(spy.calls))
	}
}

// -- invalid resolution token drops with no resolver
// invocation. Pin the four-enum invariant on the consumer
// boundary, defence-in-depth above the resolver's own
// validation.
func TestHandleSOCIncidentResolved_InvalidResolution_Drops(t *testing.T) {
	app, spy := buildEscalationApp(t)
	payload := escalation.IncidentResolved{
		IncidentID: "x",
		TenantID:   "t",
		Resolution: "NOT_A_REAL_TOKEN",
		ResolvedAt: time.Now().UTC(),
		ResolvedBy: "a",
		DedupID:    "d",
		RelatedEmail: &escalation.EmailLink{
			PseudoMessageID: "m",
		},
	}
	if err := app.handleSOCIncidentResolved(context.Background(), payloadMessage{
		data:    mustMarshal(t, payload),
		subject: socResolutionSubject,
	}); err != nil {
		t.Errorf("err = %v; want nil", err)
	}
	if len(spy.calls) != 0 {
		t.Errorf("reopener calls = %d; want 0", len(spy.calls))
	}
}

// -- resolver not wired (memory-only deployment) → drop at the
// subscription boundary, return nil so the bus advances.
func TestHandleSOCIncidentResolved_NoResolver_Drops(t *testing.T) {
	app := newTestApp(t)
	// app.escalationResolver stays nil — exercise the
	// memory-only deployment path.
	payload := escalation.IncidentResolved{
		IncidentID: "x", TenantID: "t",
		Resolution: escalation.ResolutionConfirmedThreat,
		ResolvedAt: time.Now().UTC(), ResolvedBy: "a", DedupID: "d",
		RelatedEmail: &escalation.EmailLink{PseudoMessageID: "m"},
	}
	if err := app.handleSOCIncidentResolved(context.Background(), payloadMessage{
		data:    mustMarshal(t, payload),
		subject: socResolutionSubject,
	}); err != nil {
		t.Errorf("err = %v; want nil", err)
	}
}

// -- a payload that the JSON unmarshal accepts but the
// resolver's validateInput rejects (e.g. empty ResolvedBy,
// missing DedupID, zero ResolvedAt) MUST drop at the handler
// boundary with err == nil so the broker advances past the
// poison pill. Returning the validation error would tell
// JetStream to redeliver, but the message will fail
// validation identically every time — burning the
// MaxDeliver=5 budget on a permanent payload defect.
//
// The resolver tags such failures with
// escalation.ErrInvalidPayload; the handler checks
// errors.Is and demotes to a drop.
func TestHandleSOCIncidentResolved_PermanentValidationError_Drops(t *testing.T) {
	app, spy := buildEscalationApp(t)
	// ResolvedBy is empty — passes JSON unmarshal and the
	// handler's own IsValidResolution gate, fails the
	// resolver's validateInput path.
	payload := escalation.IncidentResolved{
		IncidentID: "inc-ipv",
		TenantID:   "tenant-ipv",
		Resolution: escalation.ResolutionConfirmedThreat,
		ResolvedAt: time.Now().UTC(),
		ResolvedBy: "",
		DedupID:    "dedup-ipv",
		RelatedEmail: &escalation.EmailLink{
			PseudoMessageID: "msg-ipv",
		},
	}
	if err := app.handleSOCIncidentResolved(context.Background(), payloadMessage{
		data:    mustMarshal(t, payload),
		subject: socResolutionSubject,
	}); err != nil {
		t.Errorf("err = %v; want nil for permanent validation defect", err)
	}
	if len(spy.calls) != 0 {
		t.Errorf("reopener calls = %d; want 0 (resolver should reject before side effects)", len(spy.calls))
	}
}

// -- duplicate redelivery: same DedupID twice. First call
// flips, second call short-circuits to OutcomeDuplicate
// without re-invoking the reopener. This exercises the
// JetStream-redelivery-as-no-op contract at the consumer
// boundary.
func TestHandleSOCIncidentResolved_Duplicate_NoReopen(t *testing.T) {
	app, spy := buildEscalationApp(t)
	const (
		tenantID  = "tenant-dup"
		messageID = "msg-dup"
	)
	if err := app.repos.EvaluationResults.Create(context.Background(), &repository.EvaluationResult{
		TenantID:      tenantID,
		MessageIDHash: []byte(messageID),
		Tier:          string(constant.TierCaution),
		Primary:       "Phishing",
		EvaluatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Create eval: %v", err)
	}
	if err := app.repos.BannerStates.MarkDelivered(context.Background(), repository.MarkDeliveredInput{
		TenantID:           tenantID,
		MessageIDHash:      []byte(messageID),
		At:                 time.Now().UTC(),
		Provider:           "gmail",
		DeliveredMessageID: messageID,
		DeliveredEmail:     "r@example.test",
	}); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}
	payload := escalation.IncidentResolved{
		IncidentID: "inc-dup",
		TenantID:   tenantID,
		Resolution: escalation.ResolutionConfirmedThreat,
		ResolvedAt: time.Now().UTC(),
		ResolvedBy: "analyst-dup",
		DedupID:    "dedup-dup",
		RelatedEmail: &escalation.EmailLink{
			PseudoMessageID: messageID,
		},
	}
	body := mustMarshal(t, payload)
	for i := 0; i < 2; i++ {
		if err := app.handleSOCIncidentResolved(context.Background(), payloadMessage{
			data:    body,
			subject: socResolutionSubject,
		}); err != nil {
			t.Fatalf("delivery %d: %v", i+1, err)
		}
	}
	if len(spy.calls) != 1 {
		t.Errorf("reopener calls = %d; want 1 (duplicate must collapse)", len(spy.calls))
	}
}

// -- bodyTenantHeaderShim: when the producer doesn't stamp the
// canonical sn360 tenant-id header, the shim derives it from
// the IncidentResolved body's tenant_id field and overlays it
// on the message before the inner handler runs. This is the
// defence-in-depth seam that makes the SOC consumer immune to
// cross-repo header-stamping regressions.
func TestBodyTenantHeaderShim_DerivesFromBody(t *testing.T) {
	app, _ := buildEscalationApp(t)

	payload := escalation.IncidentResolved{
		IncidentID: "inc-shim",
		TenantID:   "tenant-derived",
		Resolution: escalation.ResolutionInconclusive,
		ResolvedAt: time.Now().UTC(),
		ResolvedBy: "analyst-shim",
		DedupID:    "dedup-shim",
		RelatedEmail: &escalation.EmailLink{
			PseudoMessageID: "msg-shim",
		},
	}
	body := mustMarshal(t, payload)

	var observed map[string]string
	captured := func(_ context.Context, msg events.Message) error {
		observed = msg.Headers()
		return nil
	}
	shim := app.bodyTenantHeaderShim(captured)

	// Case 1: producer omitted the header → shim overlays
	// body tenant_id.
	if err := shim(context.Background(), payloadMessage{data: body, subject: socResolutionSubject}); err != nil {
		t.Fatalf("shim: %v", err)
	}
	if got := observed[events.HeaderTenantID]; got != "tenant-derived" {
		t.Errorf("body-derived header = %q; want tenant-derived", got)
	}

	// Case 2: producer stamped the header → shim leaves it
	// alone (no body parse, no overlay allocation).
	observed = nil
	headed := headerMessage{
		payloadMessage: payloadMessage{data: body, subject: socResolutionSubject},
		headers:        map[string]string{events.HeaderTenantID: "tenant-from-header"},
	}
	if err := shim(context.Background(), headed); err != nil {
		t.Fatalf("shim with header: %v", err)
	}
	if got := observed[events.HeaderTenantID]; got != "tenant-from-header" {
		t.Errorf("header-preferred = %q; want tenant-from-header", got)
	}

	// Case 3: malformed body AND no header → shim falls
	// through with no panic; inner handler will drop the
	// message at the resolver boundary.
	observed = map[string]string{"sentinel": "left-intact"}
	innerCalled := false
	pass := func(_ context.Context, msg events.Message) error {
		innerCalled = true
		// confirm no synthetic tenant-id header was added
		if _, ok := msg.Headers()[events.HeaderTenantID]; ok {
			t.Errorf("malformed-body case should not synthesise tenant header")
		}
		return nil
	}
	if err := app.bodyTenantHeaderShim(pass)(context.Background(), payloadMessage{
		data: []byte("{not-json"), subject: socResolutionSubject,
	}); err != nil {
		t.Fatalf("shim malformed: %v", err)
	}
	if !innerCalled {
		t.Errorf("inner handler not invoked on malformed body")
	}
}

// -- bodyTenantHeaderShim propagates errors from the inner
// handler without swallowing them. This pins the contract that
// the shim is a strictly additive overlay; it must never
// silently absorb a downstream error.
func TestBodyTenantHeaderShim_PropagatesInnerError(t *testing.T) {
	app, _ := buildEscalationApp(t)
	want := errors.New("inner-handler boom")
	shim := app.bodyTenantHeaderShim(func(context.Context, events.Message) error {
		return want
	})
	err := shim(context.Background(), payloadMessage{
		data: mustMarshal(t, escalation.IncidentResolved{
			IncidentID: "x", TenantID: "t", Resolution: escalation.ResolutionInconclusive,
			ResolvedAt: time.Now().UTC(), ResolvedBy: "a", DedupID: "d",
		}),
		subject: socResolutionSubject,
	})
	if !errors.Is(err, want) {
		t.Errorf("err = %v; want %v", err, want)
	}
}
