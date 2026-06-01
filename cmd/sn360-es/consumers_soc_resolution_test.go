// Copyright 2024-2026 SN360. All rights reserved.
// Use of this source code is governed by the proprietary license
// that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/escalation"
)

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
