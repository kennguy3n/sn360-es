package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// authReq wraps httptest.NewRequest with an authenticated context for
// the supplied tenant — matches what the JWT middleware would do in
// production. Tests that need to assert the unauthenticated path call
// httptest.NewRequest directly.
func authReq(method, target, body, tenantID string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req = req.WithContext(middleware.ContextWithTenantID(req.Context(), tenantID))
	return req
}

type stubEscalationPublisher struct{}

func (stubEscalationPublisher) Publish(_ context.Context, _ string, _ []byte, _ ...events.PublishOption) error {
	return nil
}

func newTestEscalationService(t *testing.T) *agent.EscalationService {
	t.Helper()
	svc, err := agent.NewEscalationService(agent.EscalationServiceConfig{
		Publisher: stubEscalationPublisher{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:     func() time.Time { return time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("escalation svc: %v", err)
	}
	return svc
}

// seedTicket creates a real ticket via Escalate so the test can later
// resolve / load it without poking at internal store state.
func seedTicket(t *testing.T, svc *agent.EscalationService) dto.EscalationTicket {
	t.Helper()
	tk, err := svc.Escalate(context.Background(), "acme", dto.EscalationIncident{
		PseudoMessageID: "pmid-1",
		Tier:            "HighRisk",
		Category:        "LIKELY_PHISHING",
		Reason:          dto.EscalationReasonConfirmedBreach,
	})
	if err != nil {
		t.Fatalf("escalate: %v", err)
	}
	return tk
}

func TestEscalationHandler_ServeResolve_OK(t *testing.T) {
	svc := newTestEscalationService(t)
	tk := seedTicket(t, svc)
	h := NewEscalationHandler(nil, svc)

	body, _ := json.Marshal(map[string]any{
		"ticket_id":     tk.TicketID,
		"resolver_hash": "secops-1",
		"outcome":       string(dto.OutcomeConfirmedPhishing),
		"notes":         "Verified",
	})
	req := authReq(http.MethodPost, "/v1/escalation/resolve", string(body), "acme")
	rec := httptest.NewRecorder()
	h.ServeResolve(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp dto.EscalationTicket
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Outcome != dto.OutcomeConfirmedPhishing {
		t.Fatalf("outcome=%q", resp.Outcome)
	}
}

func TestEscalationHandler_ServeResolve_Rejections(t *testing.T) {
	svc := newTestEscalationService(t)
	h := NewEscalationHandler(nil, svc)

	cases := []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "wrong method", method: http.MethodGet, body: "", want: http.StatusMethodNotAllowed},
		{name: "invalid JSON", method: http.MethodPost, body: "garbage", want: http.StatusBadRequest},
		{name: "missing ticket_id", method: http.MethodPost, body: `{"outcome":"confirmed_phishing"}`, want: http.StatusBadRequest},
		{name: "invalid outcome", method: http.MethodPost, body: `{"ticket_id":"x","outcome":"bogus"}`, want: http.StatusBadRequest},
		{name: "unknown field", method: http.MethodPost, body: `{"ticket_id":"x","outcome":"closed_no_action","extra":"x"}`, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := authReq(tc.method, "/v1/escalation/resolve", tc.body, "acme")
			rec := httptest.NewRecorder()
			h.ServeResolve(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestEscalationHandler_RejectsCrossTenant is the regression test for
// the bug where ServeResolve / ServeGet sourced ticket_id from the
// request but never enforced the caller's tenant. Tenant B must not
// be able to load or resolve a ticket created by tenant A.
func TestEscalationHandler_RejectsCrossTenant(t *testing.T) {
	svc := newTestEscalationService(t)
	tk := seedTicket(t, svc) // seeded under tenant "acme"
	h := NewEscalationHandler(nil, svc)

	// GET as a different tenant must return 404, not 200.
	getReq := authReq(http.MethodGet, "/v1/escalation/"+tk.TicketID, "", "other-tenant")
	getRec := httptest.NewRecorder()
	h.ServeGet(getRec, getReq)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant GET: status=%d want=404 body=%s", getRec.Code, getRec.Body.String())
	}

	// POST resolve as a different tenant must fail (the service
	// returns ticket-not-found which the handler maps to 400 by
	// design — the contract is that a successful cross-tenant
	// resolution is impossible).
	body, _ := json.Marshal(map[string]any{
		"ticket_id":     tk.TicketID,
		"resolver_hash": "attacker",
		"outcome":       string(dto.OutcomeClosedNoAction),
	})
	resolveReq := authReq(http.MethodPost, "/v1/escalation/resolve", string(body), "other-tenant")
	resolveRec := httptest.NewRecorder()
	h.ServeResolve(resolveRec, resolveReq)
	if resolveRec.Code == http.StatusOK {
		t.Fatalf("cross-tenant POST resolve unexpectedly succeeded: body=%s", resolveRec.Body.String())
	}

	// Sanity: the rightful owner can still load it.
	owner := authReq(http.MethodGet, "/v1/escalation/"+tk.TicketID, "", "acme")
	ownerRec := httptest.NewRecorder()
	h.ServeGet(ownerRec, owner)
	if ownerRec.Code != http.StatusOK {
		t.Fatalf("owner GET: status=%d body=%s", ownerRec.Code, ownerRec.Body.String())
	}
}

// TestEscalationHandler_RejectsUnauthenticated covers the
// no-JWT-claim path. The handler must refuse the request with 401 so
// missing auth cannot be papered over by a default tenant.
func TestEscalationHandler_RejectsUnauthenticated(t *testing.T) {
	svc := newTestEscalationService(t)
	h := NewEscalationHandler(nil, svc)

	getReq := httptest.NewRequest(http.MethodGet, "/v1/escalation/anything", nil)
	getRec := httptest.NewRecorder()
	h.ServeGet(getRec, getReq)
	if getRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET: status=%d want=401", getRec.Code)
	}

	resolveReq := httptest.NewRequest(http.MethodPost, "/v1/escalation/resolve",
		strings.NewReader(`{"ticket_id":"x","outcome":"closed_no_action"}`))
	resolveRec := httptest.NewRecorder()
	h.ServeResolve(resolveRec, resolveReq)
	if resolveRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST: status=%d want=401", resolveRec.Code)
	}
}

// TestEscalationHandler_AuthChecksBeforeBodyParsing locks in the
// auth-first ordering: an unauthenticated caller must see 401 for
// every malformed-body variant the handler would otherwise reject
// with 400. Without this ordering, an unauthenticated caller could
// probe the request schema (field names, DisallowUnknownFields rules,
// length limits) by observing 400 vs. 401 — a minor information leak
// that compounds with any future schema rev.
func TestEscalationHandler_AuthChecksBeforeBodyParsing(t *testing.T) {
	svc := newTestEscalationService(t)
	h := NewEscalationHandler(nil, svc)

	cases := []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: "garbage"},
		{name: "missing ticket_id", body: `{"outcome":"confirmed_phishing"}`},
		{name: "unknown field", body: `{"ticket_id":"x","outcome":"closed_no_action","extra":"x"}`},
		{name: "empty body", body: ""},
		{name: "huge body", body: strings.Repeat("a", 1024*1024)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/escalation/resolve",
				strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h.ServeResolve(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated %s: status=%d want=401 (auth must fire before body parsing)",
					tc.name, rec.Code)
			}
		})
	}
}

func TestEscalationHandler_ServeGet_OK(t *testing.T) {
	svc := newTestEscalationService(t)
	tk := seedTicket(t, svc)
	h := NewEscalationHandler(nil, svc)

	req := authReq(http.MethodGet, "/v1/escalation/"+tk.TicketID, "", "acme")
	rec := httptest.NewRecorder()
	h.ServeGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp dto.EscalationTicket
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.TicketID != tk.TicketID {
		t.Fatalf("got %q want %q", resp.TicketID, tk.TicketID)
	}
}

func TestEscalationHandler_ServeGet_Rejections(t *testing.T) {
	svc := newTestEscalationService(t)
	h := NewEscalationHandler(nil, svc)

	cases := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{name: "wrong method", method: http.MethodPost, path: "/v1/escalation/abc", want: http.StatusMethodNotAllowed},
		{name: "missing id", method: http.MethodGet, path: "/v1/escalation/", want: http.StatusBadRequest},
		{name: "not found", method: http.MethodGet, path: "/v1/escalation/missing", want: http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := authReq(tc.method, tc.path, "", "acme")
			rec := httptest.NewRecorder()
			h.ServeGet(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestEscalationHandler_NilService asserts the operator-facing 503
// path: when the service is unwired, an *authenticated* caller sees
// 503 so SREs can detect the misconfiguration. The unauthenticated
// counterpart is covered by TestEscalationHandler_NilService_AuthFirst.
func TestEscalationHandler_NilService(t *testing.T) {
	h := NewEscalationHandler(nil, nil)
	// Authenticated request — the nil-service branch is reachable
	// only after auth (see ServeResolve / ServeGet comments).
	req := authReq(http.MethodPost, "/v1/escalation/resolve",
		`{"ticket_id":"x","outcome":"closed_no_action"}`, "acme")
	rec := httptest.NewRecorder()
	h.ServeResolve(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestEscalationHandler_NilService_AuthFirst locks in the
// architecturally-correct auth-first ordering: an *unauthenticated*
// caller hitting a handler whose service is unwired must see 401, not
// 503. Without this ordering a probing client could distinguish "this
// endpoint exists but is unconfigured" (503) from "this endpoint is
// auth-protected" (401) and use the differential to fingerprint
// deployments — exactly the schema-probing class Devin Review #6
// flagged on the body-parsing branch.
func TestEscalationHandler_NilService_AuthFirst(t *testing.T) {
	h := NewEscalationHandler(nil, nil)
	// Resolve: unauthenticated + nil service must be 401.
	resolveReq := httptest.NewRequest(http.MethodPost, "/v1/escalation/resolve",
		strings.NewReader(`{"ticket_id":"x","outcome":"closed_no_action"}`))
	resolveRec := httptest.NewRecorder()
	h.ServeResolve(resolveRec, resolveReq)
	if resolveRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth POST: status=%d want=401 body=%s",
			resolveRec.Code, resolveRec.Body.String())
	}
	// Get: same property.
	getReq := httptest.NewRequest(http.MethodGet, "/v1/escalation/anything", nil)
	getRec := httptest.NewRecorder()
	h.ServeGet(getRec, getReq)
	if getRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth GET: status=%d want=401 body=%s",
			getRec.Code, getRec.Body.String())
	}
}
