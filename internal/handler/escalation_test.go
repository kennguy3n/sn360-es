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

// withTenant stamps the request's context with a verified tenant ID so
// the handler tests can exercise the post-auth code path without going
// through the JWT middleware (which is exercised end-to-end elsewhere).
func withTenant(req *http.Request, tenantID string) *http.Request {
	return req.WithContext(middleware.ContextWithTenantID(req.Context(), tenantID))
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
	tk := seedTicket(t, svc) // owned by "acme"
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
		// method check runs before the auth gate (405 is a protocol
		// signal that doesn't leak resource state).
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

	// POST resolve as a different tenant must fail. The store collapses
	// the cross-tenant case into ErrTicketNotFound (the compound
	// (tenant_id, ticket_id) lookup returns "not found" for both
	// "doesn't exist" and "belongs to another tenant"), and the
	// handler maps ErrTicketNotFound to 404 with the same response
	// body as a genuine miss — see
	// TestEscalationHandler_ServeResolve_NotFoundAndCrossTenantIndistinguishable
	// for the regression test that pins the indistinguishability.
	// This assertion only checks status != 200 because the more
	// specific 404 contract is locked in by the dedicated test.
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

// TestEscalationHandler_ServeResolve_NotFoundAndCrossTenantIndistinguishable
// pins the architectural invariant that ticket-not-found and
// cross-tenant-resolve must return the SAME status code and the SAME
// response body. A regression that maps not-found to 400 and
// tenant-mismatch to 404 (or vice versa) re-introduces the existence
// fingerprinting vulnerability that the tenant-scoped store lookup
// was built to close: an authenticated caller from tenant B could
// otherwise probe a ticket ID and learn from the status code whether
// it belongs to tenant A.
func TestEscalationHandler_ServeResolve_NotFoundAndCrossTenantIndistinguishable(t *testing.T) {
	svc := newTestEscalationService(t)
	tk := seedTicket(t, svc) // owned by "acme"
	h := NewEscalationHandler(nil, svc)

	// Case 1: non-existent ticket ID (caller's own tenant).
	body1, _ := json.Marshal(map[string]any{
		"ticket_id":     "esc_doesnotexist000000000000000000000000",
		"resolver_hash": "secops-1",
		"outcome":       string(dto.OutcomeConfirmedPhishing),
	})
	req1 := withTenant(httptest.NewRequest(http.MethodPost, "/v1/escalation/resolve", strings.NewReader(string(body1))), tk.TenantID)
	rec1 := httptest.NewRecorder()
	h.ServeResolve(rec1, req1)

	// Case 2: real ticket, cross-tenant attacker.
	body2, _ := json.Marshal(map[string]any{
		"ticket_id":     tk.TicketID,
		"resolver_hash": "secops-1",
		"outcome":       string(dto.OutcomeConfirmedPhishing),
	})
	req2 := withTenant(httptest.NewRequest(http.MethodPost, "/v1/escalation/resolve", strings.NewReader(string(body2))), "different-tenant")
	rec2 := httptest.NewRecorder()
	h.ServeResolve(rec2, req2)

	if rec1.Code != http.StatusNotFound {
		t.Fatalf("not-found case: expected 404, got %d (body=%s)", rec1.Code, rec1.Body.String())
	}
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant case: expected 404, got %d (body=%s)", rec2.Code, rec2.Body.String())
	}
	if rec1.Code != rec2.Code {
		t.Fatalf("status code MUST be identical (existence leak): not-found=%d cross-tenant=%d", rec1.Code, rec2.Code)
	}
	if rec1.Body.String() != rec2.Body.String() {
		t.Fatalf("response body MUST be byte-identical (existence leak):\n  not-found=%q\n  cross-tenant=%q", rec1.Body.String(), rec2.Body.String())
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

	req := authReq(http.MethodGet, "/v1/escalation/"+tk.TicketID, "", tk.TenantID)
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

// TestEscalationHandler_ServeGet_CrossTenantReturns404 pins the
// defense-in-depth handler-level tenant check added to address the
// Devin Review finding: a ticket owned by tenant A must NOT be
// observable to an authenticated caller from tenant B. The response
// MUST be 404 (indistinguishable from a non-existent ticket), not 403
// — returning 403 would leak the existence of tickets from foreign
// tenants via the caller's ability to enumerate ticket IDs.
func TestEscalationHandler_ServeGet_CrossTenantReturns404(t *testing.T) {
	svc := newTestEscalationService(t)
	tk := seedTicket(t, svc) // owned by "acme"
	h := NewEscalationHandler(nil, svc)

	req := withTenant(httptest.NewRequest(http.MethodGet, "/v1/escalation/"+tk.TicketID, nil), "different-tenant")
	rec := httptest.NewRecorder()
	h.ServeGet(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant GET should return 404, got status=%d body=%s", rec.Code, rec.Body.String())
	}
	// Body must NOT contain anything that could leak the ticket's
	// existence to the wrong tenant (e.g. its actual tenant ID,
	// timeline, outcome, ...).
	body := rec.Body.String()
	if strings.Contains(body, "acme") || strings.Contains(body, tk.TicketID) {
		t.Fatalf("cross-tenant 404 body leaked owner data: %s", body)
	}
}

// TestEscalationHandler_ServeResolve_AlreadyResolvedReturns409 locks
// in the business-rule-conflict mapping: re-resolving a ticket that
// is already in a non-pending state must return 409 (the canonical
// "request conflicts with current resource state" status), NOT 400.
// Returning 400 historically misled clients into thinking their
// payload was malformed when the underlying issue was that another
// SOC operator had already closed the incident. The bot-flagged
// edited finding called this out specifically — 400 for non-input
// errors mis-classifies the failure to the caller.
func TestEscalationHandler_ServeResolve_AlreadyResolvedReturns409(t *testing.T) {
	svc := newTestEscalationService(t)
	tk := seedTicket(t, svc)
	h := NewEscalationHandler(nil, svc)

	body, _ := json.Marshal(map[string]any{
		"ticket_id":     tk.TicketID,
		"resolver_hash": "secops-1",
		"outcome":       string(dto.OutcomeConfirmedPhishing),
	})

	// First resolve succeeds (200).
	first := authReq(http.MethodPost, "/v1/escalation/resolve", string(body), tk.TenantID)
	firstRec := httptest.NewRecorder()
	h.ServeResolve(firstRec, first)
	if firstRec.Code != http.StatusOK {
		t.Fatalf("first resolve must succeed: status=%d body=%s", firstRec.Code, firstRec.Body.String())
	}

	// Second resolve must conflict (409), not 400.
	second := authReq(http.MethodPost, "/v1/escalation/resolve", string(body), tk.TenantID)
	secondRec := httptest.NewRecorder()
	h.ServeResolve(secondRec, second)
	if secondRec.Code != http.StatusConflict {
		t.Fatalf("second resolve: status=%d want=409 body=%s",
			secondRec.Code, secondRec.Body.String())
	}
	if !strings.Contains(secondRec.Body.String(), "already resolved") {
		t.Fatalf("body should signal already-resolved: %q", secondRec.Body.String())
	}
}

// failingTicketStore is an in-memory TicketStore that wraps the real
// MemoryTicketStore and returns a synthetic db-style error from Update
// — exercising the handler's 500 branch for store / db failures.
type failingTicketStore struct {
	inner    agent.TicketStore
	updateOK bool
}

func (f *failingTicketStore) Save(ctx context.Context, t dto.EscalationTicket) error {
	return f.inner.Save(ctx, t)
}
func (f *failingTicketStore) Load(ctx context.Context, tenantID, ticketID string) (dto.EscalationTicket, bool, error) {
	return f.inner.Load(ctx, tenantID, ticketID)
}
func (f *failingTicketStore) Update(ctx context.Context, tenantID, ticketID string, mutate func(*dto.EscalationTicket) error) (dto.EscalationTicket, error) {
	if f.updateOK {
		return f.inner.Update(ctx, tenantID, ticketID, mutate)
	}
	// Synthetic db-down error: NOT one of the sentinels the handler
	// recognises (ErrTicketNotFound, ErrInvalidOutcome,
	// ErrAlreadyResolved, ErrTicketTenantIDRequired). The handler must
	// classify this as 500, not 400 — that's the regression the bot
	// flagged when it escalated the Info finding to a 🚩 bug.
	return dto.EscalationTicket{}, io.ErrUnexpectedEOF
}

// TestEscalationHandler_ServeResolve_StoreErrorReturns500 locks in
// the server-fault mapping: a database / store error from
// ResolveEscalation must surface as 500, NOT 400. Without this
// regression test, a future refactor could silently re-collapse all
// non-NotFound errors back into 400 (which is what the bot edited the
// Info comment to a 🚩 bug about).
func TestEscalationHandler_ServeResolve_StoreErrorReturns500(t *testing.T) {
	store := &failingTicketStore{inner: agent.NewMemoryTicketStore()}
	// Seed a ticket through the un-failing inner store directly so
	// the resolve path reaches the failing Update branch (rather than
	// erroring at the seeding step).
	store.updateOK = true
	helperSvc, err := agent.NewEscalationService(agent.EscalationServiceConfig{
		Publisher: stubEscalationPublisher{},
		Store:     store,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:     func() time.Time { return time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("helper svc: %v", err)
	}
	tk := seedTicket(t, helperSvc)
	// Flip the store to failing-mode for the actual handler call.
	store.updateOK = false

	h := NewEscalationHandler(nil, helperSvc)

	body, _ := json.Marshal(map[string]any{
		"ticket_id":     tk.TicketID,
		"resolver_hash": "secops-1",
		"outcome":       string(dto.OutcomeConfirmedPhishing),
	})
	req := authReq(http.MethodPost, "/v1/escalation/resolve", string(body), tk.TenantID)
	rec := httptest.NewRecorder()
	h.ServeResolve(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("store-error case: status=%d want=500 body=%s",
			rec.Code, rec.Body.String())
	}
	// 500 body must NOT echo the wrapped store error to the caller —
	// the public response is generic on purpose. The diagnostic
	// detail lives in the slog warn line, not on the wire.
	if strings.Contains(rec.Body.String(), "EOF") || strings.Contains(rec.Body.String(), "unexpected") {
		t.Fatalf("500 body leaked wrapped store error: %q", rec.Body.String())
	}
}

// failingPublisher is a stub EscalationPublisher that always errors —
// exercising the handler's 500 branch for publish failures.
type failingPublisher struct{}

func (failingPublisher) Publish(_ context.Context, _ string, _ []byte, _ ...events.PublishOption) error {
	return io.ErrClosedPipe
}

// TestEscalationHandler_ServeResolve_PublishErrorReturns500 covers
// the NATS-publish-failure branch: even though the ticket update
// succeeded in the store, a downstream publish failure is a
// server-side problem, not a client-input problem. 500 is the right
// signal so the caller (or the surrounding retry / circuit-breaker
// layer) knows the request itself wasn't malformed.
//
// Setup quirk: the EscalationService publishes on BOTH the Escalate
// and Resolve paths, so a publisher that fails unconditionally would
// also break seedTicket(). We seed via a working publisher first,
// then construct a second service pointing at the SAME store but
// with the failing publisher so only the Resolve path hits the
// failure branch.
func TestEscalationHandler_ServeResolve_PublishErrorReturns500(t *testing.T) {
	store := agent.NewMemoryTicketStore()
	clock := func() time.Time { return time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC) }

	// Step 1: working publisher used for the Escalate seed step.
	seedSvc, err := agent.NewEscalationService(agent.EscalationServiceConfig{
		Publisher: stubEscalationPublisher{},
		Store:     store,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:     clock,
	})
	if err != nil {
		t.Fatalf("seed svc: %v", err)
	}
	tk := seedTicket(t, seedSvc)

	// Step 2: failing publisher used for the Resolve under test.
	svc, err := agent.NewEscalationService(agent.EscalationServiceConfig{
		Publisher: failingPublisher{},
		Store:     store,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:     clock,
	})
	if err != nil {
		t.Fatalf("svc: %v", err)
	}
	h := NewEscalationHandler(nil, svc)

	body, _ := json.Marshal(map[string]any{
		"ticket_id":     tk.TicketID,
		"resolver_hash": "secops-1",
		"outcome":       string(dto.OutcomeConfirmedPhishing),
	})
	req := authReq(http.MethodPost, "/v1/escalation/resolve", string(body), tk.TenantID)
	rec := httptest.NewRecorder()
	h.ServeResolve(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("publish-error case: status=%d want=500 body=%s",
			rec.Code, rec.Body.String())
	}
}

// TestEscalationHandler_ServeGet_UnauthenticatedReturns401 pins the
// pre-Load auth gate: a request that reaches the handler without a
// verified tenant (i.e. the route was wired without the auth
// middleware, OR the test harness bypassed it) must receive 401 —
// NOT proceed to load + leak. Loading first and then returning 404
// would allow an unauthenticated caller to enumerate ticket IDs by
// observing the timing difference between hits and misses.
func TestEscalationHandler_ServeGet_UnauthenticatedReturns401(t *testing.T) {
	svc := newTestEscalationService(t)
	tk := seedTicket(t, svc)
	h := NewEscalationHandler(nil, svc)

	req := httptest.NewRequest(http.MethodGet, "/v1/escalation/"+tk.TicketID, nil)
	rec := httptest.NewRecorder()
	h.ServeGet(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET should return 401, got status=%d body=%s", rec.Code, rec.Body.String())
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
