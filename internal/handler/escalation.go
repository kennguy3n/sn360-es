package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
)

// EscalationHandler serves POST /v1/escalation/resolve so SecOps can
// record the outcome of an escalated incident. The handler also
// exposes GET /v1/escalation/{ticket_id} for inspection.
type EscalationHandler struct {
	logger *slog.Logger
	svc    *agent.EscalationService
}

// NewEscalationHandler wires the handler.
func NewEscalationHandler(logger *slog.Logger, svc *agent.EscalationService) *EscalationHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &EscalationHandler{logger: logger, svc: svc}
}

type resolveRequest struct {
	TicketID     string                `json:"ticket_id"`
	ResolverHash string                `json:"resolver_hash"`
	Outcome      dto.EscalationOutcome `json:"outcome"`
	Notes        string                `json:"notes"`
}

// ServeResolve handles POST /v1/escalation/resolve.
func (h *EscalationHandler) ServeResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Authenticate BEFORE every *resource-observable* branch — body
	// parse, nil-service infrastructure check, ticket lookup, anything
	// whose result could differ across deployments or tenants. The
	// HTTP method check above is intentionally allowed to precede
	// auth because 405 is a protocol-level signal that the route
	// exists for a different verb; it is the same for every caller,
	// the same in every environment, and conveys nothing about the
	// resource or the tenant. From this point onward, however, an
	// unauthenticated caller sees exactly one response (401)
	// regardless of whether the body is malformed, the service is
	// unwired, or the ticket is missing. Without this ordering an
	// unauth caller could distinguish 503 (service unconfigured) from
	// 400 (bad body) and use the differential to fingerprint
	// deployments. tenantID is sourced from the verified JWT claim,
	// never from the request body — a caller cannot trick the service
	// into resolving another tenant's ticket by lying about their
	// tenant.
	tenantID := middleware.TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "escalation service not configured")
		return
	}
	// Auth gate before body parsing: an unauthenticated caller must
	// not be able to fingerprint the request schema by observing
	// 400-on-bad-JSON vs 200-on-success differences. Mirrors the
	// ServeGet auth gate; the auth boundary is the handler's
	// outermost ring, defense-in-depth above the service layer's
	// mandatory tenantID parameter.
	callerTenant := middleware.TenantIDFromContext(r.Context())
	if callerTenant == "" {
		h.logger.WarnContext(r.Context(), "escalation: unauthenticated POST /v1/escalation/resolve",
			slog.String("remote", r.RemoteAddr),
		)
		writeError(w, http.StatusUnauthorized, "unauthorised")
		return
	}
	var req resolveRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.TicketID = strings.TrimSpace(req.TicketID)
	if req.TicketID == "" {
		writeError(w, http.StatusBadRequest, "ticket_id is required")
		return
	}
	ticket, err := h.svc.ResolveEscalation(r.Context(), tenantID, req.TicketID, req.ResolverHash, req.Outcome, req.Notes)
	if err != nil {
		// Cross-tenant attempts AND ticket-not-found both return 404
		// with the SAME response body. The two cases must be
		// indistinguishable to the caller — otherwise an authenticated
		// caller from tenant B could fingerprint which ticket IDs
		// exist in tenant A by probing the endpoint:
		//   - 404 "ticket not found"  -> doesn't exist OR belongs to another tenant
		//   - 400 "resolve failed"    -> exists, belongs to me, but blocked by a business rule
		// Returning 403 (or a distinct 404 body) for the tenant-mismatch
		// case would leak ticket-existence to cross-tenant attackers,
		// which is the very invariant the service-layer tenant check
		// was added to enforce. The slog.WarnContext inside the service
		// already captured the caller_tenant / ticket_tenant pair for
		// the operator audit trail.
		if errors.Is(err, agent.ErrTicketTenantMismatch) || errors.Is(err, agent.ErrTicketNotFound) {
			writeError(w, http.StatusNotFound, "ticket not found")
			return
		}
		h.logger.WarnContext(r.Context(), "escalation: resolve failed",
			slog.String("ticket_id", req.TicketID),
			slog.Any("error", err),
		)
		// Don't echo the wrapped store/db error to clients — the
		// logger above keeps the diagnostic detail, and the public
		// response stays generic to avoid leaking implementation
		// hints (db rows, table names, internal IDs, ...).
		// Note: 400 here is for genuine input-validation failures
		// (invalid outcome, already-resolved business rule) — NOT
		// for ticket-not-found, which is gated to 404 above.
		writeError(w, http.StatusBadRequest, "resolve failed")
		return
	}
	writeJSON(w, http.StatusOK, ticket)
}

// ServeGet handles GET /v1/escalation/{ticket_id}.
func (h *EscalationHandler) ServeGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Authenticate before any other resource-observable branch — see
	// the rationale on ServeResolve. The 405 method check above is
	// allowed to precede auth (constant protocol-level signal); from
	// here on, an unauth caller cannot distinguish 503 (nil service)
	// from 400 (empty ticket_id) because both collapse to 401.
	tenantID := middleware.TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "escalation service not configured")
		return
	}
	ticketID := strings.TrimPrefix(r.URL.Path, "/v1/escalation/")
	ticketID = strings.TrimSpace(ticketID)
	if ticketID == "" {
		writeError(w, http.StatusBadRequest, "ticket_id is required")
		return
	}
	ticket, ok, err := h.svc.Load(r.Context(), tenantID, ticketID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}
	// Tenant isolation: cross-tenant accesses return 404 (not 403)
	// so the response is indistinguishable from a non-existent
	// ticket. Returning 403 would leak the existence of a ticket
	// owned by a different tenant; the OpenAPI spec for this route
	// explicitly documents this 404-on-mismatch behaviour, and a
	// caller cannot distinguish "ticket exists, wrong tenant" from
	// "ticket never existed" via the response alone.
	//
	// This is a defense-in-depth check at the handler boundary;
	// when PR #44's `WHERE tenant_id = $1` store-level filter lands,
	// the store will also refuse the lookup before the row ever
	// reaches us. Both layers are intentional — the handler check
	// also covers in-memory and mock stores used in tests + the
	// CommunityEdition demo deployment.
	if ticket.TenantID != tenantID {
		h.logger.WarnContext(r.Context(), "escalation: cross-tenant GET attempt",
			slog.String("ticket_id", ticketID),
			slog.String("caller_tenant", tenantID),
			slog.String("ticket_tenant", ticket.TenantID),
		)
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}
	writeJSON(w, http.StatusOK, ticket)
}
