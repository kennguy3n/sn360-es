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
		// Returning 403 (or a distinct 404 body) for the cross-tenant
		// case would leak ticket-existence to cross-tenant attackers,
		// which is the very invariant the store-level (tenant_id,
		// ticket_id) compound lookup was added to enforce. The store
		// collapses "wrong tenant" and "not present" into the same
		// ErrTicketNotFound sentinel; the handler reflects that into
		// the wire surface as an indistinguishable 404.
		if errors.Is(err, agent.ErrTicketNotFound) {
			// Log every ErrTicketNotFound at warn level so operators
			// have visibility into potential cross-tenant probing
			// attempts. The store collapses "wrong tenant" and "not
			// present" into the same sentinel, so the log line here
			// cannot distinguish the two cases — but a sustained
			// burst of these for unrelated ticket IDs from the same
			// caller is the signal we want operators to see. This
			// mirrors the cross-tenant log line on ServeGet so both
			// endpoints emit symmetric observability for the same
			// class of attack surface.
			h.logger.WarnContext(r.Context(), "escalation: resolve target not found",
				slog.String("ticket_id", req.TicketID),
				slog.String("caller_tenant", tenantID),
			)
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
		//
		// Classify the remaining errors into client- vs server-fault
		// buckets so the wire response matches the underlying cause:
		//
		//   - ErrInvalidOutcome      -> 400: caller sent a bogus outcome
		//   - ErrAlreadyResolved     -> 409: business-rule conflict on
		//                              the ticket's current state
		//   - ErrTicketTenantIDRequired -> 400: defence-in-depth; the
		//                              auth gate above already rejects
		//                              empty tenants with 401, so this
		//                              branch is structurally unreachable
		//                              today but kept here so a future
		//                              refactor that loosens the gate
		//                              still returns a client error
		//   - ErrTicketIDRequired    -> 400: defence-in-depth; the
		//                              handler validates the path
		//                              parameter at the top of
		//                              ServeResolve before reaching
		//                              the service, so this branch is
		//                              structurally unreachable from
		//                              the HTTP layer today. Kept so
		//                              non-HTTP callers (event-bus,
		//                              future gRPC/CLI) classify the
		//                              same shape of failure the same
		//                              way the HTTP path does
		//   - anything else (db connection errors from the postgres
		//     ticket store, JSON marshal failures, NATS publish
		//     failures) -> 500: server-fault, the caller did nothing
		//     wrong. Returning 400 for these would mislead clients
		//     into believing their payload was malformed.
		switch {
		case errors.Is(err, agent.ErrInvalidOutcome),
			errors.Is(err, agent.ErrTicketTenantIDRequired),
			errors.Is(err, agent.ErrTicketIDRequired):
			writeError(w, http.StatusBadRequest, "resolve failed")
		case errors.Is(err, agent.ErrAlreadyResolved):
			writeError(w, http.StatusConflict, "already resolved")
		default:
			writeError(w, http.StatusInternalServerError, "resolve failed")
		}
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
	// This is a defense-in-depth check at the handler boundary.
	// The store-level filter has already landed (PR #44): both
	// MemoryTicketStore.Load (internal/service/agent/escalation.go,
	// compound (tenantID, ticketID) key) and PostgresTicketStore.Load
	// (internal/service/agent/postgres_ticket_store.go, WHERE
	// tenant_id = $1 AND ticket_id = $2) refuse cross-tenant
	// lookups before the row ever reaches us — Load returns ok=false
	// and the `if !ok` branch above handles them as 404.
	//
	// The handler-side check below is still kept because:
	//   * defence in depth — a future custom TicketStore that
	//     forgets to filter by tenant_id would still be caught here;
	//   * it provides the cross-tenant WarnContext audit log even
	//     if/when a store implementation returns the row by mistake
	//     (the store path silently returns ok=false today, which is
	//     correct from a leak-prevention standpoint but loses the
	//     "someone tried to peek at another tenant's ticket" signal
	//     that the WarnContext below preserves).
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
