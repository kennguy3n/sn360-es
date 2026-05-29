package handler

import (
	"encoding/json"
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
	// Authenticate BEFORE every other observable branch — body parse,
	// nil-service infrastructure check, anything that could differ on
	// status code or body. An unauthenticated caller therefore sees
	// exactly one response (401) regardless of whether the body is
	// malformed, the service is unwired, or the request is otherwise
	// fine. Without this ordering an unauth caller could distinguish
	// 503 (service unconfigured) from 400 (bad body) from 405 (wrong
	// method) and use the differential to fingerprint deployments.
	// tenantID is sourced from the verified JWT claim, never from
	// the request body — a caller cannot trick the service into
	// resolving another tenant's ticket by lying about their tenant.
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
		h.logger.WarnContext(r.Context(), "escalation: resolve failed",
			slog.String("ticket_id", req.TicketID),
			slog.Any("error", err),
		)
		// Don't echo the wrapped store/db error to clients — the
		// logger above keeps the diagnostic detail, and the public
		// response stays generic to avoid leaking implementation
		// hints (db rows, table names, internal IDs, ...).
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
	// Authenticate before any other observable branch — see the
	// rationale on ServeResolve. Without auth-first, an unauth caller
	// could distinguish 503 (nil service) from 400 (empty ticket_id)
	// from 401 (auth required) and use the differential to fingerprint
	// deployments.
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
	writeJSON(w, http.StatusOK, ticket)
}
