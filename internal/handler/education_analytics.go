package handler

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/education"
)

// EducationAnalyticsHandler serves
//
//	GET /v1/education/analytics?tenant_id={tid}&range=90d
//
// returning the aggregated training-programme analytics for a tenant:
// campaign completion rates, click rates by attack type and difficulty,
// the resilience trend, the most-clicked templates, and per-regulatory-
// regime completion.
//
// The range query param accepts "Nd"/"Nh"/"Nm" notation (shared with
// the dashboard handler's parseRange); it defaults to 90 days.
type EducationAnalyticsHandler struct {
	logger  *slog.Logger
	service *education.AnalyticsService
}

// NewEducationAnalyticsHandler wires the handler. service is optional:
// when nil the handler responds 503 to every request so the route stays
// navigable in partially-wired deployments, mirroring the dashboard
// handler's degradation contract.
func NewEducationAnalyticsHandler(logger *slog.Logger, service *education.AnalyticsService) *EducationAnalyticsHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &EducationAnalyticsHandler{logger: logger, service: service}
}

// defaultAnalyticsRange is used when the range query param is absent.
const defaultAnalyticsRange = "90d"

// ServeHTTP implements http.Handler.
func (h *EducationAnalyticsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.service == nil {
		writeError(w, http.StatusServiceUnavailable, "education analytics not configured")
		return
	}

	// Resolve the effective tenant. The JWT-bound tenant is
	// authoritative; a disagreeing query tenant_id is rejected 403.
	// Shared with the dashboard handler via resolveTenant so the two
	// endpoints enforce tenant scoping identically.
	tenantID, ok := resolveTenant(w, r, h.logger)
	if !ok {
		return
	}

	rangeStr := strings.TrimSpace(r.URL.Query().Get("range"))
	if rangeStr == "" {
		rangeStr = defaultAnalyticsRange
	}
	dur, err := parseRange(rangeStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid range")
		return
	}
	now := time.Now().UTC()
	tr := dto.TimeRange{Start: now.Add(-dur), End: now}

	analytics, err := h.service.ComputeAnalytics(r.Context(), tenantID, tr)
	if err != nil {
		h.logger.WarnContext(r.Context(), "education analytics: compute failed",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err),
		)
		writeError(w, http.StatusInternalServerError, "analytics computation failed")
		return
	}
	writeJSON(w, http.StatusOK, analytics)
}
