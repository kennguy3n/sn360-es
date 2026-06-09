package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/dashboard"
)

// DashboardHandler serves GET /v1/dashboard/summary?range=7d&tenant_id=...
//
// The range query param accepts "Nd" or "Nh" notation (e.g. "7d",
// "24h", "168h"). If absent it defaults to 7 days.
type DashboardHandler struct {
	logger *slog.Logger
	gen    *dashboard.DashboardGenerator
}

// NewDashboardHandler wires the handler. gen is optional: when nil
// the handler responds 503 to every request so the route stays
// navigable in partially-wired deployments (see the README "Project
// Status" matrix entry for /v1/dashboard/summary).
func NewDashboardHandler(logger *slog.Logger, gen *dashboard.DashboardGenerator) *DashboardHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &DashboardHandler{logger: logger, gen: gen}
}

// ServeHTTP implements http.Handler.
func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.gen == nil {
		writeError(w, http.StatusServiceUnavailable, "dashboard service not configured")
		return
	}
	tenantID, ok := resolveTenant(w, r, h.logger)
	if !ok {
		return
	}
	rangeStr := strings.TrimSpace(r.URL.Query().Get("range"))
	if rangeStr == "" {
		rangeStr = "7d"
	}
	dur, err := parseRange(rangeStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid range")
		return
	}
	now := time.Now().UTC()
	tr := dto.TimeRange{Start: now.Add(-dur), End: now}
	summary, err := h.gen.GenerateSummary(r.Context(), tenantID, tr)
	if err != nil {
		h.logger.WarnContext(r.Context(), "dashboard: generate failed",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err),
		)
		writeError(w, http.StatusInternalServerError, "dashboard generation failed")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// errInvalidRange is returned by parseRange for any malformed or
// non-positive input. It is intentionally a plain error sentinel so
// callers can write their own HTTP response — using
// http.ErrAbortHandler here would abort the connection if the error
// ever propagated to the net/http recovery handler.
var errInvalidRange = errors.New("dashboard: invalid range")

// maxRange caps how far back any range-driven read (dashboard summary,
// education analytics) may look. Without it a caller could pass an
// arbitrarily large window (e.g. range=99999d) and force the underlying
// stores to scan a tenant's entire campaign/interaction history in one
// request. One year is comfortably above the largest documented default
// (90d) while bounding worst-case query cost. parseRange clamps rather
// than rejecting so an over-large request still returns useful data over
// the widest supported window instead of a 400 the caller must handle.
const maxRange = 366 * 24 * time.Hour

func parseRange(s string) (time.Duration, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 2 {
		return 0, errInvalidRange
	}
	unit := s[len(s)-1]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errInvalidRange, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%w: value must be positive", errInvalidRange)
	}
	var unitDur time.Duration
	switch unit {
	case 'd':
		unitDur = 24 * time.Hour
	case 'h':
		unitDur = time.Hour
	case 'm':
		unitDur = time.Minute
	default:
		return 0, fmt.Errorf("%w: unknown unit %q", errInvalidRange, unit)
	}
	// Clamp n to the cap's worth of this unit *before* multiplying, so an
	// absurd value (e.g. range=9999999999d) collapses to maxRange instead
	// of overflowing int64 and wrapping to a negative duration.
	if maxN := int(maxRange / unitDur); n > maxN {
		return maxRange, nil
	}
	return time.Duration(n) * unitDur, nil
}
