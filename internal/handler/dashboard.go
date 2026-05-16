package handler

import (
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

// NewDashboardHandler wires the handler. gen must be non-nil.
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
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id is required")
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

func parseRange(s string) (time.Duration, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 2 {
		return 0, http.ErrAbortHandler
	}
	unit := s[len(s)-1]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, err
	}
	switch unit {
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'm':
		return time.Duration(n) * time.Minute, nil
	}
	return 0, http.ErrAbortHandler
}
