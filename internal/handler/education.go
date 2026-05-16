package handler

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/service/education"
)

// EducationHandler serves GET /v1/education/lesson/{category}?locale=en.
// It returns a single MicroLesson rendered as JSON.
type EducationHandler struct {
	logger  *slog.Logger
	service *education.MicroLessonService
}

// NewEducationHandler wires the handler. service is required.
func NewEducationHandler(logger *slog.Logger, service *education.MicroLessonService) *EducationHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &EducationHandler{logger: logger, service: service}
}

// ServeHTTP implements http.Handler.
func (h *EducationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.service == nil {
		writeError(w, http.StatusServiceUnavailable, "education service not configured")
		return
	}
	// Path: /v1/education/lesson/{CATEGORY}
	categoryStr := strings.TrimPrefix(r.URL.Path, "/v1/education/lesson/")
	categoryStr = strings.TrimSpace(categoryStr)
	if categoryStr == "" {
		writeError(w, http.StatusBadRequest, "category is required")
		return
	}
	category := constant.Category(categoryStr)
	if !category.Valid() {
		writeError(w, http.StatusBadRequest, "unknown category")
		return
	}
	locale := strings.TrimSpace(r.URL.Query().Get("locale"))
	if locale == "" {
		locale = "en"
	}
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	userHash := strings.TrimSpace(r.URL.Query().Get("user_hash"))
	pseudoMsg := strings.TrimSpace(r.URL.Query().Get("pseudo_message_id"))

	req := education.ServeRequest{
		TenantID:        tenantID,
		UserHash:        userHash,
		Category:        category,
		Locale:          locale,
		PseudoMessageID: pseudoMsg,
	}
	if tenantID == "" {
		// Allow anonymous lookups (e.g. content previews) — return the
		// lesson without publishing the trigger event.
		lesson, ok := h.service.GetLesson(r.Context(), category, locale)
		if !ok {
			writeError(w, http.StatusNotFound, "no lesson available")
			return
		}
		writeJSON(w, http.StatusOK, lesson)
		return
	}
	lesson, err := h.service.Serve(r.Context(), req)
	if err != nil {
		h.logger.WarnContext(r.Context(), "education: serve failed",
			slog.String("category", string(category)),
			slog.String("locale", locale),
			slog.Any("error", err),
		)
		writeError(w, http.StatusNotFound, "no lesson available")
		return
	}
	writeJSON(w, http.StatusOK, lesson)
}
