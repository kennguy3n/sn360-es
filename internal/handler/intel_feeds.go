// Package handler — intel_feeds.go implements the admin-only HTTP
// surface for managing threat-intel feeds and inspecting indicators.
//
// All routes require a JWT with `scp=admin_api`. The handler emits
// uniform 401 / 403 / 404 / 409 / 422 responses with a JSON
// `{"error": "..."}` body that matches the wider handler convention
// (see banner_action.go writeError).
package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/pkg/intel"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// IntelFeedRefresher is the (optional) hook used by the
// /v1/intel/feeds/{id}/refresh endpoint to force a fresh poll
// outside the worker's normal schedule. Production wires
// internal/service/worker.IntelJob.PollFeed; tests substitute a
// stub.
type IntelFeedRefresher interface {
	// PollFeed runs a single poll of the named feed and returns
	// the number of indicators inserted+updated by the upsert.
	PollFeed(ctx context.Context, feedID string) (int, error)
}

// IntelFeedsHandler serves the /v1/intel/* admin surface.
type IntelFeedsHandler struct {
	logger    *slog.Logger
	store     intel.IntelStore
	refresher IntelFeedRefresher
}

// NewIntelFeedsHandler constructs the handler. logger is required;
// refresher may be nil (in which case /refresh returns 501).
func NewIntelFeedsHandler(logger *slog.Logger, store intel.IntelStore, refresher IntelFeedRefresher) *IntelFeedsHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &IntelFeedsHandler{logger: logger, store: store, refresher: refresher}
}

// ServeFeeds dispatches /v1/intel/feeds and /v1/intel/feeds/{id}
// (with optional /refresh suffix). It is mounted once under the
// "/v1/intel/feeds" path prefix in routes.go.
func (h *IntelFeedsHandler) ServeFeeds(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "intel_store_unavailable")
		return
	}
	if !h.assertAdmin(w, r) {
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v1/intel/feeds")
	path = strings.TrimSuffix(path, "/")
	switch {
	case path == "":
		switch r.Method {
		case http.MethodGet:
			h.listFeeds(w, r)
		case http.MethodPost:
			h.createFeed(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		}
	case strings.HasSuffix(path, "/refresh"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/refresh")
		if id == "" {
			writeError(w, http.StatusBadRequest, "missing_feed_id")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		h.refreshFeed(w, r, id)
	default:
		id := strings.TrimPrefix(path, "/")
		if id == "" || strings.ContainsRune(id, '/') {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		switch r.Method {
		case http.MethodPatch:
			h.patchFeed(w, r, id)
		case http.MethodDelete:
			h.deleteFeed(w, r, id)
		case http.MethodGet:
			h.getFeed(w, r, id)
		default:
			w.Header().Set("Allow", "GET, PATCH, DELETE")
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		}
	}
}

// ServeIndicators handles GET /v1/intel/indicators?indicator=...
func (h *IntelFeedsHandler) ServeIndicators(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "intel_store_unavailable")
		return
	}
	if !h.assertAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	ind := strings.TrimSpace(r.URL.Query().Get("indicator"))
	if ind == "" {
		writeError(w, http.StatusBadRequest, "missing_indicator")
		return
	}
	matches, err := h.store.FindByIndicator(r.Context(), ind)
	if err != nil {
		h.logger.WarnContext(r.Context(), "intel: FindByIndicator failed", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "lookup_failed")
		return
	}
	writeJSON(w, http.StatusOK, indicatorLookupResponse{
		Indicator: ind,
		Matches:   matchedIndicatorsAPI(matches),
	})
}

// assertAdmin enforces the admin_api JWT scope. Returns true when
// the request is allowed to proceed. Logs and writes the error
// response otherwise.
func (h *IntelFeedsHandler) assertAdmin(w http.ResponseWriter, r *http.Request) bool {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_claims")
		return false
	}
	if claims.Scope != privacy.ScopeAdminAPI {
		// Uniform 403 — no claim leak.
		writeError(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}

// listFeeds GET /v1/intel/feeds
func (h *IntelFeedsHandler) listFeeds(w http.ResponseWriter, r *http.Request) {
	feeds, err := h.store.ListFeeds(r.Context())
	if err != nil {
		h.logger.WarnContext(r.Context(), "intel: ListFeeds failed", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "list_failed")
		return
	}
	out := make([]feedAPI, 0, len(feeds))
	for _, f := range feeds {
		out = append(out, feedToAPI(f))
	}
	writeJSON(w, http.StatusOK, feedListResponse{Feeds: out})
}

// createFeed POST /v1/intel/feeds
func (h *IntelFeedsHandler) createFeed(w http.ResponseWriter, r *http.Request) {
	var req createFeedRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" || req.Provider == "" || req.URL == "" {
		writeError(w, http.StatusBadRequest, "name_provider_url_required")
		return
	}
	interval := 15 * time.Minute
	if req.FetchIntervalSec > 0 {
		interval = time.Duration(req.FetchIntervalSec) * time.Second
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	created, err := h.store.CreateFeed(r.Context(), intel.Feed{
		Name:          req.Name,
		Provider:      req.Provider,
		URL:           req.URL,
		FetchInterval: interval,
		Enabled:       enabled,
	})
	switch {
	case errors.Is(err, intel.ErrFeedExists):
		writeError(w, http.StatusConflict, "feed_name_conflict")
		return
	case err != nil:
		h.logger.WarnContext(r.Context(), "intel: CreateFeed failed",
			slog.String("name", req.Name), slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, feedToAPI(created))
}

// patchFeed PATCH /v1/intel/feeds/{id}
func (h *IntelFeedsHandler) patchFeed(w http.ResponseWriter, r *http.Request, id string) {
	var req patchFeedRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	patch := intel.FeedPatch{}
	if req.URL != nil {
		patch.URL = req.URL
	}
	if req.FetchIntervalSec != nil {
		d := time.Duration(*req.FetchIntervalSec) * time.Second
		patch.FetchInterval = &d
	}
	if req.Enabled != nil {
		patch.Enabled = req.Enabled
	}
	updated, err := h.store.UpdateFeed(r.Context(), id, patch)
	switch {
	case errors.Is(err, intel.ErrFeedNotFound):
		writeError(w, http.StatusNotFound, "feed_not_found")
		return
	case err != nil:
		h.logger.WarnContext(r.Context(), "intel: UpdateFeed failed",
			slog.String("feed_id", id), slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "update_failed")
		return
	}
	writeJSON(w, http.StatusOK, feedToAPI(updated))
}

// deleteFeed DELETE /v1/intel/feeds/{id}
func (h *IntelFeedsHandler) deleteFeed(w http.ResponseWriter, r *http.Request, id string) {
	err := h.store.DeleteFeed(r.Context(), id)
	switch {
	case errors.Is(err, intel.ErrFeedNotFound):
		writeError(w, http.StatusNotFound, "feed_not_found")
		return
	case err != nil:
		h.logger.WarnContext(r.Context(), "intel: DeleteFeed failed",
			slog.String("feed_id", id), slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "delete_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getFeed GET /v1/intel/feeds/{id}
func (h *IntelFeedsHandler) getFeed(w http.ResponseWriter, r *http.Request, id string) {
	f, err := h.store.GetFeed(r.Context(), id)
	switch {
	case errors.Is(err, intel.ErrFeedNotFound):
		writeError(w, http.StatusNotFound, "feed_not_found")
		return
	case err != nil:
		h.logger.WarnContext(r.Context(), "intel: GetFeed failed",
			slog.String("feed_id", id), slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "get_failed")
		return
	}
	writeJSON(w, http.StatusOK, feedToAPI(f))
}

// refreshFeed POST /v1/intel/feeds/{id}/refresh
func (h *IntelFeedsHandler) refreshFeed(w http.ResponseWriter, r *http.Request, id string) {
	if h.refresher == nil {
		writeError(w, http.StatusNotImplemented, "refresh_unavailable")
		return
	}
	n, err := h.refresher.PollFeed(r.Context(), id)
	switch {
	case errors.Is(err, intel.ErrFeedNotFound):
		writeError(w, http.StatusNotFound, "feed_not_found")
		return
	case err != nil:
		h.logger.WarnContext(r.Context(), "intel: refresh failed",
			slog.String("feed_id", id), slog.Any("error", err))
		writeError(w, http.StatusBadGateway, "refresh_failed")
		return
	}
	writeJSON(w, http.StatusOK, refreshResponse{IndicatorsUpserted: n})
}

// decodeJSON validates Content-Type and decodes into out. Returns
// false when the response was already written (caller short-circuits).
func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	const limit = 1 << 20 // 1 MiB cap on admin bodies
	body, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil {
		writeError(w, http.StatusBadRequest, "body_read_failed")
		return false
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "empty_body")
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

// --- DTOs ---

type createFeedRequest struct {
	Name             string `json:"name"`
	Provider         string `json:"provider"`
	URL              string `json:"url"`
	FetchIntervalSec int64  `json:"fetch_interval_sec,omitempty"`
	Enabled          *bool  `json:"enabled,omitempty"`
}

type patchFeedRequest struct {
	URL              *string `json:"url,omitempty"`
	FetchIntervalSec *int64  `json:"fetch_interval_sec,omitempty"`
	Enabled          *bool   `json:"enabled,omitempty"`
}

type feedAPI struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Provider            string `json:"provider"`
	URL                 string `json:"url"`
	FetchIntervalSec    int64  `json:"fetch_interval_sec"`
	Enabled             bool   `json:"enabled"`
	LastFetchedAt       string `json:"last_fetched_at,omitempty"`
	LastOK              *bool  `json:"last_ok,omitempty"`
	LastError           string `json:"last_error,omitempty"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	CreatedAt           string `json:"created_at"`
}

func feedToAPI(f intel.Feed) feedAPI {
	out := feedAPI{
		ID:                  f.ID,
		Name:                f.Name,
		Provider:            f.Provider,
		URL:                 f.URL,
		FetchIntervalSec:    int64(f.FetchInterval / time.Second),
		Enabled:             f.Enabled,
		LastOK:              f.LastOK,
		LastError:           f.LastError,
		ConsecutiveFailures: f.ConsecutiveFailures,
		CreatedAt:           f.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if f.LastFetchedAt != nil {
		out.LastFetchedAt = f.LastFetchedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

type feedListResponse struct {
	Feeds []feedAPI `json:"feeds"`
}

type refreshResponse struct {
	IndicatorsUpserted int `json:"indicators_upserted"`
}

type indicatorLookupResponse struct {
	Indicator string                `json:"indicator"`
	Matches   []matchedIndicatorAPI `json:"matches"`
}

type matchedIndicatorAPI struct {
	HashHex       string    `json:"hash_hex"`
	Indicator     string    `json:"indicator"`
	IndicatorType string    `json:"indicator_type"`
	FeedID        string    `json:"feed_id"`
	FeedName      string    `json:"feed_name"`
	Severity      int       `json:"severity"`
	Tags          []string  `json:"tags,omitempty"`
	LastSeen      time.Time `json:"last_seen"`
}

func matchedIndicatorsAPI(in []intel.MatchedIndicator) []matchedIndicatorAPI {
	out := make([]matchedIndicatorAPI, 0, len(in))
	for _, m := range in {
		out = append(out, matchedIndicatorAPI{
			HashHex:       hex.EncodeToString(m.Hash),
			Indicator:     m.Indicator,
			IndicatorType: string(m.IndicatorType),
			FeedID:        m.FeedID,
			FeedName:      m.FeedName,
			Severity:      m.Severity,
			Tags:          m.Tags,
			LastSeen:      m.LastSeen,
		})
	}
	return out
}
