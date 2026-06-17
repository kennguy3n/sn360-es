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
	"mime"
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
	// providers, when non-empty, is the set of provider keys the
	// admin API accepts on POST /v1/intel/feeds. Production wires
	// the populated intel.DefaultRegistry's Providers() result
	// (see routes.go), which keeps the handler aligned with the
	// constructors actually registered for poll-time use without
	// hardcoding a second list. Leave empty to skip provider-key
	// validation (test default — the in-memory store does not
	// need the registry plumbed in).
	providers map[string]struct{}
}

// NewIntelFeedsHandler constructs the handler. logger is required;
// refresher may be nil (in which case /refresh returns 501).
func NewIntelFeedsHandler(logger *slog.Logger, store intel.IntelStore, refresher IntelFeedRefresher) *IntelFeedsHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &IntelFeedsHandler{logger: logger, store: store, refresher: refresher}
}

// WithProviders returns h with the provider-key validator populated
// from the supplied slice. The handler rejects POST /v1/intel/feeds
// requests whose provider field is not in this set with a 400.
//
// Production passes intel.DefaultRegistry.Providers() so the admin
// API only accepts providers that have a registered Constructor (and
// will therefore actually poll once the feed is created). Without
// this guard, MemoryIntelStore would silently accept an unknown
// provider name — a divergence from the Postgres CHECK constraint
// (migrations/0024_threat_intel_feeds.up.sql) that the dev/test
// backend used to share.
//
// Returns the receiver so the call composes naturally at wiring time:
//
//	handler.NewIntelFeedsHandler(...).WithProviders(intel.DefaultRegistry.Providers())
func (h *IntelFeedsHandler) WithProviders(providers []string) *IntelFeedsHandler {
	if h == nil {
		return h
	}
	if len(providers) == 0 {
		h.providers = nil
		return h
	}
	set := make(map[string]struct{}, len(providers))
	for _, p := range providers {
		set[p] = struct{}{}
	}
	h.providers = set
	return h
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
	// Normalise via EffectiveScope so the empty-means-banner_action
	// default is treated uniformly with the rest of the scope sites
	// (a legacy empty-scope token must never satisfy admin_api).
	if privacy.EffectiveScope(claims.Scope) != privacy.ScopeAdminAPI {
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
	// Trim before the empty check so a whitespace-only payload also
	// short-circuits with a clear 400 in both backends. PgIntelStore
	// would catch an empty URL via the CHECK (length(url) > 0)
	// constraint on intel_feeds (returning a 500) but would happily
	// store a whitespace-only one; MemoryIntelStore would accept
	// either silently. The patch path applies the same trim — see
	// patchFeed below.
	req.Name = strings.TrimSpace(req.Name)
	req.Provider = strings.TrimSpace(req.Provider)
	req.URL = strings.TrimSpace(req.URL)
	if req.Name == "" || req.Provider == "" || req.URL == "" {
		writeError(w, http.StatusBadRequest, "name_provider_url_required")
		return
	}
	// If the handler was wired with the registry's provider keys,
	// reject anything outside the set with a 400. This mirrors the
	// Postgres CHECK (provider IN ('urlhaus','misp','stix-taxii',
	// 'csv')) constraint and the OpenAPI enum, so dev/test (memory)
	// behaviour matches production. We deliberately do not advertise
	// the accepted set in the error body — callers see the same
	// enum in the OpenAPI document.
	if h.providers != nil {
		if _, ok := h.providers[req.Provider]; !ok {
			writeError(w, http.StatusBadRequest, "provider_unknown")
			return
		}
	}
	interval := 15 * time.Minute
	if req.FetchIntervalSec != 0 {
		// Reject anything below the OpenAPI minimum (60s).
		// Zero falls through to the 15-minute default. The
		// PATCH path uses the same validator below; keeping
		// CREATE and PATCH aligned avoids the regression where
		// a feed can be created at 30s OR patched to 30s and
		// hammer the upstream provider once per worker tick
		// (see filterDue in internal/service/worker/intel_worker.go).
		if err := validateFetchIntervalSec(req.FetchIntervalSec); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
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
		// Reject empty/whitespace URLs at the handler so the dev/test
		// in-memory backend and production Postgres backend behave
		// identically. PgIntelStore would otherwise return a 500 from
		// the CHECK (length(url) > 0) constraint on intel_feeds
		// (migrations/0024_threat_intel_feeds.up.sql) while
		// MemoryIntelStore silently accepted the empty URL, creating
		// a feed the worker could never poll. Trim whitespace too so
		// the more obvious "URL is just spaces" case also short-
		// circuits with a clear 400.
		trimmed := strings.TrimSpace(*req.URL)
		if trimmed == "" {
			writeError(w, http.StatusBadRequest, "url_empty")
			return
		}
		patch.URL = &trimmed
	}
	if req.FetchIntervalSec != nil {
		// Same OpenAPI minimum (60s) the create path enforces.
		// Without this, PATCH {"fetch_interval_sec": 0} would
		// pin the feed's nextDue at exactly LastFetchedAt and
		// the worker would re-poll on every tick (default 1m)
		// — potentially earning the deployment a rate-limit
		// from URLhaus / MISP / the TAXII provider.
		if err := validateFetchIntervalSec(*req.FetchIntervalSec); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
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

// minFetchIntervalSec is the minimum poll cadence the admin API
// accepts on either CREATE or PATCH. The constant mirrors the
// OpenAPI `minimum: 60` constraint on the `fetch_interval_sec`
// field (see api/openapi.yaml). Anything lower would let an
// operator (or a typo) pin nextDue at or before the worker's tick
// (default 1m, see WORKER_INTEL_INTERVAL), causing the worker to
// re-poll the same feed every cycle and earn the deployment a
// rate-limit from URLhaus / MISP / the TAXII provider.
const minFetchIntervalSec int64 = 60

// validateFetchIntervalSec returns a non-nil error whose message is
// the wire-error code the caller should pass to writeError when the
// supplied value is outside the documented range. Returning an
// error (rather than emitting the response inline) keeps the create /
// patch handlers responsible for their own response paths and makes
// the validator trivially unit-testable.
func validateFetchIntervalSec(v int64) error {
	if v < minFetchIntervalSec {
		return errFetchIntervalBelowMin
	}
	return nil
}

// errFetchIntervalBelowMin is the canonical wire-error code returned
// to clients on CREATE / PATCH with fetch_interval_sec < 60. The
// `_err` suffix on the variable is deliberately omitted so the
// constant reads naturally at the call sites.
var errFetchIntervalBelowMin = wireError("fetch_interval_sec_below_minimum")

// wireError is the error-string type used for handler-level
// validation responses. It exists only so writeError's "msg" arg
// stays a plain string at the call site while the validator can
// return a typed error value.
type wireError string

func (e wireError) Error() string { return string(e) }

// decodeJSON validates the Content-Type header, decodes the body into
// `out`, and rejects unknown fields. Returns false when the response
// was already written (caller short-circuits).
//
// Content-Type handling. We require `application/json` (charset and
// other parameters are tolerated, e.g. `application/json; charset=utf-8`)
// and return 415 Unsupported Media Type when a request body is supplied
// under a non-JSON content type. An entirely missing Content-Type
// header is permitted so the endpoint stays curl-friendly when the
// caller forgot the `-H` flag — the json decoder will still reject any
// non-JSON payload below with a 400. The 415 path matters because the
// admin API is occasionally hit by misconfigured automations that POST
// form-encoded bodies; without the explicit check those got a vague
// "invalid_json" instead of an actionable "wrong content type".
func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType, _, err := mime.ParseMediaType(ct)
		if err != nil || !strings.EqualFold(mediaType, "application/json") {
			w.Header().Set("Accept-Post", "application/json")
			writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
			return false
		}
	}
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
