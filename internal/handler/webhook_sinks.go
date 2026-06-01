// Package handler — webhook_sinks.go implements the WS-5B.2 CRUD
// surface for per-tenant standalone webhook sinks (the routes
// documented in api/openapi.yaml).
//
// Auth contract: every endpoint requires the caller to carry a JWT
// with privacy.RoleAdmin (gated upstream by
// middleware.RequireAdmin) AND a tid claim matching the
// {tenant_id} path segment. Cross-tenant requests fail closed with
// 403 — the database RLS policy also rejects them, but the handler
// catches the mismatch first so the audit row records the
// originating tenant rather than a generic "row not found".
//
// Secret handling: the 32-byte HMAC secret is generated server-side
// on create + rotate, returned ONCE in base64 in the response body,
// and never logged, never written to the audit table, and never
// echoed in subsequent reads. The DB row holds only the AES-encrypted
// ciphertext (envelope-encryption via privacy.Encryptor).
package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/webhooksink"
	"github.com/kennguy3n/sn360-es/pkg/sinks/webhook"
)

// WebhookSinkDispatcher is the dispatcher the test endpoint
// invokes. The DispatchTestEvent method synthesises a benign
// event and POSTs it to the customer endpoint so the operator can
// verify connectivity + signature on the receiving side.
type WebhookSinkDispatcher interface {
	DispatchTestEvent(ctx context.Context, sink *repository.WebhookSink) (webhook.PublishResult, error)
}

// WebhookSinksHandler serves the /v1/tenants/{tenant_id}/webhook-sinks
// surface. Mounted only when both the repository and the dispatcher
// are wired; the route table omits the prefix otherwise so callers
// see a clean 404 rather than a 503-on-every-request shape.
type WebhookSinksHandler struct {
	logger     *slog.Logger
	repo       repository.WebhookSinkRepository
	encryptor  webhooksink.SecretEncryptor
	dispatcher WebhookSinkDispatcher
}

// NewWebhookSinksHandler wires the handler. repo + encryptor are
// required; dispatcher is required for the test endpoint and may
// be nil (the route then returns 503).
func NewWebhookSinksHandler(
	logger *slog.Logger,
	repo repository.WebhookSinkRepository,
	encryptor webhooksink.SecretEncryptor,
	dispatcher WebhookSinkDispatcher,
) (*WebhookSinksHandler, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if repo == nil {
		return nil, errors.New("webhook_sinks: repo is required")
	}
	if encryptor == nil {
		return nil, errors.New("webhook_sinks: encryptor is required")
	}
	return &WebhookSinksHandler{
		logger:     logger,
		repo:       repo,
		encryptor:  encryptor,
		dispatcher: dispatcher,
	}, nil
}

// ----- Wire shapes ----------------------------------------------------------

// webhookSinkResponse is the persisted view of a sink. NEVER carries
// the plaintext HMAC secret; the create + rotate endpoints embed
// the secret in their own response shapes.
type webhookSinkResponse struct {
	ID           string                        `json:"id"`
	TenantID     string                        `json:"tenant_id"`
	Name         string                        `json:"name"`
	URL          string                        `json:"url"`
	Format       repository.WebhookSinkFormat  `json:"format"`
	EventFilters repository.WebhookSinkFilters `json:"event_filters"`
	Enabled      bool                          `json:"enabled"`
	CreatedAt    time.Time                     `json:"created_at"`
	UpdatedAt    time.Time                     `json:"updated_at"`
}

// webhookSinkCreateRequest is the POST body. hmac_secret_b64 is
// returned in the response, never accepted from the request — the
// scope requires server-generated secrets.
type webhookSinkCreateRequest struct {
	Name         string                         `json:"name"`
	URL          string                         `json:"url"`
	Format       repository.WebhookSinkFormat   `json:"format"`
	EventFilters *repository.WebhookSinkFilters `json:"event_filters,omitempty"`
	Enabled      *bool                          `json:"enabled,omitempty"`
}

// webhookSinkCreateResponse extends the persisted view with the
// plaintext HMAC secret. This is the ONE response in the API that
// surfaces the secret; subsequent GETs and PATCH responses omit it.
type webhookSinkCreateResponse struct {
	webhookSinkResponse
	HMACSecretBase64 string `json:"hmac_secret_b64"`
}

// webhookSinkUpdateRequest is the PATCH body. All fields are
// optional pointers so "omit" reliably means "don't touch this
// field". Name updates are NOT supported (the table's UNIQUE
// (tenant_id, name) makes rename a multi-step migration we don't
// want to leak into the API yet).
type webhookSinkUpdateRequest struct {
	URL          *string                        `json:"url,omitempty"`
	Format       *repository.WebhookSinkFormat  `json:"format,omitempty"`
	EventFilters *repository.WebhookSinkFilters `json:"event_filters,omitempty"`
	Enabled      *bool                          `json:"enabled,omitempty"`
}

// webhookSinkListResponse wraps the list reply so we can add cursor
// pagination later without a breaking change.
type webhookSinkListResponse struct {
	Sinks []webhookSinkResponse `json:"sinks"`
}

// webhookSinkTestResponse is the body of POST .../test. The customer-
// facing HTTP status is the headline; latency + outcome are
// included for end-to-end diagnostics.
type webhookSinkTestResponse struct {
	Outcome    string `json:"outcome"`
	HTTPStatus int    `json:"http_status"`
	LatencyMS  int64  `json:"latency_ms"`
	Cause      string `json:"cause,omitempty"`
}

// ----- Routing --------------------------------------------------------------

// pathPrefix matches paths beginning /v1/tenants/.../webhook-sinks.
const webhookSinksRoutePrefix = "/v1/tenants/"

// ServeHTTP routes /v1/tenants/{tenant_id}/webhook-sinks[...] to
// the matching handler method. The router is hand-rolled because
// the rest of the binary uses stdlib net/http.ServeMux which does
// not support path variables natively on the legacy mux.
func (h *WebhookSinksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tenantID, suffix, ok := parseTenantSinksPath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !h.tenantBoundedAuthz(w, r, tenantID) {
		return
	}
	switch {
	case suffix == "":
		// /v1/tenants/{tid}/webhook-sinks
		switch r.Method {
		case http.MethodGet:
			h.serveList(w, r, tenantID)
		case http.MethodPost:
			h.serveCreate(w, r, tenantID)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case strings.HasSuffix(suffix, "/test"):
		// /v1/tenants/{tid}/webhook-sinks/{id}/test
		id := strings.TrimSuffix(suffix, "/test")
		id = strings.TrimPrefix(id, "/")
		if id == "" || strings.Contains(id, "/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.serveTest(w, r, tenantID, id)
	default:
		// /v1/tenants/{tid}/webhook-sinks/{id}
		id := strings.TrimPrefix(suffix, "/")
		if id == "" || strings.Contains(id, "/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			h.serveGet(w, r, tenantID, id)
		case http.MethodPatch:
			h.serveUpdate(w, r, tenantID, id)
		case http.MethodDelete:
			h.serveDelete(w, r, tenantID, id)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

// parseTenantSinksPath splits /v1/tenants/{tid}/webhook-sinks{rest}
// into (tid, rest, ok). rest is "" for the collection endpoint,
// "/<id>" for an item, "/<id>/test" for the test sub-resource. ok
// is false when the path doesn't match the prefix pattern at all.
func parseTenantSinksPath(p string) (tenantID, suffix string, ok bool) {
	if !strings.HasPrefix(p, webhookSinksRoutePrefix) {
		return "", "", false
	}
	rest := p[len(webhookSinksRoutePrefix):]
	// rest is "{tid}/webhook-sinks{rest}"
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return "", "", false
	}
	tenantID = rest[:slash]
	tail := rest[slash:] // "/webhook-sinks..."
	const seg = "/webhook-sinks"
	if !strings.HasPrefix(tail, seg) {
		return "", "", false
	}
	suffix = tail[len(seg):]
	// Reject `/webhook-sinksXXX` style paths where the prefix
	// match accepts any continuation. The collection endpoint
	// has an empty suffix; sub-resources start with '/'. Anything
	// else is a malformed path and must 404 at the parser layer
	// rather than traversing into the repo with a garbled id.
	if suffix != "" && suffix[0] != '/' {
		return "", "", false
	}
	if tenantID == "" {
		return "", "", false
	}
	return tenantID, suffix, true
}

// tenantBoundedAuthz cross-checks the path's tenant_id against the
// JWT's tid claim. JWT validity is enforced upstream by JWTAuth +
// RequireAdmin; this routine fails closed on a mismatch.
func (h *WebhookSinksHandler) tenantBoundedAuthz(w http.ResponseWriter, r *http.Request, pathTenant string) bool {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		// Should not happen — RequireAdmin already rejected
		// the request — but treat as a defensive 403.
		writeError(w, http.StatusForbidden, "admin_required")
		return false
	}
	// Fail closed when the JWT carries no tenant binding at all
	// or when it binds to a different tenant. JWTAuth rejects
	// empty `tid` tokens upstream today, but treating an empty
	// claim as "match anything" would silently re-open the
	// cross-tenant boundary if that upstream invariant ever
	// drifted (e.g. a new auth middleware that doesn't enforce
	// tid, or a test injecting claims via ContextWithClaims).
	if claims.TenantID == "" || claims.TenantID != pathTenant {
		h.logger.WarnContext(r.Context(), "webhook_sinks: tenant claim mismatch",
			slog.String("path_tenant", pathTenant),
			slog.String("claim_tenant", claims.TenantID))
		writeError(w, http.StatusForbidden, "tenant_mismatch")
		return false
	}
	return true
}

// ----- Endpoints ------------------------------------------------------------

func (h *WebhookSinksHandler) serveList(w http.ResponseWriter, r *http.Request, tenantID string) {
	sinks, err := h.repo.List(r.Context(), tenantID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "webhook_sinks: list failed",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]webhookSinkResponse, 0, len(sinks))
	for i := range sinks {
		out = append(out, toWebhookSinkResponse(&sinks[i]))
	}
	writeJSON(w, http.StatusOK, webhookSinkListResponse{Sinks: out})
}

func (h *WebhookSinksHandler) serveGet(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	sink, err := h.repo.GetByID(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		h.logger.ErrorContext(r.Context(), "webhook_sinks: get failed",
			slog.String("tenant_id", tenantID),
			slog.String("sink_id", id),
			slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, toWebhookSinkResponse(sink))
}

func (h *WebhookSinksHandler) serveCreate(w http.ResponseWriter, r *http.Request, tenantID string) {
	var req webhookSinkCreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.URL = strings.TrimSpace(req.URL)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := validateWebhookURL(req.URL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	format := req.Format
	if format == "" {
		format = repository.WebhookSinkFormatECS
	}
	if !format.Valid() {
		writeError(w, http.StatusBadRequest, "invalid format")
		return
	}
	var filters repository.WebhookSinkFilters
	if req.EventFilters != nil {
		filters = *req.EventFilters
	}
	if err := validateFilters(&filters); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	// Server-generated 32-byte HMAC secret. Returned in the
	// response body ONCE; the persisted row holds only the
	// envelope-encrypted ciphertext.
	secret, err := webhook.GenerateSecret()
	if err != nil {
		h.logger.ErrorContext(r.Context(), "webhook_sinks: generate secret failed",
			slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Safety net: any early-return below leaves the raw secret
	// in memory until GC. The happy path scrubs it inline
	// immediately after b64-encoding (see below), so this defer
	// is a no-op on success and a backstop on error paths.
	defer zeroSecret(secret)
	cipher, err := h.encryptor.Encrypt(r.Context(), tenantID, secret)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "webhook_sinks: encrypt secret failed",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	sink := &repository.WebhookSink{
		TenantID:             tenantID,
		Name:                 req.Name,
		URL:                  req.URL,
		HMACSecretCiphertext: cipher,
		Format:               format,
		EventFilters:         filters,
		Enabled:              enabled,
	}
	if err := h.repo.Create(r.Context(), sink); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "sink with that name already exists")
			return
		}
		h.logger.ErrorContext(r.Context(), "webhook_sinks: create failed",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.appendAudit(r.Context(), sink, repository.WebhookSinkAuditActionCreated, "")
	// Encode into the response struct, then immediately scrub
	// the raw secret buffer. The encoded string is a fresh copy
	// owned by `resp` — we no longer need the []byte and want
	// to minimise the window during which the plaintext key
	// sits in resident memory (defense-in-depth against a
	// post-response panic / log dump). The deferred zeroSecret
	// above is idempotent against already-zero bytes.
	encoded := base64.StdEncoding.EncodeToString(secret)
	zeroSecret(secret)
	resp := webhookSinkCreateResponse{
		webhookSinkResponse: toWebhookSinkResponse(sink),
		HMACSecretBase64:    encoded,
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *WebhookSinksHandler) serveUpdate(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	var req webhookSinkUpdateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	upd := repository.WebhookSinkUpdate{}
	if req.URL != nil {
		u := strings.TrimSpace(*req.URL)
		if err := validateWebhookURL(u); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		upd.URL = &u
	}
	if req.Format != nil {
		if !req.Format.Valid() {
			writeError(w, http.StatusBadRequest, "invalid format")
			return
		}
		upd.Format = req.Format
	}
	if req.EventFilters != nil {
		if err := validateFilters(req.EventFilters); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		upd.EventFilters = req.EventFilters
	}
	if req.Enabled != nil {
		upd.Enabled = req.Enabled
	}
	sink, err := h.repo.Update(r.Context(), tenantID, id, upd)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		h.logger.ErrorContext(r.Context(), "webhook_sinks: update failed",
			slog.String("tenant_id", tenantID),
			slog.String("sink_id", id),
			slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.appendAudit(r.Context(), sink, repository.WebhookSinkAuditActionUpdated, "")
	writeJSON(w, http.StatusOK, toWebhookSinkResponse(sink))
}

func (h *WebhookSinksHandler) serveDelete(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	// Single-statement soft-delete-and-return. We rely on the
	// repo to return the row snapshot atomically with the delete
	// so the audit row records the pre-delete name/URL/format
	// values without a TOCTOU window against a concurrent
	// Update or a competing soft-delete from another admin.
	sink, err := h.repo.SoftDelete(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		h.logger.ErrorContext(r.Context(), "webhook_sinks: delete failed",
			slog.String("tenant_id", tenantID),
			slog.String("sink_id", id),
			slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.appendAudit(r.Context(), sink, repository.WebhookSinkAuditActionDeleted, "")
	w.WriteHeader(http.StatusNoContent)
}

func (h *WebhookSinksHandler) serveTest(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	if h.dispatcher == nil {
		writeError(w, http.StatusServiceUnavailable, "dispatcher not wired")
		return
	}
	sink, err := h.repo.GetByID(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		h.logger.ErrorContext(r.Context(), "webhook_sinks: test-lookup failed",
			slog.String("tenant_id", tenantID),
			slog.String("sink_id", id),
			slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !sink.Enabled {
		// Refuse to test a disabled sink — the dispatcher
		// would skip it on the live path so the test result
		// would be misleading. The operator should re-enable
		// (PATCH enabled=true) first.
		writeError(w, http.StatusConflict, "sink disabled; enable it before testing")
		return
	}
	result, dErr := h.dispatcher.DispatchTestEvent(r.Context(), sink)
	body := webhookSinkTestResponse{
		Outcome:    result.Outcome.String(),
		HTTPStatus: result.HTTPStatus,
		LatencyMS:  result.LatencyMS,
		Cause:      result.Cause,
	}
	if dErr != nil && result.Outcome == webhook.OutcomeUnknown {
		// Dispatcher couldn't even attempt the publish
		// (format / sign / decrypt failure). Report 502 so
		// the operator can tell the difference between "sink
		// reachable but errored" and "config broken".
		h.logger.WarnContext(r.Context(), "webhook_sinks: test dispatch failed",
			slog.String("sink_id", id),
			slog.Any("error", dErr))
		body.Cause = dErr.Error()
		writeJSON(w, http.StatusBadGateway, body)
		return
	}
	// 200 in every other case — the caller reads HTTPStatus +
	// Outcome to decide whether the receiver is happy.
	writeJSON(w, http.StatusOK, body)
}

// ----- Helpers --------------------------------------------------------------

// validateWebhookURL accepts only well-formed https:// URLs. Localhost
// and link-local addresses are accepted (operators may want to point
// a sink at a docker-compose receiver during onboarding); the SSRF
// surface is contained because the HTTPPublisher posts JSON / CEF
// with no follow-redirect (CheckRedirect returns
// http.ErrUseLastResponse, see pkg/sinks/webhook/publisher.go) and a
// hard 5s timeout, so a 307/308 from the customer endpoint cannot
// silently re-send the signed body over an attacker-controlled
// http:// or link-local target.
func validateWebhookURL(raw string) error {
	if raw == "" {
		return errors.New("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("url is not a valid URL")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("url must use https://")
	}
	if u.Host == "" {
		return errors.New("url must include a host")
	}
	return nil
}

// validateFilters checks min_tier + categories against the canonical
// constant set so a typo in the JSON doesn't silently disable the
// filter at dispatcher time.
func validateFilters(f *repository.WebhookSinkFilters) error {
	if f == nil {
		return nil
	}
	if f.MinTier != "" {
		t := constant.Tier(f.MinTier)
		if !t.Valid() {
			return fmt.Errorf("event_filters.min_tier %q is not a known tier", f.MinTier)
		}
	}
	for _, c := range f.Categories {
		cat := constant.Category(c)
		if !cat.Valid() {
			return fmt.Errorf("event_filters.categories contains unknown category %q", c)
		}
	}
	if f.RateLimitPerMinute < 0 {
		return errors.New("event_filters.rate_limit_per_minute must be >= 0")
	}
	return nil
}

func toWebhookSinkResponse(s *repository.WebhookSink) webhookSinkResponse {
	return webhookSinkResponse{
		ID:           s.ID,
		TenantID:     s.TenantID,
		Name:         s.Name,
		URL:          s.URL,
		Format:       s.Format,
		EventFilters: s.EventFilters,
		Enabled:      s.Enabled,
		CreatedAt:    s.CreatedAt,
		UpdatedAt:    s.UpdatedAt,
	}
}

// appendAudit records a CRUD audit row. Failure is logged but not
// propagated to the caller — the operation has already succeeded
// against the live row and rolling back over an audit failure would
// surprise operators.
func (h *WebhookSinksHandler) appendAudit(ctx context.Context, sink *repository.WebhookSink, action repository.WebhookSinkAuditAction, reason string) {
	if sink == nil {
		return
	}
	// Each CRUD audit row is its own event — there's no
	// upstream message-id we want to dedup on — so a fresh
	// UUID per call satisfies the table's NOT NULL dedup_id
	// constraint without conflating two operations.
	entry := repository.WebhookSinkAuditEntry{
		TenantID: sink.TenantID,
		SinkID:   sink.ID,
		SinkName: sink.Name,
		Action:   action,
		Reason:   reason,
		DedupID:  uuid.NewString(),
	}
	if err := h.repo.AppendAudit(ctx, entry); err != nil {
		h.logger.WarnContext(ctx, "webhook_sinks: audit append failed",
			slog.String("sink_id", sink.ID),
			slog.String("action", string(action)),
			slog.Any("error", err))
	}
}

// zeroSecret overwrites s with zeros. Callers defer this on the
// generated HMAC secret so the plaintext key is scrubbed from the
// goroutine stack the moment the response is written.
func zeroSecret(s []byte) {
	for i := range s {
		s[i] = 0
	}
}
