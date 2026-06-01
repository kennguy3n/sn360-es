package handler

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/investigation"
)

// InvestigationHandler serves the WS-3b operator-facing
// investigation API:
//
//	GET /v1/investigation/message/{pseudo_id}
//	GET /v1/investigation/sender/{sender_hash}
//
// Both endpoints are read-only, tenant-scoped, and return 404 on
// either "not found" or "cross-tenant attempt" so the response
// surface cannot fingerprint which message IDs or sender hashes
// exist in which tenant.
type InvestigationHandler struct {
	logger *slog.Logger
	svc    *investigation.Service
}

// NewInvestigationHandler wires the handler. svc may be nil in
// degraded deployments (no Postgres / no repository registry); the
// handler routes such requests to a 503 with a generic body.
func NewInvestigationHandler(logger *slog.Logger, svc *investigation.Service) *InvestigationHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &InvestigationHandler{logger: logger, svc: svc}
}

// ServeMessage handles GET /v1/investigation/message/{pseudo_id}.
//
// Response body (200): messageTrailResponse below.
func (h *InvestigationHandler) ServeMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Authenticate BEFORE every *resource-observable* branch — the
	// nil-service infrastructure check, the path parameter parse,
	// the service call, anything whose result could differ across
	// deployments or tenants. The 405 method check above is
	// intentionally allowed to precede auth because 405 is a
	// protocol-level signal that the route exists for a different
	// verb; it is the same in every environment and conveys
	// nothing about the resource. From this point onward, however,
	// an unauthenticated caller sees exactly one response (401)
	// regardless of whether the path is malformed, the service is
	// unwired, or the message is missing. Without this ordering an
	// unauth caller could distinguish 503 (service unconfigured)
	// from 400 (bad path) and use the differential to fingerprint
	// deployments. tenantID is sourced from the verified JWT claim,
	// never from a header or path parameter — a caller cannot
	// trick the service into reading another tenant's verdict by
	// lying about their tenant in the URL.
	tenantID := middleware.TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "investigation service not configured")
		return
	}
	pseudoID := strings.TrimPrefix(r.URL.Path, "/v1/investigation/message/")
	pseudoID = strings.TrimSpace(pseudoID)
	if pseudoID == "" || strings.Contains(pseudoID, "/") {
		writeError(w, http.StatusBadRequest, "pseudo_message_id is required")
		return
	}
	trail, err := h.svc.MessageTrail(r.Context(), tenantID, pseudoID)
	if err != nil {
		// Cross-tenant attempts AND not-found both return 404
		// with the SAME response body. The two cases must be
		// indistinguishable to the caller — otherwise an
		// authenticated caller from tenant B could fingerprint
		// which message IDs exist in tenant A by probing the
		// endpoint:
		//   - 404 "not found"  -> doesn't exist OR belongs to another tenant
		//   - 200 with body    -> exists, belongs to me
		// The service collapses "wrong tenant" and "not present"
		// into the same ErrNotFound sentinel; the handler reflects
		// that into the wire surface as an indistinguishable 404.
		if errors.Is(err, investigation.ErrNotFound) {
			h.logger.WarnContext(r.Context(), "investigation: message trail target not found",
				slog.String("pseudo_message_id", pseudoID),
				slog.String("caller_tenant", tenantID),
			)
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		switch {
		case errors.Is(err, investigation.ErrMessageIDRequired),
			errors.Is(err, investigation.ErrTenantIDRequired):
			// Structurally unreachable — both are guarded above —
			// but kept as defense-in-depth so a future refactor
			// that loosens the gates still maps to a client error.
			writeError(w, http.StatusBadRequest, "invalid request")
		default:
			h.logger.WarnContext(r.Context(), "investigation: message trail failed",
				slog.String("pseudo_message_id", pseudoID),
				slog.Any("error", err),
			)
			writeError(w, http.StatusInternalServerError, "lookup failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, newMessageTrailResponse(trail))
}

// ServeSender handles GET /v1/investigation/sender/{sender_hash}.
//
// The {sender_hash} path parameter is a base64url-encoded BYTEA
// (no padding, no slashes — fits cleanly into a URL path). The
// handler decodes it before forwarding to the service so the
// service-layer sees the same raw bytes the repository indexed on.
//
// Optional query parameters:
//
//	?limit=N        (1..repository.EvalListBySenderMaxLimit)
//	?since_hours=H  (1..720; default 720 = 30d)
//
// Response body (200): senderTrailResponse below.
func (h *InvestigationHandler) ServeSender(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenantID := middleware.TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "investigation service not configured")
		return
	}
	rawHash := strings.TrimPrefix(r.URL.Path, "/v1/investigation/sender/")
	rawHash = strings.TrimSpace(rawHash)
	if rawHash == "" || strings.Contains(rawHash, "/") {
		writeError(w, http.StatusBadRequest, "sender_hash is required")
		return
	}
	// Accept both base64url (the canonical encoding the
	// dashboard uses — URL-safe, no padding) and base64-standard
	// with padding (defense-in-depth for clients that may not
	// strip padding). RawURLEncoding rejects '+' / '/' / '='
	// so this fallback chain cannot accept ambiguous input.
	senderHash, err := base64.RawURLEncoding.DecodeString(rawHash)
	if err != nil {
		senderHash, err = base64.URLEncoding.DecodeString(rawHash)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "sender_hash must be base64url-encoded bytes")
		return
	}
	if len(senderHash) == 0 {
		writeError(w, http.StatusBadRequest, "sender_hash is required")
		return
	}
	opts, perr := parseSenderTrailOptions(r.URL.Query())
	if perr != nil {
		writeError(w, http.StatusBadRequest, perr.Error())
		return
	}
	trail, err := h.svc.SenderTrail(r.Context(), tenantID, senderHash, opts)
	if err != nil {
		switch {
		case errors.Is(err, investigation.ErrSenderHashRequired),
			errors.Is(err, investigation.ErrTenantIDRequired):
			writeError(w, http.StatusBadRequest, "invalid request")
		default:
			h.logger.WarnContext(r.Context(), "investigation: sender trail failed",
				slog.Any("error", err),
			)
			writeError(w, http.StatusInternalServerError, "lookup failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, newSenderTrailResponse(trail))
}

// parseSenderTrailOptions validates the optional query parameters
// on /v1/investigation/sender/{...}. Bounds enforced here mirror
// the service-level defaults; the service additionally clamps to
// the repository cap. Out-of-range values produce 400 rather than
// silently snapping so the caller can correct typos.
func parseSenderTrailOptions(q map[string][]string) (investigation.SenderTrailOptions, error) {
	var out investigation.SenderTrailOptions
	if v := strings.TrimSpace(getFirst(q, "limit")); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil || n < 1 || n > repository.EvalListBySenderMaxLimit {
			return out, errors.New("limit must be an integer between 1 and " + strconv.Itoa(repository.EvalListBySenderMaxLimit))
		}
		out.Limit = n
	}
	if v := strings.TrimSpace(getFirst(q, "since_hours")); v != "" {
		// Cap at 30 days (720 hours) so a caller cannot turn the
		// per-sender aggregation into an unbounded historical
		// scan. The service-level default is 30 days anyway —
		// this just makes the upper bound explicit.
		n, perr := strconv.Atoi(v)
		if perr != nil || n < 1 || n > 720 {
			return out, errors.New("since_hours must be an integer between 1 and 720")
		}
		out.Since = time.Duration(n) * time.Hour
	}
	return out, nil
}

func getFirst(q map[string][]string, key string) string {
	if v, ok := q[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

// messageTrailResponse is the JSON shape the handler returns for
// /v1/investigation/message/{pseudo_id}. Field names follow the
// snake_case convention used elsewhere in the public API.
type messageTrailResponse struct {
	Result               evaluationResultJSON      `json:"result"`
	CommunicationHistory *communicationHistoryJSON `json:"communication_history,omitempty"`
}

// senderTrailResponse is the JSON shape the handler returns for
// /v1/investigation/sender/{sender_hash}. SenderHash is echoed back
// (base64url) so the caller can confirm the decode round-tripped.
type senderTrailResponse struct {
	SenderHash             string                     `json:"sender_hash"`
	Verdicts               []evaluationResultJSON     `json:"verdicts"`
	CommunicationHistories []communicationHistoryJSON `json:"communication_histories"`
	Aggregate              senderTrailAggregateJSON   `json:"aggregate"`
}

type evaluationResultJSON struct {
	ID            string    `json:"id"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	Score         int       `json:"score"`
	Tier          string    `json:"tier"`
	Primary       string    `json:"primary_category,omitempty"`
	Secondary     []string  `json:"secondary_categories,omitempty"`
	ReasonCodes   []string  `json:"reason_codes,omitempty"`
	Degraded      bool      `json:"degraded,omitempty"`
	SenderHash    string    `json:"sender_hash,omitempty"`
	RecipientHash string    `json:"recipient_hash,omitempty"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
}

type communicationHistoryJSON struct {
	SenderHash    string    `json:"sender_hash"`
	RecipientHash string    `json:"recipient_hash"`
	SenderDomain  string    `json:"sender_domain,omitempty"`
	Count7d       int       `json:"count_7d"`
	Count30d      int       `json:"count_30d"`
	TypicalHour   int       `json:"typical_hour"`
	Relationship  string    `json:"relationship,omitempty"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

type senderTrailAggregateJSON struct {
	TotalVerdicts        int       `json:"total_verdicts"`
	HighRiskVerdicts     int       `json:"high_risk_verdicts"`
	MaxScore             int       `json:"max_score"`
	LastVerdictAt        time.Time `json:"last_verdict_at,omitempty"`
	DistinctRecipients   int       `json:"distinct_recipients"`
	TotalSightingsWindow int       `json:"total_sightings_window"`
}

func newMessageTrailResponse(t investigation.MessageTrail) messageTrailResponse {
	out := messageTrailResponse{Result: newEvaluationResultJSON(t.Result)}
	if t.CommunicationHistory != nil {
		ch := newCommunicationHistoryJSON(*t.CommunicationHistory)
		out.CommunicationHistory = &ch
	}
	return out
}

func newSenderTrailResponse(t investigation.SenderTrail) senderTrailResponse {
	out := senderTrailResponse{
		SenderHash:             base64.RawURLEncoding.EncodeToString(t.SenderHash),
		Verdicts:               make([]evaluationResultJSON, 0, len(t.Verdicts)),
		CommunicationHistories: make([]communicationHistoryJSON, 0, len(t.CommunicationHistories)),
		Aggregate: senderTrailAggregateJSON{
			TotalVerdicts:        t.Aggregate.TotalVerdicts,
			HighRiskVerdicts:     t.Aggregate.HighRiskVerdicts,
			MaxScore:             t.Aggregate.MaxScore,
			LastVerdictAt:        t.Aggregate.LastVerdictAt,
			DistinctRecipients:   t.Aggregate.DistinctRecipients,
			TotalSightingsWindow: t.Aggregate.TotalSightingsWindow,
		},
	}
	for _, v := range t.Verdicts {
		out.Verdicts = append(out.Verdicts, newEvaluationResultJSON(v))
	}
	for _, h := range t.CommunicationHistories {
		out.CommunicationHistories = append(out.CommunicationHistories, newCommunicationHistoryJSON(h))
	}
	return out
}

func newEvaluationResultJSON(r repository.EvaluationResult) evaluationResultJSON {
	return evaluationResultJSON{
		ID:            r.ID,
		CorrelationID: r.CorrelationID,
		Score:         r.Score,
		Tier:          r.Tier,
		Primary:       r.Primary,
		Secondary:     append([]string(nil), r.Secondary...),
		ReasonCodes:   append([]string(nil), r.ReasonCodes...),
		Degraded:      r.Degraded,
		SenderHash:    encodeHashOrEmpty(r.SenderHash),
		RecipientHash: encodeHashOrEmpty(r.RecipientHash),
		EvaluatedAt:   r.EvaluatedAt,
	}
}

func newCommunicationHistoryJSON(h repository.CommunicationHistory) communicationHistoryJSON {
	return communicationHistoryJSON{
		SenderHash:    encodeHashOrEmpty(h.SenderHash),
		RecipientHash: encodeHashOrEmpty(h.RecipientHash),
		SenderDomain:  h.SenderDomain,
		Count7d:       h.Count7d,
		Count30d:      h.Count30d,
		TypicalHour:   h.TypicalHour,
		Relationship:  h.Relationship,
		FirstSeenAt:   h.FirstSeenAt,
		LastSeenAt:    h.LastSeenAt,
	}
}

func encodeHashOrEmpty(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
