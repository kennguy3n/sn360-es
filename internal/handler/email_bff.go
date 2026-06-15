package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/dashboard"
	"github.com/kennguy3n/sn360-es/internal/service/investigation"
)

// EmailBFFHandler serves the tenant-scoped, read-only
// backend-for-frontend surface consumed by the sme-dashboard portal's
// Email Security console:
//
//	GET /internal/tenants/{tid}/email-security/summary
//	GET /internal/tenants/{tid}/email-security/messages
//	GET /internal/tenants/{tid}/email-security/messages/{mid}
//
// Unlike the public /v1/* surface, these routes read the tenant from
// the URL path (not a JWT claim) because they are mounted ONLY on the
// internal listener (see cmd/sn360-es/internal_routes.go), which is
// not exposed to tenants — the dashboard-proxy is the single trusted
// caller and asserts the tenant identity from the authenticated
// session. The handler still binds the Postgres connection to that
// tenant via the TenantBinder before any read, so the row-level
// security policy from migration 0018 stays authoritative even though
// the global JWT/TenantConn middleware chain is not in front of this
// listener.
//
// The shapes returned here are privacy-preserving: the platform never
// persists raw subjects or addresses, so the console renders
// verdict-centric rows (tier, category, score, reason codes, sender
// pseudonym) rather than message content. This is intentional and is
// what the portal types model.
type EmailBFFHandler struct {
	logger *slog.Logger
	dash   *dashboard.DashboardGenerator
	inv    *investigation.Service
	eval   repository.EvaluationResultRepository
	binder TenantBinder
}

// NewEmailBFFHandler wires the handler. binder is REQUIRED to be
// non-nil (pass NopTenantBinder{} for in-memory/dev deployments) so
// the "this deployment does not enforce RLS" decision is explicit
// rather than an implicit nil — mirroring NewQuarantineHandler. The
// three data dependencies may individually be nil in partially-wired
// deployments; each route degrades to 503 when its dependency is
// absent so the listener stays navigable. logger may be nil.
func NewEmailBFFHandler(
	logger *slog.Logger,
	dash *dashboard.DashboardGenerator,
	inv *investigation.Service,
	eval repository.EvaluationResultRepository,
	binder TenantBinder,
) (*EmailBFFHandler, error) {
	if binder == nil {
		return nil, errors.New("email bff handler: tenant binder is required (use NopTenantBinder{} for in-memory deployments)")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &EmailBFFHandler{
		logger: logger,
		dash:   dash,
		inv:    inv,
		eval:   eval,
		binder: binder,
	}, nil
}

const (
	// emailSummaryWindow is the look-back the summary headline counts
	// are computed over. The portal's stat cards are labelled "24h".
	emailSummaryWindow = 24 * time.Hour
	// emailSummaryRecent caps how many recent verdicts the summary
	// inlines for the "recent verdicts" panel.
	emailSummaryRecent = 10
	// emailMessagesDefaultLimit / emailMessagesMaxLimit bound the
	// Threat Explorer page size. The max is well under the
	// repository's own 500-row guard but keeps a single page cheap
	// to render.
	emailMessagesDefaultLimit = 50
	emailMessagesMaxLimit     = 200
	// emailTopThreats caps the threats-by-category breakdown.
	emailTopThreats = 6
)

// uuidRE matches any-version UUIDs. Tenant ids are Postgres uuid
// columns everywhere, so a path segment that is not a UUID is
// rejected with 400 before it is ever forwarded into WithTenant or a
// query parameter — a malformed value cannot smuggle SQL or a path
// traversal through this surface.
var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// tenantFromPath reads, validates, and returns the {tid} path value.
// On any problem it writes the HTTP error and returns ok=false.
func (h *EmailBFFHandler) tenantFromPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	tid := strings.TrimSpace(r.PathValue("tid"))
	if !uuidRE.MatchString(tid) {
		writeError(w, http.StatusBadRequest, "tenant id must be a UUID")
		return "", false
	}
	return strings.ToLower(tid), true
}

// emailThreatJSON pairs a threat category with its count for the
// summary breakdown.
type emailThreatJSON struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// emailMessageJSON is one verdict-centric row in the Threat Explorer
// and in the summary's recent list. MessageID is the pseudonymised
// message identifier the portal passes back into the detail route; it
// is NOT a UUID and may need URL-encoding by the caller.
type emailMessageJSON struct {
	MessageID   string    `json:"message_id"`
	Tier        string    `json:"tier"`
	Score       int       `json:"score"`
	Category    string    `json:"primary_category,omitempty"`
	Secondary   []string  `json:"secondary_categories,omitempty"`
	ReasonCodes []string  `json:"reason_codes,omitempty"`
	Verdict     string    `json:"verdict"`
	Degraded    bool      `json:"degraded,omitempty"`
	SenderHash  string    `json:"sender_hash,omitempty"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// emailSummaryJSON matches the portal's EmailSecuritySummary type.
type emailSummaryJSON struct {
	ModuleEnabled  bool               `json:"module_enabled"`
	Scanned24h     int                `json:"scanned_24h"`
	Blocked24h     int                `json:"blocked_24h"`
	Quarantined24h int                `json:"quarantined_24h"`
	TopThreats     []emailThreatJSON  `json:"top_threats"`
	Recent         []emailMessageJSON `json:"recent"`
}

// emailMessagesJSON is the Threat Explorer list envelope.
type emailMessagesJSON struct {
	Messages []emailMessageJSON `json:"messages"`
	Count    int                `json:"count"`
}

// emailMessageDetailJSON is the drill-in for a single verdict. It
// reuses the investigation API's evaluation-result and
// communication-history shapes and adds the derived plain verdict and
// the optional sender-reputation trail.
type emailMessageDetailJSON struct {
	Result               evaluationResultJSON      `json:"result"`
	Verdict              string                    `json:"verdict"`
	CommunicationHistory *communicationHistoryJSON `json:"communication_history,omitempty"`
	Sender               *senderTrailResponse      `json:"sender,omitempty"`
}

// deriveVerdict maps the platform's automated tier (or the analyst
// override when present) onto the three-state plain-language verdict
// the console renders. FinalVerdict, when set by the escalation
// resolver (migration 0021), is authoritative.
func deriveVerdict(r repository.EvaluationResult) string {
	if r.FinalVerdict != "" {
		return r.FinalVerdict
	}
	switch strings.ToLower(r.Tier) {
	case "blocked":
		return "malicious"
	case "high":
		return "suspicious"
	default:
		return "benign"
	}
}

func newEmailMessageJSON(r repository.EvaluationResult) emailMessageJSON {
	return emailMessageJSON{
		// MessageIDHash stores the UTF-8 bytes of the pseudonymised
		// message identifier (written as []byte(res.MessageID) by the
		// evaluate consumer), NOT a binary hash — so it round-trips with
		// string(), unlike SenderHash below which is real BLAKE2 hash
		// bytes and must be base64url-encoded for the wire.
		MessageID:   string(r.MessageIDHash),
		Tier:        r.Tier,
		Score:       r.Score,
		Category:    r.Primary,
		Secondary:   append([]string(nil), r.Secondary...),
		ReasonCodes: append([]string(nil), r.ReasonCodes...),
		Verdict:     deriveVerdict(r),
		Degraded:    r.Degraded,
		SenderHash:  encodeHashOrEmpty(r.SenderHash),
		EvaluatedAt: r.EvaluatedAt,
	}
}

// ServeSummary handles GET .../email-security/summary. It returns the
// portal's EmailSecuritySummary shape derived from the dashboard
// generator's 24h rollup plus the most recent verdicts.
func (h *EmailBFFHandler) ServeSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenantID, ok := h.tenantFromPath(w, r)
	if !ok {
		return
	}
	if h.dash == nil {
		writeError(w, http.StatusServiceUnavailable, "email security summary not configured")
		return
	}
	ctx, release, bindErr := h.binder.WithTenant(r.Context(), tenantID)
	if bindErr != nil {
		h.logger.ErrorContext(r.Context(), "email bff: tenant bind failed",
			slog.String("tenant_id", tenantID), slog.Any("error", bindErr))
		writeError(w, http.StatusServiceUnavailable, "tenant binding unavailable")
		return
	}
	defer func() { _ = release() }()

	now := time.Now().UTC()
	tr := dto.TimeRange{Start: now.Add(-emailSummaryWindow), End: now}
	summary, err := h.dash.GenerateSummary(ctx, tenantID, tr)
	if err != nil {
		h.logger.WarnContext(ctx, "email bff: summary generate failed",
			slog.String("tenant_id", tenantID), slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "summary generation failed")
		return
	}

	out := emailSummaryJSON{
		ModuleEnabled:  true,
		Scanned24h:     summary.EmailsProcessed,
		Blocked24h:     tierCount(summary.ThreatsByTier, "blocked"),
		Quarantined24h: summary.Quarantine.Quarantined,
		TopThreats:     topThreats(summary.ThreatsByCat),
		Recent:         []emailMessageJSON{},
	}
	if h.eval != nil {
		recent, rerr := h.eval.ListRecent(ctx, tenantID, emailSummaryRecent)
		if rerr != nil {
			h.logger.WarnContext(ctx, "email bff: recent verdicts failed",
				slog.String("tenant_id", tenantID), slog.Any("error", rerr))
		} else {
			for i := range recent {
				out.Recent = append(out.Recent, newEmailMessageJSON(recent[i]))
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ServeMessages handles GET .../email-security/messages. It returns
// the most recent verdicts (newest first) with optional filtering.
//
// Query parameters:
//
//	?limit=N        1..emailMessagesMaxLimit (default 50)
//	?tier=blocked   case-insensitive exact tier match
//	?verdict=...    one of malicious|suspicious|benign (derived)
//	?since_hours=H  1..720 look-back (default: no lower bound)
func (h *EmailBFFHandler) ServeMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenantID, ok := h.tenantFromPath(w, r)
	if !ok {
		return
	}
	if h.eval == nil {
		writeError(w, http.StatusServiceUnavailable, "email security messages not configured")
		return
	}
	limit := parseLimit(r.URL.Query().Get("limit"), emailMessagesDefaultLimit, emailMessagesMaxLimit)
	tierFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tier")))
	verdictFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("verdict")))
	since := parseSinceHours(r.URL.Query().Get("since_hours"))

	ctx, release, bindErr := h.binder.WithTenant(r.Context(), tenantID)
	if bindErr != nil {
		h.logger.ErrorContext(r.Context(), "email bff: tenant bind failed",
			slog.String("tenant_id", tenantID), slog.Any("error", bindErr))
		writeError(w, http.StatusServiceUnavailable, "tenant binding unavailable")
		return
	}
	defer func() { _ = release() }()

	// Over-fetch a bounded multiple so post-filtering by tier/verdict/
	// time still tends to fill the requested page without an unbounded
	// scan. ListRecent now clamps to EvalListRecentMaxLimit itself, so
	// we cap the over-fetch at the same ceiling here to keep the
	// request cheap and make the page-fill intent explicit at the call
	// site (the repository would clamp anything larger anyway).
	fetch := limit
	if tierFilter != "" || verdictFilter != "" || since > 0 {
		fetch = limit * 4
		if fetch > repository.EvalListRecentMaxLimit {
			fetch = repository.EvalListRecentMaxLimit
		}
	}
	rows, err := h.eval.ListRecent(ctx, tenantID, fetch)
	if err != nil {
		h.logger.WarnContext(ctx, "email bff: list messages failed",
			slog.String("tenant_id", tenantID), slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "message lookup failed")
		return
	}

	var cutoff time.Time
	if since > 0 {
		cutoff = time.Now().UTC().Add(-since)
	}
	out := emailMessagesJSON{Messages: make([]emailMessageJSON, 0, limit)}
	for i := range rows {
		row := rows[i]
		if tierFilter != "" && strings.ToLower(row.Tier) != tierFilter {
			continue
		}
		if verdictFilter != "" && deriveVerdict(row) != verdictFilter {
			continue
		}
		if since > 0 && row.EvaluatedAt.Before(cutoff) {
			continue
		}
		out.Messages = append(out.Messages, newEmailMessageJSON(row))
		if len(out.Messages) >= limit {
			break
		}
	}
	out.Count = len(out.Messages)
	writeJSON(w, http.StatusOK, out)
}

// ServeMessageDetail handles GET .../email-security/messages/{mid}.
// It returns the full verdict, the relationship snapshot, and (when
// the row carries a sender pseudonym) the sender-reputation trail so
// the console can render "is this sender normally trusted?".
//
// As with the investigation API, a not-found row and a cross-tenant
// probe both return 404 with the same body so the surface cannot
// fingerprint which message ids exist in which tenant.
func (h *EmailBFFHandler) ServeMessageDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenantID, ok := h.tenantFromPath(w, r)
	if !ok {
		return
	}
	if h.inv == nil {
		writeError(w, http.StatusServiceUnavailable, "email security investigation not configured")
		return
	}
	mid := strings.TrimSpace(r.PathValue("mid"))
	if mid == "" {
		writeError(w, http.StatusBadRequest, "message id is required")
		return
	}
	ctx, release, bindErr := h.binder.WithTenant(r.Context(), tenantID)
	if bindErr != nil {
		h.logger.ErrorContext(r.Context(), "email bff: tenant bind failed",
			slog.String("tenant_id", tenantID), slog.Any("error", bindErr))
		writeError(w, http.StatusServiceUnavailable, "tenant binding unavailable")
		return
	}
	defer func() { _ = release() }()

	trail, err := h.inv.MessageTrail(ctx, tenantID, mid)
	if err != nil {
		if errors.Is(err, investigation.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		h.logger.WarnContext(ctx, "email bff: message trail failed",
			slog.String("tenant_id", tenantID), slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	detail := emailMessageDetailJSON{
		Result:  newEvaluationResultJSON(trail.Result),
		Verdict: deriveVerdict(trail.Result),
	}
	if trail.CommunicationHistory != nil {
		ch := newCommunicationHistoryJSON(*trail.CommunicationHistory)
		detail.CommunicationHistory = &ch
	}
	if len(trail.Result.SenderHash) > 0 {
		senderTrail, serr := h.inv.SenderTrail(ctx, tenantID, trail.Result.SenderHash, investigation.SenderTrailOptions{})
		if serr != nil {
			// Sender reputation is supplementary; a failure here must
			// not blank out the verdict the operator came to read.
			h.logger.WarnContext(ctx, "email bff: sender trail failed (continuing without reputation)",
				slog.String("tenant_id", tenantID), slog.Any("error", serr))
		} else {
			resp := newSenderTrailResponse(senderTrail)
			detail.Sender = &resp
		}
	}
	writeJSON(w, http.StatusOK, detail)
}

// tierCount returns the count for the named tier in the breakdown, or
// 0 when absent. The tier match is case-insensitive.
func tierCount(tiers []dto.TierCount, name string) int {
	for _, t := range tiers {
		if strings.EqualFold(t.Tier, name) {
			return t.Count
		}
	}
	return 0
}

// topThreats sorts the category breakdown by count (descending) and
// returns at most emailTopThreats entries. Ties break on the category
// name so the order is deterministic for tests and snapshots.
func topThreats(cats []dto.CategoryCount) []emailThreatJSON {
	sorted := append([]dto.CategoryCount(nil), cats...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Count != sorted[j].Count {
			return sorted[i].Count > sorted[j].Count
		}
		return sorted[i].Category < sorted[j].Category
	})
	out := make([]emailThreatJSON, 0, emailTopThreats)
	for _, c := range sorted {
		if len(out) >= emailTopThreats {
			break
		}
		out = append(out, emailThreatJSON{Kind: c.Category, Count: c.Count})
	}
	return out
}

// parseLimit clamps a caller-supplied limit to [1, hi], defaulting to
// def for absent/garbage input.
func parseLimit(raw string, def, hi int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	if n > hi {
		return hi
	}
	return n
}

// parseSinceHours parses a 1..720 hour look-back. Returns 0 (meaning
// "no lower bound") for absent or out-of-range input.
func parseSinceHours(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > 720 {
		return 0
	}
	return time.Duration(n) * time.Hour
}
