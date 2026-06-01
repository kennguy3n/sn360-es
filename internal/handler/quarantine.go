package handler

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/selfrelease"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// QuarantineHandler serves POST /v1/quarantine/release. The endpoint
// accepts a signed action token plus an optional restored-body
// string. The token is the only authoritative source of
// (tenant, pseudonymised_message_id); the body field is a hint
// passed through to the provider.
//
// Scope dispatch (WS-3a):
//
//   - scp="banner_action" (or unset, for legacy tokens): the
//     SOC-operator / support-agent release path. Calls
//     ReleaseService directly with the token's tenant + pmid.
//
//   - scp="quarantine_release": the WS-3a recipient self-service
//     path. Calls selfrelease.Service which walks the
//     not_found / tier2_blocked / rate_limited / released /
//     already_released state machine, writing exactly one audit
//     row per attempt. The handler converts the resulting Outcome
//     into a uniform 200/202/403/404/429 response. Cross-tenant
//     attempts surface as not_found so the response body cannot
//     fingerprint quarantine state across tenants.
//
// Auth ordering: token validation happens BEFORE any resource
// lookup. Expired and signature-invalid tokens both return 401
// with the SAME response body ("invalid token"), but the audit
// outcome differentiates them so SOC can tell "expired link the
// recipient kept around" from "someone tampered with the URL".
type QuarantineHandler struct {
	logger      *slog.Logger
	verifier    *privacy.JWTIssuer
	release     *action.ReleaseService
	selfRelease *selfrelease.Service
	// binder pins a Postgres conn to the verified tenant for the
	// self-release path. Always non-nil — the constructor rejects
	// nil binders. In-memory / dev deployments pass NopTenantBinder{}
	// at the wire site so the "this deployment skips the bind"
	// decision is a deliberate type-level declaration rather than
	// an implicit nil-check inside ServeHTTP. The previous nil-as-
	// no-op arrangement was a silent-failure shape: a future wiring
	// regression that dropped the binder in a Postgres-backed
	// deployment would silently disable the rate limiter (COUNT
	// returns 0 under unbound RLS) and drop audit INSERTs (WITH
	// CHECK rejects). See TenantBinder + NopTenantBinder in
	// tenant_binder.go for the threat model.
	binder TenantBinder
}

// NewQuarantineHandler wires up the handler. verifier and release
// must be non-nil. selfRelease is optional — when nil, the handler
// refuses tokens with scp="quarantine_release" via a uniform
// 401 ("invalid token") so the deployment doesn't accidentally
// expose the operator path under a recipient-style token. binder
// is REQUIRED to be non-nil: production deployments pass the real
// `pgQuarantineBinder` adapter; in-memory / dev deployments pass
// `NopTenantBinder{}` as the explicit no-op. Returning an error
// on a nil binder is the type-enforced version of the invariant
// Devin Review round 7 flagged: a future wiring regression that
// omitted the binder in a Postgres-backed deployment would have
// silently disabled the rate limiter (COUNT returns 0 under
// unbound RLS) and dropped audit INSERTs (WITH CHECK rejects).
// Now it fails loudly at startup instead. logger may be nil
// (defaults to slog.Default).
func NewQuarantineHandler(
	logger *slog.Logger,
	verifier *privacy.JWTIssuer,
	release *action.ReleaseService,
	selfRelease *selfrelease.Service,
	binder TenantBinder,
) (*QuarantineHandler, error) {
	if binder == nil {
		return nil, errors.New("handler: tenant binder is required (use NopTenantBinder{} for in-memory deployments)")
	}
	if verifier == nil {
		return nil, errors.New("quarantine handler: verifier is required")
	}
	if release == nil {
		return nil, errors.New("quarantine handler: release service is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &QuarantineHandler{
		logger:      logger,
		verifier:    verifier,
		release:     release,
		selfRelease: selfRelease,
		binder:      binder,
	}, nil
}

type quarantineReleaseRequest struct {
	Token        string `json:"token"`
	RequestedBy  string `json:"requested_by,omitempty"`
	RestoredBody string `json:"restored_body,omitempty"`
}

type quarantineReleaseResponse struct {
	Reason       string   `json:"reason"`
	Restored     bool     `json:"restored"`
	NewTier      string   `json:"new_tier,omitempty"`
	OriginalTier string   `json:"original_tier,omitempty"`
	Explanations []string `json:"explanations,omitempty"`
	ReportPath   string   `json:"report_path,omitempty"`
}

// ServeHTTP implements http.Handler. See the package doc comment
// for the scope-dispatch contract.
func (h *QuarantineHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	req, parseErr := decodeReleaseRequest(r, w)
	if parseErr != nil {
		// decodeReleaseRequest already wrote the response.
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	// Auth-before-resource: verify the JWT BEFORE any state
	// lookup. We use VerifyDetail so the audit layer can
	// differentiate "expired" from "invalid" without leaking
	// that distinction on the wire.
	verifyRes, vErr := h.verifier.VerifyDetail(req.Token)
	if vErr != nil {
		h.handleAuthFailure(r, w, verifyRes, vErr)
		return
	}
	claims := verifyRes.Claims
	if claims == nil || claims.TenantID == "" || claims.PseudonymizedMessage == "" {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	correlationID := strings.TrimSpace(r.Header.Get("X-Correlation-ID"))

	scope := claims.Scope
	if scope == "" {
		scope = privacy.ScopeBannerAction
	}
	switch scope {
	case privacy.ScopeQuarantineRelease:
		h.serveSelfRelease(r, w, claims, correlationID)
	case privacy.ScopeBannerAction:
		h.serveOperatorRelease(r, w, claims, req, correlationID)
	default:
		// Unknown scope: refuse with the same 401 body as a
		// signature-invalid token so an attacker cannot probe
		// for which scopes the deployment supports.
		h.logger.WarnContext(r.Context(), "quarantine release: unknown token scope",
			slog.String("scope", scope),
			slog.String("tenant_id", claims.TenantID))
		writeError(w, http.StatusUnauthorized, "invalid token")
	}
}

// serveOperatorRelease handles the SOC-operator / support-agent
// release path (scp="banner_action" or legacy unset scope). Behaviour
// preserved from the pre-WS-3a implementation.
func (h *QuarantineHandler) serveOperatorRelease(
	r *http.Request,
	w http.ResponseWriter,
	claims *privacy.ActionClaims,
	req quarantineReleaseRequest,
	correlationID string,
) {
	// Propagate the upstream correlation ID so the release outcome
	// event (es.action.quarantine.release) can be joined back to
	// the HTTP request — and through it to the original evaluation
	// — by the same correlation_id that middleware / clients
	// already log against the request. We read X-Correlation-ID
	// directly here rather than from request context because
	// RequestLogger only surfaces the header for logging
	// (request_logger.go:73) and the canonical project pattern is
	// "read at the boundary, hand it to the service layer".
	outcome, err := h.release.Release(r.Context(), action.ReleaseRequest{
		TenantID:             claims.TenantID,
		PseudonymizedMessage: claims.PseudonymizedMessage,
		RequestedBy:          req.RequestedBy,
		RestoredBody:         req.RestoredBody,
		CorrelationID:        correlationID,
	})
	if err != nil {
		status, public := classifyReleaseError(err)
		h.logger.WarnContext(r.Context(), "quarantine release failed",
			slog.String("tenant_id", claims.TenantID),
			slog.Int("status", status),
			slog.Any("error", err),
		)
		writeError(w, status, public)
		return
	}
	resp := quarantineReleaseResponse{
		Reason:       string(outcome.Reason),
		Restored:     outcome.Restored,
		NewTier:      string(outcome.Verdict.Tier),
		OriginalTier: string(outcome.Original),
		Explanations: outcome.Explanations,
		ReportPath:   outcome.ReportPath,
	}
	status := http.StatusOK
	switch outcome.Reason {
	case action.ReleaseNotFound:
		status = http.StatusNotFound
	case action.ReleaseRefused:
		status = http.StatusConflict
	case action.ReleaseAllowed:
		status = http.StatusAccepted
	}
	writeJSON(w, status, resp)
}

// serveSelfRelease handles the WS-3a recipient self-service path
// (scp="quarantine_release"). All outcomes flow through one audit
// row each (the not_found / tier2_blocked / rate_limited /
// released / already_released closed set). Cross-tenant attempts
// flow to not_found.
func (h *QuarantineHandler) serveSelfRelease(
	r *http.Request,
	w http.ResponseWriter,
	claims *privacy.ActionClaims,
	correlationID string,
) {
	if h.selfRelease == nil {
		// No self-release service wired into this deployment.
		// Treat the token as invalid rather than leaking the
		// deployment shape.
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	recipientHash, err := hex.DecodeString(claims.RecipientUserHash)
	if err != nil || len(recipientHash) == 0 {
		// A self-release token without a usable recipient
		// hash is malformed; return the uniform 401.
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	// Bind the Postgres conn to the verified tenant for the rest
	// of this request — this is what activates RLS on the
	// `tenant_release_policies` read, the `quarantine_release_audit`
	// COUNT query that drives the rate-limit gate, and the
	// `quarantine_release_audit` INSERT that writes the outcome
	// row. The endpoint sits in the auth-skip list (the recipient
	// JWT is in the POST body, not the Authorization header, so
	// the JWTAuth + TenantConnBinder middleware chain doesn't run
	// here), so this is the only chance to bind. If the bind
	// itself fails (pool exhausted, Postgres dropped the
	// session) we fail the request — running the service unbound
	// would silently see zero rows under RLS and bypass the rate
	// limit, which is strictly worse than a 503.
	// Binder is guaranteed non-nil by the constructor; in-memory
	// deployments pass NopTenantBinder{} so the WithTenant call
	// here is a uniform no-op for them rather than a hidden
	// nil-bypass. The 503 branch below remains the production
	// failure mode for genuine pool / Postgres outages — it's
	// dead code under the Nop binder but the test fixture
	// (`stubTenantBinder` in quarantine_selfrelease_test.go)
	// exercises it directly.
	boundCtx, release, bindErr := h.binder.WithTenant(r.Context(), claims.TenantID)
	if bindErr != nil {
		h.logger.WarnContext(r.Context(), "selfrelease: bind tenant conn",
			slog.String("tenant_id", claims.TenantID),
			slog.Any("error", bindErr))
		writeError(w, http.StatusServiceUnavailable, "release temporarily unavailable")
		return
	}
	defer func() {
		if relErr := release(); relErr != nil {
			h.logger.WarnContext(r.Context(), "selfrelease: release bound conn",
				slog.Any("error", relErr))
		}
	}()
	ctx := boundCtx
	res, err := h.selfRelease.Release(ctx, selfrelease.Request{
		TenantID:          claims.TenantID,
		PseudoMessageID:   claims.PseudonymizedMessage,
		RecipientUserHash: recipientHash,
		CorrelationID:     correlationID,
	})
	if err != nil {
		h.logger.WarnContext(ctx, "selfrelease: service failed",
			slog.String("tenant_id", claims.TenantID),
			slog.Any("error", err))
		writeError(w, http.StatusServiceUnavailable, "release temporarily unavailable")
		return
	}
	writeSelfReleaseOutcome(w, res.Outcome, res.Restored)
}

// handleAuthFailure writes the uniform 401 response and audits the
// auth-failure outcome when a tenant binding can be recovered
// from the partially-parsed claims. We never differentiate
// "expired" from "invalid signature" on the wire.
func (h *QuarantineHandler) handleAuthFailure(r *http.Request, w http.ResponseWriter, res privacy.VerifyResult, vErr error) {
	h.logger.WarnContext(r.Context(), "quarantine release: verify token",
		slog.Any("error", vErr),
		slog.Bool("expired", res.Expired),
	)
	// Only attempt to audit if the partial claims carry a
	// quarantine_release scope; auth failures on banner-action
	// tokens are out of scope for the WS-3a audit table.
	if h.selfRelease != nil && res.Claims != nil && res.Claims.Scope == privacy.ScopeQuarantineRelease {
		outcome := repository.QuarantineReleaseOutcomeInvalidToken
		reason := "token signature / claims invalid"
		if res.Expired {
			outcome = repository.QuarantineReleaseOutcomeTokenExpired
			reason = "token exp claim is in the past"
		}
		recipientHash, _ := hex.DecodeString(res.Claims.RecipientUserHash)
		correlationID := strings.TrimSpace(r.Header.Get("X-Correlation-ID"))
		// The audit INSERT also runs against the RLS-protected
		// `quarantine_release_audit`. Bind the conn to the partial
		// (unverified-claim) tenant first so the INSERT's WITH
		// CHECK clause passes. Note the conceptual subtlety: we
		// trust the claimed `tid` enough to bind it for the audit
		// write, even though we just rejected the JWT as
		// unverifiable — because the bind value affects which
		// tenant's audit table the row lands in, and writing
		// `token_expired` / `invalid_token` rows under the
		// attacker-claimed `tid` is exactly what we want (SOC for
		// the claimed tenant sees the attempt). If the bind fails
		// we still return 401, just with no audit row written —
		// the audit gap is logged inside AuditAuthFailure.
		ctx := r.Context()
		// h.binder is constructor-enforced non-nil; NopTenantBinder
		// is the in-memory no-op. We still guard on
		// res.Claims.TenantID != "" because the partial claims
		// object may carry an empty tid (malformed JWT payload),
		// and binding to an empty tenant would set the GUC to a
		// value that fails the tenants(id) FK on the subsequent
		// audit INSERT — wasting the write attempt.
		if res.Claims.TenantID != "" {
			boundCtx, release, bindErr := h.binder.WithTenant(ctx, res.Claims.TenantID)
			if bindErr != nil {
				h.logger.WarnContext(ctx, "selfrelease: bind tenant conn for auth-failure audit",
					slog.String("tenant_id", res.Claims.TenantID),
					slog.Any("error", bindErr))
				writeError(w, http.StatusUnauthorized, "invalid token")
				return
			}
			defer func() {
				if relErr := release(); relErr != nil {
					h.logger.WarnContext(ctx, "selfrelease: release bound conn (auth-failure)",
						slog.Any("error", relErr))
				}
			}()
			ctx = boundCtx
		}
		// Audit-write failure is logged inside AuditAuthFailure;
		// we always return 401 to the client regardless.
		_, _ = h.selfRelease.AuditAuthFailure(ctx,
			res.Claims.TenantID,
			res.Claims.PseudonymizedMessage,
			recipientHash,
			correlationID,
			outcome,
			reason)
	}
	writeError(w, http.StatusUnauthorized, "invalid token")
}

// decodeReleaseRequest extracts the release request from the
// HTTP body, accepting either application/json (canonical for
// programmatic clients / the operator flow) or
// application/x-www-form-urlencoded (the form the self-release
// banner posts — inline <form action=URL method=POST>). When the
// body is malformed or oversized, the response is written
// directly and a non-nil error is returned so the caller can
// abort. Returning a value-and-error pair would let the caller
// double-write; we keep the side-effect-on-error contract here.
func decodeReleaseRequest(r *http.Request, w http.ResponseWriter) (quarantineReleaseRequest, error) {
	var req quarantineReleaseRequest
	ct := r.Header.Get("Content-Type")
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = ct[:idx]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	switch ct {
	case "application/x-www-form-urlencoded":
		// The banner-posted form only carries the token; other
		// fields are JSON-only and intentionally absent here.
		r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid form body")
			return req, err
		}
		req.Token = strings.TrimSpace(r.PostFormValue("token"))
	default:
		// Default to JSON for unset / unknown / explicit
		// application/json. DisallowUnknownFields keeps the
		// schema strict for the operator flow.
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return req, err
		}
		req.Token = strings.TrimSpace(req.Token)
	}
	return req, nil
}

// selfReleaseResponse is the wire shape returned by the
// scp="quarantine_release" path. Outcome is the closed-set string
// from repository.QuarantineReleaseOutcome*; Restored is true only
// for outcome="released". No additional fields are surfaced — the
// cross-tenant indistinguishability rule forbids leaking the
// underlying state machine state to the client.
type selfReleaseResponse struct {
	Outcome  string `json:"outcome"`
	Restored bool   `json:"restored"`
}

// writeSelfReleaseOutcome maps a selfrelease.Service outcome to
// the HTTP status code + body. The mapping is intentionally
// uniform across tenants: identical inputs produce identical wire
// responses regardless of which tenant the token was minted for.
func writeSelfReleaseOutcome(w http.ResponseWriter, outcome repository.QuarantineReleaseOutcome, restored bool) {
	resp := selfReleaseResponse{Outcome: string(outcome), Restored: restored}
	var status int
	switch outcome {
	case repository.QuarantineReleaseOutcomeReleased:
		status = http.StatusAccepted
	case repository.QuarantineReleaseOutcomeAlreadyReleased:
		status = http.StatusOK
	case repository.QuarantineReleaseOutcomeRateLimited:
		status = http.StatusTooManyRequests
	case repository.QuarantineReleaseOutcomeTier2Blocked,
		repository.QuarantineReleaseOutcomeReleaseRefused:
		// Both safety-stack refusals surface as 403. The
		// audit row distinguishes them (persisted-bit gate
		// vs. runner re-eval) for SOC review while the wire
		// remains uniform.
		status = http.StatusForbidden
	case repository.QuarantineReleaseOutcomeNotFound,
		repository.QuarantineReleaseOutcomeTokenExpired,
		repository.QuarantineReleaseOutcomeInvalidToken:
		// Cross-tenant indistinguishability: not_found is the
		// canonical "don't tell the client why" outcome.
		// Token-expired/invalid arrive here only when the
		// caller forgot the auth-fail path; we still emit 404
		// rather than 401 so we never leak which message IDs
		// exist for which tenant.
		status = http.StatusNotFound
	default:
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, resp)
}

// classifyReleaseError maps a ReleaseService error to an HTTP status
// code + a public error message that hides internal details. The
// sentinel errors (action.ErrInvalidInput, action.ErrNotFound,
// action.ErrProviderUnavailable) are tested with errors.Is so wrapped
// errors classify correctly. Any unrecognised error falls through to
// 500 / "release failed" — the original error is still logged at the
// call site.
func classifyReleaseError(err error) (int, string) {
	switch {
	case errors.Is(err, action.ErrInvalidInput):
		return http.StatusBadRequest, "invalid release request"
	case errors.Is(err, action.ErrNotFound):
		return http.StatusNotFound, "quarantine record not found"
	case errors.Is(err, action.ErrProviderUnavailable):
		return http.StatusServiceUnavailable, "release temporarily unavailable"
	default:
		return http.StatusInternalServerError, "release failed"
	}
}
