package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// JWKSHandler serves the RFC 7517 JSON Web Key Set at
// /.well-known/jwks.json. It exposes the public half of the
// asymmetric signing keys this deployment uses so out-of-cluster
// verifiers (downstream platforms, partner products, the future
// eventbus signature consumer) can verify ES256 tokens without
// sharing the HS256 secret.
//
// The handler:
//
//   - Returns 200 with `{"keys":[...]}` when an ES256 public key is
//     configured.
//   - Returns 200 with `{"keys":[]}` when the deployment is HS256-only
//     (this is a well-formed-but-empty key set, the documented signal
//     that asymmetric verification material is not yet available).
//   - Returns 500 only when the issuer's PublicJWKS call fails for an
//     unexpected reason (e.g. a key with the wrong curve sneaks past
//     boot validation). Operators should treat 500 from JWKS as a
//     boot-validation regression in the JWT subsystem.
//
// The endpoint is intentionally NOT JWT-protected (see
// defaultAuthSkipPaths in cmd/sn360-es/routes.go): a JWKS endpoint
// must be reachable BEFORE the consumer has fetched a token,
// otherwise the consumer has no way to bootstrap. The data served
// is, by construction, the public key half — no secrets leak.
//
// Caching: the handler sets a 5-minute Cache-Control header. JWKS
// keys rotate at human time scales (key rolls are deliberate
// operational events), so a 5-minute cache strikes a balance between
// "consumer reacts quickly to a key change" and "JWKS endpoint is
// not the bottleneck for every token verify".
type JWKSHandler struct {
	logger *slog.Logger
	issuer *privacy.JWTIssuer
}

// NewJWKSHandler constructs a JWKS handler. issuer must be non-nil
// — when sn360-es is deployed without any JWT issuer wired (dev runs
// with no banner secret and no ES256 keys), the route should not be
// registered at all. The handler itself does not nil-check the
// issuer in the hot path; callers are responsible for not registering
// it with a nil issuer.
func NewJWKSHandler(logger *slog.Logger, issuer *privacy.JWTIssuer) *JWKSHandler {
	return &JWKSHandler{logger: logger, issuer: issuer}
}

// ServeHTTP handles GET (and HEAD, per RFC 9110 §9.3.2). All other
// verbs are rejected with 405.
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		// Error responses use application/json so a consumer
		// that parses the body (e.g. a JWKS-pinning verifier
		// surfacing the error to ops) doesn't see a
		// text/plain Content-Type pointing at a JSON-shaped
		// body. http.Error would otherwise force text/plain
		// here. Routes through the shared writeError helper
		// (see banner_action.go) so the {"error":"..."}
		// envelope matches every other handler in the
		// package.
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	jwks, err := h.issuer.PublicJWKS()
	if err != nil {
		if h.logger != nil {
			h.logger.Error("jwks: build public key set failed", slog.Any("error", err))
		}
		writeError(w, http.StatusInternalServerError, "jwks_unavailable")
		return
	}

	// 5-minute cache balances rotation responsiveness against
	// repeated round-trips for every verify. RFC 7517 does not
	// prescribe a cache strategy; this matches common practice
	// (e.g. Google's certs endpoint serves Cache-Control:
	// max-age=N with N in the 1-hour range; we pick a shorter
	// window because a JWKS roll inside the same datacentre is
	// not a slow operation).
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")

	// HEAD: emit headers only (net/http already suppresses the body
	// at the transport layer, but skipping the encode keeps the
	// hot path cheap).
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		if h.logger != nil {
			h.logger.Warn("jwks: encode response failed", slog.Any("error", err))
		}
	}
}
