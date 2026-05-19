package handler

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
)

// PushWebhookHandler handles POST callbacks from Gmail Pub/Sub and
// Microsoft Graph Change Notifications. It authenticates the caller
// via SignatureVerifier (provider-specific) before dispatching to
// the PushManager for processing.
type PushWebhookHandler struct {
	Manager           *ingestion.PushManager
	Logger            *slog.Logger
	SignatureVerifier PushSignatureVerifier
}

// log returns a non-nil logger. The Logger field is a struct-literal
// field rather than a constructor parameter so a wiring mistake can
// leave it nil; falling back to slog.Default() keeps the handler
// from panicking on the warn paths.
func (h *PushWebhookHandler) log() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// ServeHTTP handles POST /v1/push/{provider}/{tenant}.
func (h *PushWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse path: /v1/push/{provider}/{tenantID}
	path := strings.TrimPrefix(r.URL.Path, "/v1/push/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "invalid path: expected /v1/push/{provider}/{tenant}", http.StatusBadRequest)
		return
	}
	provider := parts[0]
	tenantID := strings.TrimRight(parts[1], "/")
	if strings.Contains(tenantID, "/") {
		http.Error(w, "invalid tenant ID: must not contain slashes", http.StatusBadRequest)
		return
	}

	// Microsoft Graph sends a one-shot validation request with a
	// validationToken query param that must be echoed back
	// VERBATIM as text/plain. Microsoft compares the echoed value
	// byte-for-byte against what it sent: any mutation (HTML
	// escaping, trimming, re-encoding) fails subscription
	// validation. Defense-in-depth against a browser rendering the
	// body as HTML is handled at the response-header layer:
	//
	//   - Content-Type: text/plain; charset=utf-8
	//   - X-Content-Type-Options: nosniff
	//
	// which together stop content-type sniffing without changing
	// the response bytes.
	if vt := r.URL.Query().Get("validationToken"); vt != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(vt))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		h.log().Warn("push_webhook: read body failed", slog.Any("error", err))
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}

	// Authenticate the caller BEFORE dispatching to the push
	// manager. This stops unauthenticated traffic from triggering
	// expensive provider fetches and from polluting tenant state
	// with attacker-controlled payloads.
	if h.SignatureVerifier == nil {
		// Mis-wired deployment: refuse rather than implicitly
		// trusting the caller. Local-dev wiring should pass an
		// explicit "accept" verifier (PushSignatureRouter with a
		// nil entry) so this branch only fires on real
		// mis-configuration.
		h.log().Warn("push_webhook: signature verifier not configured",
			slog.String("provider", provider),
			slog.String("tenant", tenantID))
		http.Error(w, "push verifier not configured", http.StatusInternalServerError)
		return
	}
	if verr := h.SignatureVerifier.VerifyPush(r.Context(), provider, tenantID, r, body); verr != nil {
		// Treat all verification failures as 401 to avoid
		// distinguishing "missing" from "invalid" in the wire
		// response (which would give an attacker free oracle
		// bits). The provider/tenant identifiers are logged at
		// Warn so on-call can correlate failures.
		h.log().Warn("push_webhook: signature verification failed",
			slog.String("provider", provider),
			slog.String("tenant", tenantID),
			slog.Any("error", verr))
		status := http.StatusUnauthorized
		body := "unauthorized"
		if errors.Is(verr, ErrPushProviderUnknown) {
			// Unknown provider is a client misuse (wrong path
			// segment), not an auth failure, so surface a more
			// accurate body together with the 400 status code.
			status = http.StatusBadRequest
			body = "unknown provider"
		}
		http.Error(w, body, status)
		return
	}

	if err := ingestion.HandlePushNotification(r.Context(), h.Manager, provider, tenantID, json.RawMessage(body)); err != nil {
		h.log().Warn("push_webhook: handle notification failed",
			slog.String("provider", provider),
			slog.String("tenant", tenantID),
			slog.Any("error", err))
		// Return 200 anyway to avoid provider retry storms. The
		// message will be picked up by the poll fallback.
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
}
