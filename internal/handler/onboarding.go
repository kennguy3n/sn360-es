package handler

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/kennguy3n/sn360-es/internal/service/onboarding"
)

// OnboardingService is the interface the handler expects from the
// onboarding service. Kept minimal to allow easy testing.
type OnboardingService interface {
	AuthURL(provider onboarding.ProviderType, tenantID string) (string, error)
	HandleCallback(ctx context.Context, stateTok, code string) (string, onboarding.ProviderType, error)
	Revoke(ctx context.Context, tenantID string, provider onboarding.ProviderType) error
}

// OnboardingHandler exposes HTTP endpoints for the OAuth onboarding
// consent flow. It validates inputs, delegates to the Service, and
// returns structured JSON responses.
type OnboardingHandler struct {
	svc    OnboardingService
	logger *slog.Logger
}

// NewOnboardingHandler constructs a handler.
func NewOnboardingHandler(logger *slog.Logger, svc OnboardingService) *OnboardingHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &OnboardingHandler{svc: svc, logger: logger}
}

// ServeStart handles GET /v1/onboarding/start.
// Query params: provider, tenant_id.
// Returns: {"redirect_url": "..."}.
func (h *OnboardingHandler) ServeStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, onboardingErrorResp("method not allowed"))
		return
	}
	provider := onboarding.ProviderType(r.URL.Query().Get("provider"))
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, onboardingErrorResp("tenant_id is required"))
		return
	}
	if provider == "" {
		writeJSON(w, http.StatusBadRequest, onboardingErrorResp("provider is required"))
		return
	}
	url, err := h.svc.AuthURL(provider, tenantID)
	if err != nil {
		h.logger.Error("onboarding: auth URL failed",
			slog.String("err", err.Error()),
			slog.String("tenant_id", tenantID))
		writeJSON(w, http.StatusBadRequest, onboardingErrorResp(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect_url": url})
}

// ServeCallback handles GET /v1/onboarding/callback.
// Query params: state, code.
// Returns: {"tenant_id": "...", "provider": "...", "status": "onboarding_started"}.
func (h *OnboardingHandler) ServeCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, onboardingErrorResp("method not allowed"))
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		writeJSON(w, http.StatusBadRequest, onboardingErrorResp("state and code are required"))
		return
	}
	tenantID, provider, err := h.svc.HandleCallback(r.Context(), state, code)
	if err != nil {
		h.logger.Warn("onboarding: callback failed",
			slog.String("err", err.Error()))
		writeJSON(w, http.StatusUnauthorized, onboardingErrorResp(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"tenant_id": tenantID,
		"provider":  string(provider),
		"status":    "onboarding_started",
	})
}

// ServeStatus handles GET /v1/onboarding/status.
// Query params: tenant_id.
// Returns: {"tenant_id": "...", "status": "active"}.
func (h *OnboardingHandler) ServeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, onboardingErrorResp("method not allowed"))
		return
	}
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, onboardingErrorResp("tenant_id is required"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"tenant_id": tenantID,
		"status":    "active",
	})
}

// ServeRevoke handles DELETE /v1/onboarding/revoke.
// Query params: tenant_id, provider.
func (h *OnboardingHandler) ServeRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, onboardingErrorResp("method not allowed"))
		return
	}
	tenantID := r.URL.Query().Get("tenant_id")
	provider := onboarding.ProviderType(r.URL.Query().Get("provider"))
	if tenantID == "" || provider == "" {
		writeJSON(w, http.StatusBadRequest, onboardingErrorResp("tenant_id and provider are required"))
		return
	}
	if err := h.svc.Revoke(r.Context(), tenantID, provider); err != nil {
		h.logger.Error("onboarding: revoke failed",
			slog.String("err", err.Error()),
			slog.String("tenant_id", tenantID))
		writeJSON(w, http.StatusInternalServerError, onboardingErrorResp("revoke failed"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func onboardingErrorResp(msg string) map[string]string {
	return map[string]string{"error": msg}
}
