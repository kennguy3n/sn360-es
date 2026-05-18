package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
)

// PushWebhookHandler handles POST callbacks from Gmail Pub/Sub and
// Microsoft Graph Change Notifications. It dispatches to the
// PushManager for processing.
type PushWebhookHandler struct {
	Manager *ingestion.PushManager
	Logger  *slog.Logger
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

	// Microsoft Graph sends a validation request with a
	// validationToken query param that must be echoed back.
	if vt := r.URL.Query().Get("validationToken"); vt != "" {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(vt))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		h.Logger.Warn("push_webhook: read body failed", slog.Any("error", err))
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}

	if err := ingestion.HandlePushNotification(r.Context(), h.Manager, provider, tenantID, json.RawMessage(body)); err != nil {
		h.Logger.Warn("push_webhook: handle notification failed",
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
