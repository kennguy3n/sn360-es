// Package handler exposes HTTP entry points for SN360-ES. Each
// handler is a thin shim that decodes the request, calls into the
// matching internal/service package, and writes a typed response.
package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// BannerActionHandler serves the POST /v1/banner/action endpoint that
// receives one-click feedback from injected banners. It validates the
// signed token, normalises the action, and delegates to the
// FeedbackService. The handler itself only knows how to translate
// between HTTP and the service contract.
type BannerActionHandler struct {
	logger   *slog.Logger
	feedback *action.FeedbackService
}

// NewBannerActionHandler wires up the handler. feedback must be
// non-nil; logger may be nil (defaults to slog.Default).
func NewBannerActionHandler(logger *slog.Logger, feedback *action.FeedbackService) *BannerActionHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &BannerActionHandler{logger: logger, feedback: feedback}
}

// bannerActionRequest is the JSON payload posted by the banner. The
// payload deliberately carries no PII — the signed token is the only
// authoritative source for tenant + message ID.
type bannerActionRequest struct {
	Token  string `json:"token"`
	Action string `json:"action"`
}

// bannerActionResponse is the success body. Failures use the standard
// error envelope below.
type bannerActionResponse struct {
	Status               string `json:"status"`
	Action               string `json:"action"`
	PseudonymizedMessage string `json:"pseudonymized_message_id"`
}

type errorEnvelope struct {
	Error string `json:"error"`
}

// ServeHTTP implements http.Handler.
func (h *BannerActionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req bannerActionRequest
	// Cap the body to a small budget; banner payloads are sub-1KB.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	req.Action = strings.TrimSpace(strings.ToLower(req.Action))
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	if req.Action == "" {
		writeError(w, http.StatusBadRequest, "action is required")
		return
	}
	feedbackReq := action.FeedbackRequest{
		Token:  req.Token,
		Action: action.FeedbackAction(req.Action),
	}
	pmid, err := h.feedback.Process(r.Context(), feedbackReq)
	if err != nil {
		// Avoid echoing token-level detail back to the caller; log
		// the full error server-side and respond with a generic 400.
		h.logger.WarnContext(r.Context(), "banner action rejected",
			slog.String("action", req.Action),
			slog.Any("error", err),
		)
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	resp := bannerActionResponse{
		Status:               "accepted",
		Action:               req.Action,
		PseudonymizedMessage: pmid,
	}
	writeJSON(w, http.StatusAccepted, resp)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorEnvelope{Error: msg})
}
