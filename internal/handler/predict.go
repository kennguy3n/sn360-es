package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/kennguy3n/sn360-es/internal/service/predict"
)

// PredictHandler serves the two pre-send / pre-open add-in endpoints:
//
//	POST /v1/predict/recipient
//	POST /v1/predict/open
//
// Both endpoints must reply within the add-in's 300ms p95 latency
// budget (PROPOSAL.md §6). The handler performs lightweight JSON
// parsing only — all logic lives in internal/service/predict.
type PredictHandler struct {
	logger    *slog.Logger
	recipient *predict.RecipientService
	open      *predict.OpenService
}

// NewPredictHandler wires the handler. Either service may be nil — the
// corresponding endpoint will return 503 in that case.
func NewPredictHandler(logger *slog.Logger, recipient *predict.RecipientService, open *predict.OpenService) *PredictHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &PredictHandler{logger: logger, recipient: recipient, open: open}
}

// ServeRecipient handles POST /v1/predict/recipient.
func (h *PredictHandler) ServeRecipient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.recipient == nil {
		writeError(w, http.StatusServiceUnavailable, "predict service not configured")
		return
	}
	var req predict.RecipientRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	res, err := h.recipient.Predict(r.Context(), req)
	if err != nil {
		h.logger.WarnContext(r.Context(), "predict: recipient failed",
			slog.Any("error", err),
		)
		// Generic public message; full error stays in the logs.
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ServeOpen handles POST /v1/predict/open.
func (h *PredictHandler) ServeOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.open == nil {
		writeError(w, http.StatusServiceUnavailable, "predict service not configured")
		return
	}
	var req predict.OpenRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	res, err := h.open.Predict(r.Context(), req)
	if err != nil {
		h.logger.WarnContext(r.Context(), "predict: open failed",
			slog.Any("error", err),
		)
		// Generic public message; full error stays in the logs.
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	writeJSON(w, http.StatusOK, res)
}
