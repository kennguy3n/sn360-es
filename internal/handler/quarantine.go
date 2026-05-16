package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// QuarantineHandler serves POST /v1/quarantine/release. The endpoint
// accepts a signed action token (issued by the support agent) plus an
// optional restored-body string. The token is the only authoritative
// source of (tenant, pseudonymised_message_id); the body field is a
// hint passed through to the provider.
type QuarantineHandler struct {
	logger   *slog.Logger
	verifier *privacy.JWTIssuer
	release  *action.ReleaseService
}

// NewQuarantineHandler wires up the handler. verifier and release
// must be non-nil; logger may be nil (defaults to slog.Default).
func NewQuarantineHandler(logger *slog.Logger, verifier *privacy.JWTIssuer, release *action.ReleaseService) (*QuarantineHandler, error) {
	if verifier == nil {
		return nil, errors.New("quarantine handler: verifier is required")
	}
	if release == nil {
		return nil, errors.New("quarantine handler: release service is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &QuarantineHandler{logger: logger, verifier: verifier, release: release}, nil
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

// ServeHTTP implements http.Handler.
func (h *QuarantineHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req quarantineReleaseRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	claims, err := h.verifier.Verify(req.Token)
	if err != nil {
		h.logger.WarnContext(r.Context(), "quarantine release: verify token",
			slog.Any("error", err),
		)
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	if claims.TenantID == "" || claims.PseudonymizedMessage == "" {
		writeError(w, http.StatusBadRequest, "token missing required claims")
		return
	}
	outcome, err := h.release.Release(r.Context(), action.ReleaseRequest{
		TenantID:             claims.TenantID,
		PseudonymizedMessage: claims.PseudonymizedMessage,
		RequestedBy:          req.RequestedBy,
		RestoredBody:         req.RestoredBody,
	})
	if err != nil {
		h.logger.WarnContext(r.Context(), "quarantine release failed",
			slog.String("tenant_id", claims.TenantID),
			slog.Any("error", err),
		)
		writeError(w, http.StatusInternalServerError, "release failed")
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
