package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
)

// VendorHandler exposes vendor management CRUD endpoints.
type VendorHandler struct {
	vendors repository.VendorRepository
	logger  *slog.Logger
}

// NewVendorHandler constructs the vendor handler.
func NewVendorHandler(logger *slog.Logger, vendors repository.VendorRepository) *VendorHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &VendorHandler{vendors: vendors, logger: logger}
}

type vendorCreateRequest struct {
	TenantID    string `json:"tenant_id"`
	Domain      string `json:"domain"`
	DisplayName string `json:"display_name"`
}

type vendorApproveRequest struct {
	TenantID string `json:"tenant_id"`
}

// ServeList handles GET /v1/vendors?tenant_id={id}
func (h *VendorHandler) ServeList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id required")
		return
	}
	vendors, err := h.vendors.List(r.Context(), tenantID, 0)
	if err != nil {
		h.logger.Error("vendor list failed", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if vendors == nil {
		vendors = []repository.Vendor{}
	}
	writeJSON(w, http.StatusOK, vendors)
}

// ServeCreate handles POST /v1/vendors
func (h *VendorHandler) ServeCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Cap body size and reject unknown fields, matching the rest of
	// the handler package (quarantine.go, escalation.go, predict.go).
	// 8 KiB is well above any legitimate vendor-create payload.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024))
	dec.DisallowUnknownFields()
	var req vendorCreateRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.TenantID == "" || req.Domain == "" {
		writeError(w, http.StatusBadRequest, "tenant_id and domain required")
		return
	}
	now := time.Now().UTC()
	v := &repository.Vendor{
		TenantID:       req.TenantID,
		Domain:         strings.ToLower(req.Domain),
		DisplayName:    req.DisplayName,
		Approved:       false,
		AutoDiscovered: false,
		Confidence:     1.0,
		LastSeenAt:     now,
	}
	if err := h.vendors.Upsert(r.Context(), v); err != nil {
		h.logger.Error("vendor create failed", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

// ServeApprove handles PUT /v1/vendors/{domain}/approve
func (h *VendorHandler) ServeApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	domain := extractVendorDomain(r.URL.Path, "/approve")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain required in path")
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024))
	dec.DisallowUnknownFields()
	var req vendorApproveRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.TenantID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id required")
		return
	}
	v, err := h.vendors.GetByDomain(r.Context(), req.TenantID, domain)
	if err != nil {
		writeError(w, http.StatusNotFound, "vendor not found")
		return
	}
	v.Approved = true
	v.UpdatedAt = time.Now().UTC()
	if err := h.vendors.Upsert(r.Context(), v); err != nil {
		h.logger.Error("vendor approve failed", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// ServeRevoke handles PUT /v1/vendors/{domain}/revoke
func (h *VendorHandler) ServeRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	domain := extractVendorDomain(r.URL.Path, "/revoke")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain required in path")
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024))
	dec.DisallowUnknownFields()
	var req vendorApproveRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.TenantID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id required")
		return
	}
	v, err := h.vendors.GetByDomain(r.Context(), req.TenantID, domain)
	if err != nil {
		writeError(w, http.StatusNotFound, "vendor not found")
		return
	}
	v.Approved = false
	v.UpdatedAt = time.Now().UTC()
	if err := h.vendors.Upsert(r.Context(), v); err != nil {
		h.logger.Error("vendor revoke failed", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// ServeDelete handles DELETE /v1/vendors/{domain}?tenant_id={id}
func (h *VendorHandler) ServeDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	domain := extractVendorDomainForDelete(r.URL.Path)
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain required in path")
		return
	}
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id required")
		return
	}
	if err := h.vendors.Delete(r.Context(), tenantID, domain); err != nil {
		h.logger.Error("vendor delete failed", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// extractVendorDomain extracts the domain from a path like
// /v1/vendors/{domain}/{suffix}
func extractVendorDomain(path, suffix string) string {
	path = strings.TrimSuffix(path, suffix)
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "v1" && parts[1] == "vendors" {
		return strings.ToLower(parts[2])
	}
	return ""
}

// extractVendorDomainForDelete extracts domain from
// /v1/vendors/{domain}.
//
// Returns "" for any path with extra trailing segments
// (e.g. /v1/vendors/foo/wat). This is defence-in-depth
// against a surprise-delete vector: the dispatcher in
// cmd/sn360-es/routes.go already gates DELETE on a positive
// 3-segment shape check, but the extractor itself MUST
// refuse loose inputs so a future caller that bypasses the
// dispatcher (worker fan-out, admin tooling, internal
// migration script) doesn't accidentally delete the
// wrong vendor. PR #51 Devin Review finding
// ANALYSIS_..._0004 (round 4) flagged the asymmetry.
func extractVendorDomainForDelete(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 3 && parts[0] == "v1" && parts[1] == "vendors" {
		return strings.ToLower(parts[2])
	}
	return ""
}
