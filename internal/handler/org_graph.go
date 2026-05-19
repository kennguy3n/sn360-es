package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
)

// OrgGraphHandler serves the persisted org graph snapshot.
type OrgGraphHandler struct {
	graphs repository.OrgGraphRepository
	logger *slog.Logger
}

// NewOrgGraphHandler constructs the handler.
func NewOrgGraphHandler(logger *slog.Logger, graphs repository.OrgGraphRepository) *OrgGraphHandler {
	return &OrgGraphHandler{graphs: graphs, logger: logger}
}

type orgGraphResponse struct {
	TenantID        string          `json:"tenant_id"`
	BuiltAt         time.Time       `json:"built_at"`
	Graph           json.RawMessage `json:"graph"`
	HighRiskCount   int             `json:"high_risk_count"`
	DepartmentCount int             `json:"department_count"`
	EmployeeCount   int             `json:"employee_count"`
	GroupCount      int             `json:"group_count"`
}

// ServeHTTP handles GET /v1/org-graph?tenant_id={id}.
func (h *OrgGraphHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		http.Error(w, `{"error":"tenant_id required"}`, http.StatusBadRequest)
		return
	}

	snap, err := h.graphs.GetByTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			http.Error(w, `{"error":"no org graph for tenant"}`, http.StatusNotFound)
			return
		}
		h.logger.Warn("org_graph: fetch failed",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err))
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	resp := orgGraphResponse{
		TenantID:        snap.TenantID,
		BuiltAt:         snap.BuiltAt,
		Graph:           snap.GraphJSON,
		HighRiskCount:   len(snap.HighRiskIDs),
		DepartmentCount: snap.DepartmentCount,
		EmployeeCount:   snap.EmployeeCount,
		GroupCount:      snap.GroupCount,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
