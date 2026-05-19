package handler

import (
	"context"
	"log/slog"
	"net/http"
)

// GWSSetupStatus is the step-by-step validation response for the
// GWS domain-wide delegation setup wizard.
type GWSSetupStatus struct {
	ServiceAccountConfigured bool     `json:"service_account_configured"`
	DelegatedAdminConfigured bool     `json:"delegated_admin_configured"`
	DomainConfigured         bool     `json:"domain_configured"`
	DirectoryAccessOK        bool     `json:"directory_access_ok"`
	GmailAccessOK            bool     `json:"gmail_access_ok"`
	StepsRemaining           []string `json:"steps_remaining"`
}

// GWSSetupChecker validates each step of the GWS domain-wide
// delegation configuration. Implementations live in cmd/sn360-es
// where the real provider clients are available.
type GWSSetupChecker interface {
	CheckServiceAccount() bool
	CheckDelegatedAdmin() bool
	CheckDomain() bool
	CheckDirectoryAccess(ctx context.Context, tenantID string) bool
	CheckGmailAccess(ctx context.Context, tenantID string) bool
}

// OnboardingWizardHandler serves the GWS setup-status endpoint.
type OnboardingWizardHandler struct {
	checker GWSSetupChecker
	logger  *slog.Logger
}

// NewOnboardingWizardHandler constructs the wizard handler.
func NewOnboardingWizardHandler(logger *slog.Logger, checker GWSSetupChecker) *OnboardingWizardHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &OnboardingWizardHandler{checker: checker, logger: logger}
}

// ServeGWSSetupStatus handles GET /v1/onboarding/gws-setup-status.
func (h *OnboardingWizardHandler) ServeGWSSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}

	status := GWSSetupStatus{
		ServiceAccountConfigured: h.checker.CheckServiceAccount(),
		DelegatedAdminConfigured: h.checker.CheckDelegatedAdmin(),
		DomainConfigured:         h.checker.CheckDomain(),
	}

	// Only test live connectivity when the static config is in place.
	if status.ServiceAccountConfigured && status.DelegatedAdminConfigured && status.DomainConfigured {
		status.DirectoryAccessOK = h.checker.CheckDirectoryAccess(r.Context(), tenantID)
		status.GmailAccessOK = h.checker.CheckGmailAccess(r.Context(), tenantID)
	}

	var steps []string
	if !status.ServiceAccountConfigured {
		steps = append(steps, "Set GWS_SERVICE_ACCOUNT_JSON to the path or inline JSON of a service account key with domain-wide delegation")
	}
	if !status.DelegatedAdminConfigured {
		steps = append(steps, "Set GWS_DELEGATED_ADMIN to the admin user email the service account impersonates")
	}
	if !status.DomainConfigured {
		steps = append(steps, "Set GWS_DOMAIN to your workspace primary domain (e.g. example.com)")
	}
	if status.ServiceAccountConfigured && status.DelegatedAdminConfigured && status.DomainConfigured {
		if !status.DirectoryAccessOK {
			steps = append(steps, "Grant the service account domain-wide delegation with scope https://www.googleapis.com/auth/admin.directory.user.readonly in Google Admin Console > Security > API Controls")
		}
		if !status.GmailAccessOK {
			steps = append(steps, "Grant the service account domain-wide delegation with scope https://www.googleapis.com/auth/gmail.modify in Google Admin Console > Security > API Controls")
		}
	}
	status.StepsRemaining = steps
	if status.StepsRemaining == nil {
		status.StepsRemaining = []string{}
	}

	writeJSON(w, http.StatusOK, status)
}
