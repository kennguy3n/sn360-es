package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"log/slog"

	"github.com/kennguy3n/sn360-es/internal/service/onboarding"
)

type mockOnboardingService struct {
	authURLFn      func(provider onboarding.ProviderType, tenantID string) (string, error)
	handleCallback func(ctx context.Context, state, code string) (string, onboarding.ProviderType, error)
	revokeFn       func(ctx context.Context, tenantID string, provider onboarding.ProviderType) error
}

func (m *mockOnboardingService) AuthURL(provider onboarding.ProviderType, tenantID string) (string, error) {
	if m.authURLFn != nil {
		return m.authURLFn(provider, tenantID)
	}
	return "https://accounts.google.com/o/oauth2/v2/auth?state=abc", nil
}

func (m *mockOnboardingService) HandleCallback(ctx context.Context, state, code string) (string, onboarding.ProviderType, error) {
	if m.handleCallback != nil {
		return m.handleCallback(ctx, state, code)
	}
	return "tenant-1", onboarding.ProviderGoogle, nil
}

func (m *mockOnboardingService) Revoke(ctx context.Context, tenantID string, provider onboarding.ProviderType) error {
	if m.revokeFn != nil {
		return m.revokeFn(ctx, tenantID, provider)
	}
	return nil
}

func TestOnboardingHandler_ServeStart(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantStatus int
	}{
		{"valid", "?provider=google_workspace&tenant_id=t1", http.StatusOK},
		{"missing_tenant", "?provider=google_workspace", http.StatusBadRequest},
		{"missing_provider", "?tenant_id=t1", http.StatusBadRequest},
		{"wrong_method", "?provider=google_workspace&tenant_id=t1", http.StatusMethodNotAllowed},
	}

	svc := &mockOnboardingService{}
	h := NewOnboardingHandler(slog.Default(), svc)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := http.MethodGet
			if tt.name == "wrong_method" {
				method = http.MethodPost
			}
			req := httptest.NewRequest(method, "/v1/onboarding/start"+tt.query, nil)
			rr := httptest.NewRecorder()
			h.ServeStart(rr, req)
			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestOnboardingHandler_ServeCallback(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantStatus int
	}{
		{"valid", "?state=abc&code=xyz", http.StatusOK},
		{"missing_state", "?code=xyz", http.StatusBadRequest},
		{"missing_code", "?state=abc", http.StatusBadRequest},
	}

	svc := &mockOnboardingService{}
	h := NewOnboardingHandler(slog.Default(), svc)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/onboarding/callback"+tt.query, nil)
			rr := httptest.NewRecorder()
			h.ServeCallback(rr, req)
			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestOnboardingHandler_ServeStatus(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantStatus int
	}{
		{"valid", "?tenant_id=t1", http.StatusOK},
		{"missing_tenant", "", http.StatusBadRequest},
	}

	svc := &mockOnboardingService{}
	h := NewOnboardingHandler(slog.Default(), svc)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/onboarding/status"+tt.query, nil)
			rr := httptest.NewRecorder()
			h.ServeStatus(rr, req)
			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestOnboardingHandler_ServeRevoke(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		query      string
		wantStatus int
	}{
		{"valid", http.MethodDelete, "?tenant_id=t1&provider=google_workspace", http.StatusOK},
		{"wrong_method", http.MethodGet, "?tenant_id=t1&provider=google_workspace", http.StatusMethodNotAllowed},
		{"missing_fields", http.MethodDelete, "?tenant_id=t1", http.StatusBadRequest},
	}

	svc := &mockOnboardingService{}
	h := NewOnboardingHandler(slog.Default(), svc)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/v1/onboarding/revoke"+tt.query, nil)
			rr := httptest.NewRecorder()
			h.ServeRevoke(rr, req)
			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}
