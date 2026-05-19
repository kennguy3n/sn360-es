package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/pkg/email_provider/gmail"
)

// gwsSetupChecker implements handler.GWSSetupChecker by validating
// GWS domain-wide delegation configuration step by step.
type gwsSetupChecker struct {
	cfg    *config.Config
	logger *slog.Logger
}

func (c *gwsSetupChecker) CheckServiceAccount() bool {
	return c.cfg.GWS.ServiceAccountJSON != ""
}

func (c *gwsSetupChecker) CheckDelegatedAdmin() bool {
	return c.cfg.GWS.DelegatedAdmin != ""
}

func (c *gwsSetupChecker) CheckDomain() bool {
	return c.cfg.GWS.Domain != ""
}

func (c *gwsSetupChecker) CheckDirectoryAccess(ctx context.Context, tenantID string) bool {
	dc := c.buildDirectoryClient()
	if dc == nil {
		return false
	}
	_, err := dc.ListUsers(ctx, tenantID)
	if err != nil {
		c.logger.Warn("gws-setup-check: directory access failed",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err))
		return false
	}
	return true
}

func (c *gwsSetupChecker) CheckGmailAccess(ctx context.Context, _ string) bool {
	if !c.cfg.GWS.HasGmail() {
		return false
	}
	sa, err := gmail.LoadServiceAccount(c.cfg.GWS.ServiceAccountJSON)
	if err != nil {
		return false
	}
	tokens, err := gmail.NewJWTBearerSource(gmail.JWTBearerConfig{
		ServiceAccount:   sa,
		ImpersonatedUser: c.cfg.GWS.DelegatedAdmin,
	})
	if err != nil {
		return false
	}
	tok, err := tokens.Token(ctx)
	if err != nil {
		c.logger.Warn("gws-setup-check: gmail token acquisition failed",
			slog.Any("error", err))
		return false
	}

	// Test Gmail API access by fetching the delegated admin's profile.
	base := c.cfg.GWS.BaseURL
	if base == "" {
		base = "https://gmail.googleapis.com"
	}
	endpoint := fmt.Sprintf("%s/gmail/v1/users/%s/profile", base, c.cfg.GWS.DelegatedAdmin)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.logger.Warn("gws-setup-check: gmail profile request failed",
			slog.Any("error", err))
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body json.RawMessage
		_ = json.NewDecoder(resp.Body).Decode(&body)
		c.logger.Warn("gws-setup-check: gmail profile returned non-200",
			slog.Int("status", resp.StatusCode))
		return false
	}
	return true
}

func (c *gwsSetupChecker) buildDirectoryClient() agent.DirectoryClient {
	if !c.cfg.GWS.HasGmail() {
		return nil
	}
	sa, err := gmail.LoadServiceAccount(c.cfg.GWS.ServiceAccountJSON)
	if err != nil {
		return nil
	}
	tokens, err := gmail.NewJWTBearerSource(gmail.JWTBearerConfig{
		ServiceAccount:   sa,
		ImpersonatedUser: c.cfg.GWS.DelegatedAdmin,
	})
	if err != nil {
		return nil
	}
	dc, err := gmail.NewDirectoryClient(gmail.DirectoryClientConfig{
		TokenSource:  tokens,
		Domain:       c.cfg.GWS.Domain,
		AdminBaseURL: c.cfg.GWS.AdminBaseURL,
	})
	if err != nil {
		return nil
	}
	return dc
}
