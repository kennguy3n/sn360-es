package config

import (
	"strings"
	"testing"
)

func TestLoad_IAMCore_Defaults(t *testing.T) {
	withEnv(t, map[string]string{
		"APP_NAME":    "sn360-es-test",
		"ENVIRONMENT": "local",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DirectorySyncSource != DirectorySourceNative {
		t.Errorf("DirectorySyncSource = %q, want native (default)", cfg.DirectorySyncSource)
	}
	if cfg.IAMCore.JWKSEndpoint != "" || cfg.IAMCore.Issuer != "" {
		t.Errorf("IAMCore = %+v, want empty by default", cfg.IAMCore)
	}
}

func TestLoad_IAMCore_ReadsEnv(t *testing.T) {
	withEnv(t, map[string]string{
		"APP_NAME":                  "sn360-es-test",
		"ENVIRONMENT":               "local",
		"IAM_CORE_JWKS_URL":         "https://iam.example.com/.well-known/jwks.json",
		"IAM_CORE_ISSUER":           "https://iam.example.com/",
		"IAM_CORE_MANAGEMENT_URL":   "https://iam.example.com",
		"IAM_CORE_MANAGEMENT_TOKEN": "mgmt-token",
		"DIRECTORY_SYNC_SOURCE":     "IAM-CORE", // upper-cased: must normalise
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.IAMCore.JWKSEndpoint != "https://iam.example.com/.well-known/jwks.json" {
		t.Errorf("JWKSEndpoint = %q", cfg.IAMCore.JWKSEndpoint)
	}
	if cfg.IAMCore.Issuer != "https://iam.example.com/" {
		t.Errorf("Issuer = %q", cfg.IAMCore.Issuer)
	}
	if cfg.DirectorySyncSource != DirectorySourceIAMCore {
		t.Errorf("DirectorySyncSource = %q, want iam-core (normalised)", cfg.DirectorySyncSource)
	}
}

func TestDirectorySyncSource_Valid(t *testing.T) {
	for _, s := range []DirectorySyncSource{DirectorySourceNative, DirectorySourceIAMCore} {
		if !s.Valid() {
			t.Errorf("%q.Valid() = false, want true", s)
		}
	}
	for _, bad := range []DirectorySyncSource{"", "iamcore", "Native", "x"} {
		if bad.Valid() {
			t.Errorf("%q.Valid() = true, want false", bad)
		}
	}
}

func TestValidate_DirectorySyncSource_RejectsTypo(t *testing.T) {
	cfg := validProdConfig()
	cfg.DirectorySyncSource = "iamcore" // missing hyphen
	if err := cfg.validate(); err == nil {
		t.Fatal("expected validate() to reject DIRECTORY_SYNC_SOURCE typo")
	}
}

func TestValidate_DirectorySyncSource_EmptyTreatedAsNative(t *testing.T) {
	cfg := validProdConfig() // leaves DirectorySyncSource zero-valued
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate() rejected empty DIRECTORY_SYNC_SOURCE: %v", err)
	}
}

func TestValidate_IAMCoreSource_RequiresManagementURL(t *testing.T) {
	cfg := validProdConfig()
	cfg.DirectorySyncSource = DirectorySourceIAMCore
	cfg.IAMCore.ManagementToken = "tok"
	// ManagementURL deliberately empty.
	err := cfg.validate()
	if err == nil || !strings.Contains(err.Error(), "IAM_CORE_MANAGEMENT_URL") {
		t.Fatalf("expected IAM_CORE_MANAGEMENT_URL error, got %v", err)
	}
}

func TestValidate_IAMCoreSource_RequiresManagementToken(t *testing.T) {
	cfg := validProdConfig()
	cfg.DirectorySyncSource = DirectorySourceIAMCore
	cfg.IAMCore.ManagementURL = "https://iam.example.com"
	// ManagementToken deliberately empty.
	err := cfg.validate()
	if err == nil || !strings.Contains(err.Error(), "IAM_CORE_MANAGEMENT_TOKEN") {
		t.Fatalf("expected IAM_CORE_MANAGEMENT_TOKEN error, got %v", err)
	}
}

func TestValidate_IAMCoreSource_AcceptsFullyConfigured(t *testing.T) {
	cfg := validProdConfig()
	cfg.DirectorySyncSource = DirectorySourceIAMCore
	cfg.IAMCore.ManagementURL = "https://iam.example.com"
	cfg.IAMCore.ManagementToken = "tok"
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate() rejected fully-configured iam-core source: %v", err)
	}
}

func TestValidate_IAMCoreJWKS_RequiresIssuer(t *testing.T) {
	cfg := validProdConfig()
	cfg.IAMCore.JWKSEndpoint = "https://iam.example.com/.well-known/jwks.json"
	// Issuer deliberately empty.
	err := cfg.validate()
	if err == nil || !strings.Contains(err.Error(), "IAM_CORE_ISSUER") {
		t.Fatalf("expected IAM_CORE_ISSUER error, got %v", err)
	}
}
