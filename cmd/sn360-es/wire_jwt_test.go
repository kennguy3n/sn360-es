package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// jwtIssueOptions returns a minimal IssueOptions for tests that just
// need to round-trip a token through the issuer. We deliberately
// keep this empty so the test surface does not couple to whichever
// optional fields IssueOptions grows in future.
func jwtIssueOptions() privacy.IssueOptions {
	return privacy.IssueOptions{}
}

// writeES256KeyPair writes a fresh ECDSA P-256 keypair to PEM files
// in dir and returns the two paths. Used by the wiring tests below.
func writeES256KeyPair(t *testing.T, dir string) (privPath, pubPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("priv der: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("pub der: %v", err)
	}
	privPath = filepath.Join(dir, "priv.pem")
	pubPath = filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return privPath, pubPath
}

func TestBuildJWTIssuer_HS256_DefaultPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.Banner.TokenSecret = "this-is-a-very-long-banner-secret-32+ chars"
	cfg.Banner.TokenTTL = 7 * 24 * time.Hour
	cfg.JWT.SigningAlg = "hs256"
	iss := buildJWTIssuer(cfg, discardLogger())
	if iss == nil {
		t.Fatal("expected non-nil HS256 issuer")
	}
	tok, err := iss.Issue("t", "m", jwtIssueOptions())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := iss.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestBuildJWTIssuer_HS256_NoSecret_ReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.JWT.SigningAlg = "hs256"
	if iss := buildJWTIssuer(cfg, discardLogger()); iss != nil {
		t.Fatal("expected nil issuer when BANNER_TOKEN_SECRET is unset")
	}
}

func TestBuildJWTIssuer_ES256_HappyPath(t *testing.T) {
	privPath, pubPath := writeES256KeyPair(t, t.TempDir())
	cfg := &config.Config{}
	cfg.JWT.SigningAlg = "es256"
	cfg.JWT.PrivateKeyPath = privPath
	cfg.JWT.PublicKeyPath = pubPath
	cfg.JWT.KeyID = "boot-kid"
	cfg.Banner.TokenTTL = time.Hour
	iss := buildJWTIssuer(cfg, discardLogger())
	if iss == nil {
		t.Fatal("expected non-nil ES256 issuer")
	}
	tok, err := iss.Issue("t", "m", jwtIssueOptions())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := iss.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
	jwks, err := iss.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != "boot-kid" {
		t.Errorf("JWKS shape mismatch: %+v", jwks)
	}
}

func TestBuildJWTIssuer_ES256_MissingKey_ReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.JWT.SigningAlg = "es256"
	cfg.Banner.TokenTTL = time.Hour
	if iss := buildJWTIssuer(cfg, discardLogger()); iss != nil {
		t.Fatal("expected nil issuer for ES256 with no key paths")
	}
}

func TestBuildJWTIssuer_ES256_InvalidPath_ReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.JWT.SigningAlg = "es256"
	cfg.JWT.PrivateKeyPath = filepath.Join(t.TempDir(), "missing.pem")
	cfg.JWT.PublicKeyPath = filepath.Join(t.TempDir(), "missing.pem")
	if iss := buildJWTIssuer(cfg, discardLogger()); iss != nil {
		t.Fatal("expected nil issuer when key files are missing")
	}
}

func TestBuildJWTIssuer_UnknownAlg_ReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.JWT.SigningAlg = "rsa-pkcs1-v1.5"
	cfg.Banner.TokenSecret = "this-is-a-very-long-banner-secret-32+ chars"
	if iss := buildJWTIssuer(cfg, discardLogger()); iss != nil {
		t.Fatal("expected nil issuer for unknown algorithm")
	}
}

// TestBuildJWTIssuer_HS256_StalePrivateKeyPath_Survives pins the
// regression for Devin Review finding #3: an operator who rolls
// BACK from ES256 to HS256 may leave JWT_PRIVATE_KEY_PATH pointing
// at a missing/invalid file. HS256 doesn't NEED the private key,
// so this misconfiguration must NOT disable the issuer — the
// HS256 path stays live and we ignore the stale env var entirely.
func TestBuildJWTIssuer_HS256_StalePrivateKeyPath_Survives(t *testing.T) {
	cfg := &config.Config{}
	cfg.Banner.TokenSecret = "this-is-a-very-long-banner-secret-32+ chars"
	cfg.JWT.SigningAlg = "hs256"
	cfg.JWT.PrivateKeyPath = filepath.Join(t.TempDir(), "stale-from-es256-rollback.pem")
	iss := buildJWTIssuer(cfg, discardLogger())
	if iss == nil {
		t.Fatal("HS256 issuer must survive a stale JWT_PRIVATE_KEY_PATH; expected non-nil issuer")
	}
	tok, err := iss.Issue("t", "m", jwtIssueOptions())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := iss.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestBuildJWTIssuer_HS256_StalePublicKeyPath_DegradesToHS256Only
// pins the parallel case for JWT_PUBLIC_KEY_PATH. In HS256 mode the
// public key is OPTIONAL dual-verify material; load failure should
// log a warning and degrade to HS256-only verification rather than
// returning nil.
func TestBuildJWTIssuer_HS256_StalePublicKeyPath_DegradesToHS256Only(t *testing.T) {
	cfg := &config.Config{}
	cfg.Banner.TokenSecret = "this-is-a-very-long-banner-secret-32+ chars"
	cfg.JWT.SigningAlg = "hs256"
	cfg.JWT.PublicKeyPath = filepath.Join(t.TempDir(), "stale.pem")
	iss := buildJWTIssuer(cfg, discardLogger())
	if iss == nil {
		t.Fatal("HS256 issuer must survive a stale JWT_PUBLIC_KEY_PATH; expected non-nil issuer")
	}
	// Degradation invariant: JWKS is empty when the public key load
	// failed (the issuer is HS256-only after the warning).
	jwks, err := iss.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(jwks.Keys) != 0 {
		t.Fatalf("expected empty JWKS after stale-path degradation, got %d keys", len(jwks.Keys))
	}
}

// TestBuildJWTIssuer_HS256_GoodPublicKeyPath_EnablesDualVerify pins
// the positive case: an HS256-issuing deployment that wants to
// dual-verify ES256 tokens from a sibling sets JWT_PUBLIC_KEY_PATH
// alongside BANNER_TOKEN_SECRET. The resulting issuer is HS256 for
// new tokens but accepts both algorithms at verify time.
func TestBuildJWTIssuer_HS256_GoodPublicKeyPath_EnablesDualVerify(t *testing.T) {
	_, pubPath := writeES256KeyPair(t, t.TempDir())
	cfg := &config.Config{}
	cfg.Banner.TokenSecret = "this-is-a-very-long-banner-secret-32+ chars"
	cfg.JWT.SigningAlg = "hs256"
	cfg.JWT.PublicKeyPath = pubPath
	iss := buildJWTIssuer(cfg, discardLogger())
	if iss == nil {
		t.Fatal("expected non-nil HS256 + dual-verify issuer")
	}
	jwks, err := iss.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected JWKS to publish the dual-verify public key, got %d keys", len(jwks.Keys))
	}
}

// TestBuildJWTIssuer_DualVerifyMode pins the migration shape: the
// operator sets JWT_SIGNING_ALG=es256 with both the new keys AND
// the legacy BANNER_TOKEN_SECRET still in place. New tokens are
// signed ES256; in-flight HS256 tokens still verify until their
// TTL expires.
func TestBuildJWTIssuer_DualVerifyMode(t *testing.T) {
	privPath, pubPath := writeES256KeyPair(t, t.TempDir())
	cfg := &config.Config{}
	cfg.JWT.SigningAlg = "es256"
	cfg.JWT.PrivateKeyPath = privPath
	cfg.JWT.PublicKeyPath = pubPath
	cfg.Banner.TokenSecret = "this-is-a-very-long-banner-secret-32+ chars"
	cfg.Banner.TokenTTL = time.Hour
	iss := buildJWTIssuer(cfg, discardLogger())
	if iss == nil {
		t.Fatal("expected non-nil dual-verify issuer")
	}
	// The new-mode token must verify under the dual issuer.
	tok, err := iss.Issue("t", "m", jwtIssueOptions())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := iss.Verify(tok); err != nil {
		t.Fatalf("verify dual-mode token: %v", err)
	}
}
