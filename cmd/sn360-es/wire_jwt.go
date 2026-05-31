package main

import (
	"log/slog"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// buildJWTIssuer constructs the platform JWT issuer from cfg.
//
// The issuer is the single sign/verify dependency for:
//
//   - Banner action tokens (Report Phishing / Mark Safe / Trust
//     Sender) consumed by end-recipients.
//   - URL-rewriter interstitial tokens.
//   - Quarantine release tokens.
//   - The platform-wide JWTAuth middleware that gates /v1/* routes.
//
// Algorithm selection is driven by cfg.JWT.SigningAlg (default
// "hs256"):
//
//   - "hs256": HMAC-SHA-256 using BANNER_TOKEN_SECRET. This is the
//     legacy default; every existing deployment continues to work
//     unchanged when JWT_SIGNING_ALG is unset. The function returns
//     nil (rather than an error) when BANNER_TOKEN_SECRET is empty,
//     matching the pre-existing behaviour where signed-action flows
//     are simply disabled in that case.
//   - "es256": ECDSA P-256 using PEM-encoded keys loaded from
//     JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH. BANNER_TOKEN_SECRET
//     may still be set; when it is, the resulting issuer dual-verifies
//     HS256 tokens in-flight during a migration window.
//
// On any configuration error (missing/invalid keys, unknown algorithm,
// short secret) the function logs at warn level and returns nil. The
// caller treats a nil issuer as "signed-action flows disabled" \u2014 the
// exact same degradation path the legacy code already implemented for
// HS256.
//
// The function never logs key material; PEM-load errors come back
// wrapped without the file contents, by design.
func buildJWTIssuer(cfg *config.Config, logger *slog.Logger) *privacy.JWTIssuer {
	alg := strings.ToLower(strings.TrimSpace(cfg.JWT.SigningAlg))
	if alg == "" {
		alg = "hs256"
	}

	// TTL is shared across algorithms \u2014 the BANNER_TOKEN_TTL knob
	// (Banner.TokenTTL) keeps its existing meaning. Default 7 days
	// matches the post-Phase-1 quick-win fix (PR #49) that reduced
	// the upper bound from 30 days; we apply the same floor here so
	// an ES256-only deployment that ignores BANNER_TOKEN_TTL still
	// gets a sane default.
	ttl := cfg.Banner.TokenTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}

	jcfg := privacy.JWTConfig{
		Issuer: "sn360-es",
		TTL:    ttl,
		KeyID:  cfg.JWT.KeyID,
	}

	// HS256 secret (always loaded when present, even for ES256
	// issuers \u2014 it serves as the dual-verify legacy material).
	if cfg.Banner.TokenSecret != "" {
		jcfg.Secret = []byte(cfg.Banner.TokenSecret)
	}

	// ES256 key material. Loaded only when the operator asks for it
	// OR when JWT_PUBLIC_KEY_PATH is set on its own (which is the
	// dual-verify shape: HS256-issuing replicas may want to accept
	// ES256 tokens emitted by a sibling deployment).
	if cfg.JWT.PrivateKeyPath != "" {
		priv, err := privacy.LoadECDSAPrivateKeyFromFile(cfg.JWT.PrivateKeyPath)
		if err != nil {
			logger.Warn("sn360-es: jwt private key load failed; signed-action flows disabled",
				slog.Any("error", err),
				slog.String("path", cfg.JWT.PrivateKeyPath),
			)
			return nil
		}
		jcfg.PrivateKey = priv
		// When only the private-key path is set, fall back to the
		// embedded public half so the issuer can verify its own
		// tokens without a separate file.
		jcfg.PublicKey = &priv.PublicKey
	}
	if cfg.JWT.PublicKeyPath != "" {
		pub, err := privacy.LoadECDSAPublicKeyFromFile(cfg.JWT.PublicKeyPath)
		if err != nil {
			logger.Warn("sn360-es: jwt public key load failed; signed-action flows disabled",
				slog.Any("error", err),
				slog.String("path", cfg.JWT.PublicKeyPath),
			)
			return nil
		}
		// Operator-provided public key takes precedence over the
		// one embedded in the private key file \u2014 this is what
		// makes independent rotation of the public-half possible
		// during ES256 key roll.
		jcfg.PublicKey = pub
	}

	switch alg {
	case "hs256":
		jcfg.SigningAlg = privacy.SigningAlgHS256
		if jcfg.Secret == nil {
			logger.Info("sn360-es: banner token secret not configured; signed-action flows disabled")
			return nil
		}
	case "es256":
		jcfg.SigningAlg = privacy.SigningAlgES256
		if jcfg.PrivateKey == nil || jcfg.PublicKey == nil {
			logger.Warn("sn360-es: JWT_SIGNING_ALG=es256 requires JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH; signed-action flows disabled")
			return nil
		}
	default:
		logger.Warn("sn360-es: unknown JWT_SIGNING_ALG; signed-action flows disabled",
			slog.String("alg", alg),
		)
		return nil
	}

	issuer, err := privacy.NewJWTIssuer(jcfg)
	if err != nil {
		logger.Warn("sn360-es: jwt issuer init failed; signed-action flows disabled",
			slog.Any("error", err),
			slog.String("alg", string(jcfg.SigningAlg)),
		)
		return nil
	}

	// Observability: log the active algorithm + verifier set at
	// boot so an operator can see at a glance whether the deployment
	// is still on HS256, has migrated to ES256, or is in dual-verify
	// mode. No key material is logged.
	verifiers := []string{}
	if jcfg.Secret != nil {
		verifiers = append(verifiers, "HS256")
	}
	if jcfg.PublicKey != nil {
		verifiers = append(verifiers, "ES256")
	}
	logger.Info("sn360-es: jwt issuer ready",
		slog.String("signing_alg", string(jcfg.SigningAlg)),
		slog.String("verifies", strings.Join(verifiers, ",")),
		slog.Bool("kid_set", jcfg.KeyID != ""),
	)
	return issuer
}
