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

	// TTL is shared across algorithms — the BANNER_TOKEN_TTL knob
	// (Banner.TokenTTL) keeps its existing meaning. loadBanner()
	// already defaults the env var to 7 days when unset, so this
	// floor is a defensive duplicate for operators who pass a
	// JWTConfig directly (e.g. tests) or zero out the field by
	// mistake. We never want a 0-second issuer.
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
	// issuers — it serves as the dual-verify legacy material).
	if cfg.Banner.TokenSecret != "" {
		jcfg.Secret = []byte(cfg.Banner.TokenSecret)
	}

	// Key loading is algorithm-aware. The ordering matters: an
	// operator who rolls back from ES256 to HS256 may leave the
	// JWT_PRIVATE_KEY_PATH / JWT_PUBLIC_KEY_PATH env vars pointing
	// at stale or missing files. In HS256 mode those failures must
	// NOT kill the issuer (HS256 doesn't need ECDSA material to
	// run), so we treat them as warnings and continue. In ES256
	// mode they remain fatal — issuing without keys is impossible.
	switch alg {
	case "hs256":
		jcfg.SigningAlg = privacy.SigningAlgHS256
		if jcfg.Secret == nil {
			logger.Info("sn360-es: banner token secret not configured; signed-action flows disabled")
			return nil
		}
		// HS256 mode treats ECDSA key paths as optional dual-verify
		// material. JWT_PRIVATE_KEY_PATH is irrelevant (HS256
		// issuers never sign with ECDSA) so we deliberately skip
		// it — loading it would be a footgun where a stale path
		// from a previous ES256 attempt disables the HS256 path.
		// JWT_PUBLIC_KEY_PATH IS loaded best-effort: when set, it
		// enables dual-verify of ES256 tokens issued by a sibling
		// deployment; load failures degrade to HS256-only with a
		// warning rather than killing the issuer.
		if cfg.JWT.PublicKeyPath != "" {
			pub, err := privacy.LoadECDSAPublicKeyFromFile(cfg.JWT.PublicKeyPath)
			if err != nil {
				logger.Warn("sn360-es: dual-verify public key load failed; HS256-only verification active",
					slog.Any("error", err),
					slog.String("path", cfg.JWT.PublicKeyPath),
				)
			} else {
				jcfg.PublicKey = pub
			}
		}
	case "es256":
		jcfg.SigningAlg = privacy.SigningAlgES256
		if cfg.JWT.PrivateKeyPath == "" || cfg.JWT.PublicKeyPath == "" {
			logger.Warn("sn360-es: JWT_SIGNING_ALG=es256 requires JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH; signed-action flows disabled",
				slog.String("private_path_set", boolToStr(cfg.JWT.PrivateKeyPath != "")),
				slog.String("public_path_set", boolToStr(cfg.JWT.PublicKeyPath != "")),
			)
			return nil
		}
		priv, err := privacy.LoadECDSAPrivateKeyFromFile(cfg.JWT.PrivateKeyPath)
		if err != nil {
			logger.Warn("sn360-es: jwt private key load failed; signed-action flows disabled",
				slog.Any("error", err),
				slog.String("path", cfg.JWT.PrivateKeyPath),
			)
			return nil
		}
		jcfg.PrivateKey = priv
		// Default the public half to the one embedded in the
		// private key so a JWKS publisher always has SOMETHING
		// to publish even if the operator-provided public-key file
		// fails to load below. This is overridden by the explicit
		// public-key file on success.
		jcfg.PublicKey = &priv.PublicKey
		pub, err := privacy.LoadECDSAPublicKeyFromFile(cfg.JWT.PublicKeyPath)
		if err != nil {
			logger.Warn("sn360-es: jwt public key load failed; signed-action flows disabled",
				slog.Any("error", err),
				slog.String("path", cfg.JWT.PublicKeyPath),
			)
			return nil
		}
		// Operator-provided public key takes precedence over the
		// one embedded in the private key file — this is what
		// makes independent rotation of the public-half possible
		// during ES256 key roll.
		jcfg.PublicKey = pub
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

// boolToStr renders a bool as "yes" / "no" for log labels. We use
// strings instead of slog.Bool so the misconfiguration log line
// produces grep-friendly output ("private_path_set=no") in plain-
// text deployments where the slog handler doesn't quote booleans.
func boolToStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
