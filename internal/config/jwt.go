package config

// JWT carries the JWT signing/verification knobs for the platform's
// /v1/* session tokens (and the banner / interstitial / quarantine
// token classes that share the same JWTIssuer).
//
// The legacy BANNER_TOKEN_SECRET environment variable continues to
// drive HS256 issuance; it is intentionally NOT moved here because
// rotating it would require redeploying every consumer that knows
// the secret out-of-band (banner addins, etc.). Instead, JWT just
// adds the new asymmetric inputs alongside the HS256 secret. This
// keeps the existing deployment surface unchanged.
//
// Configuration knobs:
//
//   - SigningAlg selects the algorithm Issue() will stamp onto fresh
//     tokens. Default "hs256" preserves the existing behaviour.
//     "es256" switches issuance to ECDSA P-256.
//   - PrivateKeyPath / PublicKeyPath point at PEM-encoded ECDSA P-256
//     keys on disk. Required when SigningAlg == "es256". May also be
//     set under SigningAlg == "hs256" so the issuer can verify ES256
//     tokens issued by a sibling deployment (transition mode).
//   - KeyID stamps the JWS `kid` header so JWKS-pinning consumers can
//     pick the right key out of a multi-entry JWKS. Optional; when
//     empty, the JWKS endpoint falls back to the RFC 7638 thumbprint.
type JWT struct {
	SigningAlg     string
	PrivateKeyPath string
	PublicKeyPath  string
	KeyID          string
}

// loadJWT loads the JWT subsystem config from the environment. All
// fields are optional — the application defers to BANNER_TOKEN_SECRET
// + HS256 when no ES256 material is configured, exactly matching
// pre-existing behaviour.
func loadJWT() JWT {
	return JWT{
		// "hs256" is the default for backward compatibility; "es256"
		// opts into ECDSA P-256 signing.
		SigningAlg:     getStr("JWT_SIGNING_ALG", "hs256"),
		PrivateKeyPath: getStr("JWT_PRIVATE_KEY_PATH", ""),
		PublicKeyPath:  getStr("JWT_PUBLIC_KEY_PATH", ""),
		KeyID:          getStr("JWT_KEY_ID", ""),
	}
}
