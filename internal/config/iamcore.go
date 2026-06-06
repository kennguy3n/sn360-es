package config

// IAMCore carries the uneycom/iam-core integration settings.
//
// sn360-es integrates with iam-core in two independent, opt-in ways:
//
//   - Dual-issuer JWT validation (see internal/middleware): when
//     JWKSEndpoint and Issuer are set, the auth middleware accepts
//     iam-core access tokens alongside the existing privacy-package
//     tokens, extracting the `tenant_id` claim. Leaving these empty
//     keeps the single-issuer behaviour.
//   - Directory sync source (see DirectorySyncSource on Config): when
//     the directory-sync worker is pointed at iam-core, it pulls the
//     user roster from iam-core's Management API instead of the native
//     provider. That path uses ManagementURL / ManagementToken below.
//
// Every field is optional so a standalone sn360-es deployment that is
// not paired with iam-core keeps its existing behaviour with no extra
// configuration.
type IAMCore struct {
	// JWKSEndpoint is the absolute URL of iam-core's JWKS document
	// (e.g. https://iam.example.com/.well-known/jwks.json), used by
	// the dual-issuer middleware to validate iam-core token
	// signatures. Empty disables the secondary issuer.
	JWKSEndpoint string

	// Issuer is the expected `iss` claim on iam-core access tokens.
	// Required when JWKSEndpoint is set.
	Issuer string

	// ManagementURL is the base URL of iam-core's Management API
	// (e.g. https://iam.example.com). The directory-sync worker
	// appends /api/v1/management/users?tenant_id={tid} when
	// DirectorySyncSource is "iam-core". Required when the source is
	// iam-core.
	ManagementURL string

	// ManagementToken is the bearer token presented to the iam-core
	// Management API. The token must carry the `read:users` scope.
	// Required when DirectorySyncSource is "iam-core".
	ManagementToken string
}

func loadIAMCore() IAMCore {
	return IAMCore{
		JWKSEndpoint:    getStr("IAM_CORE_JWKS_URL", ""),
		Issuer:          getStr("IAM_CORE_ISSUER", ""),
		ManagementURL:   getStr("IAM_CORE_MANAGEMENT_URL", ""),
		ManagementToken: getStr("IAM_CORE_MANAGEMENT_TOKEN", ""),
	}
}
