package config

import "strings"

// GWS holds Google Workspace API credentials. ServiceAccountJSON is
// the path or inline JSON of a service-account key with domain-wide
// delegation; DelegatedAdmin is the admin user the service account
// impersonates when calling the Admin SDK Directory API.
//
// All fields are optional: when ServiceAccountJSON is empty the GWS
// provider is disabled and the action consumers / mailbox poller
// fall back to logging-only mode.
type GWS struct {
	ServiceAccountJSON string
	DelegatedAdmin     string
	// Domain is the workspace primary domain (e.g. "example.com");
	// used by the mailbox poller's Admin SDK list-users call.
	Domain string
	// BaseURL overrides the Gmail / Admin API endpoint; left blank in
	// production. Tests use httptest server URLs here.
	BaseURL string
	// AdminBaseURL overrides the Admin SDK endpoint; production
	// leaves this blank to use https://admin.googleapis.com.
	AdminBaseURL string
	// OAuthClientID and OAuthClientSecret are the web-application
	// OAuth 2.0 credentials used by the self-service onboarding
	// consent flow (separate from the domain-wide-delegation service
	// account). Only needed when the onboarding service is enabled.
	OAuthClientID     string
	OAuthClientSecret string
}

// HasGmail reports whether enough fields are set to build a Gmail
// provider. Domain is required because the mailbox poller's Admin
// SDK list-users call needs it; without it the poller silently
// observes zero mailboxes and the provider registry would hold an
// unreachable entry. Keeping Domain in the predicate ensures the
// provider registry, mailbox poller, and directory client all agree
// on a single "Gmail is wired" gate.
func (g GWS) HasGmail() bool {
	return g.ServiceAccountJSON != "" && g.DelegatedAdmin != "" && g.Domain != ""
}

func loadGWS() GWS {
	return GWS{
		// ServiceAccountJSON is either a file path or inline
		// JSON. JSON tolerates surrounding whitespace, but a
		// stray newline at the end of a file path (Helm `tpl`
		// indirection, k8s ConfigMap rendering, `echo $path`
		// piping) makes os.ReadFile fail with a "no such file"
		// the operator then has to debug. Trim here so the same
		// invariant the other four credential fields enforce
		// — no leading/trailing whitespace — applies uniformly.
		ServiceAccountJSON: strings.TrimSpace(getStr("GWS_SERVICE_ACCOUNT_JSON", "")),
		DelegatedAdmin:     strings.TrimSpace(getStr("GWS_DELEGATED_ADMIN", "")),
		// Domain is the registry key the provider lookup
		// matches against the MailboxProvider's emitted
		// TenantID. Both flow from this single field, so we
		// trim once at the source — otherwise a stray space
		// in GWS_DOMAIN silently desyncs the registry key
		// (which used to be trimmed in providers.go) from
		// the TenantID (which is not), and action consumers
		// drop every event for the tenant.
		Domain:            strings.TrimSpace(getStr("GWS_DOMAIN", "")),
		BaseURL:           getStr("GWS_GMAIL_BASE_URL", ""),
		AdminBaseURL:      getStr("GWS_ADMIN_BASE_URL", ""),
		OAuthClientID:     strings.TrimSpace(getStr("GWS_OAUTH_CLIENT_ID", "")),
		OAuthClientSecret: getStr("GWS_OAUTH_CLIENT_SECRET", ""),
	}
}

// O365 holds Microsoft 365 client-credentials configuration. All
// fields are optional; when ClientID + ClientSecret + TenantID are
// not all set the O365 provider is disabled.
type O365 struct {
	ClientID     string
	ClientSecret string
	TenantID     string
	// BaseURL overrides the Graph API endpoint; tests inject
	// httptest URLs here.
	BaseURL string
	// TokenURL overrides https://login.microsoftonline.com when the
	// caller needs to point at a mock OAuth server.
	TokenURL string
	// ResolveNestedGroups enables transitiveMemberOf queries so
	// users inherit parent-group memberships.
	ResolveNestedGroups bool
}

// HasOutlook reports whether enough fields are set to build an
// Outlook provider.
func (o O365) HasOutlook() bool {
	return o.ClientID != "" && o.ClientSecret != "" && o.TenantID != ""
}

func loadO365() O365 {
	return O365{
		ClientID:     strings.TrimSpace(getStr("O365_CLIENT_ID", "")),
		ClientSecret: getStr("O365_CLIENT_SECRET", ""),
		// TenantID has the same registry-key invariant as
		// GWS.Domain above — trim at the source.
		TenantID:            strings.TrimSpace(getStr("O365_TENANT_ID", "")),
		BaseURL:             getStr("O365_BASE_URL", ""),
		TokenURL:            getStr("O365_TOKEN_URL", ""),
		ResolveNestedGroups: getBool("O365_RESOLVE_NESTED_GROUPS", true),
	}
}

// Zoho holds Zoho Mail API configuration.
//
// Zoho is a multi-data-center cloud — every API endpoint has six
// regional variants. Selecting the right region is non-optional:
// hitting accounts.zoho.com when the tenant lives in accounts.zoho.eu
// returns 401 with no helpful body. DataCenter holds the short region
// code; the package's BaseURL / AccountsURL helpers map it onto the
// correct hostnames.
//
// All fields are optional: when ClientID/ClientSecret/OrgID are not
// all set the Zoho provider is disabled and the action consumers /
// mailbox poller fall back to logging-only mode.
type Zoho struct {
	ClientID     string
	ClientSecret string
	// OrgID is the Zoho Mail organisation ID (an integer rendered as
	// a string), required for /api/organization and /api/users.
	OrgID string
	// Domain is the primary tenant domain (e.g. "example.com").
	// Used as the provider-registry key so a single ZOHO_DOMAIN flows
	// to the MailboxProvider's emitted TenantID.
	Domain string
	// BaseURL overrides the Zoho Mail REST endpoint. Defaults to
	// https://mail.<region>.zoho.<tld> derived from DataCenter.
	BaseURL string
	// AccountsURL overrides the Zoho OAuth accounts endpoint. Defaults
	// to https://accounts.zoho.<tld> derived from DataCenter.
	AccountsURL string
	// DataCenter selects the Zoho data center region. Valid values:
	// "com" (US, default), "eu", "in", "com.au", "com.cn", "jp".
	DataCenter string
	// RefreshToken is the long-lived OAuth refresh token issued by the
	// Zoho API Console for the configured ClientID/ClientSecret. The
	// token source exchanges it for short-lived access tokens.
	RefreshToken string
}

// HasZoho reports whether enough fields are set to build a Zoho
// provider from the boot-time environment. Domain is required for
// the same provider-registry-key invariant as GWS.Domain;
// RefreshToken is required because the env-based path calls
// NewRefreshTokenSource which itself requires a long-lived refresh
// token (the onboarding-token path goes through buildZohoEntryFromToken
// and supplies the access token directly, so this predicate does not
// gate that flow).
func (z Zoho) HasZoho() bool {
	return z.ClientID != "" && z.ClientSecret != "" &&
		z.OrgID != "" && z.Domain != "" && z.RefreshToken != ""
}

// zohoDataCenterOrDefault normalises the operator-supplied data
// centre. Empty / whitespace-only input maps to "com" (US), matching
// the documented default in .env.example. Unknown values are passed
// through (lower-cased) so the *BaseURL helpers can fall through to
// their default switch arm rather than this code silently rewriting
// invalid input.
func zohoDataCenterOrDefault(raw string) string {
	dc := strings.ToLower(strings.TrimSpace(raw))
	if dc == "" {
		return "com"
	}
	return dc
}

func loadZoho() Zoho {
	return Zoho{
		ClientID:     strings.TrimSpace(getStr("ZOHO_CLIENT_ID", "")),
		ClientSecret: getStr("ZOHO_CLIENT_SECRET", ""),
		OrgID:        strings.TrimSpace(getStr("ZOHO_ORG_ID", "")),
		// Domain is the provider-registry key — trim at the
		// source for the same invariant as GWS.Domain.
		Domain:      strings.TrimSpace(getStr("ZOHO_DOMAIN", "")),
		BaseURL:     strings.TrimSpace(getStr("ZOHO_BASE_URL", "")),
		AccountsURL: strings.TrimSpace(getStr("ZOHO_ACCOUNTS_URL", "")),
		// DataCenter defaults to "com" (US) when unset. We
		// normalise here rather than at every consumer so the
		// stored config matches the .env.example documentation
		// and so the provider-init log line reports the
		// effective region rather than an empty string.
		DataCenter:   zohoDataCenterOrDefault(getStr("ZOHO_DATA_CENTER", "")),
		RefreshToken: getStr("ZOHO_REFRESH_TOKEN", ""),
	}
}

// Fastmail holds Fastmail (JMAP) configuration.
//
// Fastmail does not implement OAuth2 for personal/SMB API access; the
// service authenticates with an app-specific password ("API token")
// that the operator generates in the Fastmail settings UI. The token
// carries the JMAP scope and is sent as a Bearer token on every JMAP
// request.
//
// All fields are optional: when APIToken/AccountID are not both set
// the Fastmail provider is disabled.
type Fastmail struct {
	// APIToken is the long-lived bearer token (an app-specific
	// password with JMAP scope) used on every JMAP call.
	APIToken string
	// BaseURL overrides the JMAP session endpoint. Defaults to
	// https://api.fastmail.com.
	BaseURL string
	// AccountID is the Fastmail account identifier used as the
	// accountId argument on JMAP method calls and as the provider-
	// registry key.
	AccountID string
}

// HasFastmail reports whether enough fields are set to build a
// Fastmail provider.
func (f Fastmail) HasFastmail() bool {
	return f.APIToken != "" && f.AccountID != ""
}

func loadFastmail() Fastmail {
	return Fastmail{
		APIToken: getStr("FASTMAIL_API_TOKEN", ""),
		// AccountID is the provider-registry key — trim at
		// the source.
		AccountID: strings.TrimSpace(getStr("FASTMAIL_ACCOUNT_ID", "")),
		BaseURL:   strings.TrimSpace(getStr("FASTMAIL_BASE_URL", "")),
	}
}

// WorkMail holds Amazon WorkMail configuration.
//
// WorkMail authentication is unusual: directory operations use the
// AWS SDK (SigV4 with IAM credentials) while mail operations use EWS
// (Exchange Web Services) over HTTPS with basic auth derived from
// the WorkMail Access Control Rules. SN360-ES uses IAM credentials
// for both code paths; the EWS endpoint signs requests with the same
// credentials.
//
// When AccessKeyID / SecretAccessKey are empty the SDK falls back to
// the default AWS credential chain (env vars, EC2 instance role,
// shared credentials file). This keeps single-binary deployments
// running on EC2/ECS clean.
type WorkMail struct {
	// OrganizationID is the WorkMail organization ID
	// (e.g. m-1234567890abcdef…). Required.
	OrganizationID string
	// Region is the AWS region the WorkMail org lives in
	// (e.g. us-east-1). Required.
	Region string
	// AccessKeyID + SecretAccessKey are the static IAM credentials.
	// When empty, the default AWS credential chain is used.
	AccessKeyID     string
	SecretAccessKey string
	// SessionToken is the optional STS session token paired with a
	// short-lived AccessKeyID/SecretAccessKey set.
	SessionToken string
	// EWSBaseURL is the Exchange Web Services endpoint for WorkMail.
	// When empty, defaults to
	// https://ews.mail.<region>.awsapps.com/EWS/Exchange.asmx.
	EWSBaseURL string
	// WorkMailBaseURL overrides the WorkMail SDK endpoint. Default
	// is the standard https://workmail.<region>.amazonaws.com URL
	// auto-derived from Region.
	WorkMailBaseURL string
}

// HasWorkMail reports whether enough fields are set to build a
// WorkMail provider. OrganizationID also doubles as the provider-
// registry key, so unlike GWS/Zoho there is no separate Domain field.
func (w WorkMail) HasWorkMail() bool {
	return w.OrganizationID != "" && w.Region != ""
}

func loadWorkMail() WorkMail {
	return WorkMail{
		OrganizationID:  strings.TrimSpace(getStr("WORKMAIL_ORGANIZATION_ID", "")),
		Region:          strings.ToLower(strings.TrimSpace(getStr("WORKMAIL_REGION", ""))),
		AccessKeyID:     strings.TrimSpace(getStr("WORKMAIL_ACCESS_KEY_ID", "")),
		SecretAccessKey: getStr("WORKMAIL_SECRET_ACCESS_KEY", ""),
		SessionToken:    getStr("WORKMAIL_SESSION_TOKEN", ""),
		EWSBaseURL:      strings.TrimSpace(getStr("WORKMAIL_EWS_BASE_URL", "")),
		WorkMailBaseURL: strings.TrimSpace(getStr("WORKMAIL_BASE_URL", "")),
	}
}
