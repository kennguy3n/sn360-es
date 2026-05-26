# Tenant Requirements & Setup Guide: SN360-ES on Zoho Mail, Fastmail, and Amazon WorkMail

*The same level of source-of-truth deep-dive we publish for [Gmail and Outlook](./tenant-requirements-gmail-outlook.md), now covering the three additional providers SN360-ES ships native packages for: Zoho Mail, Fastmail (JMAP), and Amazon WorkMail.*

---

## Why a Multi-Provider Deep-Dive?

Email security has historically been a two-vendor world — Google and Microsoft. That covers a large share of the enterprise market, but it leaves three categories underserved:

1. **Zoho Mail** customers — typically India / EU / APAC SMBs and the long tail of self-hosted Zoho One deployments — who do not want a vendor that "supports Zoho" by proxying everything through an IMAP shim.
2. **Fastmail** customers — privacy-conscious teams running on JMAP — for whom a Microsoft Graph-shaped integration is the wrong shape entirely.
3. **Amazon WorkMail** customers — AWS-native shops who already federate identity through IAM and have no appetite for adding a second SAML / OAuth lifecycle just for their email security tool.

SN360-ES treats each provider as a **first-class transport** — a native package under [`pkg/email_provider/`](../pkg/email_provider/) implementing the same six interfaces (`TokenSource`, `DirectoryClient`, `MailboxProvider`, `LabelProvider`, `BannerInjector`, `BodyRewriter`, `QuarantineProvider`) as Gmail and Outlook. There is no proxy, no IMAP scrape, no third-party broker. The privacy boundary documented in the Gmail/Outlook post applies unchanged to all three new providers.

If you are a buyer doing due diligence, jump to the [Summary Capability Matrix](#5-summary-capability-matrix). If you are an engineer onboarding the platform, the per-provider sections below mirror the file layout of the existing Gmail/Outlook deep-dive.

---

## 1. Zoho Mail

### 1.1 What You Provision in Zoho

A Zoho Mail org admin performs a one-time setup in the **Zoho API Console** for the matching data centre:

| Data Centre | API Console | Accounts host | Mail host |
|---|---|---|---|
| `com` (US, default) | https://api-console.zoho.com | `accounts.zoho.com` | `mail.zoho.com/api` |
| `eu` | https://api-console.zoho.eu | `accounts.zoho.eu` | `mail.zoho.eu/api` |
| `in` | https://api-console.zoho.in | `accounts.zoho.in` | `mail.zoho.in/api` |
| `com.au` | https://api-console.zoho.com.au | `accounts.zoho.com.au` | `mail.zoho.com.au/api` |
| `com.cn` | https://api-console.zoho.com.cn | `accounts.zoho.com.cn` | `mail.zoho.com.cn/api` |
| `jp` | https://api-console.zoho.jp | `accounts.zoho.jp` | `mail.zoho.jp/api` |

Choose the data centre that matches where your Zoho Mail tenancy is hosted — Zoho's six DCs are independent, and an `accounts.zoho.com` token will be rejected by `mail.zoho.eu`. The selection wires into [`pkg/email_provider/zoho/client.go`](../pkg/email_provider/zoho/client.go) (`MailBaseURL`) and [`pkg/email_provider/zoho/token_source.go`](../pkg/email_provider/zoho/token_source.go) (`AccountsBaseURL`); both helpers fall back to `com` when `ZOHO_DATA_CENTER` is unset.

In the chosen API console:

1. Create a **Server-based Application**.
2. Configure the redirect URI to match your SN360-ES onboarding callback (`https://api.example.com/v1/onboarding/callback`).
3. Grant the application these scopes:

   | Scope | Why SN360-ES needs it |
   |---|---|
   | `ZohoMail.messages.ALL` | Read, splice banners, and quarantine-move messages via the Mail REST API. |
   | `ZohoMail.folders.ALL` | Create the hidden quarantine folder (`SN360 / Quarantined`) and list inbox folders during ingestion. |
   | `ZohoMail.tags.ALL` | Idempotently provision SN360 verdict tags and apply them to scored messages. |
   | `ZohoMail.accounts.READ` | Resolve the per-user account ID required for `/api/accounts/{accountId}/messages/*` endpoints. |
   | `ZohoMail.organization.READ` | Read the org's `zoid` for post-consent validation and enumerate users/groups for the directory client. |

4. Save the **Client ID** and **Client Secret**.
5. Run the OAuth consent flow once via SN360-ES (`GET /v1/onboarding/start?provider=zoho_mail&tenant_id=<id>`). Zoho will redirect to the callback and SN360-ES will exchange the code for a long-lived **refresh token** — this only works because the onboarding handler sets `access_type=offline` for Zoho ([`internal/service/onboarding/oauth.go`](../internal/service/onboarding/oauth.go) `AuthURL`).
6. Look up the org's `zoid` via `GET https://mail.zoho.<tld>/api/organization` and set `ZOHO_ORG_ID` to match.

### 1.2 What You Hand to SN360-ES

```bash
ZOHO_CLIENT_ID=<from api console>
ZOHO_CLIENT_SECRET=<from api console>
ZOHO_REFRESH_TOKEN=<from /v1/onboarding/start flow, stored encrypted at rest>
ZOHO_ORG_ID=<zoid from /api/organization>
ZOHO_DOMAIN=example.com           # primary mail domain
ZOHO_DATA_CENTER=eu               # one of: com, eu, in, com.au, com.cn, jp
# Optional overrides — used only for tests / air-gapped proxies:
# ZOHO_BASE_URL=
# ZOHO_ACCOUNTS_URL=
```

The full env block lives in [`.env.example`](../.env.example) and is loaded by [`internal/config/config.go`](../internal/config/config.go). `ZOHO_DATA_CENTER` is lower-cased at load time so registry keys can't desync from the canonical hostnames.

### 1.3 How the Token Flow Works at Runtime

Zoho uses a vanilla **OAuth2 refresh-token grant**. SN360-ES's [`RefreshTokenSource`](../pkg/email_provider/zoho/token_source.go) does the following on every API call:

1. If a cached access token is present and has more than 60s of life left, return it.
2. Otherwise `POST` to `{AccountsBaseURL(dc)}/oauth/v2/token` with `grant_type=refresh_token`, `client_id`, `client_secret`, and `refresh_token`.
3. Cache the returned access token with `now + expires_in - 60s` and return it.

The 60s pre-expiry refresh is the same safety margin used by Outlook's `ClientCredentialsSource` and Gmail's JWT bearer — it prevents the rare race where a token expires mid-flight on a long-running API call. Refresh tokens are persisted via the same encrypted `TokenStore` interface used by Microsoft, so a Zoho rotation is a one-line `Save` against the existing storage.

### 1.4 Capability Matrix

| Capability | How SN360-ES does it | File |
|---|---|---|
| Labeling | Zoho Mail Tags API. `EnsureLabel` is idempotent — checks `GET /api/tags`, falls back to `POST /api/tags`, caches the tag ID per name. | [`pkg/email_provider/zoho/label_provider.go`](../pkg/email_provider/zoho/label_provider.go) |
| Banner injection | Direct body PATCH via `PUT /api/accounts/{aid}/messages/{mid}`. Same mutate-in-place pattern as Outlook (no shadow copy needed). | [`pkg/email_provider/zoho/banner_injector.go`](../pkg/email_provider/zoho/banner_injector.go) |
| URL rewriting | The provider-agnostic action consumer rewrites links in the HTML body before calling `BannerInjector`/`BodyRewriter`; the body is then PUT back. | [`pkg/email_provider/zoho/body_rewriter.go`](../pkg/email_provider/zoho/body_rewriter.go) |
| Quarantine | Hidden `SN360 / Quarantined` folder created via `POST /api/accounts/{aid}/folders`; messages moved via `PUT /api/accounts/{aid}/updatemessage` with `moveToFolder`. Default Zoho `Spam` folder is intentionally **not** used (tenant retention policies can destroy messages there). | [`pkg/email_provider/zoho/quarantine_provider.go`](../pkg/email_provider/zoho/quarantine_provider.go) |
| Directory | Zoho Mail Organization API. `ListUsers` paginates `/api/organization/{orgId}/accounts`; `ListGroups` paginates `/api/organization/{orgId}/groups`. Delta sync uses Zoho's `modifiedTime` filter (no native delta state token). | [`pkg/email_provider/zoho/directory_client.go`](../pkg/email_provider/zoho/directory_client.go) |
| Push ingestion | Not used. Zoho's webhook offering is limited and per-account; SN360-ES polls via the same `ingestion.Poller` it uses elsewhere. | [`pkg/email_provider/zoho/mailbox_provider.go`](../pkg/email_provider/zoho/mailbox_provider.go) |
| Delta sync | `modifiedTime` filter on `/api/organization/{orgId}/accounts` — same idea as GWS's `updatedMin`. Falls back to full sync on first run. | (above) |
| Add-ins | Not yet — the `gws-setup-status` analogue for Zoho is the post-consent validator at `validateZoho` ([`internal/service/onboarding/post_consent_validator.go`](../internal/service/onboarding/post_consent_validator.go)). |

### 1.5 Limitations

- **Stricter rate limits.** Zoho's per-minute REST quotas are tighter than Gmail or Graph. SN360-ES's existing circuit breaker + adaptive backoff (configured via `CB_*` env vars) covers this transparently, but high-volume tenants should expect the polling cadence to throttle.
- **No domain-wide delegation analogue.** Every Zoho org needs its own OAuth consent — there is no equivalent of Google's DWD that lets a single service-account JSON cover an arbitrary number of orgs. This is an architectural choice on Zoho's side and applies to every Zoho integration on the market.
- **Tag scoping.** Zoho tags are per-account, not per-org. The label provider provisions the SN360 verdict tags lazily on first apply, so high-fanout broadcast scenarios will see one extra tag-create round trip on the first message to a never-tagged account.

---

## 2. Fastmail (JMAP)

### 2.1 What You Provision in Fastmail

Fastmail is the only provider in SN360-ES today that does **not** use OAuth. Instead it uses **app-specific API tokens** minted by the user.

1. Log in to Fastmail.
2. Go to **Settings → Privacy & Security → Integrations → API tokens**.
3. Create a new token with the **mail** scope (`urn:ietf:params:jmap:core` + `urn:ietf:params:jmap:mail`).
4. Discover your account ID by hitting `GET https://api.fastmail.com/.well-known/jmap` with that token — the response includes the primary account ID under `primaryAccounts."urn:ietf:params:jmap:mail"`.

There is no admin console, no consent flow, and no refresh-token roundtrip. The token is a static bearer, persisted in the same encrypted `TokenStore` used by Gmail / Outlook / Zoho.

### 2.2 What You Hand to SN360-ES

```bash
FASTMAIL_API_TOKEN=<from settings>
FASTMAIL_ACCOUNT_ID=<from /.well-known/jmap>
# Optional override (only useful for tests):
# FASTMAIL_BASE_URL=https://api.fastmail.com
```

### 2.3 How JMAP Works

JMAP ([RFC 8620](https://datatracker.ietf.org/doc/html/rfc8620) / [RFC 8621](https://datatracker.ietf.org/doc/html/rfc8621)) is a fundamentally different shape from REST. The SN360-ES Fastmail client at [`pkg/email_provider/fastmail/jmap_client.go`](../pkg/email_provider/fastmail/jmap_client.go) implements the protocol as follows:

1. **Session discovery.** `GET /.well-known/jmap` with `Authorization: Bearer <token>` returns a `Session` object whose `apiUrl` is the endpoint for all subsequent method calls. The client caches this for the lifetime of the process; Fastmail's session URL is stable.
2. **Method invocations.** Every operation is a `POST {apiUrl}` whose body is a JSON object with `using` (capability URIs) and `methodCalls` — an array of `[methodName, args, callId]` triples. The server returns a parallel `methodResponses` array.
3. **Back-references.** Calls within a single request can reference each other via `#callId` so a single round-trip can do *"query → fetch by query result IDs"* without an extra latency hop. SN360-ES's `FetchNew` uses this for `Email/query` followed by `Email/get` in one request.

### 2.4 Capability Matrix

| Capability | How SN360-ES does it | File |
|---|---|---|
| Labeling | JMAP `Mailbox/set` for create (mailboxes are Fastmail's label primitive); `Email/set` with `mailboxIds` for apply/remove. | [`pkg/email_provider/fastmail/label_provider.go`](../pkg/email_provider/fastmail/label_provider.go) |
| Banner injection | **Upload → Import → Destroy** rewrite pattern. JMAP bodies are immutable: the injector downloads the raw RFC822 via `Blob/get`, splices the banner into the parsed MIME tree, uploads the new blob, calls `Email/import` with the original mailbox IDs + keywords, then `Email/set` to destroy the original. Idempotent because SN360-ES doesn't depend on JMAP id stability — the tier-verdict label is the dedup key. | [`pkg/email_provider/fastmail/banner_injector.go`](../pkg/email_provider/fastmail/banner_injector.go) |
| URL rewriting | Shares the upload/import/destroy code path with banner injection — the body rewriter caches the raw RFC822 between `FetchBody` and `WriteBody` so a single recreate covers both edits. | [`pkg/email_provider/fastmail/body_rewriter.go`](../pkg/email_provider/fastmail/body_rewriter.go) |
| Quarantine | Hidden mailbox `SN360 / Quarantined` created via `Mailbox/set` with `role: null`; messages moved via `Email/set` updating `mailboxIds`. | [`pkg/email_provider/fastmail/quarantine_provider.go`](../pkg/email_provider/fastmail/quarantine_provider.go) |
| Directory | `Identity/get` for the configured account. `ListUsers` returns the account's identities mapped to `DiscoveredUser`. `ListGroups` returns empty — Fastmail has no group construct. Delta sync is the JMAP state token from `Identity/changes`. | [`pkg/email_provider/fastmail/directory_client.go`](../pkg/email_provider/fastmail/directory_client.go) |
| Push ingestion | Not yet wired — JMAP supports a server-sent-events `EventSource` endpoint, but SN360-ES currently polls. Pollers run at the same cadence as Gmail/Outlook. | [`pkg/email_provider/fastmail/mailbox_provider.go`](../pkg/email_provider/fastmail/mailbox_provider.go) |
| Delta sync | Native — JMAP `Email/changes` and `Identity/changes` both return server-issued state tokens that the next call can resume from. | (above) |

### 2.5 Limitations

- **No enterprise directory.** Fastmail does not have groups, departments, or job titles. The sensitivity classifier — which relies on these signals via the Tier 1 encoder ([`internal/service/agent/sensitivity.go`](../internal/service/agent/sensitivity.go)) — will be running with a thinner feature vector. For SMB tenants this is acceptable; for 500+ seat enterprises it materially hurts classification quality and Fastmail is not recommended as the primary provider.
- **Single-account scope.** Each Fastmail API token is scoped to one account. SN360-ES models a Fastmail "tenant" as a single account in the registry; multi-account orgs would need one token per account.
- **No native body mutation.** The upload/import/destroy pattern means every banner injection or URL rewrite produces a new JMAP message ID. SN360-ES is designed to tolerate this — the dedup happens at the verdict-label layer, not at message-ID identity — but tenants who depend on stable IDs in downstream systems should be aware.

---

## 3. Amazon WorkMail

### 3.1 What You Provision in AWS

WorkMail uses **AWS IAM** for both directory and mail operations — there is no OAuth flow. The setup happens in three places:

1. **WorkMail console.** Note the **Organization ID** and **region** of the WorkMail org. Today WorkMail is available in `us-east-1`, `us-west-2`, and `eu-west-1`.

2. **IAM.** Create an IAM user or role with this minimal policy:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": [
         "workmail:ListUsers",
         "workmail:ListGroups",
         "workmail:DescribeUser",
         "workmail:DescribeGroup",
         "workmail:ListGroupMembers"
       ],
       "Resource": "arn:aws:workmail:<region>:<account>:organization/<org-id>"
     }]
   }
   ```

3. **WorkMail Access Control Rule.** WorkMail's EWS endpoint enforces a separate access-control layer on top of IAM. Add an Allow rule for the IAM identity to impersonate users via EWS:

   - **Effect**: Allow
   - **Protocols**: Web Services (EWS)
   - **Actions**: All
   - **User IDs**: `*` (or a scoped list, in which case SN360-ES is limited to those users)
   - **Impersonation Role**: the IAM identity above

### 3.2 What You Hand to SN360-ES

```bash
WORKMAIL_ORGANIZATION_ID=m-xxxxxxxxxxxxxxxx
WORKMAIL_REGION=us-east-1
# Credentials are optional. When left empty the standard AWS credential
# chain is used (env vars, shared credentials file, EC2/ECS instance
# role). Static credentials below are for environments without an
# instance role:
# WORKMAIL_ACCESS_KEY_ID=
# WORKMAIL_SECRET_ACCESS_KEY=
# Optional EWS override:
# WORKMAIL_EWS_BASE_URL=
```

By default the EWS endpoint is derived as `https://ews.mail.<region>.awsapps.com/EWS/Exchange.asmx` and the JSON API endpoint as `https://workmail.<region>.amazonaws.com` — both implemented in [`pkg/email_provider/workmail/client.go`](../pkg/email_provider/workmail/client.go) and [`pkg/email_provider/workmail/ews_client.go`](../pkg/email_provider/workmail/ews_client.go).

### 3.3 How the Auth Flow Works

SN360-ES signs every WorkMail and EWS request with **SigV4** ([`pkg/email_provider/workmail/sigv4.go`](../pkg/email_provider/workmail/sigv4.go)). The signer is implemented from the stdlib only — no AWS SDK dependency — because the repo had zero AWS SDK imports prior to this provider and we did not want to take on `aws-sdk-go-v2`'s transitive cost for a single service.

- Static credentials come from `WORKMAIL_ACCESS_KEY_ID` / `WORKMAIL_SECRET_ACCESS_KEY`.
- If those are empty, `EnvCredentials` picks up the standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` chain.
- `ChainedCredentials` walks the providers in order so an EC2/ECS instance role transparently works without configuration.

The signer derives the per-request signing key (`AWS4 → date → region → service → "aws4_request"`) and produces a canonical request that AWS validates at the edge. SN360-ES's EWS client adds an `ExchangeImpersonation` SOAP header so per-user calls (FindItem, GetItem, UpdateItem, MoveItem) target the correct mailbox without needing per-user IAM.

### 3.4 Capability Matrix

| Capability | How SN360-ES does it | File |
|---|---|---|
| Labeling | EWS Categories. `UpdateItem` with an `item:Categories` array adds or removes string tags — the same model Outlook uses for native Categories. | [`pkg/email_provider/workmail/label_provider.go`](../pkg/email_provider/workmail/label_provider.go) |
| Banner injection | `UpdateItem` with a `Body` property update. Body is mutable in EWS, so this is a direct PATCH (same shape as Outlook). The injector promotes plain-text bodies to HTML before splicing. | [`pkg/email_provider/workmail/banner_injector.go`](../pkg/email_provider/workmail/banner_injector.go) |
| URL rewriting | `GetItem` to fetch body → rewrite in process → `UpdateItem` to write back. Shares the SOAP envelope builder with the banner injector. | [`pkg/email_provider/workmail/body_rewriter.go`](../pkg/email_provider/workmail/body_rewriter.go) |
| Quarantine | `CreateFolder` to provision `SN360 / Blocked` under the inbox parent; `MoveItem` to relocate messages. The default Junk Email folder is intentionally **not** used — tenant retention policies can destroy junk-folder messages, the same rationale as Outlook. | [`pkg/email_provider/workmail/quarantine_provider.go`](../pkg/email_provider/workmail/quarantine_provider.go) |
| Directory | WorkMail JSON API. `ListUsers` paginates `AWSWorkMail_20171001.ListUsers`; `ListGroups` paginates `ListGroups`. User `State` (ENABLED/DISABLED/DELETED) maps to `IsSuspended`; `UserRole` (USER/RESOURCE/SYSTEM_USER) maps to `IsSharedMailbox`/`IsServiceAccount`. | [`pkg/email_provider/workmail/directory_client.go`](../pkg/email_provider/workmail/directory_client.go) |
| Push ingestion | Not natively supported by EWS. SN360-ES polls. | [`pkg/email_provider/workmail/mailbox_provider.go`](../pkg/email_provider/workmail/mailbox_provider.go) |
| Delta sync | None native — `ListUsers` does not accept a since-time token. SN360-ES does a full directory sync each cycle and the agent diffs against stored state. For mailbox content, EWS `FindItem` with a `DateTimeReceived` restriction does provide incremental fetch. | (above) |

### 3.5 Limitations

- **EWS is SOAP.** Every mail operation is an XML envelope, not JSON. The performance hit relative to Graph/Gmail is small (the wire format is heavier but the round trip count is identical) but the implementation surface is larger; the EWS parser at [`pkg/email_provider/workmail/ews_parse.go`](../pkg/email_provider/workmail/ews_parse.go) handles the parts SN360-ES needs and nothing more.
- **No native push.** WorkMail does not expose push subscriptions of any flavour. The poller's interval is the floor on detection latency. (Gmail and O365 are sub-second on push; WorkMail is whatever you set `INGESTION_INTERVAL` to.)
- **No directory delta.** Re-enumerating the user list every cycle costs O(users / page-size) round-trips. For a 10k-user org the full sync is ~10 page requests; the agent caches the result for the polling interval.
- **Region availability.** WorkMail is currently only available in `us-east-1`, `us-west-2`, `eu-west-1`. Tenants outside those regions cannot use WorkMail and should pick one of the other providers.

---

## 4. Onboarding Behaviour by Provider

| Provider | OAuth consent flow | Refresh token | Post-consent check | Onboarding endpoint |
|---|---|---|---|---|
| Google Workspace | Yes (`google_workspace`) | Yes (service-account JWT) | Admin SDK `/users?maxResults=1` | `GET /v1/onboarding/start?provider=google_workspace` |
| Microsoft 365 | Yes (`microsoft_365`) | Yes (client credentials) | Graph `/v1.0/organization` | `GET /v1/onboarding/start?provider=microsoft_365` |
| Zoho Mail | Yes (`zoho_mail`) | Yes (offline refresh token) | `/api/organization` (zoid match) | `GET /v1/onboarding/start?provider=zoho_mail` |
| Fastmail | **No** — static API token | n/a | Confirmed by first JMAP call | `AuthURL` returns an explicit error; configure via env only |
| Amazon WorkMail | **No** — AWS IAM | n/a | Confirmed by first SigV4 API call | `AuthURL` returns an explicit error; configure via env / IAM role |

Fastmail and WorkMail intentionally short-circuit `AuthURL` with an error message that explains why no consent URL is produced — the onboarding handler relays this to the operator, so an attempt to onboard them through the OAuth flow fails fast rather than silently. See [`internal/service/onboarding/oauth.go`](../internal/service/onboarding/oauth.go) `AuthURL`.

---

## 5. Summary Capability Matrix

| Capability | Gmail | Outlook | Zoho Mail | Fastmail | WorkMail |
|---|---|---|---|---|---|
| **Auth model** | Service account + DWD | OAuth2 client credentials | OAuth2 refresh token | Static API token | AWS IAM (SigV4) |
| **Per-tenant onboarding** | Single SA, multi-tenant | OAuth per tenant | OAuth per tenant | Token per account | IAM identity per org |
| **Directory: users** | Admin SDK | Graph `/users` | `/api/organization/{orgId}/accounts` | `Identity/get` (limited) | WorkMail `ListUsers` |
| **Directory: groups** | Admin SDK | Graph `/groups` | `/api/organization/{orgId}/groups` | — (no groups) | WorkMail `ListGroups` |
| **Directory: delta sync** | `updatedMin` | `delta` token | `modifiedTime` filter | JMAP state token | Full sync each cycle |
| **Mail scopes** | `gmail.modify` | `Mail.ReadWrite` | `ZohoMail.messages.ALL` | `urn:ietf:params:jmap:mail` | EWS via ACL rule |
| **Labeling** | Gmail labels | Categories | Tags | Mailboxes-as-labels | Categories |
| **Banner injection** | Shadow-copy (import + trash) | Direct PATCH | Direct PUT | Upload/import/destroy | Direct EWS UpdateItem |
| **URL rewriting** | Same as banner | Same as banner | Same as banner | Same as banner | Same as banner |
| **Quarantine** | Hidden Gmail label + filter | Hidden Outlook folder | Hidden Zoho folder | Hidden JMAP mailbox | Hidden EWS folder |
| **Default Spam/Junk folder?** | **No** | **No** | **No** | **No** | **No** |
| **Push ingestion** | Pub/Sub | Graph subscriptions | Polling | Polling (JMAP EventSource possible) | Polling |
| **Add-ins / UX surface** | (planned) | (planned) | — | — | — |

The "default folder = no" row is deliberate and uniform: tenant retention policies on `Spam` / `Junk Email` can destroy quarantined messages without warning. Every SN360-ES provider provisions a dedicated `SN360 / Quarantined` (or `SN360 / Blocked` for WorkMail) folder that is opt-in to tenant retention.

---

## 6. Privacy Architecture (Unchanged)

The provider is a **transport layer** — the privacy boundary is the same for all five providers and is documented in the [Gmail/Outlook deep-dive](./tenant-requirements-gmail-outlook.md#7-the-privacy-boundary-end-to-end). Specifically:

1. **Pseudonymization at the edge.** Email addresses, message IDs, and URLs are Blake2b-keyed before they touch any persistent store. See [`pkg/privacy/pseudonymize.go`](../pkg/privacy/pseudonymize.go).
2. **AES-256-GCM envelope encryption.** Anything that needs to survive a process restart (quarantine ciphertext, decrypted URL state, tenant-scoped config) is encrypted under a per-tenant KMS data key. See [`pkg/privacy/encryptor.go`](../pkg/privacy/encryptor.go).
3. **Zero-knowledge evaluation.** Tier 1 and Tier 2 evaluators receive pseudonymized features only; the cleartext body lives in the provider call's goroutine and is dropped on return.

When you add Zoho, Fastmail, or WorkMail to SN360-ES, none of this changes. The new provider packages call the same `privacy.Sanitizer` and the same `privacy.Encryptor` as Gmail and Outlook. The same auditor-friendly statement applies: *"every byte of customer mail that enters SN360-ES is either dropped at goroutine exit, hashed before it touches disk, or encrypted under a key the customer can destroy at will."*

---

## 7. Closing — One Platform, Five Providers

For a **buyer**: SN360-ES now meets you wherever your mail lives — Google, Microsoft, Zoho, Fastmail, or Amazon. Every connector ships with the same privacy boundary, the same provider abstraction, and the same minimal-scope footprint.

For an **operator**: any of the five providers connects through the same `GET /v1/onboarding/*` surface, with the two non-OAuth providers (Fastmail, WorkMail) explicitly documented as env-only — no second-class behaviour, no hidden caveats.

For a **builder**: the seam is `pkg/email_provider/<name>/`. Each new package implements six interfaces, plugs into [`cmd/sn360-es/providers.go`](../cmd/sn360-es/providers.go) via a `buildXEntry` function, and inherits the same privacy facade. The five packages in the repo today are the working reference for a sixth.

If you want the long-form on Gmail and Outlook, that is still over in [`blog/tenant-requirements-gmail-outlook.md`](./tenant-requirements-gmail-outlook.md). This post is the equivalent record for the three providers that complete the matrix.
