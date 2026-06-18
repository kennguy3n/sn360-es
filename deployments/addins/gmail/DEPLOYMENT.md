# Gmail (Apps Script) Add-in — Deployment Guide

This guide covers deploying the **sn360 pre-send security warning** Gmail
Apps Script add-in to Google Workspace tenants. It is written so a
non-Devin operator (an IT admin or release engineer) can follow it
without further guidance.

## What this add-in does

The add-in registers a Gmail **compose-time send-disposition trigger**
(`gmail.composeTrigger.onTriggerFunction = sn360PreSendTrigger`) that
fires at compose-render and (more importantly for our use case) at
send-button confirmation when the trigger function returns a card. It
performs three checks (see [the source](src/presend.gs) for the full
implementation):

1. **Recipient risk check** — calls `POST /v1/predict/recipient` with
   SHA-256-hashed recipient addresses and their domains and inspects the
   risk score returned by the backend.
2. **Lookalike domain detection** — runs a Damerau-Levenshtein (OSA)
   distance ≤ 2 comparison between each recipient's domain and the
   user's cached set of known domains (sender + previously-seen,
   non-flagged recipients).
3. **External-thread-going-external** — if the current Gmail thread has
   been internal-only and the user is adding an external recipient,
   surface a warning. Thread participants are fetched via
   `Gmail.Users.Threads.get(METADATA)` from the advanced Gmail service.

If any check fires at level ≥ 3, the add-in returns a branded `Card`
that leads with a plain-language headline (what's risky), a colored
severity label and a one-line "why it matters", and the single safe
action to take. The user confirms before the send proceeds. See
**Branding & warning UX** below.

## Branding & warning UX (ShieldNet 360)

The warning surfaces follow the ShieldNet 360 brand and plain-language
voice (implemented in [`src/presend.gs`](src/presend.gs) and
[`src/preopen.gs`](src/preopen.gs)):

- **One message taxonomy, shared with Outlook.** Pre-send and pre-open
  warnings use the same 25-key localized bundle and the same severity
  ramp, so a given risk reads identically in Gmail and Outlook.
- **Plain language, no jargon.** Cards say what's risky, why it matters,
  and the one safe action — never internal codes, tiers, or categories.
- **Severity ramp** (brand tokens): critical `#e40014`, high `#ff6900`,
  medium `#edb200`, low/info `#255fe5`, rendered as a colored severity
  label inside the card body.
- **14 locales, RTL-correct.** All copy is keyed; `ar` renders
  right-to-left.

### Gmail CardService styling limits (documented)

CardService is intentionally constrained — an add-on cannot ship custom
CSS, web fonts, or arbitrary colors the way an Office.js task pane can.
We match the brand within those limits:

| Brand element | Gmail support | What we do |
|---|---|---|
| Logo | ✅ `logoUrl` in `appsscript.json` | ShieldNet 360 mark (`https://shieldnet360.com/icon.png`). |
| Severity colors | ⚠️ inline `<font color>` only | Severity label colored with the brand token via `<font color="…">`. |
| Brand-blue primary action | ⚠️ `TextButton` only | Action is a `TextButton`; Google controls the exact button chrome (it cannot be a filled brand-blue button). |
| Noto Sans typeface | ❌ not configurable | Cards render in Google's card font. This is a platform limit, not a brand deviation. |
| Custom layout / spacing | ❌ fixed | Card header + text paragraphs + text button only. |

## Performance budget

Gmail compose-time triggers have a soft **30-second** execution-quota
window (Apps Script script-runtime quotas are 6 minutes total per
execution, but Gmail enforces a UI-responsiveness budget closer to 30 s
before the compose UI gives up on the trigger response). Our internal
budget:

| Stage                              | p95 target |
|------------------------------------|------------|
| `Gmail.Users.Threads.get` (METADATA)| < 200 ms   |
| `UrlFetchApp.fetch('/v1/predict/recipient')` | < 400 ms (Apps Script's UrlFetchApp has a 60 s ceiling — we don't extend it) |
| Damerau-Levenshtein on ≤ 50 known domains | < 5 ms |
| Total trigger                       | < 1 s p95  |

The handler fails open on any thrown exception so transient backend
errors never block legitimate sends.

## Prerequisites

- A **Google Workspace** organization with **Marketplace allowlist /
  install authority** access (Super Admin, or a Marketplace App
  Administrator).
- A **Google Cloud project** that will host the Apps Script deployment
  artifact (the same project Apps Script publishes the add-in from).
- A backend endpoint reachable from end-user browsers at
  `https://api.<your-tenant>.example.com/v1/predict/recipient`. Set
  `API_BASE_URL` in `src/presend.gs` accordingly before deployment.
- `clasp` CLI installed locally (`npm install -g @google/clasp`) and
  signed in as the release engineer's account.

## OAuth scopes

The add-in requests the following scopes (declared in
[`appsscript.json`](appsscript.json)). Justification per scope:

| Scope | Why |
|-------|-----|
| `https://www.googleapis.com/auth/script.locale` | Reads the user's locale so warnings render in their language fallback. |
| `https://www.googleapis.com/auth/gmail.addons.execute` | Required by every Gmail compose trigger. |
| `https://www.googleapis.com/auth/script.external_request` | Required for `UrlFetchApp.fetch('/v1/predict/recipient')`. |
| `https://www.googleapis.com/auth/userinfo.email` | Read the sender's email so the recipient-risk request body carries an authenticated `sender_domain`. |
| `https://www.googleapis.com/auth/gmail.readonly` | Read **thread metadata** (From / To / Cc / Bcc headers) to compute the external-thread-going-external check. We never read message bodies. |
| `https://www.googleapis.com/auth/gmail.addons.current.message.readonly` | Read the headers of the current compose draft (recipients) from inside the trigger context. |

The Marketplace verification process (Step 5 below) requires a
**Sensitive Scope Justification** for `gmail.readonly`. The text used
in our submission is in
`deployments/addins/gmail/OAUTH_VERIFICATION_JUSTIFICATION.md` (kept out
of this guide because it's tenant-specific marketing copy).

## Step 1 — Validate the manifest locally

`clasp` validates the manifest on every `clasp push`:

```bash
cd deployments/addins/gmail/
clasp login
clasp push
```

A clean push reports:

```
└─ src/presend.gs
└─ appsscript.json
Pushed 2 files.
```

Errors here are typically scope or `runtimeVersion` problems and will
also block Marketplace submission. The repo's `clasp.json` (created by
`clasp create` once per environment) is intentionally **not** committed:
the script ID is tenant-specific.

## Step 2 — Initial project creation (one-time per environment)

```bash
cd deployments/addins/gmail/
clasp login                        # signs into the GCP project that
                                   # will host the script
clasp create --type standalone --title "sn360 Pre-Send Security"
# → writes ./clasp.json with the new script ID
clasp push                         # uploads appsscript.json + src/
```

The created Apps Script project is bound to a Google Cloud project. If
you intend to publish via the Marketplace, attach the script to the
**same** GCP project that owns your OAuth client configuration:

1. In the Apps Script editor (open via the URL `clasp open` prints),
   click **Project Settings → Google Cloud Platform (GCP) Project →
   Change project** and paste the GCP project number.

## Step 3 — Internal install (smoke test)

Inside the Apps Script editor:

1. Click **Deploy → Test deployments → Application(s): Gmail Add-on →
   Install**. This installs the trigger into the release engineer's
   own mailbox.
2. Open Gmail, compose a new mail, add a recipient. The compose trigger
   renders the add-in pane.
3. Click Send. The pre-send trigger should fire. Watch the **Apps
   Script → Executions** tab for the function invocation log.

If the trigger fails to fire:
- Verify `appsscript.json` declares `gmail.composeTrigger.onTriggerFunction`
  (currently `sn360PreSendTrigger`).
- Verify the user has consented to all OAuth scopes (Apps Script will
  re-prompt on scope changes).

## Step 4 — Production install via the Google Workspace Marketplace

Marketplace publishing is the **supported path** for tenant-wide
rollouts. The flow:

1. Open the **Google Cloud Console** at
   https://console.cloud.google.com → select the GCP project bound to
   the script.
2. Navigate to **APIs & Services → Marketplace SDK** (enable it once if
   needed).
3. Open **APP CONFIGURATION** and fill out:
   - **App name**, **Description**, **Detailed description**, **Category**.
   - **Application URL**: link to your privacy / overview page.
   - **OAuth scopes**: should exactly match `appsscript.json`. If the
     Marketplace SDK detects a mismatch the submission is rejected.
   - **Apps Script deployment ID**: from `Deploy → New deployment →
     Add-on` in the Apps Script editor.
4. Open **STORE LISTING** and provide:
   - **Logo** (96 × 96 PNG, transparent background).
   - **Banner** (220 × 140 PNG).
   - **Screenshots** (3-5, 1280 × 800 PNG showing the warning card).
   - **Terms of Service**, **Privacy Policy** (the privacy policy must
     explicitly document that recipients are SHA-256 hashed and that
     domains are sent in cleartext).
   - **Support email**.
5. Open **PUBLISH** → set distribution to **Public** (Marketplace
   listing) or **Internal** (only members of your Workspace
   organization). For an internal rollout select **Internal** and
   you can skip the verification steps below.

## Step 5 — OAuth verification (Public listings only)

If you select **Public** in Step 4 and your scope set includes
`gmail.readonly`, Google requires an **OAuth verification**:

1. Submit at https://console.cloud.google.com/apis/credentials/consent.
2. Provide:
   - **App information**: name, support email, dev contact email.
   - **Authorized domains**: the apex domain hosting your privacy &
     ToS URLs.
   - **Scopes**: select the same scopes from `appsscript.json`.
   - **Sensitive Scope Justification**: a 200-500 word explanation of
     why your app reads gmail metadata. The contents of
     `OAUTH_VERIFICATION_JUSTIFICATION.md` (kept out of the public repo,
     stored in the release engineer's password vault) is the template.
   - **Demo video**: a 1-3 minute screen recording showing the
     add-in operating on a clean test account. Upload to YouTube
     **Unlisted**.
   - **Privacy policy** & **Terms of Service** URLs.
3. Submit. Google's verification takes **4-6 weeks** for sensitive
   scopes; expect ≥ 1 round of feedback.
4. After verification, return to the Marketplace SDK → **PUBLISH** →
   click **Publish**. The listing goes live within 24 hours.

## Step 6 — Domain-wide install (Workspace admin)

For your **own** Workspace organization, the admin can install the
add-in to every user without going through public Marketplace
verification:

1. Sign in to the **Google Admin Console** at
   https://admin.google.com.
2. Navigate to **Apps → Google Workspace Marketplace apps**.
3. Click **Add app → Search apps**. Search by the Marketplace listing
   name (Step 4) or paste the internal listing URL.
4. Click **Domain install** and select either:
   - **Anyone at <org>** (default).
   - A specific Organizational Unit (OU) — useful for a pilot rollout
     to the `Security/` OU first.
5. Approve the OAuth scopes on behalf of the organization. Once
   approved, the add-in is installed for every user in the target OU
   within a few minutes.

End users will see the add-in in the right-hand rail of their Gmail
compose pane. The pre-send trigger fires automatically on Send — no
per-user setup required.

## Step 7 — Verification

On a pilot user's account:

1. Compose a new mail to an internal recipient and Send. Expected: no
   card.
2. Compose a mail to a known-suspicious recipient set up by the
   `/v1/predict/recipient` test fixture. Expected: the user sees an
   "sn360: pre-send security check" card and the send is held until
   they acknowledge.
3. From the Apps Script editor open **Executions** and confirm the
   trigger ran and completed. There should be no quota or scope errors.

## Telemetry

- Per-user activations: **Apps Script → Executions** filter by function
  name `sn360PreSendTrigger`.
- Backend telemetry: as with Outlook, captured on the
  `/v1/predict/recipient` server side — see the sn360 dashboards.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| User sees no card on a known-bad recipient | Add-on not installed for that user / OU | Confirm in **Admin Console → Marketplace apps**; reinstall on the user's OU. |
| Card appears but Send proceeds anyway | The trigger returned an empty card array, or threw and was caught | Open **Apps Script → Executions**; investigate the most recent invocation for that user. |
| All sends are silently fast-failing | The trigger is throwing during fetch | Check `UrlFetchApp.fetch` errors in Executions; confirm `/v1/predict/recipient` is reachable from Google's egress (IP allowlist on the API gateway). |
| Trigger never fires | Compose trigger function name mismatch | Confirm `onTriggerFunction: sn360PreSendTrigger` in `appsscript.json` exactly matches the exported function name. |
| Marketplace submission rejected on scopes | `gmail.readonly` justification too thin | Expand the **Sensitive Scope Justification** with the headers-only narrative; emphasize we never read bodies. |

## Source-of-truth references

- Gmail add-on compose trigger:
  https://developers.google.com/workspace/add-ons/concepts/gmail-triggers
- Gmail send-time validation pattern:
  https://developers.google.com/workspace/add-ons/concepts/email-validation
- `CardService` API:
  https://developers.google.com/apps-script/reference/card-service
- Advanced Gmail service `Users.threads.get`:
  https://developers.google.com/gmail/api/reference/rest/v1/users.threads/get
- Workspace Marketplace SDK overview:
  https://developers.google.com/workspace/marketplace/overview
- OAuth verification for sensitive scopes:
  https://support.google.com/cloud/answer/9110914
