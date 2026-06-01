# Outlook (Office.js) Add-in — Deployment Guide

This guide covers deploying the **sn360 pre-send security warning** Office.js
add-in to Microsoft 365 tenants. It is intentionally written so a non-Devin
operator (an IT admin or release engineer) can follow it without further
guidance.

## What this add-in does

The add-in registers an **on-send event handler** (`messageSending`) that
runs in the user's mailbox at the moment they click Send. It performs three
checks (see [the source](src/presend.js) for the full implementation):

1. **Recipient risk check** — calls `POST /v1/predict/recipient` with
   SHA-256-hashed recipient addresses and their domains and inspects the
   risk score returned by the backend.
2. **Lookalike domain detection** — runs a Damerau-Levenshtein (OSA)
   distance ≤ 2 comparison between each recipient's domain and the user's
   cached set of known domains (sender + previously-seen, non-flagged
   recipients).
3. **External-thread-going-external** — if the current conversation has been
   internal-only and the user is adding an external recipient, surface a
   warning.

If any check fires at level ≥ 3 (WarnWarning tier), the user sees an
`InsightMessage` notification and the send is held up until they
acknowledge.

## Performance budget

Office.js pre-send handlers must complete within **30 seconds** (Office's
hard timeout — exceeding it causes the send to be permitted with no
warning). Our internal budget:

| Stage                              | p95 target |
|------------------------------------|------------|
| Recipient gather + cache lookup    | < 50 ms    |
| `POST /v1/predict/recipient` round-trip | < 250 ms (with `AbortController` at 250 ms) |
| Damerau-Levenshtein on ≤ 50 known domains | < 5 ms |
| Total handler                       | < 1 s p95  |

The 250 ms fetch timeout is hard-coded in `presend.js` (`FETCH_TIMEOUT_MS`)
and the handler fails open on any error to preserve user productivity.

## Prerequisites

- Microsoft 365 tenant with **Microsoft 365 Admin Center** access (Global
  Admin or Exchange Admin role).
- HTTPS-served add-in assets at a stable, publicly reachable URL. We deploy
  the static manifest assets behind the same CDN that fronts the sn360 web
  client; for self-hosted tenants, any HTTPS bucket (Azure Blob + Front
  Door, S3 + CloudFront) works.
- A backend endpoint reachable from end-user browsers at
  `https://api.<your-tenant>.example.com/v1/predict/recipient`. Update
  `API_BASE_URL` in `src/presend.js` accordingly OR set it via the
  manifest's `WebApplicationInfo` / runtime config before publishing.
- Outlook clients on **Mailbox 1.11+** (covers Outlook 2019, Outlook for
  Microsoft 365 build 16.0.13127+, Outlook on the web, Outlook for
  Mac 16.32+, and Outlook mobile that supports unified manifest). Older
  builds will silently skip the add-in.

## Step 1 — Validate the manifest

Run the official validator before every release:

```bash
npm install --global office-addin-manifest
office-addin-manifest validate deployments/addins/outlook/manifest.json
```

A clean run prints:

```
The manifest is valid.
```

`office-addin-manifest` is the manifest linter Microsoft ships and uses
inside Partner Center. Failures here will be rejected by the M365 Admin
Center upload.

> NOTE — the manifest you have today is the legacy XML manifest. If you are
> targeting **Outlook on Windows ≥ Version 2304** *and* want to ship via
> AppSource, convert to the unified-manifest JSON form using
> `office-addin-manifest convert`. The handler code in `src/presend.js` is
> manifest-format-agnostic.

## Step 2 — Host the manifest + assets

Upload the manifest and accompanying assets (`src/`, any icons referenced
by `<IconUrl>` etc.) to HTTPS storage. The manifest references absolute
URLs — every `<SourceLocation>`, `<bt:Url>`, icon, and runtime URL must
resolve.

Quick smoke test:

```bash
curl -fsSI https://addins.<your-tenant>.example.com/outlook/presend.js
# HTTP/2 200
```

A 404 here ⇒ the on-send handler will not load and the warning will be
silently skipped.

## Step 3 — Centralized deployment via the M365 Admin Center

Centralized Deployment (the supported path for tenant-wide rollouts) lets
you push the add-in to specific users / groups without manual sideload.

1. Sign in to the **Microsoft 365 Admin Center**
   (https://admin.microsoft.com).
2. Navigate to **Settings → Integrated apps**.
3. Click **Upload custom apps → Provide link to manifest file** and paste
   the URL of your uploaded `manifest.json`.
4. On the **Users** page, choose:
   - **Just me** (smoke-test on the release engineer's account first).
   - **Specific users / groups** (recommended for staged rollouts; bind
     to a Microsoft 365 Group like `sn360-pilot`).
   - **Entire organization** (only after a successful pilot).
5. Review the requested permissions:
   - `ReadWriteMailbox` (required to read the draft and surface
     notifications).
6. Click **Finish deployment**. Microsoft propagates the assignment to
   target mailboxes within 6 hours (sometimes < 1 hour for small tenants).

Pre-send handlers are a **per-mailbox** feature: as soon as the assignment
reaches a mailbox, the next Send click will run our handler.

## Step 4 — Verification

On a pilot user's mailbox:

1. Compose a new mail to an internal recipient and Send. Expected: no
   warning (recipient risk = 0, lookalike check passes, thread baseline
   trivially internal).
2. Compose a mail to a known-suspicious recipient set up by the
   `/v1/predict/recipient` test fixture (the backend has a test tenant
   that always returns `overall_level: 4`). Expected: the user sees an
   "Outlook security check" notification and the send is held until
   they acknowledge.
3. Open Edge / Chrome devtools attached to Outlook on the web
   (`F12 → Sources`) and confirm `presend.js` is loaded; no JS errors
   should be logged.

If verification fails, see [Troubleshooting](#troubleshooting).

## Step 5 — Telemetry

The add-in is intentionally chatty in the M365 add-in telemetry channel.
Open **Microsoft 365 Admin Center → Integrated apps → Usage** to see
per-user activations. Backend telemetry is captured on the
`/v1/predict/recipient` server side — see the sn360 dashboards for the
warning-emission and false-positive-rate panels.

## Step 6 — Partner Center submission checklist (AppSource)

If you intend to publish to **AppSource** rather than only sideload, you
must additionally:

- [ ] Sign in to **Partner Center**
  (https://partner.microsoft.com/dashboard/marketplace-offers).
- [ ] Create / select the **Office Add-in** offer.
- [ ] Upload the validated manifest (Step 1 must already be green).
- [ ] Provide marketing assets: 48 × 48, 64 × 64, 80 × 80, 128 × 128 PNG
  icons (we keep masters under `deployments/addins/outlook/assets/`).
- [ ] Provide a **Privacy URL** (the recipient hashing implementation is
  documented in [`src/presend.js`](src/presend.js) — link to the public
  privacy page that explains we send SHA-256 hashes, never raw emails,
  and that domains are sent in cleartext as non-PII routing context).
- [ ] Provide a **Support URL** (typically your support portal /
  `mailto:` for low-volume tenants).
- [ ] Provide **Terms of Use** for the add-in.
- [ ] Complete the **App Compliance Program** questionnaire (Microsoft
  prefers EM+S / Microsoft 365 Certification, but Publisher Attestation
  is enough for an initial release).
- [ ] Pass Microsoft's **store validation** (the same `office-addin-manifest
  validate` is run in their pipeline plus a runtime smoke test).
- [ ] Once approved, the offer moves to "Live" within 24-72 hours.

## Manifest changes & version bumps

Every change to `manifest.json` (adding a new on-send event, raising the
`MinVersion`, changing a `<SourceLocation>` URL) requires a version bump
in `<Version>x.y.z</Version>` and a new Centralized Deployment upload.
Outlook caches manifests per-mailbox by version; the cache will not
refresh otherwise.

This add-in's manifest is **1.1.0** today. The pre-send event handler
requires Mailbox 1.11; older mailboxes silently skip the event but the
add-in continues to load.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| User sees no warning on a known-bad recipient | Manifest not deployed to that mailbox, or Outlook mailbox version < 1.11 | Check **Integrated apps → Users**; confirm the user is in the deployment target. Check the user's Outlook build (`File → Office Account → About`). |
| Warning appears but the send completes anyway | `sendMode: "promptUser"` is misconfigured — Outlook treats unknown modes as "soft warn" | Confirm `<Event Type="MessageSending" SendMode="PromptUser" />` (or the `sendMode` extension property) in `manifest.json`. |
| All sends are silently fast-failing | The handler is hitting an exception path | Open browser devtools attached to Outlook on the web and watch the console; check the `/v1/predict/recipient` endpoint is reachable from the user's network. |
| `/v1/predict/recipient` returns 401 | Tenant context not propagating | Add-in passes the tenant via the Office identity token header — confirm Exchange has issued an identity token to the add-in for that user. |
| Manifest upload rejected | Asset URL not HTTPS or manifest XSD violation | Re-run `office-addin-manifest validate`; ensure all URLs are HTTPS and absolute. |

## Source-of-truth references

- Pre-send event flow & event arg shape:
  https://learn.microsoft.com/en-us/office/dev/add-ins/outlook/smart-alerts-onmessagesend-walkthrough
- Mailbox requirement set 1.11:
  https://learn.microsoft.com/en-us/javascript/api/requirement-sets/outlook/requirement-set-1.11/outlook-requirement-set-1.11
- `notificationMessages` API:
  https://learn.microsoft.com/en-us/javascript/api/outlook/office.notificationmessages
- Centralized Deployment admin guide:
  https://learn.microsoft.com/en-us/microsoft-365/admin/manage/manage-deployment-of-add-ins
- Partner Center submission overview:
  https://learn.microsoft.com/en-us/office/dev/store/submit-to-appsource-via-partner-center
