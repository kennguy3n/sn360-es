/*
 * SN360 Outlook Pre-Send Add-in
 *
 * Wires the messageSending and messageRecipientsChanged events to the
 * SN360 /v1/predict/recipient endpoint. Recipient addresses are
 * pseudonymised via a SHA-256 of (tenant|lowercased-email) before
 * leaving the mailbox, so no raw PII is sent to the predict service.
 */
/* global Office, fetch, crypto */
(function () {
  "use strict";

  const API_BASE = (typeof window !== "undefined" && window.SN360_API_BASE) || "https://api.sn360.example.com";
  const TIMEOUT_MS = 250;

  function tenantId() {
    if (typeof Office === "undefined" || !Office.context || !Office.context.mailbox) return "";
    var profile = Office.context.mailbox.userProfile;
    var email = (profile && profile.emailAddress) ? profile.emailAddress : "";
    var at = email.indexOf("@");
    return at < 0 ? "outlook" : email.substring(at + 1).toLowerCase();
  }

  function senderEmail() {
    if (typeof Office === "undefined" || !Office.context || !Office.context.mailbox) return "";
    var profile = Office.context.mailbox.userProfile;
    return (profile && profile.emailAddress) ? profile.emailAddress : "";
  }

  async function sha256Hex(str) {
    const buf = new TextEncoder().encode(str);
    const hash = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  async function hashRecipient(tenant, email) {
    return sha256Hex(tenant + "|" + (email || "").toLowerCase().trim());
  }

  function domainOf(email) {
    if (!email) return "";
    const at = email.indexOf("@");
    return at < 0 ? "" : email.substring(at + 1).toLowerCase();
  }

  async function buildRequest(tenant, sender, recipients, threadIsInternal) {
    const list = [];
    for (const r of recipients) {
      const dom = domainOf(r.emailAddress);
      // is_known_contact is intentionally omitted. Office.js's
      // RecipientObject does not expose contact-store membership, so
      // the previous !!r.isKnownContact always evaluated to false and
      // caused the backend to emit unusual_external_recipient on every
      // external recipient. Let the server fall back to its own
      // contact-store lookup instead.
      list.push({
        user_hash: await hashRecipient(tenant, r.emailAddress),
        domain: dom,
        is_external: r.recipientType !== "Internal",
      });
    }
    const senderKey = (sender || "").toLowerCase().trim();
    return {
      tenant_id: tenant,
      sender_hash: await sha256Hex(tenant + "|" + senderKey),
      recipients: list,
      thread_is_internal: !!threadIsInternal,
    };
  }

  async function callPredict(body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const r = await fetch(API_BASE + "/v1/predict/recipient", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!r.ok) return { overall_level: 0, warnings: [] };
      return await r.json();
    } catch (_) {
      // Fail-open: never block sends on transport errors.
      return { overall_level: 0, warnings: [] };
    } finally {
      clearTimeout(timer);
    }
  }

  function showSendConfirmation(eventArgs, response) {
    if (!response || (response.overall_level || 0) < 3) {
      eventArgs.completed({ allowEvent: true });
      return;
    }
    const top = (response.warnings && response.warnings[0]) || { message: "Suspicious recipient detected." };
    const msg = "SN360 warning: " + top.message + "\n\nSend anyway?";
    Office.context.mailbox.item.notificationMessages.replaceAsync("sn360-presend", {
      type: Office.MailboxEnums.ItemNotificationMessageType.ErrorMessage,
      message: msg,
    });
    // For Manifest v3 smart-alerts the add-in returns sendModeOverride;
    // dialog UX is shown via the smart-alert smartAlertOptions in the
    // manifest. We resolve the event so Outlook can present the dialog.
    eventArgs.completed({ allowEvent: false });
  }

  async function onMessageSend(eventArgs) {
    try {
      const item = Office.context.mailbox.item;
      const toResult = await new Promise((resolve) => item.to.getAsync(resolve));
      const ccResult = await new Promise((resolve) => item.cc.getAsync(resolve));
      const recipients = (toResult.value || []).concat(ccResult.value || []);
      if (!recipients.length) {
        eventArgs.completed({ allowEvent: true });
        return;
      }
      const body = await buildRequest(tenantId(), senderEmail(), recipients, false);
      const resp = await callPredict(body);
      showSendConfirmation(eventArgs, resp);
    } catch (err) {
      // Fail-open on any unexpected error.
      eventArgs.completed({ allowEvent: true });
    }
  }

  async function onMessageRecipientsChanged(eventArgs) {
    eventArgs.completed();
  }

  if (typeof Office !== "undefined" && Office.actions) {
    Office.actions.associate("sn360-on-message-send", onMessageSend);
    Office.actions.associate("sn360-on-message-recipients-changed", onMessageRecipientsChanged);
  }

  // Exposed for tests.
  if (typeof module !== "undefined" && module.exports) {
    module.exports = { buildRequest, sha256Hex, domainOf };
  }
})();
