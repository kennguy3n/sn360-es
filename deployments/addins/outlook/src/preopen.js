/*
 * SN360 Outlook Pre-Open Add-in
 *
 * Calls /v1/predict/open with the message's pseudonymised ID + tier as
 * exported by the SN360 banner injector. For Warning+ tier messages we
 * render an "Are you sure?" infobar before the user reads the body.
 */
/* global Office, fetch */
(function () {
  "use strict";

  const API_BASE = (typeof window !== "undefined" && window.SN360_API_BASE) || "https://api.sn360.example.com";
  const TIMEOUT_MS = 250;

  function tenantId() {
    // Mirror the Gmail add-on: tenant ID is derived from the user's
    // email domain so cross-platform analytics & caching key by the
    // same value regardless of which client the user is on.
    if (typeof Office === "undefined" || !Office.context || !Office.context.mailbox) return "";
    var profile = Office.context.mailbox.userProfile;
    var email = (profile && profile.emailAddress) ? profile.emailAddress : "";
    var at = email.indexOf("@");
    return at < 0 ? "outlook" : email.substring(at + 1).toLowerCase();
  }

  function parseBannerHeader(value) {
    // Format: "tier=<tier>; category=<cat>; pmid=<id>".
    var meta = { tier: "", category: "", pseudo_message_id: "" };
    if (!value) return meta;
    var parts = String(value).split(";");
    for (var i = 0; i < parts.length; i++) {
      var kv = parts[i].split("=");
      if (kv.length !== 2) continue;
      var key = kv[0].trim().toLowerCase();
      var val = kv[1].trim();
      if (key === "tier") meta.tier = val;
      else if (key === "category") meta.category = val;
      else if (key === "pmid") meta.pseudo_message_id = val;
    }
    return meta;
  }

  function readBannerMeta(item) {
    // The banner injector embeds (tier, category, pseudo_message_id)
    // in an X-SN360-Banner internet header. The add-in surfaces it
    // via the Office.js InternetHeaders API (requires MailboxEnums
    // Mailbox 1.8+; the manifest sets MinimumVersion=1.8).
    return new Promise((resolve) => {
      try {
        if (!item || !item.internetHeaders || typeof item.internetHeaders.getAsync !== "function") {
          return resolve(null);
        }
        item.internetHeaders.getAsync(["x-sn360-banner"], (res) => {
          if (!res || res.status !== "succeeded" || !res.value) return resolve(null);
          var raw = res.value["x-sn360-banner"] || res.value["X-SN360-Banner"];
          if (!raw) return resolve(null);
          resolve(parseBannerHeader(raw));
        });
      } catch (_) {
        resolve(null);
      }
    });
  }

  async function callPredictOpen(req) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const r = await fetch(API_BASE + "/v1/predict/open", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
        signal: controller.signal,
      });
      if (!r.ok) return { show_warning: false };
      return await r.json();
    } catch (_) {
      return { show_warning: false };
    } finally {
      clearTimeout(timer);
    }
  }

  function presentWarning(eventArgs, resp) {
    if (!resp || !resp.show_warning) {
      if (eventArgs && eventArgs.completed) eventArgs.completed();
      return;
    }
    try {
      Office.context.mailbox.item.notificationMessages.replaceAsync("sn360-preopen", {
        type: Office.MailboxEnums.ItemNotificationMessageType.InformationalMessage,
        message: "SN360: " + (resp.message || "This message has been flagged. Open with care."),
        icon: "icon-color",
        persistent: true,
      });
    } catch (_) {
      // Best-effort UI.
    }
    if (eventArgs && eventArgs.completed) eventArgs.completed();
  }

  async function onMessageRead(eventArgs) {
    try {
      const item = Office.context.mailbox.item;
      const meta = await readBannerMeta(item);
      if (!meta || !meta.pseudo_message_id) {
        eventArgs.completed();
        return;
      }
      const resp = await callPredictOpen({
        tenant_id: tenantId(),
        pseudo_message_id: meta.pseudo_message_id,
        tier: meta.tier || "",
        category: meta.category || "",
      });
      presentWarning(eventArgs, resp);
    } catch (_) {
      eventArgs.completed();
    }
  }

  if (typeof Office !== "undefined" && Office.actions) {
    Office.actions.associate("sn360-on-message-read", onMessageRead);
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { presentWarning };
  }
})();
