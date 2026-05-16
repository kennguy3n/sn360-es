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
    if (typeof Office === "undefined" || !Office.context || !Office.context.mailbox) return "";
    return Office.context.mailbox.diagnostics ? Office.context.mailbox.diagnostics.hostName : "outlook";
  }

  function readBannerMeta(item) {
    // The banner injector embeds (tier, category, pseudo_message_id)
    // in an X-SN360-Banner internet header. The add-in surfaces it
    // via the InternetHeaders API.
    return new Promise((resolve) => {
      try {
        item.getCustomPropertiesAsync((res) => {
          if (res.status !== "succeeded" || !res.value) return resolve(null);
          resolve({
            tier: res.value.get("sn360-tier") || "",
            category: res.value.get("sn360-category") || "",
            pseudo_message_id: res.value.get("sn360-pmid") || "",
          });
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
