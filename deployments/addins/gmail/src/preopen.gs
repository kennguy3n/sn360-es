/*
 * SN360 Gmail Add-on — Pre-Open Trigger
 *
 * Bound to the contextualTriggers in appsscript.json. Reads the
 * SN360 banner metadata from the message internet headers and, for
 * Warning+ tier messages, surfaces a CardService warning before the
 * user opens the body.
 */

// SN360_API_BASE is declared in presend.gs so both files share the
// same global. Apps Script loads all `.gs` files into a single global
// scope, so duplicating the declaration with `var` here would shadow
// any value set elsewhere. We intentionally do NOT redeclare it.

function sn360PreOpenTrigger(e) {
  if (!e || !e.gmail || !e.gmail.messageId) return [];
  var accessToken = e.gmail.accessToken || (e.messageMetadata && e.messageMetadata.accessToken);
  if (!accessToken) return [];
  GmailApp.setCurrentMessageAccessToken(accessToken);
  var msg = GmailApp.getMessageById(e.gmail.messageId);
  if (!msg) return [];
  var meta = parseBannerHeader_(readMessageHeaders_(msg));
  if (!meta || !meta.pseudo_message_id) return [];
  var tenant = tenantIdFromUser_();
  var locale = sn360Locale_(e);
  var resp = callPredict_("/v1/predict/open", {
    tenant_id: tenant,
    pseudo_message_id: meta.pseudo_message_id,
    tier: meta.tier || "",
    category: meta.category || "",
  });
  if (!resp || !resp.show_warning) return [];
  return [buildOpenWarningCard_(resp, meta.tier, locale)];
}

// Map the SN360 banner tier to the shared severity ramp and the
// plain-language title / why / "what to do" keys. Mirrors the Outlook
// pre-open add-in so a given tier reads identically on both platforms.
// Returns null for tiers we don't warn on, so the caller falls back to
// the server-supplied message rather than an empty banner.
function presentationForTier_(tier) {
  var key = String(tier || "").toLowerCase();
  if (key === "blocked" || key === "block") {
    return { titleKey: "open_title_blocked", bodyKey: "open_body_blocked", actionKey: "open_action_report", level: 4 };
  }
  if (key === "high_risk" || key === "high") {
    return { titleKey: "open_title_high", bodyKey: "open_body_high", actionKey: "open_action_report", level: 3 };
  }
  if (key === "warning" || key === "warn") {
    return { titleKey: "open_title_warning", bodyKey: "open_body_warning", actionKey: "open_action_proceed", level: 2 };
  }
  if (key === "caution") {
    return { titleKey: "open_title_caution", bodyKey: "open_body_caution", actionKey: "open_action_proceed", level: 1 };
  }
  return null;
}

function buildOpenWarningCard_(resp, tier, locale) {
  // severityForLevel_, localizedMessage_, escapeHtml_ and sn360Locale_
  // all live in presend.gs; Apps Script loads every .gs file into one
  // global scope, so they are available here (same pattern as
  // callPredict_ / tenantIdFromUser_ above).
  var pres = presentationForTier_(tier || (resp && resp.tier));
  var section = CardService.newCardSection();
  if (pres) {
    var sev = severityForLevel_(pres.level, locale);
    section
      .addWidget(
        CardService.newTextParagraph().setText(
          "<b>" + escapeHtml_(localizedMessage_(pres.titleKey, locale, {})) + "</b>"
        )
      )
      .addWidget(
        CardService.newTextParagraph().setText(
          '<font color="' +
            sev.color +
            '"><b>' +
            escapeHtml_(sev.label) +
            "</b></font> · " +
            escapeHtml_(localizedMessage_(pres.bodyKey, locale, {}))
        )
      )
      .addWidget(
        CardService.newTextParagraph().setText(
          escapeHtml_(localizedMessage_(pres.actionKey, locale, {}))
        )
      );
  } else {
    // Unknown tier: keep the branded header but fall back to whatever
    // message the server supplied; if it's empty, use the localized
    // generic flag line so we never render an empty card (mirrors the
    // Outlook pre-open fallback).
    section.addWidget(
      CardService.newTextParagraph().setText(
        escapeHtml_(
          (resp && resp.message) ||
            localizedMessage_("open_generic_flagged", locale, {})
        )
      )
    );
  }
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader().setTitle(
        localizedMessage_("safety_check", locale, {})
      )
    )
    .addSection(section)
    .build();
}

// readMessageHeaders_ returns just the header block of an RFC 2822
// message. Apps Script does not expose a per-header accessor for
// custom (X-) headers, so we fall back to getRawContent — but we
// truncate after the first blank line so the message body and any
// attachments are never parsed. Large messages with attachments would
// otherwise burn Apps Script execution quota for no benefit.
function readMessageHeaders_(msg) {
  var raw = msg.getRawContent();
  if (!raw) return "";
  var sep = raw.indexOf("\r\n\r\n");
  if (sep < 0) sep = raw.indexOf("\n\n");
  if (sep < 0) return raw;
  return raw.substring(0, sep);
}

function parseBannerHeader_(headerBlock) {
  if (!headerBlock) return null;
  // Format: "X-SN360-Banner: tier=<tier>; category=<cat>; pmid=<id>"
  // RFC 2822 allows headers to be folded across multiple lines;
  // continuation lines start with whitespace (SP or HTAB). We unfold
  // the header value before parsing so long pseudo_message_ids or
  // future fields don't silently break parsing.
  var lines = headerBlock.split(/\r?\n/);
  var headerLine = null;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (headerLine !== null) {
      if (line.length > 0 && (line.charAt(0) === " " || line.charAt(0) === "\t")) {
        headerLine += " " + line.substring(1);
        continue;
      }
      break;
    }
    if (line.toLowerCase().indexOf("x-sn360-banner:") === 0) {
      headerLine = line;
    }
  }
  if (headerLine === null) return null;
  var parts = headerLine.substring("x-sn360-banner:".length).split(";");
  var meta = { tier: "", category: "", pseudo_message_id: "" };
  for (var j = 0; j < parts.length; j++) {
    // Split on the first "=" only so future values containing "="
    // (e.g. base64-encoded pseudo_message_ids) aren't silently
    // dropped.
    var eq = parts[j].indexOf("=");
    if (eq <= 0) continue;
    var key = parts[j].substring(0, eq).trim().toLowerCase();
    var value = parts[j].substring(eq + 1).trim();
    if (key === "tier") meta.tier = value;
    else if (key === "category") meta.category = value;
    else if (key === "pmid") meta.pseudo_message_id = value;
  }
  return meta;
}
