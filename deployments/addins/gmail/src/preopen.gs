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
  var resp = callPredict_("/v1/predict/open", {
    tenant_id: tenant,
    pseudo_message_id: meta.pseudo_message_id,
    tier: meta.tier || "",
    category: meta.category || "",
  });
  if (!resp || !resp.show_warning) return [];
  return [buildOpenWarningCard_(resp)];
}

function buildOpenWarningCard_(resp) {
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText("<b>" + (resp.code || "warning") + "</b>"))
    .addWidget(CardService.newTextParagraph().setText(resp.message || ""));
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("SN360 Open Warning"))
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
  var lines = headerBlock.split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (line.toLowerCase().indexOf("x-sn360-banner:") !== 0) continue;
    var parts = line.substring("x-sn360-banner:".length).split(";");
    var meta = { tier: "", category: "", pseudo_message_id: "" };
    for (var j = 0; j < parts.length; j++) {
      var kv = parts[j].split("=");
      if (kv.length !== 2) continue;
      var key = kv[0].trim().toLowerCase();
      var value = kv[1].trim();
      if (key === "tier") meta.tier = value;
      else if (key === "category") meta.category = value;
      else if (key === "pmid") meta.pseudo_message_id = value;
    }
    return meta;
  }
  return null;
}
