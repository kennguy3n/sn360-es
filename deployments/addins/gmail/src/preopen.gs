/*
 * SN360 Gmail Add-on — Pre-Open Trigger
 *
 * Bound to the contextualTriggers in appsscript.json. Reads the
 * SN360 banner metadata from the message internet headers and, for
 * Warning+ tier messages, surfaces a CardService warning before the
 * user opens the body.
 */

var SN360_API_BASE = SN360_API_BASE || "https://api.sn360.example.com";

function sn360PreOpenTrigger(e) {
  if (!e || !e.gmail || !e.gmail.messageId) return [];
  var accessToken = e.gmail.accessToken || (e.messageMetadata && e.messageMetadata.accessToken);
  if (!accessToken) return [];
  GmailApp.setCurrentMessageAccessToken(accessToken);
  var msg = GmailApp.getMessageById(e.gmail.messageId);
  if (!msg) return [];
  var meta = parseBannerHeader_(msg.getRawContent());
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

function parseBannerHeader_(raw) {
  if (!raw) return null;
  // Format: "X-SN360-Banner: tier=<tier>; category=<cat>; pmid=<id>"
  var lines = raw.split(/\r?\n/);
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
