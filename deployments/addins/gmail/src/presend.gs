/*
 * SN360 Gmail Add-on — Pre-Send Trigger
 *
 * Bound to the composeTrigger in appsscript.json. Calls the SN360
 * /v1/predict/recipient endpoint and surfaces a CardService warning
 * when the response carries a Warning+ overall level.
 *
 * No raw email contents are transmitted: recipients are pseudonymised
 * via SHA-256 hashes before leaving Gmail.
 */

var SN360_API_BASE = "https://api.sn360.example.com";
var SN360_TIMEOUT_MS = 250;

function sn360HomepageTrigger() {
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("SN360"))
    .addSection(CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText("SN360 is monitoring this mailbox for phishing and BEC.")
    ))
    .build();
  return [card];
}

function sn360PreSendTrigger(e) {
  var tenantId = tenantIdFromUser_();
  // Workspace Add-on compose triggers deliver the draft metadata at
  // the top level (e.draftMetadata). e.gmail.* is only populated for
  // contextual (message-read) triggers, so the previous lookup never
  // matched anything and the pre-send card was never shown. We keep
  // the e.gmail fallback so any classic Add-on deployment still works.
  var draft = e ? (e.draftMetadata || (e.gmail && e.gmail.draftMetadata)) : null;
  if (!draft || !draft.toRecipients) return [];
  var senderEmail = Session.getActiveUser().getEmail();
  var recipients = (draft.toRecipients || []).concat(draft.ccRecipients || []);
  var payload = {
    tenant_id: tenantId,
    sender_hash: sha256Hex_(tenantId + "|" + senderEmail.toLowerCase()),
    recipients: recipients.map(function (r) {
      // is_known_contact is intentionally omitted: the Gmail Add-on
      // API does not expose the user's contact graph cheaply enough
      // for the 300ms p95 budget. The server treats nil as "no
      // signal" and suppresses unusual_external_recipient for this
      // caller; sending false here would instead cause the backend
      // to emit unusual_external_recipient on every external
      // recipient (low-signal noise). When a server-side contact
      // store is wired up later (currently TODO), this client can
      // keep omitting the field and let the server enrich.
      return {
        user_hash: sha256Hex_(tenantId + "|" + (r || "").toLowerCase()),
        domain: domainOf_(r),
        is_external: !sameDomain_(r, senderEmail),
      };
    }),
    thread_is_internal: false,
  };
  var resp = callPredict_("/v1/predict/recipient", payload);
  if (!resp || (resp.overall_level || 0) < 3) return [];
  return [buildSendWarningCard_(resp)];
}

function buildSendWarningCard_(resp) {
  var section = CardService.newCardSection();
  (resp.warnings || []).forEach(function (w) {
    section.addWidget(
      CardService.newTextParagraph().setText("<b>" + w.code + "</b> — " + w.message)
    );
  });
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("SN360 Send Warning"))
    .addSection(section)
    .build();
}

function callPredict_(path, body) {
  try {
    var response = UrlFetchApp.fetch(SN360_API_BASE + path, {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(body),
      muteHttpExceptions: true,
      validateHttpsCertificates: true,
      // Apps Script doesn't expose direct timeout — keep the request
      // body tiny so the connection times out at the server side.
    });
    if (response.getResponseCode() >= 400) return null;
    return JSON.parse(response.getContentText());
  } catch (err) {
    return null;
  }
}

function tenantIdFromUser_() {
  var email = Session.getActiveUser().getEmail() || "";
  var at = email.indexOf("@");
  return at < 0 ? "gws" : email.substring(at + 1).toLowerCase();
}

function domainOf_(email) {
  if (!email) return "";
  var at = email.indexOf("@");
  return at < 0 ? "" : email.substring(at + 1).toLowerCase();
}

function sameDomain_(a, b) {
  var da = domainOf_(a);
  return da !== "" && da === domainOf_(b);
}

function sha256Hex_(s) {
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, s, Utilities.Charset.UTF_8);
  var out = "";
  for (var i = 0; i < digest.length; i++) {
    var byte = digest[i] & 0xff;
    out += ("0" + byte.toString(16)).slice(-2);
  }
  return out;
}
