/*
 * SN360 Gmail Add-on — Pre-Send Trigger
 *
 * Bound to the composeTrigger in appsscript.json. Implements the
 * three pre-send flows using Gmail
 * Add-on APIs (CardService + GmailApp + advanced Gmail service):
 *
 *   1. Recipient risk check (To/Cc/Bcc)
 *      Hashes each recipient + tenant context and POSTs the bundle
 *      to /v1/predict/recipient. High-risk responses surface a
 *      CardService notification that the user must explicitly
 *      acknowledge before resending.
 *
 *   2. Lookalike domain detection (client-side)
 *      Real Damerau-Levenshtein (Optimal String Alignment) distance
 *      computation against the user's known-domains set, cached in
 *      CacheService.getUserCache() with a 1-hour TTL (the closest
 *      Apps Script analog to Office.js's sessionData; both are
 *      ephemeral per-user key/value stores with TTL semantics).
 *      Recipient domains within distance <= 2 (but not exactly
 *      matching) of a known domain are flagged with a "did you
 *      mean" suggestion.
 *
 *   3. External-thread-going-external warning
 *      For replies, the compose trigger event carries
 *      e.gmail.threadId. We fetch the thread via the advanced
 *      Gmail service (Gmail.Users.Threads.get, METADATA format)
 *      and extract the From/To/Cc/Bcc participants of each prior
 *      message. If every prior domain matches the sender's domain
 *      (internal-only thread) and the current draft contains an
 *      external recipient not in the baseline, we warn.
 *
 * Performance budget:
 *   Gmail Add-on triggers have a 30-second hard timeout. The
 *   network call is bounded by UrlFetchApp's default timeout
 *   (Apps Script doesn't expose a per-request timeout; we keep
 *   the request body tiny so the connection times out at the
 *   server side). The Gmail.Users.Threads.get call is metadata-
 *   only and typically returns in under 500 ms. The Damerau-
 *   Levenshtein check is O(D * m * n) for D known domains and
 *   m, n <= ~50 chars per domain (typical D < 50, total < 5 ms).
 *
 * Privacy:
 *   No raw email addresses leave the mailbox. Each recipient is
 *   SHA-256-pseudonymised (tenant|lowercased-email) before being
 *   attached to the predict request.
 */

var SN360_API_BASE = "https://api.sn360.example.com";

// Soft TTL for the user-cache entries used by the lookalike
// known-domains list and predict-response cache. Apps Script's
// CacheService caps individual entries at 6 hours; 1 hour is a
// conservative middle ground.
var SN360_CACHE_TTL_SECONDS = 60 * 60;

// Distance <= 2 catches single-character substitutions, inserts,
// deletes, and adjacent transpositions ("gmial.com" ↔ "gmail.com")
// without false-positive flooding on legitimate similar domains.
var SN360_MAX_LOOKALIKE_DISTANCE = 2;

var SN360_CACHE_KEY_KNOWN_PREFIX = "sn360.known.";
var SN360_CACHE_KEY_PREDICT_PREFIX = "sn360.predict.";

function sn360HomepageTrigger() {
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("SN360"))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          "SN360 monitors this mailbox for phishing and BEC. Open the add-on inside a draft to run a pre-send check."
        )
      )
    )
    .build();
  return [card];
}

function sn360PreSendTrigger(e) {
  // Explicit fail-open: any unexpected error in our pre-send path
  // must NOT block legitimate sends. Apps Script's platform-level
  // fail-open (a throwing trigger is treated as no card returned)
  // already covers this, but mirroring Outlook's structure makes
  // the contract obvious to future maintainers and lets us record
  // the error before swallowing it.
  try {
    return sn360PreSendTriggerImpl_(e);
  } catch (err) {
    try {
      console.error("sn360PreSendTrigger failed: " + err);
    } catch (_) {
      // console may be unavailable in older Apps Script runtimes.
    }
    return [];
  }
}

function sn360PreSendTriggerImpl_(e) {
  if (!e) return [];
  // Workspace Add-on compose triggers deliver the draft metadata at
  // the top level (e.draftMetadata). e.gmail.* is only populated for
  // contextual (message-read) triggers, so the previous lookup never
  // matched anything in some Workspace configurations and the
  // pre-send card was never shown. We keep the e.gmail fallback so
  // any classic Add-on deployment still works.
  var draft = e.draftMetadata || (e.gmail && e.gmail.draftMetadata) || null;
  if (!draft) return [];

  var recipients = []
    .concat(draft.toRecipients || [])
    .concat(draft.ccRecipients || [])
    .concat(draft.bccRecipients || []);
  if (recipients.length === 0) return [];

  var tenantId = tenantIdFromUser_();
  var senderEmail = Session.getActiveUser().getEmail();
  var myDomain = domainOf_(senderEmail);
  var locale = sn360Locale_(e);

  // Determine the thread baseline for replies. For new composes,
  // e.gmail is absent or its threadId is empty, so the baseline is
  // empty and threadInternal is false.
  var baselineDomains = [];
  if (e.gmail && e.gmail.threadId) {
    var accessToken = e.gmail.accessToken || (e.messageMetadata && e.messageMetadata.accessToken);
    baselineDomains = getThreadParticipantDomains_(accessToken, e.gmail.threadId);
  }
  var threadInternal = allInternal_(baselineDomains, myDomain);

  // Build the lookalike-check set from existing known domains (the
  // sender's own domain + previously-seen non-flagged recipients)
  // plus baseline thread participants. We deliberately do NOT mix
  // in the current draft's recipient domains — otherwise every
  // recipient would "trust" its own domain and the lookalike check
  // would skip it.
  var baseKnown = loadKnownDomains_(tenantId, myDomain);
  var checkSet = baseKnown.slice();
  for (var bi = 0; bi < baselineDomains.length; bi++) {
    if (baselineDomains[bi] && checkSet.indexOf(baselineDomains[bi]) < 0) {
      checkSet.push(baselineDomains[bi]);
    }
  }

  // Client-side Damerau-Levenshtein lookalike check.
  var clientWarnings = [];
  var seenLookalike = {};
  var flaggedDomains = {};
  for (var i = 0; i < recipients.length; i++) {
    var dom = domainOf_(recipients[i]);
    if (!dom) continue;
    var hit = findLookalike_(dom, checkSet);
    if (hit && hit !== dom) {
      flaggedDomains[dom] = true;
      var userHash = sha256Hex_(tenantId + "|" + (recipients[i] || "").toLowerCase());
      if (seenLookalike[userHash]) continue;
      seenLookalike[userHash] = true;
      clientWarnings.push({
        user_hash: userHash,
        level: 4,
        code: "lookalike_recipient_client",
        message: localizedMessage_("lookalike_recipient", locale, { domain: dom, ref: hit }),
        suggestion: hit,
      });
    }
  }

  // External-thread-going-external client check.
  if (threadInternal) {
    for (var j = 0; j < recipients.length; j++) {
      var dom2 = domainOf_(recipients[j]);
      if (dom2 && dom2 !== myDomain && baselineDomains.indexOf(dom2) < 0) {
        clientWarnings.push({
          user_hash: sha256Hex_(tenantId + "|" + (recipients[j] || "").toLowerCase()),
          level: 3,
          code: "external_on_internal_thread_client",
          message: localizedMessage_("external_on_internal_thread", locale, { domain: dom2 }),
        });
        break;
      }
    }
  }

  // AFTER the lookalike check, persist non-flagged recipient domains
  // for future sends. Flagged domains are deliberately NOT persisted
  // — otherwise the user would implicitly "trust" a suspicious
  // domain just by attempting to send to it once.
  var safeRecipientDomains = [];
  for (var si = 0; si < recipients.length; si++) {
    var sd = domainOf_(recipients[si]);
    if (sd && !flaggedDomains[sd]) safeRecipientDomains.push(sd);
  }
  appendKnownDomains_(tenantId, myDomain, baselineDomains.concat(safeRecipientDomains));

  // Build + send the /v1/predict/recipient request.
  var payload = {
    tenant_id: tenantId,
    sender_hash: sha256Hex_(tenantId + "|" + senderEmail.toLowerCase()),
    recipients: recipients.map(function (r) {
      // is_known_contact intentionally omitted: see comment in the
      // Outlook add-in. Server treats nil as "no signal" and
      // suppresses unusual_external_recipient.
      return {
        user_hash: sha256Hex_(tenantId + "|" + (r || "").toLowerCase()),
        domain: domainOf_(r),
        is_external: !sameDomain_(r, senderEmail),
      };
    }),
    thread_is_internal: threadInternal,
  };
  var resp = callPredictCached_("/v1/predict/recipient", payload);
  var combined = combineWarnings_(resp, clientWarnings);

  if ((combined.overall_level || 0) < 3) return [];
  return [buildSendWarningCard_(combined, locale)];
}

// === Card rendering =====================================================

function buildSendWarningCard_(resp, locale) {
  var section = CardService.newCardSection();
  (resp.warnings || []).forEach(function (w) {
    section.addWidget(
      CardService.newTextParagraph().setText(
        "<b>" + escapeHtml_(w.code || "warning") + "</b> — " + escapeHtml_(w.message || "")
      )
    );
    if (w.suggestion) {
      // The API may emit a suggestion field on lookalike warnings.
      // CardService.newTextParagraph().setText renders a subset of
      // HTML, so we escape the substituted value before placing it
      // inside the <i> wrapper to keep malformed / hostile API
      // suggestions from breaking the card layout.
      section.addWidget(
        CardService.newTextParagraph().setText(
          "<i>" +
            escapeHtml_(
              localizedMessage_("did_you_mean", locale, {
                suggestion: w.suggestion,
              })
            ) +
            "</i>"
        )
      );
    }
  });
  // The "acknowledge" button doesn't actually send the email — Gmail
  // Add-ons can't intercept the send button itself. It dismisses the
  // notification so the user has explicitly clicked through.
  section.addWidget(
    CardService.newTextButton()
      .setText(localizedMessage_("ack_button", locale, {}))
      .setOnClickAction(
        CardService.newAction().setFunctionName("sn360AcknowledgeWarning")
      )
  );
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader().setTitle(
        localizedMessage_("warning_header", locale, {})
      )
    )
    .addSection(section)
    .build();
}

function sn360AcknowledgeWarning() {
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText(
        "Warning acknowledged. Click Send when ready."
      )
    )
    .build();
}

// === Predict API =========================================================

function callPredictCached_(path, body) {
  // Build a cache key from the path + sender hash + sorted recipient
  // hashes + thread flag. Sorting makes the key invariant to
  // recipient ordering, mirroring the Outlook cache behaviour.
  var rHashes = (body.recipients || [])
    .map(function (r) {
      return r.user_hash;
    })
    .slice()
    .sort()
    .join(",");
  var key =
    SN360_CACHE_KEY_PREDICT_PREFIX +
    path +
    "|" +
    body.sender_hash +
    "|" +
    (body.thread_is_internal ? "1" : "0") +
    "|" +
    rHashes;
  // CacheService keys are capped at 250 chars; hash long keys.
  if (key.length > 240) {
    key = SN360_CACHE_KEY_PREDICT_PREFIX + sha256Hex_(key);
  }
  var cache = safeCache_();
  if (cache) {
    var raw = cache.get(key);
    if (raw) {
      try {
        return JSON.parse(raw);
      } catch (_) {
        /* fall through to fresh request */
      }
    }
  }
  var resp = callPredict_(path, body);
  if (resp && cache) {
    try {
      cache.put(key, JSON.stringify(resp), SN360_CACHE_TTL_SECONDS);
    } catch (_) {
      /* best-effort */
    }
  }
  return resp;
}

function callPredict_(path, body) {
  try {
    var response = UrlFetchApp.fetch(SN360_API_BASE + path, {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(body),
      muteHttpExceptions: true,
      validateHttpsCertificates: true,
      // Apps Script doesn't expose a per-request timeout — we keep
      // the request body tiny so the connection times out at the
      // server side. UrlFetchApp's default ceiling is well under
      // the 30-second compose-trigger budget.
    });
    if (response.getResponseCode() >= 400) return null;
    return JSON.parse(response.getContentText());
  } catch (err) {
    return null;
  }
}

// === Thread participants (advanced Gmail service) =======================

function getThreadParticipantDomains_(accessToken, threadId) {
  if (!threadId) return [];
  try {
    if (accessToken && typeof GmailApp !== "undefined") {
      GmailApp.setCurrentMessageAccessToken(accessToken);
    }
    if (typeof Gmail === "undefined" || !Gmail.Users || !Gmail.Users.Threads) {
      return [];
    }
    var thread = Gmail.Users.Threads.get("me", threadId, {
      format: "metadata",
      metadataHeaders: ["From", "To", "Cc", "Bcc"],
    });
    var domains = {};
    var messages = (thread && thread.messages) || [];
    for (var i = 0; i < messages.length; i++) {
      var headers = (messages[i].payload && messages[i].payload.headers) || [];
      for (var j = 0; j < headers.length; j++) {
        var name = headers[j].name;
        if (name !== "From" && name !== "To" && name !== "Cc" && name !== "Bcc") {
          continue;
        }
        var addrs = parseAddresses_(headers[j].value || "");
        for (var k = 0; k < addrs.length; k++) {
          var dom = domainOf_(addrs[k]);
          if (dom) domains[dom] = true;
        }
      }
    }
    return Object.keys(domains);
  } catch (_) {
    return [];
  }
}

// parseAddresses parses an RFC 2822 address list — "Display Name
// <foo@bar.com>, baz@qux.com" — into bare addresses. We tolerate
// missing display names, missing angle brackets, and embedded
// commas inside quoted display names.
function parseAddresses_(headerValue) {
  if (!headerValue) return [];
  var out = [];
  // Split on commas that are NOT inside double quotes. Apps Script's
  // ES5 regex engine doesn't have lookbehind, so we walk the string
  // manually.
  var parts = [];
  var depthQ = 0;
  var start = 0;
  for (var i = 0; i < headerValue.length; i++) {
    var c = headerValue.charAt(i);
    if (c === '"') {
      depthQ = depthQ ? 0 : 1;
    } else if (c === "," && !depthQ) {
      parts.push(headerValue.substring(start, i));
      start = i + 1;
    }
  }
  parts.push(headerValue.substring(start));
  for (var p = 0; p < parts.length; p++) {
    var trimmed = parts[p].replace(/^\s+|\s+$/g, "");
    if (!trimmed) continue;
    var lt = trimmed.indexOf("<");
    var gt = trimmed.lastIndexOf(">");
    var addr;
    if (lt >= 0 && gt > lt) {
      addr = trimmed.substring(lt + 1, gt);
    } else {
      addr = trimmed;
    }
    addr = addr.replace(/^\s+|\s+$/g, "").toLowerCase();
    if (addr.indexOf("@") > 0) out.push(addr);
  }
  return out;
}

// === Known domains cache ================================================

function knownDomainsCacheKey_(tenantId) {
  return SN360_CACHE_KEY_KNOWN_PREFIX + tenantId;
}

function loadKnownDomains_(tenantId, myDomain) {
  var cache = safeCache_();
  if (cache) {
    var raw = cache.get(knownDomainsCacheKey_(tenantId));
    if (raw) {
      try {
        var parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      } catch (_) {
        /* fall through */
      }
    }
  }
  return myDomain ? [myDomain] : [];
}

function appendKnownDomains_(tenantId, myDomain, newDomains) {
  var existing = loadKnownDomains_(tenantId, myDomain);
  var set = {};
  existing.forEach(function (d) {
    if (d) set[d] = true;
  });
  (newDomains || []).forEach(function (d) {
    if (d) set[String(d).toLowerCase()] = true;
  });
  var merged = Object.keys(set);
  var cache = safeCache_();
  if (cache) {
    try {
      cache.put(
        knownDomainsCacheKey_(tenantId),
        JSON.stringify(merged),
        SN360_CACHE_TTL_SECONDS
      );
    } catch (_) {
      /* best-effort */
    }
  }
  return merged;
}

function safeCache_() {
  try {
    if (typeof CacheService === "undefined") return null;
    if (typeof CacheService.getUserCache !== "function") return null;
    return CacheService.getUserCache();
  } catch (_) {
    return null;
  }
}

// === Damerau-Levenshtein ================================================
//
// Real OSA distance implementation, dependency-free. Mirrors the
// Outlook add-in's algorithm so client-side lookalike behaviour is
// consistent across platforms.

function damerauLevenshtein_(a, b) {
  a = String(a);
  b = String(b);
  if (a === b) return 0;
  if (!a) return b.length;
  if (!b) return a.length;
  var m = a.length;
  var n = b.length;
  var d = new Array(m + 1);
  for (var i = 0; i <= m; i++) {
    d[i] = new Array(n + 1);
    for (var jj = 0; jj <= n; jj++) d[i][jj] = 0;
    d[i][0] = i;
  }
  for (var j = 0; j <= n; j++) d[0][j] = j;
  for (var ii = 1; ii <= m; ii++) {
    for (var jjj = 1; jjj <= n; jjj++) {
      var cost = a.charCodeAt(ii - 1) === b.charCodeAt(jjj - 1) ? 0 : 1;
      var del = d[ii - 1][jjj] + 1;
      var ins = d[ii][jjj - 1] + 1;
      var sub = d[ii - 1][jjj - 1] + cost;
      d[ii][jjj] = Math.min(del, ins, sub);
      if (
        ii > 1 &&
        jjj > 1 &&
        a.charCodeAt(ii - 1) === b.charCodeAt(jjj - 2) &&
        a.charCodeAt(ii - 2) === b.charCodeAt(jjj - 1)
      ) {
        d[ii][jjj] = Math.min(d[ii][jjj], d[ii - 2][jjj - 2] + 1);
      }
    }
  }
  return d[m][n];
}

function findLookalike_(domain, knownDomains) {
  if (!domain) return null;
  var d = String(domain).toLowerCase();
  var kd = knownDomains || [];
  if (kd.indexOf(d) >= 0) return null;
  var best = null;
  var bestDist = SN360_MAX_LOOKALIKE_DISTANCE + 1;
  for (var i = 0; i < kd.length; i++) {
    var known = kd[i];
    if (!known) continue;
    if (Math.abs(known.length - d.length) > SN360_MAX_LOOKALIKE_DISTANCE) continue;
    var dist = damerauLevenshtein_(d, known);
    if (dist > 0 && dist <= SN360_MAX_LOOKALIKE_DISTANCE && dist < bestDist) {
      best = known;
      bestDist = dist;
    }
  }
  return best;
}

// === Warning combination ================================================

function combineWarnings_(apiResponse, clientWarnings) {
  var out = {
    overall_level: (apiResponse && apiResponse.overall_level) || 0,
    warnings: ((apiResponse && apiResponse.warnings) || []).slice(),
  };
  (clientWarnings || []).forEach(function (w) {
    out.warnings.push(w);
    if (w.level > out.overall_level) out.overall_level = w.level;
  });
  return out;
}

// === Localization =======================================================

var SN360_I18N = {
  en: {
    lookalike_recipient:
      "Recipient domain {domain} looks similar to {ref}. Did you mean {ref}?",
    external_on_internal_thread:
      "You're adding an external recipient ({domain}) to a previously internal thread.",
    did_you_mean: "Did you mean: {suggestion}",
    warning_header: "SN360 Send Warning",
    ack_button: "Acknowledge",
  },
};

function localizedMessage_(key, locale, params) {
  var lang = (locale && String(locale).substring(0, 2).toLowerCase()) || "en";
  var bundle = SN360_I18N[lang] || SN360_I18N.en;
  var msg = bundle[key] || SN360_I18N.en[key] || key;
  if (params) {
    for (var k in params) {
      if (Object.prototype.hasOwnProperty.call(params, k)) {
        msg = msg.split("{" + k + "}").join(params[k]);
      }
    }
  }
  return msg;
}

function sn360Locale_(e) {
  try {
    if (e && e.commonEventObject && e.commonEventObject.userLocale) {
      return e.commonEventObject.userLocale;
    }
    if (typeof Session !== "undefined" && typeof Session.getActiveUserLocale === "function") {
      return Session.getActiveUserLocale() || "en";
    }
  } catch (_) {
    /* fall through */
  }
  return "en";
}

// === Helpers ============================================================

function tenantIdFromUser_() {
  var email = Session.getActiveUser().getEmail() || "";
  var at = email.indexOf("@");
  return at < 0 ? "gws" : email.substring(at + 1).toLowerCase();
}

function domainOf_(email) {
  if (!email) return "";
  var s = String(email).toLowerCase();
  // Tolerate "Display <addr@dom>" style values that slipped past
  // parseAddresses_, plus bare addresses.
  var lt = s.indexOf("<");
  var gt = s.indexOf(">", lt + 1);
  if (lt >= 0 && gt > lt) s = s.substring(lt + 1, gt);
  var at = s.indexOf("@");
  return at < 0 ? "" : s.substring(at + 1).replace(/[\s>].*$/, "");
}

function sameDomain_(a, b) {
  var da = domainOf_(a);
  return da !== "" && da === domainOf_(b);
}

function allInternal_(domains, myDomain) {
  if (!domains || domains.length === 0) return false;
  if (!myDomain) return false;
  for (var i = 0; i < domains.length; i++) {
    if (domains[i] !== myDomain) return false;
  }
  return true;
}

function sha256Hex_(s) {
  var digest = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    s,
    Utilities.Charset.UTF_8
  );
  var out = "";
  for (var i = 0; i < digest.length; i++) {
    var byteVal = digest[i] & 0xff;
    out += ("0" + byteVal.toString(16)).slice(-2);
  }
  return out;
}

function escapeHtml_(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// === Test exports (Node harness only) ===================================
//
// Apps Script ignores `module.exports`; this block is consumed by the
// Node test harness in addins/gmail/test/, which loads this .gs file
// as plain JS after stubbing GmailApp / CardService / etc. The harness
// requires presend.gs as if it were CommonJS, so we expose every
// pure function under test.

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    sn360PreSendTrigger: sn360PreSendTrigger,
    sn360HomepageTrigger: sn360HomepageTrigger,
    sn360AcknowledgeWarning: sn360AcknowledgeWarning,
    buildSendWarningCard_: buildSendWarningCard_,
    callPredict_: callPredict_,
    callPredictCached_: callPredictCached_,
    getThreadParticipantDomains_: getThreadParticipantDomains_,
    parseAddresses_: parseAddresses_,
    loadKnownDomains_: loadKnownDomains_,
    appendKnownDomains_: appendKnownDomains_,
    damerauLevenshtein_: damerauLevenshtein_,
    findLookalike_: findLookalike_,
    combineWarnings_: combineWarnings_,
    localizedMessage_: localizedMessage_,
    tenantIdFromUser_: tenantIdFromUser_,
    domainOf_: domainOf_,
    sameDomain_: sameDomain_,
    allInternal_: allInternal_,
    sha256Hex_: sha256Hex_,
    escapeHtml_: escapeHtml_,
    sn360Locale_: sn360Locale_,
  };
}
