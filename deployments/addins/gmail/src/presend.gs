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

function sn360HomepageTrigger(e) {
  var locale = sn360Locale_(e);
  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader().setTitle(
        localizedMessage_("safety_check", locale, {})
      )
    )
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          localizedMessage_("home_body", locale, {})
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

// ShieldNet 360 severity ramp, shared with the Outlook add-in and the
// pre-open card. Colours mirror the brand tokens (critical #e40014,
// high #ff6900, medium #edb200, low/info #255fe5) so a given risk level
// looks identical across every SN360 surface.
function severityForLevel_(level, locale) {
  if (level >= 4) return { label: localizedMessage_("sev_critical", locale, {}), color: "#e40014" };
  if (level === 3) return { label: localizedMessage_("sev_high", locale, {}), color: "#ff6900" };
  if (level === 2) return { label: localizedMessage_("sev_medium", locale, {}), color: "#edb200" };
  return { label: localizedMessage_("sev_low", locale, {}), color: "#255fe5" };
}

// Pick the plain-language headline for the dominant pre-send concern.
// We lead with the most actionable issue (a lookalike address) and fall
// back to a neutral, reassuring prompt. The "_client" suffix on
// client-side warnings is stripped so they resolve to the same title as
// their server-side equivalents.
function sendTitleKey_(warnings) {
  var codes = (warnings || []).map(function (w) {
    return String((w && w.code) || "").replace(/_client$/, "");
  });
  if (codes.indexOf("lookalike_recipient") >= 0) return "send_title_lookalike";
  if (codes.indexOf("external_on_internal_thread") >= 0) return "send_title_external";
  return "send_title_generic";
}

function buildSendWarningCard_(resp, locale) {
  var level = (resp && resp.overall_level) || 0;
  // Mirror the Outlook add-in: if the backend returns a high level with no
  // per-warning detail, synthesize a prompt so the card always explains
  // itself and offers the safe action — never an empty body. We use a
  // distinct body line (not the headline key) so the detail doesn't simply
  // repeat the title back to the user.
  var warnings =
    resp && resp.warnings && resp.warnings.length
      ? resp.warnings
      : [{ message: localizedMessage_("send_body_generic", locale, {}) }];
  var sev = severityForLevel_(level, locale);
  var headline = localizedMessage_(sendTitleKey_(warnings), locale, {});
  var section = CardService.newCardSection();
  warnings.forEach(function (w, idx) {
    var msg = escapeHtml_(w.message || "");
    var text;
    if (idx === 0) {
      // Lead the card with the plain headline, a colour-coded severity
      // badge, the primary concern, then the one safe action — so the
      // "what happened / what to do" sit together at the top, the way a
      // first-time non-technical user reads it.
      text =
        "<b>" + escapeHtml_(headline) + "</b><br>" +
        '<font color="' + sev.color + '"><b>' + escapeHtml_(sev.label) + "</b></font> · " +
        msg +
        "<br><br>" + escapeHtml_(localizedMessage_("send_action", locale, {}));
    } else {
      text = msg;
    }
    section.addWidget(CardService.newTextParagraph().setText(text));
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
  // Add-ons can't intercept the send button itself. It confirms the
  // user has read the check and is choosing to continue (the override
  // path), then they press Gmail's own Send.
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
        localizedMessage_("safety_check", locale, {})
      )
    )
    .addSection(section)
    .build();
}

function sn360AcknowledgeWarning(e) {
  var locale = sn360Locale_(e);
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText(
        localizedMessage_("ack_confirmation", locale, {})
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

// Locale bundles for the 14 supported SN360 languages. localizedMessage_()
// keys on the 2-letter language subtag of the user locale (e.g. "pt-BR" ->
// "pt") and falls back to English for any unrecognised subtag. Keep the key
// set identical across every bundle.
var SN360_I18N = {
  en: {
    lookalike_recipient:
      "{domain} looks almost identical to {ref}, a contact you've emailed before. Did you mean {ref}?",
    external_on_internal_thread:
      "You're adding an external recipient ({domain}) to a thread that's only included your colleagues until now.",
    did_you_mean: "Did you mean {suggestion}?",
    safety_check: "ShieldNet 360 safety check",
    send_title_lookalike: "Double-check this email address",
    send_title_external: "You're emailing someone outside your company",
    send_title_generic: "Take a moment before you send",
    send_body_generic:
      "We spotted something worth a quick look before this message goes out.",
    send_action:
      "If you recognise everyone here, you can send. If not, fix the address or remove them first.",
    ack_button: "I've checked — looks right",
    ack_confirmation: "Got it — we've noted your check. Send when you're ready.",
    home_body:
      "ShieldNet 360 keeps an eye on your email. Open a draft and we'll check it before you send — and we'll flag risky messages as you read them. Nothing to set up.",
    sev_critical: "High risk",
    sev_high: "Worth a check",
    sev_medium: "Heads-up",
    sev_low: "For your awareness",
    open_title_blocked: "This message looks dangerous",
    open_title_high: "This looks like a phishing attempt",
    open_title_warning: "Take care with this message",
    open_title_caution: "A quick heads-up about this message",
    open_body_blocked:
      "It has strong signs of a scam built to steal information, money, or passwords.",
    open_body_high:
      "Someone may be pretending to be a person or company you trust.",
    open_body_warning:
      "Something here is unusual. Check who really sent it before you act on it.",
    open_body_caution:
      "It's probably fine — just stay alert before sharing anything sensitive.",
    open_action_report:
      "Don't click links or open attachments. If you weren't expecting this, report and delete it.",
    open_action_proceed:
      "It's okay to read — just don't share passwords, payment details, or codes until you're sure.",
    open_generic_flagged:
      "This message was flagged — open it with care.",
  },
  vi: {
    lookalike_recipient:
      "{domain} trông gần giống hệt {ref}, một địa chỉ bạn từng gửi trước đây. Bạn có muốn gửi tới {ref} không?",
    external_on_internal_thread:
      "Bạn đang thêm một người nhận bên ngoài ({domain}) vào cuộc trò chuyện mà đến nay chỉ có đồng nghiệp của bạn.",
    did_you_mean: "Bạn có muốn gửi tới {suggestion} không?",
    safety_check: "Kiểm tra an toàn ShieldNet 360",
    send_title_lookalike: "Kiểm tra lại địa chỉ email này",
    send_title_external: "Bạn đang gửi cho người ngoài công ty",
    send_title_generic: "Hãy kiểm tra một chút trước khi gửi",
    send_body_generic:
      "Chúng tôi nhận thấy điều gì đó đáng xem lại trước khi thư này được gửi đi.",
    send_action:
      "Nếu bạn nhận ra tất cả người nhận, bạn có thể gửi. Nếu không, hãy sửa địa chỉ hoặc xóa họ trước.",
    ack_button: "Tôi đã kiểm tra — ổn rồi",
    ack_confirmation: "Đã rõ — chúng tôi đã ghi nhận. Gửi khi bạn sẵn sàng.",
    home_body:
      "ShieldNet 360 luôn để mắt đến email của bạn. Hãy mở một thư nháp và chúng tôi sẽ kiểm tra trước khi bạn gửi — và đánh dấu thư đáng ngờ khi bạn đọc. Không cần thiết lập.",
    sev_critical: "Rủi ro cao",
    sev_high: "Nên kiểm tra",
    sev_medium: "Lưu ý",
    sev_low: "Để bạn biết",
    open_title_blocked: "Thư này có vẻ nguy hiểm",
    open_title_high: "Đây có vẻ là một nỗ lực lừa đảo",
    open_title_warning: "Hãy thận trọng với thư này",
    open_title_caution: "Một lưu ý nhanh về thư này",
    open_body_blocked:
      "Thư có nhiều dấu hiệu rõ ràng của lừa đảo nhằm đánh cắp thông tin, tiền hoặc mật khẩu.",
    open_body_high:
      "Có thể ai đó đang mạo danh một người hoặc công ty bạn tin tưởng.",
    open_body_warning:
      "Có điều gì đó bất thường ở đây. Hãy kiểm tra ai thực sự gửi thư trước khi hành động.",
    open_body_caution:
      "Có thể không sao — chỉ cần cẩn thận trước khi chia sẻ thông tin nhạy cảm.",
    open_action_report:
      "Đừng nhấp liên kết hoặc mở tệp đính kèm. Nếu bạn không mong đợi thư này, hãy báo cáo và xóa nó.",
    open_action_proceed:
      "Bạn có thể đọc — chỉ đừng chia sẻ mật khẩu, thông tin thanh toán hoặc mã cho đến khi bạn chắc chắn.",
    open_generic_flagged:
      "Thư này đã được gắn cờ — hãy mở một cách thận trọng.",
  },
  th: {
    lookalike_recipient:
      "{domain} ดูเกือบเหมือนกับ {ref} ซึ่งเป็นที่อยู่ที่คุณเคยส่งถึงมาก่อน คุณต้องการส่งถึง {ref} ใช่หรือไม่",
    external_on_internal_thread:
      "คุณกำลังเพิ่มผู้รับภายนอก ({domain}) เข้าในการสนทนาที่จนถึงตอนนี้มีแต่เพื่อนร่วมงานของคุณ",
    did_you_mean: "คุณหมายถึง {suggestion} ใช่หรือไม่",
    safety_check: "การตรวจสอบความปลอดภัย ShieldNet 360",
    send_title_lookalike: "ตรวจสอบที่อยู่อีเมลนี้อีกครั้ง",
    send_title_external: "คุณกำลังส่งอีเมลถึงคนนอกบริษัท",
    send_title_generic: "หยุดสักครู่ก่อนส่ง",
    send_body_generic:
      "เราพบบางอย่างที่ควรตรวจสอบสักครู่ก่อนที่ข้อความนี้จะถูกส่งออกไป",
    send_action:
      "หากคุณรู้จักผู้รับทุกคน คุณสามารถส่งได้ หากไม่ใช่ โปรดแก้ไขที่อยู่หรือเอาออกก่อน",
    ack_button: "ฉันตรวจสอบแล้ว — ดูถูกต้อง",
    ack_confirmation: "รับทราบ — เราบันทึกไว้แล้ว ส่งได้เมื่อคุณพร้อม",
    home_body:
      "ShieldNet 360 คอยดูแลอีเมลของคุณ เปิดอีเมลฉบับร่างแล้วเราจะตรวจสอบก่อนคุณส่ง และจะแจ้งเตือนข้อความที่เสี่ยงขณะคุณอ่าน ไม่ต้องตั้งค่าใด ๆ",
    sev_critical: "ความเสี่ยงสูง",
    sev_high: "ควรตรวจสอบ",
    sev_medium: "ข้อควรทราบ",
    sev_low: "เพื่อให้คุณทราบ",
    open_title_blocked: "ข้อความนี้ดูเป็นอันตราย",
    open_title_high: "ดูเหมือนเป็นความพยายามฟิชชิง",
    open_title_warning: "โปรดระมัดระวังกับข้อความนี้",
    open_title_caution: "ข้อควรทราบสั้น ๆ เกี่ยวกับข้อความนี้",
    open_body_blocked:
      "มีสัญญาณชัดเจนว่าเป็นการหลอกลวงเพื่อขโมยข้อมูล เงิน หรือรหัสผ่าน",
    open_body_high:
      "อาจมีใครบางคนแอบอ้างเป็นบุคคลหรือบริษัทที่คุณไว้วางใจ",
    open_body_warning:
      "มีบางอย่างผิดปกติ โปรดตรวจสอบว่าใครส่งมาจริง ๆ ก่อนดำเนินการ",
    open_body_caution:
      "อาจไม่มีปัญหา — เพียงระวังก่อนแบ่งปันข้อมูลที่ละเอียดอ่อน",
    open_action_report:
      "อย่าคลิกลิงก์หรือเปิดไฟล์แนบ หากคุณไม่ได้คาดหวังข้อความนี้ โปรดรายงานและลบทิ้ง",
    open_action_proceed:
      "อ่านได้ — เพียงอย่าแบ่งปันรหัสผ่าน ข้อมูลการชำระเงิน หรือรหัส จนกว่าคุณจะแน่ใจ",
    open_generic_flagged:
      "ข้อความนี้ถูกทำเครื่องหมายไว้ — โปรดเปิดด้วยความระมัดระวัง",
  },
  ja: {
    lookalike_recipient:
      "{domain} は、以前に送信したことのある {ref} とほぼ同じに見えます。{ref} のことではありませんか？",
    external_on_internal_thread:
      "これまで社内の同僚だけだったスレッドに、社外の宛先（{domain}）を追加しようとしています。",
    did_you_mean: "{suggestion} のことではありませんか？",
    safety_check: "ShieldNet 360 セーフティチェック",
    send_title_lookalike: "このメールアドレスをもう一度確認してください",
    send_title_external: "社外の相手にメールを送ろうとしています",
    send_title_generic: "送信する前に少し確認しましょう",
    send_body_generic: "送信する前に、少し確認しておきたい点が見つかりました。",
    send_action:
      "宛先の全員に心当たりがあれば送信できます。なければ、アドレスを修正するか宛先から削除してください。",
    ack_button: "確認しました — 問題ありません",
    ack_confirmation: "確認しました。準備ができたら送信してください。",
    home_body:
      "ShieldNet 360 がメールを見守ります。下書きを開くと送信前にチェックし、受信メールを読むときも危険なものをお知らせします。設定は不要です。",
    sev_critical: "高リスク",
    sev_high: "要確認",
    sev_medium: "ご注意",
    sev_low: "ご参考",
    open_title_blocked: "このメッセージは危険な可能性があります",
    open_title_high: "フィッシングの可能性があります",
    open_title_warning: "このメッセージにご注意ください",
    open_title_caution: "このメッセージについての簡単なお知らせ",
    open_body_blocked:
      "情報・金銭・パスワードを盗む詐欺の強い兆候があります。",
    open_body_high:
      "信頼している人物や会社になりすましている可能性があります。",
    open_body_warning:
      "通常と異なる点があります。対応する前に、本当の差出人を確認してください。",
    open_body_caution:
      "おそらく問題ありませんが、機密情報を共有する前にご注意ください。",
    open_action_report:
      "リンクのクリックや添付ファイルの開封は避けてください。心当たりがなければ、報告して削除してください。",
    open_action_proceed:
      "読んでも問題ありませんが、確信が持てるまでパスワード・支払い情報・コードは共有しないでください。",
    open_generic_flagged:
      "このメッセージはフラグが付けられました。注意して開いてください。",
  },
  ko: {
    lookalike_recipient:
      "{domain}은(는) 이전에 보낸 적 있는 {ref}과(와) 거의 똑같아 보입니다. {ref}을(를) 의도하셨나요?",
    external_on_internal_thread:
      "지금까지 동료들만 있던 대화에 외부 수신자({domain})를 추가하고 있습니다.",
    did_you_mean: "{suggestion}을(를) 의도하셨나요?",
    safety_check: "ShieldNet 360 보안 점검",
    send_title_lookalike: "이 이메일 주소를 다시 확인하세요",
    send_title_external: "회사 외부 사람에게 메일을 보내고 있습니다",
    send_title_generic: "보내기 전에 잠시 확인하세요",
    send_body_generic: "이 메일을 보내기 전에 한 번 확인해 볼 만한 점을 발견했습니다.",
    send_action:
      "여기 모든 수신자를 알아본다면 보내도 됩니다. 그렇지 않다면 주소를 고치거나 먼저 삭제하세요.",
    ack_button: "확인했습니다 — 맞습니다",
    ack_confirmation: "확인했습니다. 준비되면 보내세요.",
    home_body:
      "ShieldNet 360이 메일을 지켜봅니다. 초안을 열면 보내기 전에 확인하고, 읽을 때 위험한 메시지를 알려드립니다. 설정이 필요 없습니다.",
    sev_critical: "높은 위험",
    sev_high: "확인 권장",
    sev_medium: "참고",
    sev_low: "안내",
    open_title_blocked: "이 메시지는 위험해 보입니다",
    open_title_high: "피싱 시도로 보입니다",
    open_title_warning: "이 메시지에 주의하세요",
    open_title_caution: "이 메시지에 대한 간단한 안내",
    open_body_blocked:
      "정보, 돈 또는 비밀번호를 노리는 사기의 강한 징후가 있습니다.",
    open_body_high:
      "신뢰하는 사람이나 회사를 사칭하고 있을 수 있습니다.",
    open_body_warning:
      "비정상적인 점이 있습니다. 조치하기 전에 실제 보낸 사람을 확인하세요.",
    open_body_caution:
      "괜찮을 가능성이 높지만, 민감한 정보를 공유하기 전에 주의하세요.",
    open_action_report:
      "링크를 클릭하거나 첨부 파일을 열지 마세요. 예상치 못한 메시지라면 신고하고 삭제하세요.",
    open_action_proceed:
      "읽어도 괜찮습니다 — 확실해질 때까지 비밀번호, 결제 정보, 인증 코드는 공유하지 마세요.",
    open_generic_flagged:
      "이 메시지는 플래그가 지정되었습니다 — 주의해서 여세요.",
  },
  zh: {
    lookalike_recipient:
      "{domain} 与您以前发送过的 {ref} 几乎一模一样。您是想发送给 {ref} 吗？",
    external_on_internal_thread:
      "您正在将外部收件人（{domain}）添加到一个至今只有同事参与的会话中。",
    did_you_mean: "您是想发送给 {suggestion} 吗？",
    safety_check: "ShieldNet 360 安全检查",
    send_title_lookalike: "请再次核对这个邮箱地址",
    send_title_external: "您正在给公司以外的人发邮件",
    send_title_generic: "发送前请稍作确认",
    send_body_generic: "在这封邮件发出之前，我们发现有一处值得快速核对。",
    send_action:
      "如果您认识这里的每个人，就可以发送。如果不认识，请先更正地址或将其移除。",
    ack_button: "我已核对 — 没问题",
    ack_confirmation: "已记录。准备好后即可发送。",
    home_body:
      "ShieldNet 360 会留意您的邮件。打开草稿，我们会在发送前检查；阅读邮件时也会标记可疑内容。无需任何设置。",
    sev_critical: "高风险",
    sev_high: "建议核对",
    sev_medium: "提醒",
    sev_low: "供您参考",
    open_title_blocked: "这封邮件看起来很危险",
    open_title_high: "这看起来像是网络钓鱼",
    open_title_warning: "请谨慎对待这封邮件",
    open_title_caution: "关于这封邮件的简短提醒",
    open_body_blocked:
      "它有明显的诈骗迹象，意在窃取信息、钱财或密码。",
    open_body_high: "可能有人在冒充您信任的人或公司。",
    open_body_warning:
      "这里有些异常。在采取行动前，请核实真正的发件人。",
    open_body_caution:
      "可能没问题——只是在分享敏感信息前请保持警惕。",
    open_action_report:
      "不要点击链接或打开附件。如果您没有预料到这封邮件，请举报并删除。",
    open_action_proceed:
      "可以阅读——但在确认之前，请勿分享密码、支付信息或验证码。",
    open_generic_flagged:
      "这封邮件已被标记——请谨慎打开。",
  },
  ar: {
    lookalike_recipient:
      "يبدو {domain} مطابقًا تقريبًا لـ {ref}، وهو عنوان راسلته من قبل. هل تقصد {ref}؟",
    external_on_internal_thread:
      "أنت تضيف مستلِمًا خارجيًا ({domain}) إلى محادثة لم تضم سوى زملائك حتى الآن.",
    did_you_mean: "هل تقصد {suggestion}؟",
    safety_check: "فحص أمان ShieldNet 360",
    send_title_lookalike: "تحقق جيدًا من عنوان البريد هذا",
    send_title_external: "أنت تراسل شخصًا خارج شركتك",
    send_title_generic: "تمهّل لحظة قبل الإرسال",
    send_body_generic:
      "لاحظنا أمرًا يستحق نظرة سريعة قبل إرسال هذه الرسالة.",
    send_action:
      "إذا كنت تعرف كل المستلِمين هنا، يمكنك الإرسال. وإن لم تكن كذلك، فصحّح العنوان أو احذفهم أولًا.",
    ack_button: "لقد تحققت — يبدو صحيحًا",
    ack_confirmation: "تم — سجّلنا ذلك. أرسل عندما تكون جاهزًا.",
    home_body:
      "يراقب ShieldNet 360 بريدك. افتح مسودة وسنفحصها قبل الإرسال، وسننبهك إلى الرسائل الخطيرة أثناء قراءتها. لا حاجة لأي إعداد.",
    sev_critical: "خطر مرتفع",
    sev_high: "يستحق التحقق",
    sev_medium: "تنبيه",
    sev_low: "للعلم",
    open_title_blocked: "تبدو هذه الرسالة خطيرة",
    open_title_high: "يبدو أن هذه محاولة تصيّد احتيالي",
    open_title_warning: "توخَّ الحذر مع هذه الرسالة",
    open_title_caution: "تنبيه سريع بشأن هذه الرسالة",
    open_body_blocked:
      "تحمل علامات قوية على احتيال يهدف إلى سرقة المعلومات أو الأموال أو كلمات المرور.",
    open_body_high:
      "قد يكون أحدهم ينتحل شخصية شخص أو شركة تثق بها.",
    open_body_warning:
      "هناك أمر غير معتاد. تحقق ممن أرسلها فعلًا قبل أن تتصرف.",
    open_body_caution:
      "غالبًا لا بأس بها — لكن كن حذرًا قبل مشاركة أي معلومات حساسة.",
    open_action_report:
      "لا تنقر على الروابط ولا تفتح المرفقات. إذا لم تكن تتوقع هذه الرسالة، فأبلغ عنها واحذفها.",
    open_action_proceed:
      "لا بأس بقراءتها — لكن لا تشارك كلمات المرور أو تفاصيل الدفع أو الرموز حتى تتأكد.",
    open_generic_flagged:
      "تم وضع علامة على هذه الرسالة — افتحها بحذر.",
  },
  de: {
    lookalike_recipient:
      "{domain} sieht fast genauso aus wie {ref}, eine Adresse, an die Sie schon einmal geschrieben haben. Meinten Sie {ref}?",
    external_on_internal_thread:
      "Sie fügen einen externen Empfänger ({domain}) zu einer Unterhaltung hinzu, an der bisher nur Ihre Kolleginnen und Kollegen beteiligt waren.",
    did_you_mean: "Meinten Sie {suggestion}?",
    safety_check: "ShieldNet 360 Sicherheitscheck",
    send_title_lookalike: "Prüfen Sie diese E-Mail-Adresse noch einmal",
    send_title_external: "Sie schreiben jemandem außerhalb Ihres Unternehmens",
    send_title_generic: "Nehmen Sie sich vor dem Senden einen Moment",
    send_body_generic:
      "Uns ist etwas aufgefallen, das vor dem Senden einen kurzen Blick wert ist.",
    send_action:
      "Wenn Sie alle Empfänger kennen, können Sie senden. Andernfalls korrigieren Sie die Adresse oder entfernen Sie sie zuerst.",
    ack_button: "Geprüft — sieht richtig aus",
    ack_confirmation: "Erledigt — notiert. Senden Sie, wenn Sie bereit sind.",
    home_body:
      "ShieldNet 360 behält Ihre E-Mails im Blick. Öffnen Sie einen Entwurf, und wir prüfen ihn vor dem Senden – und markieren riskante Nachrichten beim Lesen. Keine Einrichtung nötig.",
    sev_critical: "Hohes Risiko",
    sev_high: "Bitte prüfen",
    sev_medium: "Hinweis",
    sev_low: "Zur Info",
    open_title_blocked: "Diese Nachricht sieht gefährlich aus",
    open_title_high: "Das sieht nach einem Phishing-Versuch aus",
    open_title_warning: "Seien Sie bei dieser Nachricht vorsichtig",
    open_title_caution: "Ein kurzer Hinweis zu dieser Nachricht",
    open_body_blocked:
      "Sie zeigt deutliche Anzeichen eines Betrugs, der Informationen, Geld oder Passwörter stehlen soll.",
    open_body_high:
      "Möglicherweise gibt sich jemand als eine Person oder ein Unternehmen aus, dem Sie vertrauen.",
    open_body_warning:
      "Etwas ist hier ungewöhnlich. Prüfen Sie, wer die Nachricht wirklich gesendet hat, bevor Sie handeln.",
    open_body_caution:
      "Wahrscheinlich unbedenklich – seien Sie nur vorsichtig, bevor Sie Sensibles teilen.",
    open_action_report:
      "Klicken Sie nicht auf Links und öffnen Sie keine Anhänge. Wenn Sie diese Nachricht nicht erwartet haben, melden und löschen Sie sie.",
    open_action_proceed:
      "Lesen ist in Ordnung – teilen Sie nur keine Passwörter, Zahlungsdaten oder Codes, bis Sie sicher sind.",
    open_generic_flagged:
      "Diese Nachricht wurde markiert – öffnen Sie sie mit Vorsicht.",
  },
  fr: {
    lookalike_recipient:
      "{domain} ressemble à s'y méprendre à {ref}, une adresse à laquelle vous avez déjà écrit. Vouliez-vous dire {ref} ?",
    external_on_internal_thread:
      "Vous ajoutez un destinataire externe ({domain}) à une conversation qui n'incluait que vos collègues jusqu'à présent.",
    did_you_mean: "Vouliez-vous dire {suggestion} ?",
    safety_check: "Contrôle de sécurité ShieldNet 360",
    send_title_lookalike: "Vérifiez bien cette adresse e-mail",
    send_title_external: "Vous écrivez à une personne extérieure à votre entreprise",
    send_title_generic: "Prenez un instant avant d'envoyer",
    send_body_generic:
      "Nous avons remarqué un détail à vérifier rapidement avant l'envoi de ce message.",
    send_action:
      "Si vous reconnaissez tous les destinataires, vous pouvez envoyer. Sinon, corrigez l'adresse ou retirez-les d'abord.",
    ack_button: "J'ai vérifié — c'est correct",
    ack_confirmation: "C'est noté. Envoyez quand vous êtes prêt.",
    home_body:
      "ShieldNet 360 veille sur vos e-mails. Ouvrez un brouillon et nous le vérifierons avant l'envoi — et nous signalerons les messages à risque pendant que vous les lisez. Aucune configuration requise.",
    sev_critical: "Risque élevé",
    sev_high: "À vérifier",
    sev_medium: "À noter",
    sev_low: "Pour information",
    open_title_blocked: "Ce message semble dangereux",
    open_title_high: "Cela ressemble à une tentative d'hameçonnage",
    open_title_warning: "Soyez prudent avec ce message",
    open_title_caution: "Une petite mise en garde à propos de ce message",
    open_body_blocked:
      "Il présente de forts signes d'une arnaque visant à voler des informations, de l'argent ou des mots de passe.",
    open_body_high:
      "Quelqu'un se fait peut-être passer pour une personne ou une entreprise de confiance.",
    open_body_warning:
      "Quelque chose d'inhabituel ici. Vérifiez qui l'a réellement envoyé avant d'agir.",
    open_body_caution:
      "C'est probablement sans danger — restez simplement vigilant avant de partager des informations sensibles.",
    open_action_report:
      "Ne cliquez pas sur les liens et n'ouvrez pas les pièces jointes. Si vous n'attendiez pas ce message, signalez-le et supprimez-le.",
    open_action_proceed:
      "Vous pouvez le lire — ne partagez simplement pas de mots de passe, d'informations de paiement ou de codes avant d'être sûr.",
    open_generic_flagged:
      "Ce message a été signalé — ouvrez-le avec précaution.",
  },
  es: {
    lookalike_recipient:
      "{domain} se parece muchísimo a {ref}, una dirección a la que ya has escrito. ¿Querías decir {ref}?",
    external_on_internal_thread:
      "Estás añadiendo un destinatario externo ({domain}) a una conversación en la que hasta ahora solo participaban tus compañeros.",
    did_you_mean: "¿Querías decir {suggestion}?",
    safety_check: "Comprobación de seguridad de ShieldNet 360",
    send_title_lookalike: "Vuelve a comprobar esta dirección de correo",
    send_title_external: "Estás escribiendo a alguien de fuera de tu empresa",
    send_title_generic: "Tómate un momento antes de enviar",
    send_body_generic:
      "Hemos detectado algo que conviene revisar antes de enviar este mensaje.",
    send_action:
      "Si reconoces a todos los destinatarios, puedes enviar. Si no, corrige la dirección o quítalos primero.",
    ack_button: "Lo he comprobado — está bien",
    ack_confirmation: "Hecho — lo anotamos. Envía cuando quieras.",
    home_body:
      "ShieldNet 360 vigila tu correo. Abre un borrador y lo revisaremos antes de enviar, y marcaremos los mensajes de riesgo mientras los lees. Sin configuración.",
    sev_critical: "Riesgo alto",
    sev_high: "Conviene comprobar",
    sev_medium: "Aviso",
    sev_low: "Para tu información",
    open_title_blocked: "Este mensaje parece peligroso",
    open_title_high: "Esto parece un intento de phishing",
    open_title_warning: "Ten cuidado con este mensaje",
    open_title_caution: "Un aviso rápido sobre este mensaje",
    open_body_blocked:
      "Tiene claros indicios de una estafa creada para robar información, dinero o contraseñas.",
    open_body_high:
      "Puede que alguien se esté haciendo pasar por una persona o empresa de confianza.",
    open_body_warning:
      "Hay algo inusual aquí. Comprueba quién lo envió realmente antes de actuar.",
    open_body_caution:
      "Probablemente no haya problema, pero mantente alerta antes de compartir algo sensible.",
    open_action_report:
      "No hagas clic en enlaces ni abras adjuntos. Si no esperabas este mensaje, denúncialo y elimínalo.",
    open_action_proceed:
      "Puedes leerlo, pero no compartas contraseñas, datos de pago ni códigos hasta estar seguro.",
    open_generic_flagged:
      "Este mensaje se ha marcado: ábrelo con cuidado.",
  },
  pt: {
    lookalike_recipient:
      "{domain} parece quase idêntico a {ref}, um endereço para o qual você já enviou. Você quis dizer {ref}?",
    external_on_internal_thread:
      "Você está adicionando um destinatário externo ({domain}) a uma conversa que até agora só incluía seus colegas.",
    did_you_mean: "Você quis dizer {suggestion}?",
    safety_check: "Verificação de segurança do ShieldNet 360",
    send_title_lookalike: "Confira novamente este endereço de e-mail",
    send_title_external: "Você está enviando para alguém de fora da sua empresa",
    send_title_generic: "Reserve um momento antes de enviar",
    send_body_generic:
      "Notamos algo que vale uma verificação rápida antes de enviar esta mensagem.",
    send_action:
      "Se você reconhece todos os destinatários, pode enviar. Caso contrário, corrija o endereço ou remova-os primeiro.",
    ack_button: "Eu verifiquei — está certo",
    ack_confirmation: "Pronto — anotado. Envie quando estiver pronto.",
    home_body:
      "O ShieldNet 360 fica de olho no seu e-mail. Abra um rascunho e nós o verificaremos antes do envio — e sinalizaremos mensagens arriscadas enquanto você lê. Sem configuração.",
    sev_critical: "Risco alto",
    sev_high: "Vale conferir",
    sev_medium: "Atenção",
    sev_low: "Para sua informação",
    open_title_blocked: "Esta mensagem parece perigosa",
    open_title_high: "Isto parece uma tentativa de phishing",
    open_title_warning: "Tenha cuidado com esta mensagem",
    open_title_caution: "Um aviso rápido sobre esta mensagem",
    open_body_blocked:
      "Ela tem fortes sinais de um golpe criado para roubar informações, dinheiro ou senhas.",
    open_body_high:
      "Alguém pode estar se passando por uma pessoa ou empresa em que você confia.",
    open_body_warning:
      "Há algo incomum aqui. Verifique quem realmente enviou antes de agir.",
    open_body_caution:
      "Provavelmente está tudo bem — apenas fique atento antes de compartilhar algo sensível.",
    open_action_report:
      "Não clique em links nem abra anexos. Se você não esperava esta mensagem, denuncie e exclua.",
    open_action_proceed:
      "Pode ler — só não compartilhe senhas, dados de pagamento ou códigos até ter certeza.",
    open_generic_flagged:
      "Esta mensagem foi sinalizada — abra-a com cuidado.",
  },
  ms: {
    lookalike_recipient:
      "{domain} kelihatan hampir sama dengan {ref}, alamat yang pernah anda hantar sebelum ini. Adakah anda maksudkan {ref}?",
    external_on_internal_thread:
      "Anda sedang menambah penerima luar ({domain}) ke dalam perbualan yang setakat ini hanya melibatkan rakan sekerja anda.",
    did_you_mean: "Adakah anda maksudkan {suggestion}?",
    safety_check: "Pemeriksaan keselamatan ShieldNet 360",
    send_title_lookalike: "Semak semula alamat e-mel ini",
    send_title_external: "Anda menghantar e-mel kepada seseorang di luar syarikat anda",
    send_title_generic: "Luangkan seketika sebelum menghantar",
    send_body_generic:
      "Kami perasan sesuatu yang wajar disemak sebentar sebelum mesej ini dihantar.",
    send_action:
      "Jika anda mengenali semua penerima di sini, anda boleh menghantar. Jika tidak, betulkan alamat atau keluarkan mereka dahulu.",
    ack_button: "Saya sudah semak — nampak betul",
    ack_confirmation: "Selesai — kami catat. Hantar apabila anda sedia.",
    home_body:
      "ShieldNet 360 memerhati e-mel anda. Buka draf dan kami akan menyemaknya sebelum anda menghantar — dan menandai mesej berisiko semasa anda membaca. Tiada persediaan diperlukan.",
    sev_critical: "Risiko tinggi",
    sev_high: "Patut disemak",
    sev_medium: "Perhatian",
    sev_low: "Untuk makluman",
    open_title_blocked: "Mesej ini kelihatan berbahaya",
    open_title_high: "Ini kelihatan seperti percubaan pancingan data",
    open_title_warning: "Berhati-hati dengan mesej ini",
    open_title_caution: "Peringatan ringkas tentang mesej ini",
    open_body_blocked:
      "Ia menunjukkan tanda kuat penipuan yang direka untuk mencuri maklumat, wang atau kata laluan.",
    open_body_high:
      "Seseorang mungkin menyamar sebagai orang atau syarikat yang anda percayai.",
    open_body_warning:
      "Ada sesuatu yang luar biasa di sini. Sahkan siapa sebenarnya yang menghantar sebelum bertindak.",
    open_body_caution:
      "Mungkin tiada masalah — cuma berwaspada sebelum berkongsi maklumat sensitif.",
    open_action_report:
      "Jangan klik pautan atau buka lampiran. Jika anda tidak menjangkakan mesej ini, laporkan dan padamkannya.",
    open_action_proceed:
      "Anda boleh membacanya — cuma jangan kongsi kata laluan, butiran pembayaran atau kod sehingga anda pasti.",
    open_generic_flagged:
      "Mesej ini telah ditandai — bukanya dengan berhati-hati.",
  },
  id: {
    lookalike_recipient:
      "{domain} terlihat hampir sama dengan {ref}, alamat yang pernah Anda kirimi sebelumnya. Apakah maksud Anda {ref}?",
    external_on_internal_thread:
      "Anda menambahkan penerima eksternal ({domain}) ke percakapan yang sampai sekarang hanya melibatkan rekan kerja Anda.",
    did_you_mean: "Apakah maksud Anda {suggestion}?",
    safety_check: "Pemeriksaan keamanan ShieldNet 360",
    send_title_lookalike: "Periksa kembali alamat email ini",
    send_title_external: "Anda mengirim email ke seseorang di luar perusahaan Anda",
    send_title_generic: "Luangkan waktu sejenak sebelum mengirim",
    send_body_generic:
      "Kami menemukan sesuatu yang sebaiknya diperiksa sebelum pesan ini dikirim.",
    send_action:
      "Jika Anda mengenali semua penerima di sini, Anda bisa mengirim. Jika tidak, perbaiki alamatnya atau hapus mereka terlebih dahulu.",
    ack_button: "Saya sudah memeriksa — sudah benar",
    ack_confirmation: "Selesai — kami catat. Kirim saat Anda siap.",
    home_body:
      "ShieldNet 360 mengawasi email Anda. Buka draf dan kami akan memeriksanya sebelum Anda mengirim — dan menandai pesan berisiko saat Anda membaca. Tanpa pengaturan.",
    sev_critical: "Risiko tinggi",
    sev_high: "Perlu diperiksa",
    sev_medium: "Perhatian",
    sev_low: "Sebagai informasi",
    open_title_blocked: "Pesan ini tampak berbahaya",
    open_title_high: "Ini tampak seperti upaya phishing",
    open_title_warning: "Berhati-hatilah dengan pesan ini",
    open_title_caution: "Pemberitahuan singkat tentang pesan ini",
    open_body_blocked:
      "Pesan ini menunjukkan tanda kuat penipuan untuk mencuri informasi, uang, atau kata sandi.",
    open_body_high:
      "Seseorang mungkin menyamar sebagai orang atau perusahaan yang Anda percaya.",
    open_body_warning:
      "Ada yang tidak biasa di sini. Pastikan siapa yang benar-benar mengirim sebelum bertindak.",
    open_body_caution:
      "Mungkin tidak apa-apa — tetap waspada sebelum membagikan informasi sensitif.",
    open_action_report:
      "Jangan klik tautan atau buka lampiran. Jika Anda tidak mengharapkan pesan ini, laporkan dan hapus.",
    open_action_proceed:
      "Boleh dibaca — hanya saja jangan bagikan kata sandi, detail pembayaran, atau kode sampai Anda yakin.",
    open_generic_flagged:
      "Pesan ini telah ditandai — buka dengan hati-hati.",
  },
  tr: {
    lookalike_recipient:
      "{domain}, daha önce yazıştığınız {ref} adresine neredeyse birebir benziyor. {ref} demek mi istediniz?",
    external_on_internal_thread:
      "Şimdiye kadar yalnızca iş arkadaşlarınızın bulunduğu bir konuşmaya harici bir alıcı ({domain}) ekliyorsunuz.",
    did_you_mean: "{suggestion} demek mi istediniz?",
    safety_check: "ShieldNet 360 güvenlik kontrolü",
    send_title_lookalike: "Bu e-posta adresini bir kez daha kontrol edin",
    send_title_external: "Şirketinizin dışından birine e-posta gönderiyorsunuz",
    send_title_generic: "Göndermeden önce bir an durun",
    send_body_generic:
      "Bu mesaj gönderilmeden önce hızlıca göz atmaya değer bir şey fark ettik.",
    send_action:
      "Buradaki herkesi tanıyorsanız gönderebilirsiniz. Tanımıyorsanız adresi düzeltin veya onları önce çıkarın.",
    ack_button: "Kontrol ettim — doğru görünüyor",
    ack_confirmation: "Tamam — not aldık. Hazır olduğunuzda gönderin.",
    home_body:
      "ShieldNet 360 e-postanıza göz kulak olur. Bir taslak açın, göndermeden önce kontrol edelim — okurken riskli iletileri de işaretleriz. Kurulum gerekmez.",
    sev_critical: "Yüksek risk",
    sev_high: "Kontrol edilmeli",
    sev_medium: "Uyarı",
    sev_low: "Bilginize",
    open_title_blocked: "Bu ileti tehlikeli görünüyor",
    open_title_high: "Bu bir kimlik avı girişimine benziyor",
    open_title_warning: "Bu iletiye dikkat edin",
    open_title_caution: "Bu ileti hakkında kısa bir hatırlatma",
    open_body_blocked:
      "Bilgi, para veya parolaları çalmak için tasarlanmış bir dolandırıcılığın güçlü işaretlerini taşıyor.",
    open_body_high:
      "Biri güvendiğiniz bir kişi veya şirket gibi davranıyor olabilir.",
    open_body_warning:
      "Burada olağan dışı bir şey var. Harekete geçmeden önce gerçekte kimin gönderdiğini doğrulayın.",
    open_body_caution:
      "Muhtemelen sorun yok — yalnızca hassas bilgileri paylaşmadan önce dikkatli olun.",
    open_action_report:
      "Bağlantılara tıklamayın, ekleri açmayın. Bu iletiyi beklemiyorduysanız bildirin ve silin.",
    open_action_proceed:
      "Okuyabilirsiniz — yalnızca emin olana kadar parola, ödeme bilgisi veya kod paylaşmayın.",
    open_generic_flagged:
      "Bu ileti işaretlendi — dikkatli açın.",
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
