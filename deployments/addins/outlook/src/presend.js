/*
 * SN360 Outlook Pre-Send Add-in (WS-7b)
 *
 * Implements the three pre-send flows from PRODUCT_PLAN.md §7b:
 *
 *   1. Recipient risk check (To/Cc/Bcc)
 *      Hashes each recipient's email + tenant context and POSTs the
 *      bundle to /v1/predict/recipient. High-risk responses surface a
 *      warning via Office.context.mailbox.item.notificationMessages
 *      and require user confirmation before allowing the send (the
 *      manifest declares a smart-alert dialog which Outlook renders
 *      when we resolve the event with allowEvent: false).
 *
 *   2. Lookalike domain detection (client-side)
 *      Real Damerau-Levenshtein (Optimal String Alignment) distance
 *      computation against the user's known-domains set, seeded with
 *      the sender's own domain and augmented with conversation
 *      participants and previously-seen recipients (cached in
 *      Office.context.mailbox.item.sessionData with a 1-hour TTL).
 *      Recipient domains within distance <= 2 (but not exactly
 *      matching) of a known domain are flagged with a "did you mean"
 *      suggestion.
 *
 *   3. External-thread-going-external warning
 *      On the first event we observe in this compose session (either
 *      messageRecipientsChanged or messageSending), we capture the
 *      current To/Cc/Bcc as the "baseline" for this conversationId
 *      and cache it in sessionData. On send, if every domain in the
 *      baseline matches the sender's domain (internal-only thread)
 *      but the current draft has at least one external domain not
 *      present in the baseline, we warn.
 *
 * Performance budget:
 *   Office.js gives the pre-send handler a 30-second hard timeout.
 *   Our network call uses a 250 ms abort timeout, falls open on
 *   error, and re-uses cached responses within the compose session;
 *   the Damerau-Levenshtein check is O(D * m * n) for D known
 *   domains and m, n <= ~50 chars per domain (typical D < 50 ⇒
 *   well under 5 ms total); the only unbounded latency is
 *   user-think-time inside the warning dialog, after which Outlook
 *   resolves the event with allowEvent: true on user confirmation.
 *
 * Privacy:
 *   No raw email addresses leave the mailbox. Each recipient is
 *   SHA-256-pseudonymised (tenant|lowercased-email) before being
 *   attached to the predict request. Domains are sent in cleartext
 *   because they're not PII and the server needs them for the
 *   lookalike index.
 */
/* global Office, fetch, crypto */
(function () {
  "use strict";

  // === Constants ===========================================================

  const API_BASE =
    (typeof window !== "undefined" && window.SN360_API_BASE) ||
    "https://api.sn360.example.com";

  // Network timeout. We target a 250 ms p95 on /v1/predict/recipient
  // and fail-open on transport errors so a slow network never blocks
  // a legitimate send.
  const TIMEOUT_MS = 250;

  // Soft TTL for sessionData entries. sessionData is already scoped
  // to the compose item, but a long-lived compose window shouldn't
  // trust an hours-old predict response or domain cache.
  const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

  // Distance <= 2 catches single-character substitutions, inserts,
  // deletes, and adjacent transpositions ("gmial.com" ↔ "gmail.com")
  // without false-positive flooding on legitimate similar domains.
  const MAX_LOOKALIKE_DISTANCE = 2;

  // sessionData keys.
  const SK_PREDICT_PREFIX = "sn360.predict.";
  const SK_BASELINE_DOMAINS = "sn360.baseline.domains";
  const SK_BASELINE_CAPTURED = "sn360.baseline.captured";
  const SK_KNOWN_DOMAINS = "sn360.known.domains";

  // === Identity helpers ====================================================

  function safeMailbox() {
    if (typeof Office === "undefined" || !Office.context || !Office.context.mailbox) {
      return null;
    }
    return Office.context.mailbox;
  }

  function tenantId() {
    const mb = safeMailbox();
    if (!mb) return "";
    const email = (mb.userProfile && mb.userProfile.emailAddress) || "";
    const at = email.indexOf("@");
    return at < 0 ? "outlook" : email.substring(at + 1).toLowerCase();
  }

  function senderEmail() {
    const mb = safeMailbox();
    if (!mb) return "";
    return (mb.userProfile && mb.userProfile.emailAddress) || "";
  }

  function localeShort() {
    try {
      if (typeof Office === "undefined" || !Office.context) return "en";
      const raw = Office.context.displayLanguage || "en";
      return String(raw).substring(0, 2).toLowerCase();
    } catch (_) {
      return "en";
    }
  }

  // === Hashing =============================================================

  async function sha256Hex(str) {
    const buf = new TextEncoder().encode(String(str));
    const hash = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(hash))
      .map(function (b) {
        return b.toString(16).padStart(2, "0");
      })
      .join("");
  }

  async function hashRecipient(tenant, email) {
    return sha256Hex(tenant + "|" + (email || "").toLowerCase().trim());
  }

  function domainOf(email) {
    if (!email) return "";
    const at = String(email).indexOf("@");
    return at < 0 ? "" : String(email).substring(at + 1).toLowerCase();
  }

  // === Damerau-Levenshtein (Optimal String Alignment) =====================
  //
  // Minimum number of single-character edits (insert/delete/substitute)
  // plus adjacent transpositions to transform `a` into `b`. This is
  // the OSA variant — adjacent transpositions count as a single edit,
  // but a transposed character cannot be re-edited. OSA is sufficient
  // for typo-style lookalike detection at distance <= 2 and matches
  // the behaviour of the MIT-licensed `damerau-levenshtein` npm
  // package; it's used here instead of vendoring an external dep so
  // the add-in stays single-file and dependency-free at deploy time.
  //
  // O(m*n) time and O(m*n) space. For domain strings (avg ~15 chars)
  // this is < 1 ms per comparison; with the length-difference early
  // exit below, checking 50 known domains takes < 5 ms total.
  function damerauLevenshtein(a, b) {
    a = String(a);
    b = String(b);
    if (a === b) return 0;
    if (!a) return b.length;
    if (!b) return a.length;
    const m = a.length;
    const n = b.length;
    const d = new Array(m + 1);
    for (let i = 0; i <= m; i++) {
      d[i] = new Array(n + 1).fill(0);
      d[i][0] = i;
    }
    for (let j = 0; j <= n; j++) {
      d[0][j] = j;
    }
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
        d[i][j] = Math.min(
          d[i - 1][j] + 1, // deletion
          d[i][j - 1] + 1, // insertion
          d[i - 1][j - 1] + cost // substitution
        );
        if (
          i > 1 &&
          j > 1 &&
          a.charCodeAt(i - 1) === b.charCodeAt(j - 2) &&
          a.charCodeAt(i - 2) === b.charCodeAt(j - 1)
        ) {
          d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1); // transposition
        }
      }
    }
    return d[m][n];
  }

  // findLookalike returns the closest known domain within
  // MAX_LOOKALIKE_DISTANCE of `domain`, or null if either:
  //   - `domain` is exactly in `knownDomains` (not a lookalike)
  //   - no known domain is within the threshold
  // Length-difference early exit prunes obvious non-matches.
  function findLookalike(domain, knownDomains) {
    if (!domain) return null;
    const d = String(domain).toLowerCase();
    const kd = knownDomains || [];
    if (kd.indexOf(d) >= 0) return null;
    let best = null;
    let bestDist = MAX_LOOKALIKE_DISTANCE + 1;
    for (let i = 0; i < kd.length; i++) {
      const known = kd[i];
      if (!known) continue;
      if (Math.abs(known.length - d.length) > MAX_LOOKALIKE_DISTANCE) continue;
      const dist = damerauLevenshtein(d, known);
      if (dist > 0 && dist <= MAX_LOOKALIKE_DISTANCE && dist < bestDist) {
        best = known;
        bestDist = dist;
      }
    }
    return best;
  }

  // === sessionData helpers ================================================
  //
  // sessionData is a per-compose-item key/value store available on
  // Mailbox 1.11+. We wrap getAsync/setAsync in promises and degrade
  // gracefully on hosts that don't support it.

  function sessionDataAvailable() {
    const mb = safeMailbox();
    return !!(
      mb &&
      mb.item &&
      mb.item.sessionData &&
      typeof mb.item.sessionData.getAsync === "function" &&
      typeof mb.item.sessionData.setAsync === "function"
    );
  }

  function sdGet(key) {
    return new Promise(function (resolve) {
      if (!sessionDataAvailable()) return resolve(null);
      try {
        Office.context.mailbox.item.sessionData.getAsync(key, function (res) {
          if (!res || res.status !== Office.AsyncResultStatus.Succeeded) {
            return resolve(null);
          }
          resolve(res.value == null ? null : res.value);
        });
      } catch (_) {
        resolve(null);
      }
    });
  }

  function sdSet(key, value) {
    return new Promise(function (resolve) {
      if (!sessionDataAvailable()) return resolve(false);
      try {
        Office.context.mailbox.item.sessionData.setAsync(key, value, function (res) {
          resolve(!!(res && res.status === Office.AsyncResultStatus.Succeeded));
        });
      } catch (_) {
        resolve(false);
      }
    });
  }

  async function getCached(key) {
    const raw = await sdGet(key);
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object") return null;
      if (typeof parsed.ts !== "number") return null;
      if (Date.now() - parsed.ts > CACHE_TTL_MS) return null;
      return parsed.value;
    } catch (_) {
      return null;
    }
  }

  async function setCached(key, value) {
    await sdSet(key, JSON.stringify({ ts: Date.now(), value: value }));
  }

  // === Known-domains cache ================================================

  async function loadKnownDomains() {
    const cached = await getCached(SK_KNOWN_DOMAINS);
    if (cached && Array.isArray(cached)) return cached;
    // Seed with the sender's own domain. The full set is augmented as
    // the user types and as we observe baseline conversation
    // participants.
    const seed = [];
    const myDomain = domainOf(senderEmail());
    if (myDomain) seed.push(myDomain);
    await setCached(SK_KNOWN_DOMAINS, seed);
    return seed;
  }

  async function appendKnownDomains(newDomains) {
    const cached = await loadKnownDomains();
    const set = Object.create(null);
    cached.forEach(function (d) {
      if (d) set[d] = true;
    });
    (newDomains || []).forEach(function (d) {
      if (d) set[String(d).toLowerCase()] = true;
    });
    const merged = Object.keys(set);
    await setCached(SK_KNOWN_DOMAINS, merged);
    return merged;
  }

  // === Baseline (conversation) participants ===============================
  //
  // The baseline is the set of domains present at the start of the
  // compose session. For replies, this is the previous reply's
  // recipients (pre-filled by Outlook). For new composes, this is
  // typically empty. We rely on capturing it on the FIRST event we
  // observe (messageRecipientsChanged or messageSending) — the v3
  // short-lifetime runtime doesn't keep in-memory state across
  // events, so the sessionData cache is the only persistence path.

  async function captureBaseline(recipients) {
    const already = await sdGet(SK_BASELINE_CAPTURED);
    if (already) return; // already captured for this compose session
    // Mark captured upfront so concurrent events don't duplicate work.
    await sdSet(SK_BASELINE_CAPTURED, "1");
    // The baseline is only meaningful for replies/forwards, where
    // Outlook pre-fills the recipients with the conversation
    // participants. For new composes there's no prior context, so a
    // captured baseline would be a false signal (we'd treat the
    // user's freshly-typed recipients as if they were "prior thread
    // participants" and never warn). Office.js exposes the
    // conversation context via item.conversationId; an empty string
    // means new compose.
    const mb = safeMailbox();
    const item = mb && mb.item;
    const convId = (item && item.conversationId) || "";
    if (!convId) return;
    const domains = (recipients || [])
      .map(function (r) {
        return domainOf(r.emailAddress);
      })
      .filter(Boolean);
    await sdSet(SK_BASELINE_DOMAINS, JSON.stringify(domains));
  }

  async function loadBaselineDomains() {
    const raw = await sdGet(SK_BASELINE_DOMAINS);
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : null;
    } catch (_) {
      return null;
    }
  }

  // isThreadInternal returns true iff the baseline is non-empty AND
  // every baseline domain matches the sender's own domain (the
  // sender's organisation).
  function isThreadInternal(baselineDomains, myDomain) {
    if (!baselineDomains || baselineDomains.length === 0) return false;
    if (!myDomain) return false;
    for (let i = 0; i < baselineDomains.length; i++) {
      if (baselineDomains[i] !== myDomain) return false;
    }
    return true;
  }

  // === Recipient gathering ================================================
  //
  // gatherRecipients reads To, Cc, AND Bcc (per WS-7b requirement —
  // the previous implementation skipped Bcc and silently let
  // high-risk Bcc'd recipients through).

  function readField(field) {
    return new Promise(function (resolve) {
      if (!field || typeof field.getAsync !== "function") {
        return resolve({ value: [] });
      }
      try {
        field.getAsync(function (res) {
          if (!res || res.status !== Office.AsyncResultStatus.Succeeded) {
            return resolve({ value: [] });
          }
          resolve(res);
        });
      } catch (_) {
        resolve({ value: [] });
      }
    });
  }

  async function gatherRecipients(item) {
    if (!item) return [];
    const to = await readField(item.to);
    const cc = await readField(item.cc);
    const bcc = await readField(item.bcc);
    return [].concat(to.value || [], cc.value || [], bcc.value || []);
  }

  // === Build /v1/predict/recipient request ================================

  async function buildRequest(tenant, sender, recipients, threadIsInternal) {
    const list = [];
    for (const r of recipients || []) {
      const dom = domainOf(r.emailAddress);
      // is_known_contact is intentionally omitted. Office.js's
      // RecipientObject does not expose contact-store membership
      // cheaply enough for the pre-send hot path; sending false here
      // would cause the backend to emit unusual_external_recipient
      // on every external recipient (low-signal noise). The server
      // treats nil as "no signal" and suppresses the warning;
      // server-side contact-store enrichment is the planned home for
      // this signal.
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

  function predictCacheKey(body) {
    // The cache key is the sender hash plus the (sorted) recipient
    // hashes. Sorting makes the key invariant to recipient ordering,
    // so adding a recipient to the middle of the list invalidates
    // the cache the same way as appending one would.
    const rHashes = body.recipients
      .map(function (r) {
        return r.user_hash;
      })
      .slice()
      .sort()
      .join(",");
    return (
      SK_PREDICT_PREFIX +
      body.sender_hash +
      "|" +
      (body.thread_is_internal ? "1" : "0") +
      "|" +
      rHashes
    );
  }

  async function callPredict(body) {
    const key = predictCacheKey(body);
    const cached = await getCached(key);
    if (cached) return cached;
    const controller = new AbortController();
    const timer = setTimeout(function () {
      controller.abort();
    }, TIMEOUT_MS);
    try {
      const r = await fetch(API_BASE + "/v1/predict/recipient", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!r.ok) return { overall_level: 0, warnings: [] };
      const data = await r.json();
      await setCached(key, data);
      return data;
    } catch (_) {
      // Fail-open: transport errors never block legitimate sends.
      return { overall_level: 0, warnings: [] };
    } finally {
      clearTimeout(timer);
    }
  }

  // === Localization =======================================================
  //
  // Initial scope is English-only. The wrapper is locale-aware so
  // future translations can be dropped in without touching call
  // sites. Office.context.displayLanguage gives the IETF tag
  // (e.g. "en-US"); we key on the language subtag.

  const I18N = {
    en: {
      lookalike_recipient:
        "Recipient domain {domain} looks similar to {ref}. Did you mean {ref}?",
      external_on_internal_thread:
        "You're adding an external recipient ({domain}) to a previously internal thread.",
      banner_high: "SN360 warning: ",
      confirm_suffix:
        "\n\nReview the recipient list before resending if this is intentional.",
    },
  };

  function t(key, params) {
    const lang = I18N[localeShort()] || I18N.en;
    let msg = lang[key] || I18N.en[key] || key;
    if (params) {
      for (const k in params) {
        if (Object.prototype.hasOwnProperty.call(params, k)) {
          msg = msg.split("{" + k + "}").join(params[k]);
        }
      }
    }
    return msg;
  }

  // === Combine + render warnings ==========================================

  function combineWarnings(apiResponse, clientWarnings) {
    const out = {
      overall_level: (apiResponse && apiResponse.overall_level) || 0,
      warnings: ((apiResponse && apiResponse.warnings) || []).slice(),
    };
    (clientWarnings || []).forEach(function (w) {
      out.warnings.push(w);
      if (w.level > out.overall_level) out.overall_level = w.level;
    });
    return out;
  }

  function showWarning(eventArgs, response) {
    if (!response || (response.overall_level || 0) < 3) {
      eventArgs.completed({ allowEvent: true });
      return;
    }
    const top =
      (response.warnings && response.warnings[0]) ||
      { message: "Suspicious recipient detected." };
    const banner = t("banner_high") + top.message + t("confirm_suffix");
    try {
      Office.context.mailbox.item.notificationMessages.replaceAsync("sn360-presend", {
        type: Office.MailboxEnums.ItemNotificationMessageType.ErrorMessage,
        // The notification message strip is capped at 150 chars by
        // Outlook; longer messages are silently truncated server-side
        // and look unprofessional. We truncate explicitly so the
        // suffix doesn't get chopped mid-word.
        message: banner.length > 150 ? banner.substring(0, 147) + "..." : banner,
      });
    } catch (_) {
      // Best-effort UI; we never block sends on a UI render error.
    }
    // For Manifest v3 smart-alerts, allowEvent: false causes Outlook
    // to surface the smart-alert dialog declared on the runtime; the
    // user can override and resend, at which point Outlook fires
    // onMessageSend again with the user's confirmation context.
    eventArgs.completed({ allowEvent: false });
  }

  // === Main handlers ======================================================

  async function onMessageSend(eventArgs) {
    try {
      const item = Office.context.mailbox.item;
      const recipients = await gatherRecipients(item);
      if (!recipients.length) {
        eventArgs.completed({ allowEvent: true });
        return;
      }

      // Capture baseline if this is the first event we've seen for
      // this compose session. After this, the baseline is whatever
      // the user already had when the window opened (for replies,
      // that's the prior conversation participants).
      await captureBaseline(recipients);
      const baselineDomains = (await loadBaselineDomains()) || [];
      const myDomain = domainOf(senderEmail());
      const threadInternal = isThreadInternal(baselineDomains, myDomain);

      // Build the lookalike-check set from existing known domains
      // (the sender's own domain + previously-seen non-flagged
      // recipients) plus baseline participants of the current
      // thread. We deliberately do NOT mix in the current draft's
      // recipient domains here — if we did, every recipient would
      // "trust" its own domain and the lookalike check would skip
      // it (since findLookalike treats exact matches as not-a-
      // lookalike).
      const baseKnown = await loadKnownDomains();
      const checkSet = baseKnown.slice();
      baselineDomains.forEach(function (d) {
        if (d && checkSet.indexOf(d) < 0) checkSet.push(d);
      });

      // Client-side lookalike check (in addition to the server-side
      // lookalike index; client-side gives us locale-aware "did you
      // mean" messages and catches typos against the user's *own*
      // history even when the server's tenant lookalike index hasn't
      // seen the comparison yet).
      const clientWarnings = [];
      const seenLookalikeUserHashes = Object.create(null);
      const flaggedDomains = Object.create(null);
      for (const r of recipients) {
        const dom = domainOf(r.emailAddress);
        if (!dom) continue;
        const hit = findLookalike(dom, checkSet);
        if (hit && hit !== dom) {
          flaggedDomains[dom] = true;
          const userHash = await hashRecipient(tenantId(), r.emailAddress);
          if (seenLookalikeUserHashes[userHash]) continue;
          seenLookalikeUserHashes[userHash] = true;
          clientWarnings.push({
            user_hash: userHash,
            level: 4, // WarnHigh
            code: "lookalike_recipient_client",
            message: t("lookalike_recipient", { domain: dom, ref: hit }),
            suggestion: hit,
          });
        }
      }

      // External-thread-going-external check (client side). The
      // server also emits external_on_internal_thread when we set
      // thread_is_internal: true on the request, but we emit the
      // client-side version too so the message is locale-aware and
      // names the specific external domain.
      if (threadInternal) {
        for (const r of recipients) {
          const dom = domainOf(r.emailAddress);
          if (dom && dom !== myDomain && baselineDomains.indexOf(dom) < 0) {
            clientWarnings.push({
              user_hash: await hashRecipient(tenantId(), r.emailAddress),
              level: 3, // WarnWarning
              code: "external_on_internal_thread_client",
              message: t("external_on_internal_thread", { domain: dom }),
            });
            break; // one such warning per send is enough
          }
        }
      }

      // AFTER the lookalike check, persist the non-flagged recipient
      // domains for future sessions. Flagged domains are deliberately
      // NOT persisted — otherwise the user would implicitly "trust" a
      // suspicious domain just by attempting to send to it once.
      const safeRecipientDomains = recipients
        .map(function (r) {
          return domainOf(r.emailAddress);
        })
        .filter(function (d) {
          return d && !flaggedDomains[d];
        });
      await appendKnownDomains(baselineDomains.concat(safeRecipientDomains));

      const body = await buildRequest(
        tenantId(),
        senderEmail(),
        recipients,
        threadInternal
      );
      const apiResponse = await callPredict(body);
      const combined = combineWarnings(apiResponse, clientWarnings);
      showWarning(eventArgs, combined);
    } catch (_) {
      // Fail-open on any unexpected error: never block a legitimate
      // send on an add-in bug.
      eventArgs.completed({ allowEvent: true });
    }
  }

  async function onMessageRecipientsChanged(eventArgs) {
    // Best-effort: try to capture the baseline on the first
    // recipients-changed event we observe. For replies, Outlook
    // pre-fills the recipients before the user makes any change, so
    // the FIRST messageRecipientsChanged after that might already
    // include user edits; capturing here still gives us a tighter
    // baseline than waiting until onMessageSend.
    try {
      const item = Office.context.mailbox.item;
      const recipients = await gatherRecipients(item);
      await captureBaseline(recipients);
    } catch (_) {
      /* best-effort */
    }
    eventArgs.completed();
  }

  // === Wire actions =======================================================

  if (typeof Office !== "undefined" && Office.actions) {
    Office.actions.associate("sn360-on-message-send", onMessageSend);
    Office.actions.associate(
      "sn360-on-message-recipients-changed",
      onMessageRecipientsChanged
    );
  }

  // === Test exports =======================================================

  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      // Public surface (kept stable for downstream callers).
      buildRequest: buildRequest,
      sha256Hex: sha256Hex,
      domainOf: domainOf,
      // New WS-7b surface.
      damerauLevenshtein: damerauLevenshtein,
      findLookalike: findLookalike,
      isThreadInternal: isThreadInternal,
      combineWarnings: combineWarnings,
      onMessageSend: onMessageSend,
      onMessageRecipientsChanged: onMessageRecipientsChanged,
      // Internals exposed for tests only.
      _internals: {
        captureBaseline: captureBaseline,
        loadBaselineDomains: loadBaselineDomains,
        loadKnownDomains: loadKnownDomains,
        appendKnownDomains: appendKnownDomains,
        callPredict: callPredict,
        predictCacheKey: predictCacheKey,
        gatherRecipients: gatherRecipients,
        showWarning: showWarning,
        t: t,
        constants: {
          API_BASE: API_BASE,
          TIMEOUT_MS: TIMEOUT_MS,
          CACHE_TTL_MS: CACHE_TTL_MS,
          MAX_LOOKALIKE_DISTANCE: MAX_LOOKALIKE_DISTANCE,
          SK_PREDICT_PREFIX: SK_PREDICT_PREFIX,
          SK_BASELINE_DOMAINS: SK_BASELINE_DOMAINS,
          SK_BASELINE_CAPTURED: SK_BASELINE_CAPTURED,
          SK_KNOWN_DOMAINS: SK_KNOWN_DOMAINS,
        },
      },
    };
  }
})();
