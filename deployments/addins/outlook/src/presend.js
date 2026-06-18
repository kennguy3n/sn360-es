/*
 * SN360 Outlook Pre-Send Add-in
 *
 * Implements the three pre-send flows:
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

  // sessionData values tolerate ~4 KB but the underlying string ops
  // (and any future move to a stricter store such as a localStorage
  // mirror) are cheaper with bounded keys. With 50 recipients × 64
  // hex chars the joined hash list alone is ~3 KB, so once a draft
  // gets large we collapse the key to its SHA-256.
  const SK_MAX_INLINE_KEY = 240;

  async function predictCacheKey(body) {
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
    const raw =
      SK_PREDICT_PREFIX +
      body.sender_hash +
      "|" +
      (body.thread_is_internal ? "1" : "0") +
      "|" +
      rHashes;
    if (raw.length <= SK_MAX_INLINE_KEY) return raw;
    return SK_PREDICT_PREFIX + (await sha256Hex(raw));
  }

  async function callPredict(body) {
    const key = await predictCacheKey(body);
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
  // The wrapper is locale-aware: Office.context.displayLanguage gives
  // the IETF tag (e.g. "en-US", "pt-BR"); localeShort() keys on the
  // language subtag (e.g. "pt"). Bundles below cover the 14 supported
  // SN360 languages; any unrecognised subtag falls back to English via
  // t(). Keep the key set identical across every bundle.

  const I18N = {
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
      send_action:
        "If you recognise everyone here, you can send. If not, fix the address or remove them first.",
      ack_button: "I've checked — looks right",
      sev_critical: "High risk",
      sev_high: "Worth a check",
      sev_medium: "Heads-up",
      sev_low: "For your awareness",
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
      send_action:
        "Nếu bạn nhận ra tất cả người nhận, bạn có thể gửi. Nếu không, hãy sửa địa chỉ hoặc xóa họ trước.",
      ack_button: "Tôi đã kiểm tra — ổn rồi",
      sev_critical: "Rủi ro cao",
      sev_high: "Nên kiểm tra",
      sev_medium: "Lưu ý",
      sev_low: "Để bạn biết",
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
      send_action:
        "หากคุณรู้จักผู้รับทุกคน คุณสามารถส่งได้ หากไม่ใช่ โปรดแก้ไขที่อยู่หรือเอาออกก่อน",
      ack_button: "ฉันตรวจสอบแล้ว — ดูถูกต้อง",
      sev_critical: "ความเสี่ยงสูง",
      sev_high: "ควรตรวจสอบ",
      sev_medium: "ข้อควรทราบ",
      sev_low: "เพื่อให้คุณทราบ",
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
      send_action:
        "宛先の全員に心当たりがあれば送信できます。なければ、アドレスを修正するか宛先から削除してください。",
      ack_button: "確認しました — 問題ありません",
      sev_critical: "高リスク",
      sev_high: "要確認",
      sev_medium: "ご注意",
      sev_low: "ご参考",
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
      send_action:
        "여기 모든 수신자를 알아본다면 보내도 됩니다. 그렇지 않다면 주소를 고치거나 먼저 삭제하세요.",
      ack_button: "확인했습니다 — 맞습니다",
      sev_critical: "높은 위험",
      sev_high: "확인 권장",
      sev_medium: "참고",
      sev_low: "안내",
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
      send_action:
        "如果您认识这里的每个人，就可以发送。如果不认识，请先更正地址或将其移除。",
      ack_button: "我已核对 — 没问题",
      sev_critical: "高风险",
      sev_high: "建议核对",
      sev_medium: "提醒",
      sev_low: "供您参考",
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
      send_action:
        "إذا كنت تعرف كل المستلِمين هنا، يمكنك الإرسال. وإن لم تكن كذلك، فصحّح العنوان أو احذفهم أولًا.",
      ack_button: "لقد تحققت — يبدو صحيحًا",
      sev_critical: "خطر مرتفع",
      sev_high: "يستحق التحقق",
      sev_medium: "تنبيه",
      sev_low: "للعلم",
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
      send_action:
        "Wenn Sie alle Empfänger kennen, können Sie senden. Andernfalls korrigieren Sie die Adresse oder entfernen Sie sie zuerst.",
      ack_button: "Geprüft — sieht richtig aus",
      sev_critical: "Hohes Risiko",
      sev_high: "Bitte prüfen",
      sev_medium: "Hinweis",
      sev_low: "Zur Info",
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
      send_action:
        "Si vous reconnaissez tous les destinataires, vous pouvez envoyer. Sinon, corrigez l'adresse ou retirez-les d'abord.",
      ack_button: "J'ai vérifié — c'est correct",
      sev_critical: "Risque élevé",
      sev_high: "À vérifier",
      sev_medium: "À noter",
      sev_low: "Pour information",
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
      send_action:
        "Si reconoces a todos los destinatarios, puedes enviar. Si no, corrige la dirección o quítalos primero.",
      ack_button: "Lo he comprobado — está bien",
      sev_critical: "Riesgo alto",
      sev_high: "Conviene comprobar",
      sev_medium: "Aviso",
      sev_low: "Para tu información",
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
      send_action:
        "Se você reconhece todos os destinatários, pode enviar. Caso contrário, corrija o endereço ou remova-os primeiro.",
      ack_button: "Eu verifiquei — está certo",
      sev_critical: "Risco alto",
      sev_high: "Vale conferir",
      sev_medium: "Atenção",
      sev_low: "Para sua informação",
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
      send_action:
        "Jika anda mengenali semua penerima di sini, anda boleh menghantar. Jika tidak, betulkan alamat atau keluarkan mereka dahulu.",
      ack_button: "Saya sudah semak — nampak betul",
      sev_critical: "Risiko tinggi",
      sev_high: "Patut disemak",
      sev_medium: "Perhatian",
      sev_low: "Untuk makluman",
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
      send_action:
        "Jika Anda mengenali semua penerima di sini, Anda bisa mengirim. Jika tidak, perbaiki alamatnya atau hapus mereka terlebih dahulu.",
      ack_button: "Saya sudah memeriksa — sudah benar",
      sev_critical: "Risiko tinggi",
      sev_high: "Perlu diperiksa",
      sev_medium: "Perhatian",
      sev_low: "Sebagai informasi",
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
      send_action:
        "Buradaki herkesi tanıyorsanız gönderebilirsiniz. Tanımıyorsanız adresi düzeltin veya onları önce çıkarın.",
      ack_button: "Kontrol ettim — doğru görünüyor",
      sev_critical: "Yüksek risk",
      sev_high: "Kontrol edilmeli",
      sev_medium: "Uyarı",
      sev_low: "Bilginize",
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

  // The product brand name. Rendered in plain language everywhere a
  // warning surfaces; we never show the internal "SN360" code-name or
  // jargon like tier/level in the UI the end user reads.
  const BRAND = "ShieldNet 360";

  // Strip the "_client" suffix the add-in appends to client-side
  // warnings so client + server variants of the same warning resolve
  // to one plain-language title.
  function baseCode(code) {
    return String(code || "").replace(/_client$/, "");
  }

  // Map an overall warning level to a single, consistent severity ramp
  // shared with the Gmail add-on. Colours mirror the ShieldNet 360
  // brand tokens; Outlook's system notification strip can't render
  // custom colours, so the label carries the meaning there and the
  // colour is used by surfaces that can (the smart-alert markdown
  // honours the host theme).
  function severityFor(level) {
    if (level >= 4) return { label: t("sev_critical"), color: "#e40014" };
    if (level === 3) return { label: t("sev_high"), color: "#ff6900" };
    if (level === 2) return { label: t("sev_medium"), color: "#edb200" };
    return { label: t("sev_low"), color: "#255fe5" };
  }

  // Pick the plain-language headline for the dominant warning. We lead
  // with the most actionable concern (a lookalike address) and fall
  // back to a neutral, reassuring prompt.
  function titleForWarnings(warnings) {
    const codes = (warnings || []).map(function (w) {
      return baseCode(w && w.code);
    });
    if (codes.indexOf("lookalike_recipient") >= 0) {
      return t("send_title_lookalike");
    }
    if (codes.indexOf("external_on_internal_thread") >= 0) {
      return t("send_title_external");
    }
    return t("send_title_generic");
  }

  function showWarning(eventArgs, response) {
    if (!response || (response.overall_level || 0) < 3) {
      eventArgs.completed({ allowEvent: true });
      return;
    }
    const level = response.overall_level || 0;
    const sev = severityFor(level);
    const warnings =
      response.warnings && response.warnings.length
        ? response.warnings
        : [{ message: t("send_title_generic") }];
    const title = titleForWarnings(warnings);
    // A warning object can arrive without a message field (older
    // backend versions or partial responses). Fall back to the plain
    // title rather than rendering an empty detail line.
    const detail = (warnings[0] && warnings[0].message) || title;

    // 1) In-compose notification strip. System-rendered, capped at
    //    ~150 chars and no custom colour, so we lead with the brand +
    //    plain headline and let the detail trail (truncated cleanly).
    const strip = BRAND + " — " + title + ": " + detail;
    try {
      Office.context.mailbox.item.notificationMessages.replaceAsync("sn360-presend", {
        type: Office.MailboxEnums.ItemNotificationMessageType.ErrorMessage,
        message: strip.length > 150 ? strip.substring(0, 147) + "..." : strip,
      });
    } catch (_) {
      // Best-effort UI; we never block sends on a UI render error.
    }

    // 2) Smart-alert dialog. With sendMode "promptUser", allowEvent:
    //    false surfaces a blocking dialog the user can override. We
    //    supply our own plain-language copy (what's risky, why it
    //    matters, the one safe action) via errorMessage, plus a richer
    //    markdown variant for hosts that render it. The user keeps a
    //    clear override path — Outlook's dialog offers "Send anyway".
    const plain = title + "\n\n" + detail + "\n\n" + t("send_action");
    const markdown =
      "**" +
      sev.label +
      " · " +
      title +
      "**\n\n" +
      detail +
      "\n\n*" +
      t("send_action") +
      "*";
    try {
      eventArgs.completed({
        allowEvent: false,
        errorMessage: plain,
        errorMessageMarkdown: markdown,
      });
      return;
    } catch (_) {
      // Older hosts reject the extended options object; fall back to a
      // bare block so we still honour the security decision.
    }
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
