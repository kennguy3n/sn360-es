/*
 * SN360 Outlook Pre-Open Add-in
 *
 * Calls /v1/predict/open with the message's pseudonymised ID + tier as
 * exported by the SN360 banner injector. For Warning+ tier messages we
 * render a plain-language, ShieldNet 360-branded infobar before the
 * user reads the body: what's risky, why it matters, and the one safe
 * action to take. We never block the user from reading — we only make
 * the risk legible.
 */
/* global Office, fetch */
(function () {
  "use strict";

  const API_BASE = (typeof window !== "undefined" && window.SN360_API_BASE) || "https://api.sn360.example.com";
  const TIMEOUT_MS = 250;

  // Product brand name. The end user only ever sees plain language —
  // never the internal "SN360" code-name, tier numbers, or category
  // codes.
  const BRAND = "ShieldNet 360";

  // === Localization =======================================================
  //
  // Pre-open copy for the 14 supported SN360 languages, keyed on the
  // 2-letter language subtag of Office.context.displayLanguage. Keep the
  // key set identical across every bundle; t() falls back to English for
  // any unrecognised subtag or missing key.
  const I18N = {
    en: {
      safety_check: "ShieldNet 360 safety check",
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
    },
    vi: {
      safety_check: "Kiểm tra an toàn ShieldNet 360",
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
    },
    th: {
      safety_check: "การตรวจสอบความปลอดภัย ShieldNet 360",
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
    },
    ja: {
      safety_check: "ShieldNet 360 セーフティチェック",
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
    },
    ko: {
      safety_check: "ShieldNet 360 보안 점검",
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
    },
    zh: {
      safety_check: "ShieldNet 360 安全检查",
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
    },
    ar: {
      safety_check: "فحص أمان ShieldNet 360",
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
    },
    de: {
      safety_check: "ShieldNet 360 Sicherheitscheck",
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
    },
    fr: {
      safety_check: "Contrôle de sécurité ShieldNet 360",
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
    },
    es: {
      safety_check: "Comprobación de seguridad de ShieldNet 360",
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
    },
    pt: {
      safety_check: "Verificação de segurança do ShieldNet 360",
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
    },
    ms: {
      safety_check: "Pemeriksaan keselamatan ShieldNet 360",
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
    },
    id: {
      safety_check: "Pemeriksaan keamanan ShieldNet 360",
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
    },
    tr: {
      safety_check: "ShieldNet 360 güvenlik kontrolü",
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
    },
  };

  function localeShort() {
    try {
      if (typeof Office !== "undefined" && Office.context && Office.context.displayLanguage) {
        return String(Office.context.displayLanguage).substring(0, 2).toLowerCase();
      }
    } catch (_) {
      /* fall through */
    }
    return "en";
  }

  function t(key) {
    const lang = I18N[localeShort()] || I18N.en;
    return lang[key] || I18N.en[key] || key;
  }

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
      // Split on the first "=" only so future values containing "="
      // (e.g. base64-encoded pseudo_message_ids) aren't silently
      // dropped.
      var eq = parts[i].indexOf("=");
      if (eq <= 0) continue;
      var key = parts[i].substring(0, eq).trim().toLowerCase();
      var val = parts[i].substring(eq + 1).trim();
      if (key === "tier") meta.tier = val;
      else if (key === "category") meta.category = val;
      else if (key === "pmid") meta.pseudo_message_id = val;
    }
    return meta;
  }

  function readBannerMeta(item) {
    // The banner injector embeds (tier, category, pseudo_message_id)
    // in an X-SN360-Banner internet header. The add-in surfaces it
    // via the Office.js InternetHeaders API (requires Mailbox 1.8+;
    // the manifest pins minVersion=1.10 for InternetHeaders.getAsync
    // stability across Outlook on the web / desktop / mobile).
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

  // Map the banner tier to a single, consistent severity ramp shared
  // with the Gmail add-on, and to the plain-language title / why / "what
  // to do" copy. Returns null for tiers we don't warn on so the caller
  // can fall back to the server-supplied message.
  function presentationForTier(tier) {
    var key = String(tier || "").toLowerCase();
    if (key === "blocked" || key === "block") {
      return {
        titleKey: "open_title_blocked",
        bodyKey: "open_body_blocked",
        actionKey: "open_action_report",
        dangerous: true,
      };
    }
    if (key === "high_risk" || key === "high") {
      return {
        titleKey: "open_title_high",
        bodyKey: "open_body_high",
        actionKey: "open_action_report",
        dangerous: true,
      };
    }
    if (key === "warning" || key === "warn") {
      return {
        titleKey: "open_title_warning",
        bodyKey: "open_body_warning",
        actionKey: "open_action_proceed",
        dangerous: false,
      };
    }
    if (key === "caution") {
      return {
        titleKey: "open_title_caution",
        bodyKey: "open_body_caution",
        actionKey: "open_action_proceed",
        dangerous: false,
      };
    }
    return null;
  }

  function presentWarning(eventArgs, resp, tier) {
    if (!resp || !resp.show_warning) {
      if (eventArgs && eventArgs.completed) eventArgs.completed();
      return;
    }
    // Prefer our plain-language, brand-consistent copy keyed on the
    // tier. If the tier is unknown we fall back to whatever message the
    // server supplied so we never show an empty banner.
    var pres = presentationForTier(tier || resp.tier);
    var headline;
    var dangerous;
    if (pres) {
      headline = t(pres.titleKey) + ": " + t(pres.actionKey);
      dangerous = pres.dangerous;
    } else {
      headline = resp.message || "This message has been flagged. Open with care.";
      dangerous = true;
    }
    // The notification strip is system-rendered (no custom colour) and
    // capped at ~150 chars; we lead with the brand + plain headline so
    // the most useful guidance survives truncation.
    var strip = BRAND + " — " + headline;
    if (strip.length > 150) strip = strip.substring(0, 147) + "...";
    try {
      // Dangerous tiers use ErrorMessage (Outlook paints its own red
      // glyph); calmer tiers use a persistent InformationalMessage with
      // our brand icon. Office.js only honours `icon`/`persistent` on
      // InformationalMessage, so we omit them from the ErrorMessage
      // payload rather than ship properties the host ignores.
      var details = dangerous
        ? {
            type: Office.MailboxEnums.ItemNotificationMessageType.ErrorMessage,
            message: strip,
          }
        : {
            type: Office.MailboxEnums.ItemNotificationMessageType.InformationalMessage,
            message: strip,
            icon: "icon-color",
            persistent: true,
          };
      Office.context.mailbox.item.notificationMessages.replaceAsync("sn360-preopen", details);
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
      presentWarning(eventArgs, resp, meta.tier);
    } catch (_) {
      eventArgs.completed();
    }
  }

  if (typeof Office !== "undefined" && Office.actions) {
    Office.actions.associate("sn360-on-message-read", onMessageRead);
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { presentWarning, presentationForTier, t };
  }
})();
