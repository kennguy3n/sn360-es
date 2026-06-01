// tests/load/lib/corpus.js
//
// Adapters between the WS-4b corpus (`scripts/corpus/loadtest/*.json`)
// and the dto.EvaluateRequest the publisher forwards onto NATS. The
// corpus on disk is an array of TestEmail entries; each entry has a
// `payload` field with the realistic sender / recipient / subject /
// body shapes the templates emit (see scripts/corpus_generator/
// templates/templates.go).
//
// We deliberately do NOT regenerate corpus content inside k6 — it
// would force every CI run to redo ~10 MB of expensive template
// work. Instead, `make load-smoke` produces a tiny subset on
// demand, and the long-running scenarios assume the full
// 32,000-row loadtest corpus is on disk already.

import { randInt } from "./seed.js";
// `open()` is a k6-global (init-context-only) — see
// https://k6.io/docs/javascript-api/init-context/open/. It returns
// the file contents as a string, no module import required.

/**
 * loadCorpus reads the loadtest corpus into memory once at init
 * time. It supports both shapes the corpus_generator emits:
 *
 *   * `--output-dir scripts/corpus/loadtest/` produces one JSON file
 *     per category PLUS a combined `all.json`. We always load
 *     `all.json` if present.
 *   * Smoke / CI builds may use a single-file `loadtest.json`
 *     produced by the inline generator in make load-smoke.
 *
 * @param {string} path  filesystem path to the corpus JSON
 * @param {string[]} [notes]  optional sink for fall-back diagnostics.
 *                            Anything we push here lands in the
 *                            result artefact so a reader knows the
 *                            run used the inline mini-corpus.
 * @returns {Array<{tenant_hint?: string, payload: {from: string, to: string, subject: string, body_text: string}}>}
 */
export function loadCorpus(path, notes) {
  // open() throws if the file is missing; default to the inline
  // mini-corpus so a fresh checkout still produces a working smoke
  // run, and record a one-line note (not a per-VU warning) so the
  // artefact tells a reader the corpus was synthesised.
  let raw = null;
  try {
    raw = open(path);
  } catch (e) {
    if (notes && notes.indexOf("corpus-fallback") === -1) {
      notes.push(
        `corpus-fallback: ${path} not found (${e}); using inline 8-row mini-corpus. ` +
          `Regenerate via the load-corpus generator documented in scripts/corpus/loadtest/README.md.`,
      );
      notes.push("corpus-fallback");
    }
    return INLINE_FALLBACK;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error(`loadCorpus: parse ${path}: ${e}`);
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error(
      `loadCorpus: ${path} is empty or not an array (got ${typeof parsed})`,
    );
  }
  return parsed;
}

/**
 * pickEmail returns one realistic message envelope, deterministic
 * for a given (rand, iteration) pair.
 *
 * @param {Array} corpus     output of loadCorpus()
 * @param {() => number} rand mulberry32 closure
 * @returns {{from: string, to: string, subject: string, body: string, attackType: string|undefined}}
 */
export function pickEmail(corpus, rand) {
  const idx = randInt(rand, corpus.length);
  const row = corpus[idx];
  const p = row.payload || {};
  return {
    from: p.from || "sender@loadgen.test",
    to: p.to || "recipient@loadgen.test",
    subject: p.subject || "loadgen",
    body: p.body_text || "",
    attackType: row.attack_type,
    category: row.category,
  };
}

/**
 * buildPayload builds a single dto.EvaluateRequest the publisher
 * forwards onto NATS. Every field maps 1:1 to
 * internal/dto/evaluate.go so the consumer accepts it without a
 * schema bump.
 *
 *   * MessageID is per-iteration unique. We prefix with `loadgen-`
 *     so production observability dashboards can filter the
 *     synthetic traffic out.
 *   * Sender/Recipient reuse the corpus addresses but rewrite the
 *     recipient domain to the tenant's primary_domain so the
 *     management consumer's tenant routing resolves cleanly.
 *
 * @param {{scenario: string}} cfg     loadConfig() output
 * @param {string} tenantID            UUID-shaped tenant identifier
 * @param {{from,to,subject,body}} env corpus pick
 * @param {number} iteration           per-VU iteration sequence
 * @returns {object}                   dto.EvaluateRequest shape
 */
export function buildPayload(cfg, tenantID, env, iteration) {
  const msgID = `loadgen-${cfg.scenario}-${tenantID}-${iteration}-${Date.now()}`;
  const recipient = rewriteRecipient(env.to, tenantID);
  return {
    message_id: msgID,
    tenant_id: tenantID,
    correlation_id: `loadgen-${cfg.scenario}-${iteration}`,
    sender: env.from,
    recipient,
    cc: [],
    subject: env.subject,
    body: env.body,
    raw_body_hash: "",
    normalised_hash: "",
    signals: {},
    locale: "en",
    received_at: new Date().toISOString(),
  };
}

/**
 * rewriteRecipient swaps the corpus recipient's domain for one
 * derived from the tenant ID so each tenant has a recognisable
 * inbox in the management Postgres tables. We deliberately don't
 * touch the local-part — preserving the corpus' "alice", "bob",
 * "exec01" etc. keeps the realism intact.
 */
function rewriteRecipient(addr, tenantID) {
  const at = addr.lastIndexOf("@");
  const local = at >= 0 ? addr.slice(0, at) : addr;
  // tenantID is 36 chars; use the last 12 hex chars as a short
  // tenant slug so the recipient is human-readable in logs.
  const slug = tenantID.slice(-12);
  return `${local}@t-${slug}.loadgen.test`;
}

/**
 * verifyCorpus throws if the corpus is shaped wrong. This runs in
 * init context (before VUs spin up) so we can't use k6's `check()`
 * helper — it's restricted to VU code. A throw aborts the run
 * before any traffic hits the dev publisher, which is exactly what
 * we want when the corpus path is misconfigured.
 */
export function verifyCorpus(corpus) {
  if (!Array.isArray(corpus) || corpus.length === 0) {
    throw new Error(
      `verifyCorpus: expected non-empty array, got ${
        Array.isArray(corpus) ? "[]" : typeof corpus
      }`,
    );
  }
  const head = corpus[0];
  if (!head || !head.payload || typeof head.payload !== "object") {
    throw new Error(
      `verifyCorpus: first row missing payload object (got keys: ${
        head ? Object.keys(head).join(",") : "null"
      })`,
    );
  }
  return true;
}

// INLINE_FALLBACK is the 8-row mini-corpus shipped inside this file
// so that a fresh checkout can run `make load-smoke` against the dev
// stack without requiring a corpus regeneration step first. The
// rows mimic real malicious / benign category mixes — they should
// not be relied on for accuracy testing, but they exercise the
// pipeline end-to-end.
const INLINE_FALLBACK = [
  {
    test_id: "fallback-benign-internal",
    category: "benign_internal",
    attack_type: "benign",
    payload: {
      from: "alice@loadgen.test",
      to: "bob@loadgen.test",
      subject: "Tuesday status",
      body_text:
        "Hi team — here's the rollup for Tuesday. We're on track for the milestone.",
    },
  },
  {
    test_id: "fallback-credential-phishing",
    category: "credential_phishing",
    attack_type: "credential_phishing",
    payload: {
      from: "it-security@suspicious-domain.test",
      to: "carol@loadgen.test",
      subject: "Action required: re-verify your password",
      body_text:
        "Your account will be suspended in 24 hours. Click here to confirm: http://phish.test/reset",
    },
  },
  {
    test_id: "fallback-bec",
    category: "bec",
    attack_type: "bec_invoice_redirect",
    payload: {
      from: "ceo-spoofed@loadgen.test",
      to: "finance@loadgen.test",
      subject: "Quick favor — wire update",
      body_text:
        "Need this wire updated to the new account immediately. Send me the confirmation.",
    },
  },
  {
    test_id: "fallback-malware",
    category: "malware_attachment",
    attack_type: "malicious_attachment",
    payload: {
      from: "noreply@invoices-loadgen.test",
      to: "ap@loadgen.test",
      subject: "Invoice #INV-908213",
      body_text:
        "Please find the invoice attached. Open the document to view billing details.",
    },
  },
  {
    test_id: "fallback-newsletter",
    category: "benign_marketing",
    attack_type: "benign",
    payload: {
      from: "news@loadgen.test",
      to: "subscribers@loadgen.test",
      subject: "Weekly newsletter — product updates",
      body_text:
        "This week's product changes: faster ingest pipeline, new dashboard, and bug fixes.",
    },
  },
  {
    test_id: "fallback-supplier",
    category: "supplier_correspondence",
    attack_type: "benign",
    payload: {
      from: "ops@vendor.test",
      to: "procurement@loadgen.test",
      subject: "Shipment ETA update",
      body_text:
        "Shipment SH-1234 is now expected on Friday morning; tracking attached.",
    },
  },
  {
    test_id: "fallback-quishing",
    category: "qr_phishing",
    attack_type: "qr_phishing",
    payload: {
      from: "secure-portal@loadgen.test",
      to: "user@loadgen.test",
      subject: "Scan the QR to view your secure document",
      body_text: "Please scan the QR code to access your document.",
    },
  },
  {
    test_id: "fallback-out-of-office",
    category: "benign_auto_reply",
    attack_type: "benign",
    payload: {
      from: "vacation@loadgen.test",
      to: "anyone@loadgen.test",
      subject: "Out of office",
      body_text: "I'm out until Monday. For urgent matters contact backup@.",
    },
  },
];
