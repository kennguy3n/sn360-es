/*
 * Outlook pre-send add-in test harness (WS-7b)
 *
 * Mocks the Office.js context surface — userProfile, item.to/cc/bcc,
 * sessionData, notificationMessages, AsyncResultStatus, MailboxEnums,
 * and actions.associate — plus globalThis.fetch (so the predict API
 * call can be stubbed per scenario) and exercises the three pre-send
 * flows: recipient risk, client-side lookalike, and external-thread-
 * going-external.
 *
 * Uses Node's built-in test runner (node --test). The office-addin-mock
 * dependency is required at the top of the file per the WS-7b spec
 * — it surfaces install-time breakage in CI even though the bulk of
 * the Office.js mock surface used here is hand-crafted (the package's
 * load()/sync() helpers target Excel/Word/PowerPoint patterns and are
 * not a great fit for the Outlook event-handler API we exercise).
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

// Sanity-check the dependency declared in deployments/addins/package.json.
const { OfficeMockObject } = require("office-addin-mock");
void OfficeMockObject;

// === Mock builders ======================================================

function makeMockOffice(opts) {
  opts = opts || {};
  const sender = opts.sender || "alice@acme.com";
  const to = opts.to || [];
  const cc = opts.cc || [];
  const bcc = opts.bcc || [];
  const locale = opts.locale || "en-US";

  const sessionData = Object.assign({}, opts.initialSessionData || {});
  const notifications = [];

  function ok(value) {
    return { status: "succeeded", value: value };
  }
  function field(values) {
    return {
      getAsync: function (cb) {
        cb(ok(values));
      },
    };
  }
  return {
    AsyncResultStatus: { Succeeded: "succeeded", Failed: "failed" },
    MailboxEnums: {
      ItemNotificationMessageType: {
        ErrorMessage: "errorMessage",
        InformationalMessage: "informationalMessage",
      },
    },
    actions: { associate: function () {} },
    context: {
      displayLanguage: locale,
      mailbox: {
        userProfile: { emailAddress: sender },
        item: {
          to: field(to),
          cc: field(cc),
          bcc: field(bcc),
          sessionData: {
            getAsync: function (key, cb) {
              cb(ok(sessionData[key] == null ? null : sessionData[key]));
            },
            setAsync: function (key, value, cb) {
              sessionData[key] = value;
              cb(ok(undefined));
            },
          },
          notificationMessages: {
            replaceAsync: function (id, msg, cb) {
              notifications.push({ id: id, msg: msg });
              if (cb) cb(ok(undefined));
            },
          },
        },
      },
    },
    _sessionData: sessionData,
    _notifications: notifications,
  };
}

function makeRecipients(addresses, recipientType) {
  return addresses.map(function (a) {
    return { emailAddress: a, recipientType: recipientType || "ExternalUser" };
  });
}

function makeMockFetch(responseFor) {
  // responseFor: ({ url, body }) => { status, json } | "throw"
  const calls = [];
  const fn = async function (url, init) {
    let body = null;
    try {
      body = init && init.body ? JSON.parse(init.body) : null;
    } catch (_) {
      body = null;
    }
    calls.push({ url: url, body: body });
    const r = responseFor({ url: url, body: body });
    if (r === "throw") throw new Error("simulated network error");
    return {
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      json: async function () {
        return r.json;
      },
    };
  };
  fn.calls = calls;
  return fn;
}

function loadPresend(office, fetchImpl) {
  global.Office = office;
  if (fetchImpl) global.fetch = fetchImpl;
  if (!global.crypto || !global.crypto.subtle) {
    global.crypto = require("crypto").webcrypto;
  }
  const modulePath = require.resolve(path.resolve(__dirname, "../src/presend.js"));
  delete require.cache[modulePath];
  return require("../src/presend.js");
}

// === Damerau-Levenshtein ================================================

test("damerauLevenshtein", async function (t) {
  const presend = loadPresend(makeMockOffice());

  const cases = [
    { a: "hello", b: "hello", expected: 0, note: "identical" },
    { a: "hello", b: "", expected: 5, note: "empty b" },
    { a: "", b: "hello", expected: 5, note: "empty a" },
    { a: "acme.com", b: "acm3.com", expected: 1, note: "substitution" },
    { a: "gmail.com", b: "gmial.com", expected: 1, note: "transposition ai<->ia" },
    { a: "gmail.com", b: "gmaill.com", expected: 1, note: "insertion" },
    { a: "gmail.com", b: "gmal.com", expected: 1, note: "deletion" },
    { a: "acme.com", b: "ac.me.com", expected: 1, note: "insertion of '.'" },
    { a: "acme.com", b: "axxx.com", expected: 3, note: "three substitutions" },
  ];

  for (const c of cases) {
    await t.test(c.note + " '" + c.a + "' <-> '" + c.b + "'", function () {
      assert.equal(presend.damerauLevenshtein(c.a, c.b), c.expected);
    });
  }
});

// === findLookalike =====================================================

test("findLookalike", async function (t) {
  const presend = loadPresend(makeMockOffice());

  await t.test("returns null when domain matches a known domain exactly", function () {
    assert.equal(presend.findLookalike("acme.com", ["acme.com", "gmail.com"]), null);
  });

  await t.test("returns the closest known domain within threshold", function () {
    assert.equal(presend.findLookalike("acm3.com", ["acme.com"]), "acme.com");
    assert.equal(presend.findLookalike("gmial.com", ["gmail.com"]), "gmail.com");
  });

  await t.test("returns null when no known domain is within threshold", function () {
    assert.equal(presend.findLookalike("evil.example.org", ["acme.com", "gmail.com"]), null);
  });

  await t.test("returns null for empty known-domains list", function () {
    assert.equal(presend.findLookalike("acm3.com", []), null);
  });

  await t.test("prefers the closer match when multiple are within threshold", function () {
    // 'acme.cm' is distance 1 to both 'acme.com' (insertion) AND 'acme.cn' (substitution).
    // The first-best wins; we assert one of them.
    const got = presend.findLookalike("acme.cm", ["acme.com", "acme.cn"]);
    assert.ok(got === "acme.com" || got === "acme.cn");
  });
});

// === isThreadInternal ==================================================

test("isThreadInternal", async function (t) {
  const presend = loadPresend(makeMockOffice());

  await t.test("returns false for empty baseline", function () {
    assert.equal(presend.isThreadInternal([], "acme.com"), false);
  });
  await t.test("returns false when baseline contains an external domain", function () {
    assert.equal(presend.isThreadInternal(["acme.com", "vendor.com"], "acme.com"), false);
  });
  await t.test("returns true when every baseline domain matches sender domain", function () {
    assert.equal(presend.isThreadInternal(["acme.com", "acme.com"], "acme.com"), true);
  });
  await t.test("returns false when sender domain is empty", function () {
    assert.equal(presend.isThreadInternal(["acme.com"], ""), false);
  });
});

// === combineWarnings ===================================================

test("combineWarnings", async function (t) {
  const presend = loadPresend(makeMockOffice());

  await t.test("returns 0 overall when both sides are empty", function () {
    const combined = presend.combineWarnings({ overall_level: 0, warnings: [] }, []);
    assert.equal(combined.overall_level, 0);
    assert.equal(combined.warnings.length, 0);
  });

  await t.test("takes the max of server and client levels", function () {
    const api = { overall_level: 2, warnings: [{ code: "x", level: 2, message: "x" }] };
    const client = [{ code: "y", level: 4, message: "y" }];
    const combined = presend.combineWarnings(api, client);
    assert.equal(combined.overall_level, 4);
    assert.equal(combined.warnings.length, 2);
  });

  await t.test("handles missing API response", function () {
    const combined = presend.combineWarnings(null, [
      { code: "y", level: 3, message: "y" },
    ]);
    assert.equal(combined.overall_level, 3);
  });
});

// === Recipient gathering (To/Cc/Bcc) ===================================

test("gatherRecipients reads To, Cc, AND Bcc", async function () {
  const office = makeMockOffice({
    sender: "alice@acme.com",
    to: makeRecipients(["bob@acme.com"], "Internal"),
    cc: makeRecipients(["carol@partner.com"]),
    bcc: makeRecipients(["dave@evil.example.org"]),
  });
  const presend = loadPresend(office);
  const out = await presend._internals.gatherRecipients(office.context.mailbox.item);
  const emails = out.map(function (r) {
    return r.emailAddress;
  });
  assert.deepEqual(emails, ["bob@acme.com", "carol@partner.com", "dave@evil.example.org"]);
});

// === onMessageSend: Flow 1 (recipient risk) ============================

test("onMessageSend Flow 1: high-risk API response blocks send", async function () {
  const office = makeMockOffice({
    sender: "alice@acme.com",
    to: makeRecipients(["bob@partner.com"]),
  });
  const fetchImpl = makeMockFetch(function () {
    return {
      status: 200,
      json: {
        overall_level: 4,
        warnings: [
          {
            user_hash: "h1",
            level: 4,
            code: "lookalike_recipient",
            message: "Recipient domain partner.com looks similar to partner.io.",
          },
        ],
      },
    };
  });
  const presend = loadPresend(office, fetchImpl);

  let completed = null;
  await presend.onMessageSend({
    completed: function (arg) {
      completed = arg;
    },
  });
  assert.equal(completed.allowEvent, false, "high-risk should block send");
  assert.equal(office._notifications.length, 1);
  assert.match(office._notifications[0].msg.message, /ShieldNet 360/);
});

test("onMessageSend Flow 1: low-risk API response allows send", async function () {
  const office = makeMockOffice({
    sender: "alice@acme.com",
    to: makeRecipients(["bob@partner.com"]),
  });
  const fetchImpl = makeMockFetch(function () {
    return { status: 200, json: { overall_level: 0, warnings: [] } };
  });
  const presend = loadPresend(office, fetchImpl);

  let completed = null;
  await presend.onMessageSend({
    completed: function (arg) {
      completed = arg;
    },
  });
  assert.equal(completed.allowEvent, true);
  assert.equal(office._notifications.length, 0);
});

test("onMessageSend Flow 1: empty recipient list allows send without API call", async function () {
  const office = makeMockOffice({ sender: "alice@acme.com" });
  let fetchCalled = false;
  const fetchImpl = makeMockFetch(function () {
    fetchCalled = true;
    return { status: 200, json: { overall_level: 0, warnings: [] } };
  });
  const presend = loadPresend(office, fetchImpl);

  let completed = null;
  await presend.onMessageSend({
    completed: function (arg) {
      completed = arg;
    },
  });
  assert.equal(completed.allowEvent, true);
  assert.equal(fetchCalled, false, "no recipients ⇒ no API call");
});

test("onMessageSend Flow 1: API network error fails open", async function () {
  const office = makeMockOffice({
    sender: "alice@acme.com",
    to: makeRecipients(["bob@partner.com"]),
  });
  const fetchImpl = makeMockFetch(function () {
    return "throw";
  });
  const presend = loadPresend(office, fetchImpl);

  let completed = null;
  await presend.onMessageSend({
    completed: function (arg) {
      completed = arg;
    },
  });
  assert.equal(completed.allowEvent, true, "transport errors must never block sends");
});

test("onMessageSend Flow 1: Bcc recipients are included in the API call", async function () {
  const office = makeMockOffice({
    sender: "alice@acme.com",
    bcc: makeRecipients(["dave@evil.example.org"]),
  });
  const fetchImpl = makeMockFetch(function () {
    return { status: 200, json: { overall_level: 0, warnings: [] } };
  });
  const presend = loadPresend(office, fetchImpl);

  await presend.onMessageSend({ completed: function () {} });
  assert.equal(fetchImpl.calls.length, 1);
  assert.equal(fetchImpl.calls[0].body.recipients.length, 1);
  assert.equal(fetchImpl.calls[0].body.recipients[0].domain, "evil.example.org");
});

// === Flow 2: Client-side lookalike =====================================

test("onMessageSend Flow 2: client-side lookalike fires when recipient is near-miss of known domain", async function () {
  // Seed the known-domains cache with 'acme.com' (the sender's domain
  // is auto-seeded). Recipient 'acm3.com' should be flagged as a
  // lookalike via the client-side check.
  const office = makeMockOffice({
    sender: "alice@acme.com",
    to: makeRecipients(["bob@acm3.com"]),
  });
  // API returns clean — we want to verify the client-side warning
  // alone is enough to block.
  const fetchImpl = makeMockFetch(function () {
    return { status: 200, json: { overall_level: 0, warnings: [] } };
  });
  const presend = loadPresend(office, fetchImpl);

  let completed = null;
  await presend.onMessageSend({
    completed: function (arg) {
      completed = arg;
    },
  });
  assert.equal(completed.allowEvent, false, "client-side lookalike must block");
  assert.equal(office._notifications.length, 1);
  assert.match(
    office._notifications[0].msg.message,
    /acm3\.com.*acme\.com|Did you mean.*acme\.com/
  );
});

test("onMessageSend Flow 2: exact-match domain does NOT trigger lookalike", async function () {
  const office = makeMockOffice({
    sender: "alice@acme.com",
    to: makeRecipients(["bob@acme.com"], "Internal"),
  });
  const fetchImpl = makeMockFetch(function () {
    return { status: 200, json: { overall_level: 0, warnings: [] } };
  });
  const presend = loadPresend(office, fetchImpl);

  let completed = null;
  await presend.onMessageSend({
    completed: function (arg) {
      completed = arg;
    },
  });
  assert.equal(completed.allowEvent, true);
  assert.equal(office._notifications.length, 0);
});

test("showWarning: empty warnings synthesizes a distinct body, not a repeat of the title", function () {
  // High level with no per-warning detail (older/partial backend). The
  // dialog must still explain itself with a body line that differs from
  // the headline — mirroring the Gmail add-on. Never echo the title back.
  const office = makeMockOffice({ sender: "alice@acme.com" });
  const presend = loadPresend(office);

  let completed = null;
  presend._internals.showWarning(
    { completed: function (arg) { completed = arg; } },
    { overall_level: 3, warnings: [] }
  );

  assert.equal(completed.allowEvent, false, "high level must surface the blocking dialog");
  assert.notEqual(
    completed.errorMessage.indexOf("Take a moment before you send"),
    -1,
    "expected the generic headline in the dialog"
  );
  assert.notEqual(
    completed.errorMessage.indexOf("We spotted something worth a quick look"),
    -1,
    "expected a distinct generic body line, not a repeat of the headline"
  );
});

// === Flow 3: External-thread-going-external ============================

test("onMessageSend Flow 3: warns when an internal-only thread gains an external recipient", async function () {
  // Pre-seed baseline as 'acme.com' only. Then send with a new
  // external recipient 'partner.com'. The client-side check should
  // emit external_on_internal_thread_client.
  const baselineDomains = JSON.stringify(["acme.com"]);
  const office = makeMockOffice({
    sender: "alice@acme.com",
    to: makeRecipients(
      [
        "bob@acme.com", // baseline internal
        "carol@partner.com", // newly-added external
      ],
      "ExternalUser"
    ),
    initialSessionData: {
      "sn360.baseline.domains": baselineDomains,
      "sn360.baseline.captured": "1",
    },
  });
  const fetchImpl = makeMockFetch(function (req) {
    // We expect thread_is_internal=true to be sent.
    assert.equal(req.body.thread_is_internal, true);
    return { status: 200, json: { overall_level: 0, warnings: [] } };
  });
  const presend = loadPresend(office, fetchImpl);

  let completed = null;
  await presend.onMessageSend({
    completed: function (arg) {
      completed = arg;
    },
  });
  // overall_level reaches 3 (WarnWarning) via the client warning,
  // which is the threshold for blocking.
  assert.equal(completed.allowEvent, false, "external on internal thread must warn");
});

test("onMessageSend Flow 3: no warning when baseline already contains external", async function () {
  const baselineDomains = JSON.stringify(["acme.com", "vendor.com"]);
  const office = makeMockOffice({
    sender: "alice@acme.com",
    to: makeRecipients(["bob@acme.com", "carol@partner.com"], "ExternalUser"),
    initialSessionData: {
      "sn360.baseline.domains": baselineDomains,
      "sn360.baseline.captured": "1",
    },
  });
  const fetchImpl = makeMockFetch(function (req) {
    // Baseline has external ⇒ NOT internal.
    assert.equal(req.body.thread_is_internal, false);
    return { status: 200, json: { overall_level: 0, warnings: [] } };
  });
  const presend = loadPresend(office, fetchImpl);

  let completed = null;
  await presend.onMessageSend({
    completed: function (arg) {
      completed = arg;
    },
  });
  assert.equal(completed.allowEvent, true);
});

// === Predict request caching ===========================================

test("predict cache: identical recipient set ⇒ one fetch call across two sends", async function () {
  const office = makeMockOffice({
    sender: "alice@acme.com",
    to: makeRecipients(["bob@partner.com"]),
  });
  const fetchImpl = makeMockFetch(function () {
    return { status: 200, json: { overall_level: 0, warnings: [] } };
  });
  const presend = loadPresend(office, fetchImpl);

  await presend.onMessageSend({ completed: function () {} });
  await presend.onMessageSend({ completed: function () {} });
  assert.equal(fetchImpl.calls.length, 1, "second send should hit the cache");
});

test("predict cache key is invariant to recipient ordering", async function () {
  const office = makeMockOffice();
  const presend = loadPresend(office);
  const a = await presend._internals.predictCacheKey({
    sender_hash: "S",
    recipients: [{ user_hash: "h1" }, { user_hash: "h2" }, { user_hash: "h3" }],
    thread_is_internal: false,
  });
  const b = await presend._internals.predictCacheKey({
    sender_hash: "S",
    recipients: [{ user_hash: "h3" }, { user_hash: "h1" }, { user_hash: "h2" }],
    thread_is_internal: false,
  });
  assert.equal(a, b);
});

test("predict cache key collapses to SHA-256 when raw key exceeds 240 chars", async function () {
  const office = makeMockOffice();
  const presend = loadPresend(office);
  // 50 recipients × 64-char hash overflows the 240-char inline budget.
  const recipients = [];
  for (let i = 0; i < 50; i++) {
    const hex = String(i).padStart(2, "0").repeat(32);
    recipients.push({ user_hash: hex.slice(0, 64) });
  }
  const k = await presend._internals.predictCacheKey({
    sender_hash: "0123456789abcdef".repeat(4),
    recipients: recipients,
    thread_is_internal: true,
  });
  assert.ok(
    k.length < 240,
    "long cache keys must be collapsed (got length " + k.length + ")"
  );
  assert.ok(k.startsWith("sn360.predict."));
});

// === Locale-aware messages =============================================

test("locale: English locale produces English messages", async function () {
  const office = makeMockOffice({ locale: "en-US" });
  const presend = loadPresend(office);
  assert.equal(
    presend._internals.t("lookalike_recipient", { domain: "acm3.com", ref: "acme.com" }),
    "acm3.com looks almost identical to acme.com, a contact you've emailed before. Did you mean acme.com?"
  );
});

test("locale: unknown locale falls back to English", async function () {
  const office = makeMockOffice({ locale: "zz-ZZ" });
  const presend = loadPresend(office);
  // "zz" is not a supported bundle, so t() falls back to English.
  assert.match(presend._internals.t("external_on_internal_thread", { domain: "x.com" }), /external recipient/);
});

test("locale: supported non-English locale produces localized messages", async function () {
  const office = makeMockOffice({ locale: "ko-KR" });
  const presend = loadPresend(office);
  const msg = presend._internals.t("external_on_internal_thread", { domain: "x.com" });
  // Korean bundle is present; output must be the localized string, not English.
  assert.doesNotMatch(msg, /external recipient/);
  assert.match(msg, /외부 수신자/);
  assert.match(msg, /x\.com/);
});

// === Privacy: no raw email addresses in request body ==================

test("privacy: raw email addresses never appear in the predict request body", async function () {
  const office = makeMockOffice({
    sender: "alice@acme.com",
    to: makeRecipients(["bob@partner.com"]),
    bcc: makeRecipients(["dave@evil.example.org"]),
  });
  const fetchImpl = makeMockFetch(function () {
    return { status: 200, json: { overall_level: 0, warnings: [] } };
  });
  const presend = loadPresend(office, fetchImpl);

  await presend.onMessageSend({ completed: function () {} });
  const sent = JSON.stringify(fetchImpl.calls[0].body);
  assert.equal(sent.indexOf("alice@acme.com"), -1, "sender email leaked");
  assert.equal(sent.indexOf("bob@partner.com"), -1, "to recipient leaked");
  assert.equal(sent.indexOf("dave@evil.example.org"), -1, "bcc recipient leaked");
  // Domains ARE sent (not PII).
  assert.notEqual(sent.indexOf("partner.com"), -1);
});
